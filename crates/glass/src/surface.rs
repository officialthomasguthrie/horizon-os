// The Glass surface layout: the Model turned into a flat scene of primitives.
//
// `report::text` renders the model as a terminal dashboard; this renders it as a
// drawn one. The split is the same as the compositor's: layout is pure (model
// in, a `Scene` of positioned rects and text out) so it is reproducible and
// tested without a display, and the only thing a screen adds is rasterizing the
// scene to pixels (`raster`) and putting that on a GPU (the compositor). The
// scene also carries hit targets, so a click on the drawn surface maps back to
// an action (severing a channel) the same way the text view's grant id does.
//
// Coordinates are physical pixels. Text is the 8x8 bitmap font drawn at an
// integer `scale`, so a glyph cell is `8 * scale` pixels and the whole surface
// stays crisp at any size, the minimal developer look the rest of Horizon uses.

use weave::GrantId;

use crate::aura::{self, Palette, Proposal};
use crate::model::{Channel, ChannelStatus, Model, PrincipalView};

// One bitmap glyph is 8x8; everything sizes off this.
pub const GLYPH: i32 = 8;

// How many plan steps a pending proposal draws before collapsing the rest into a
// "+k more" line, so a long plan cannot grow the band off the screen. The
// standard file plans are one step, so this only bounds a pathological one.
const PROPOSAL_MAX_STEPS: usize = 6;

// An RGBA color. Opaque unless an alpha is given, for the few translucent
// overlays (the header band, the dimmed chrome).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color { r, g, b, a: 255 }
    }
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color {
        Color { r, g, b, a }
    }
}

// A dark, terminal-style palette. Status carries meaning by color: live is
// green, severed red, blocked amber, expired grey.
pub const BG: Color = Color::rgb(0x10, 0x12, 0x16);
pub const PANEL: Color = Color::rgb(0x17, 0x1a, 0x21);
pub const RULE: Color = Color::rgb(0x2a, 0x2f, 0x38);
pub const FG: Color = Color::rgb(0xc8, 0xcc, 0xd4);
pub const TITLE: Color = Color::rgb(0xe9, 0xec, 0xf1);
pub const DIM: Color = Color::rgb(0x6b, 0x73, 0x82);
pub const LIVE: Color = Color::rgb(0x46, 0xc0, 0x5a);
pub const SEVERED: Color = Color::rgb(0xe5, 0x4b, 0x4f);
pub const BLOCKED: Color = Color::rgb(0xd8, 0xa2, 0x2a);
pub const EXPIRED: Color = Color::rgb(0x7a, 0x82, 0x90);
pub const NET: Color = Color::rgb(0x4a, 0xb0, 0xd0);
pub const ACCENT: Color = Color::rgb(0x6c, 0xb6, 0xff);
pub const BAR: Color = Color::rgb(0x35, 0x52, 0x6e);
pub const BAR_HI: Color = Color::rgb(0x5a, 0x8c, 0xc0);

fn status_color(s: ChannelStatus) -> Color {
    match s {
        ChannelStatus::Live => LIVE,
        ChannelStatus::Severed => SEVERED,
        ChannelStatus::Expired => EXPIRED,
        ChannelStatus::Blocked => BLOCKED,
    }
}

// A drawable: a filled rectangle or a run of text. The scene is a flat list of
// these in paint order (back to front).
#[derive(Clone, Debug, PartialEq)]
pub enum Primitive {
    Rect {
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        color: Color,
    },
    Text {
        x: i32,
        y: i32,
        scale: i32,
        color: Color,
        text: String,
    },
}

// What a click on a region of the surface does. Only severing a live channel is
// actionable today; the kill switch the text view exposes as a grant id is a hit
// target here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Sever(GrantId),
}

// A clickable region mapped to an action.
#[derive(Clone, Debug)]
pub struct Hit {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub action: Action,
}

impl Hit {
    pub fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x && px < self.x + self.w && py >= self.y && py < self.y + self.h
    }
}

// The whole surface for one render: its size, the primitives to paint, and the
// hit targets to test clicks against.
#[derive(Clone, Debug)]
pub struct Scene {
    pub width: i32,
    pub height: i32,
    pub bg: Color,
    pub prims: Vec<Primitive>,
    pub hits: Vec<Hit>,
}

impl Scene {
    // The action under a point, if any (topmost hit wins).
    pub fn action_at(&self, x: i32, y: i32) -> Option<&Action> {
        self.hits
            .iter()
            .rev()
            .find(|h| h.contains(x, y))
            .map(|h| &h.action)
    }
}

// Width in pixels of a string drawn at `scale`.
pub fn text_width(s: &str, scale: i32) -> i32 {
    s.chars().count() as i32 * GLYPH * scale
}

// A small builder that tracks the running layout cursor and accumulates
// primitives and hits. Keeps the layout code linear and readable.
struct Surface {
    width: i32,
    height: i32,
    scale: i32,
    margin: i32,
    cell: i32,
    line: i32,
    prims: Vec<Primitive>,
    hits: Vec<Hit>,
}

impl Surface {
    fn new(width: i32, height: i32, scale: i32) -> Surface {
        let cell = GLYPH * scale;
        Surface {
            width,
            height,
            scale,
            margin: 2 * cell,
            cell,
            line: cell + 4 * scale,
            prims: Vec::new(),
            hits: Vec::new(),
        }
    }

    fn rect(&mut self, x: i32, y: i32, w: i32, h: i32, color: Color) {
        self.prims.push(Primitive::Rect { x, y, w, h, color });
    }

    // Draw text at the scene scale, return the x just past it for chaining.
    fn text(&mut self, x: i32, y: i32, color: Color, s: impl Into<String>) -> i32 {
        let s = s.into();
        let w = text_width(&s, self.scale);
        self.prims.push(Primitive::Text {
            x,
            y,
            scale: self.scale,
            color,
            text: s,
        });
        x + w
    }

    // A 1px (scaled) horizontal rule across the content width.
    fn rule(&mut self, y: i32) {
        self.rect(
            self.margin,
            y,
            self.width - 2 * self.margin,
            self.scale,
            RULE,
        );
    }
}

// Lay the model out into a scene `width` x `height`, text at `scale` (1, 2, ...).
// `palette` is the Aura command line: its filter narrows the principal list, and
// it is drawn in the band at the bottom (the launcher and command palette).
pub fn layout(model: &Model, palette: &Palette, width: u32, height: u32, scale: u32) -> Scene {
    let scale = scale.max(1) as i32;
    let mut s = Surface::new(width as i32, height as i32, scale);

    // Reserve the palette band at the very bottom and lay the rest out above it.
    // It is the input line plus one or more rows below: the one-line feedback
    // normally, or a pending Aura proposal (its steps, their capabilities, and a
    // confirm line), which grows the band upward into the room above.
    let pad = 3 * scale;
    let band_h = 2 * pad + (1 + band_below_rows(palette)) * s.line;
    let band_y = s.height - s.margin / 2 - band_h;

    let mut y = s.margin;
    y = header(&mut s, model, y);
    y += s.line / 2;
    y = timeline(&mut s, model, y);
    y += s.line / 2;
    s.rule(y);
    y += s.line;

    // The principal list, narrowed to the palette's filter and clipped to the
    // room above the band. Relative times are measured against the window end.
    let now = model.window.end_unix;
    let list_bottom = band_y - s.line;
    let filter = palette.filter.as_deref().filter(|q| !q.trim().is_empty());
    let shown: Vec<&PrincipalView> = match filter {
        Some(q) => model
            .principals
            .iter()
            .filter(|p| aura::principal_matches(p, q))
            .collect(),
        None => model.principals.iter().collect(),
    };
    if shown.is_empty() {
        let msg = match filter {
            Some(q) => format!("no match for '{q}'"),
            None => "no activity".to_string(),
        };
        s.text(s.margin, y, DIM, msg);
    } else {
        for (i, p) in shown.iter().enumerate() {
            // Stop before the band; a principal block is at least 2 rows.
            if y + 2 * s.line > list_bottom {
                let left = shown.len() - i;
                if left > 0 {
                    s.text(s.margin, y, DIM, format!("+{left} more"));
                }
                break;
            }
            y = principal(&mut s, p, now, y, list_bottom);
            y += s.line / 2;
        }
    }

    palette_band(&mut s, palette, band_y, band_h);

    Scene {
        width: s.width,
        height: s.height,
        bg: BG,
        prims: s.prims,
        hits: s.hits,
    }
}

fn header(s: &mut Surface, model: &Model, mut y: i32) -> i32 {
    // A faint band behind the header chrome.
    s.rect(0, 0, s.width, y + 2 * s.line + s.line / 2, PANEL);

    let title_end = s.text(s.margin, y, TITLE, "glass");
    s.text(
        title_end + s.cell,
        y,
        DIM,
        format!("{} window", span_label(model.window.span())),
    );
    let asof = format!("as of {}", model.window.end_unix);
    s.text(
        s.width - s.margin - text_width(&asof, s.scale),
        y,
        DIM,
        asof,
    );
    y += s.line;

    // Totals, each count colored by what it means.
    let t = model.totals;
    let segs = [
        (format!("{} principals", t.principals), FG),
        (format!("{} live", t.live), LIVE),
        (format!("{} network", t.network), NET),
        (format!("{} blocked", t.blocked), BLOCKED),
        (format!("{} severed", t.severed), SEVERED),
    ];
    let mut x = s.margin;
    for (text, color) in segs {
        x = s.text(x, y, color, text);
        x += s.cell * 2;
    }
    y + s.line
}

fn timeline(s: &mut Surface, model: &Model, y: i32) -> i32 {
    let label_end = s.text(s.margin, y, DIM, "timeline");
    let counts = format!(
        "grants {}  uses {}  denials {}  revokes {}",
        sum(model, |b| b.grants),
        sum(model, |b| b.uses),
        sum(model, |b| b.denials),
        sum(model, |b| b.revokes),
    );
    s.text(
        s.width - s.margin - text_width(&counts, s.scale),
        y,
        DIM,
        counts,
    );

    // Bars for the buckets, in a band two lines tall, baseline-aligned.
    let band = s.line * 2;
    let baseline = y + band;
    let bars_x = label_end + s.cell * 2;
    let bar_w = s.cell;
    let gap = 2 * s.scale;
    let max = model.timeline.iter().map(|b| b.total()).max().unwrap_or(0);
    for (i, b) in model.timeline.iter().enumerate() {
        let bx = bars_x + i as i32 * (bar_w + gap);
        if bx + bar_w > s.width - s.margin {
            break;
        }
        let h = if max == 0 || b.total() == 0 {
            0
        } else {
            ((band - s.scale) * b.total() as i32 / max as i32).max(s.scale)
        };
        // A faint floor tick even for empty buckets, so the axis reads.
        s.rect(bx, baseline - s.scale, bar_w, s.scale, RULE);
        if h > 0 {
            let color = if b.total() == max { BAR_HI } else { BAR };
            s.rect(bx, baseline - h, bar_w, h, color);
        }
    }
    baseline
}

fn principal(s: &mut Surface, p: &PrincipalView, now: u64, mut y: i32, list_bottom: i32) -> i32 {
    // Name, with how long ago it was last active on the right.
    let name = p.principal.to_string();
    s.text(s.margin, y, TITLE, name);
    if let Some(t) = p.last_unix {
        let ago = ago(now, t);
        s.text(s.width - s.margin - text_width(&ago, s.scale), y, DIM, ago);
    }
    y += s.line;

    for c in &p.channels {
        if y + s.line > list_bottom {
            break;
        }
        y = channel(s, c, y);
    }
    y
}

fn channel(s: &mut Surface, c: &Channel, y: i32) -> i32 {
    let col = status_color(c.status);
    // A status-colored tab at the left edge of the row.
    s.rect(s.margin - s.cell, y, s.scale * 2, s.cell, col);

    // Fixed columns: status, kind, rights, then the resource.
    let x0 = s.margin;
    let mut x = s.text(x0, y, col, c.status.label());
    x = align(x0, x, 9, s);
    x = s.text(x, y, DIM, c.kind.label());
    x = align(x0, x, 13, s);
    x = s.text(x, y, FG, c.rights.to_string());
    x = align(x0, x, 18, s);

    let res_color = if c.kind == crate::model::ChannelKind::Network {
        NET
    } else {
        FG
    };
    // Usage counts trail the resource, when there are any.
    let mut tail = String::new();
    if c.uses > 0 {
        tail.push_str(&format!("  {} {}", c.uses, plural(c.uses, "use", "uses")));
    }
    if c.denials > 0 {
        tail.push_str(&format!("  {} blocked", c.denials));
    }
    if tail.is_empty() {
        s.text(x, y, res_color, c.resource.to_string());
    } else {
        let res_end = s.text(x, y, res_color, c.resource.to_string());
        s.text(res_end + s.cell, y, DIM, tail);
    }

    // The kill switch on the right: a button for a severable channel, the grant
    // id dim for an already-dead or non-severable one.
    if let Some(g) = c.grant {
        if c.can_sever() {
            let label = "sever";
            let bw = text_width(label, s.scale) + 2 * s.cell;
            let bx = s.width - s.margin - bw;
            let bh = s.cell + 2 * s.scale;
            s.rect(bx, y - s.scale, bw, bh, Color::rgb(0x2a, 0x1a, 0x1c));
            s.text(bx + s.cell, y, SEVERED, label);
            s.hits.push(Hit {
                x: bx,
                y: y - s.scale,
                w: bw,
                h: bh,
                action: Action::Sever(g),
            });
        } else {
            let hex = g.to_hex();
            let id = short(&hex);
            s.text(s.width - s.margin - text_width(id, s.scale), y, DIM, id);
        }
    }

    let mut y = y + s.line;
    // Sub-resources actually touched, indented and dim, a few at most.
    for a in c.accessed.iter().take(3) {
        s.text(s.margin + 2 * s.cell, y, DIM, a.to_string());
        y += s.line;
    }
    if c.accessed.len() > 3 {
        s.text(
            s.margin + 2 * s.cell,
            y,
            DIM,
            format!("+{} more", c.accessed.len() - 3),
        );
        y += s.line;
    }
    y
}

// The number of text rows the band draws below the input row: one for the
// feedback line normally, or, when a proposal is pending, one per step plus one
// per capability it needs plus the confirm line (a failed proposal is just its
// one reason row). Sizing and drawing read this the same way so the band fits.
fn band_below_rows(palette: &Palette) -> i32 {
    match &palette.proposal {
        None => 1,
        Some(p) if p.failed.is_some() => 1,
        Some(p) => {
            let shown = p.steps.len().min(PROPOSAL_MAX_STEPS);
            let mut rows = 0;
            for st in p.steps.iter().take(shown) {
                rows += 1 + st.needs.len() as i32;
            }
            if p.steps.len() > shown {
                rows += 1; // the "+k more steps" line
            }
            rows + 1 // the confirm line
        }
    }
}

// The Aura command palette at the bottom: an input row (prompt, the typed line,
// and a caret at the cursor) and, under it, either a pending proposal or the
// one-line feedback (the palette's message, or the idle hint when it has none).
// The text is fixed width, so the caret sits at the cursor's character column.
fn palette_band(s: &mut Surface, palette: &Palette, y: i32, h: i32) {
    s.rect(0, y, s.width, h, PANEL);
    s.rect(0, y, s.width, s.scale, RULE);
    let pad = 3 * s.scale;
    let ty = y + pad;

    let prompt_end = s.text(s.margin, ty, ACCENT, ">");
    let text_x = prompt_end + s.cell;
    if !palette.input.is_empty() {
        s.text(text_x, ty, FG, palette.input.clone());
    }
    let caret_x = text_x + palette.cursor as i32 * s.cell;
    s.rect(
        caret_x,
        ty - s.scale,
        s.scale * 2,
        s.cell + 2 * s.scale,
        ACCENT,
    );

    match &palette.proposal {
        Some(p) => proposal_rows(s, p, ty + s.line),
        None => {
            let msg = if palette.message.trim().is_empty() {
                aura::HINT_IDLE
            } else {
                palette.message.as_str()
            };
            s.text(s.margin, ty + s.line, DIM, msg);
        }
    }
}

// Draw a pending plan under the input row: each step (its tool, effect, and the
// model's rationale, amber when the step is hard-blocked), each capability it
// needs indented beneath it (dim when held, amber when missing), and a final
// confirm line stating what Enter does. A plan the planner could not produce is
// just its reason in red. Sized by `band_below_rows`, so the band already fits.
fn proposal_rows(s: &mut Surface, p: &Proposal, mut y: i32) {
    if let Some(reason) = &p.failed {
        s.text(s.margin, y, SEVERED, format!("Aura: {reason}"));
        return;
    }
    let shown = p.steps.len().min(PROPOSAL_MAX_STEPS);
    for (i, st) in p.steps.iter().take(shown).enumerate() {
        let head = match &st.block {
            Some(b) => format!(
                "{}. {}  ({})  {} -- {b}",
                i + 1,
                st.tool,
                st.effect,
                st.rationale
            ),
            None => format!("{}. {}  ({})  {}", i + 1, st.tool, st.effect, st.rationale),
        };
        let color = if st.block.is_some() { BLOCKED } else { FG };
        s.text(s.margin, y, color, head);
        y += s.line;
        for n in &st.needs {
            let (mark, color) = if n.held {
                ("held", DIM)
            } else {
                ("missing", BLOCKED)
            };
            s.text(
                s.margin + 2 * s.cell,
                y,
                color,
                format!("{}  {}  {mark}", n.resource, n.rights),
            );
            y += s.line;
        }
    }
    if p.steps.len() > shown {
        s.text(
            s.margin,
            y,
            DIM,
            format!("+{} more steps", p.steps.len() - shown),
        );
        y += s.line;
    }
    let foot = if p.destructive { SEVERED } else { ACCENT };
    s.text(s.margin, y, foot, p.confirm_hint());
}

// Right-pad the cursor to a column (in cells) from the row's left edge, so the
// fixed columns of a channel row line up regardless of field width.
fn align(x0: i32, x: i32, col: i32, s: &Surface) -> i32 {
    (x0 + col * s.cell).max(x + s.cell)
}

fn sum(model: &Model, f: impl Fn(&crate::model::Bucket) -> u32) -> u32 {
    model.timeline.iter().map(f).sum()
}

fn ago(now: u64, t: u64) -> String {
    let d = now.saturating_sub(t);
    if d == 0 {
        return "now".to_string();
    }
    if d < 60 {
        return format!("{d}s ago");
    }
    if d < 3600 {
        return format!("{}m ago", d / 60);
    }
    if d < 86_400 {
        return format!("{}h ago", d / 3600);
    }
    format!("{}d ago", d / 86_400)
}

fn span_label(span: u64) -> String {
    if span == 0 {
        return "0s".to_string();
    }
    if span.is_multiple_of(86_400) {
        return format!("{}d", span / 86_400);
    }
    if span.is_multiple_of(3600) {
        return format!("{}h", span / 3600);
    }
    format!("{span}s")
}

fn short(hex: &str) -> &str {
    &hex[..hex.len().min(8)]
}

fn plural(n: u32, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{build, Window};
    use crate::tests_support::{demo_model, NOW};
    use crate::DEFAULT_BUCKETS;

    // Every Text primitive's string, for substring checks.
    fn texts(scene: &Scene) -> Vec<String> {
        scene
            .prims
            .iter()
            .filter_map(|p| match p {
                Primitive::Text { text, .. } => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    fn has_text(scene: &Scene, needle: &str) -> bool {
        texts(scene).iter().any(|t| t.contains(needle))
    }

    // An idle palette: nothing typed, no filter, the layout most tests want.
    fn idle() -> Palette {
        Palette::new()
    }

    #[test]
    fn scene_matches_requested_size() {
        let scene = layout(&demo_model(), &idle(), 1024, 600, 2);
        assert_eq!(scene.width, 1024);
        assert_eq!(scene.height, 600);
        assert_eq!(scene.bg, BG);
    }

    #[test]
    fn empty_model_says_no_activity() {
        let empty = build(&[], &[], Window::week(NOW), DEFAULT_BUCKETS);
        let scene = layout(&empty, &idle(), 800, 400, 2);
        assert!(has_text(&scene, "no activity"));
    }

    #[test]
    fn header_and_palette_band_are_drawn() {
        let scene = layout(&demo_model(), &idle(), 1000, 700, 2);
        assert!(has_text(&scene, "glass"));
        assert!(has_text(&scene, "principals"));
        // The idle palette shows the prompt and the verb hint.
        assert!(has_text(&scene, ">"));
        assert!(has_text(&scene, "launch"));
        assert!(has_text(&scene, "sever"));
    }

    #[test]
    fn principal_names_appear() {
        let scene = layout(&demo_model(), &idle(), 1200, 800, 2);
        for name in ["mail", "aura", "sync"] {
            assert!(has_text(&scene, name), "missing principal {name}");
        }
    }

    #[test]
    fn the_typed_line_and_its_message_are_drawn() {
        let palette = Palette {
            input: "sever mail".to_string(),
            cursor: 10,
            message: "Enter to sever 1 channel".to_string(),
            filter: Some("mail".to_string()),
            ..Palette::new()
        };
        let scene = layout(&demo_model(), &palette, 1200, 800, 2);
        assert!(has_text(&scene, "sever mail"));
        assert!(has_text(&scene, "Enter to sever 1 channel"));
    }

    #[test]
    fn a_pending_proposal_draws_its_steps_needs_and_confirm() {
        use crate::aura::{Proposal, ProposalNeed, ProposalStep};
        let proposal = Proposal::new(
            "read /etc/hosts",
            vec![ProposalStep {
                tool: "read_file".into(),
                rationale: "read /etc/hosts".into(),
                effect: "read".into(),
                needs: vec![ProposalNeed {
                    resource: "file:/etc/hosts".into(),
                    rights: "r".into(),
                    held: false,
                }],
                block: None,
            }],
        );
        let palette = Palette {
            input: "ask read /etc/hosts".to_string(),
            cursor: 19,
            proposal: Some(proposal),
            ..Palette::new()
        };
        let scene = layout(&demo_model(), &palette, 1200, 800, 2);
        // The typed intent, the tool, the needed (missing) capability, and the
        // confirm line all appear in the band.
        assert!(has_text(&scene, "ask read /etc/hosts"));
        assert!(has_text(&scene, "read_file"));
        assert!(has_text(&scene, "file:/etc/hosts"));
        assert!(has_text(&scene, "missing"));
        assert!(has_text(&scene, "approve 1 capability"));
    }

    #[test]
    fn a_failed_proposal_draws_its_reason() {
        let palette = Palette {
            input: "ask teleport".to_string(),
            cursor: 12,
            proposal: Some(crate::aura::Proposal::failed("teleport", "no such verb")),
            ..Palette::new()
        };
        let scene = layout(&demo_model(), &palette, 1000, 700, 2);
        assert!(has_text(&scene, "no such verb"));
    }

    #[test]
    fn a_filter_narrows_the_principal_list() {
        let palette = Palette {
            filter: Some("mail".to_string()),
            ..Palette::new()
        };
        let scene = layout(&demo_model(), &palette, 1200, 800, 2);
        // Only the matching principal shows; the others drop out of the list.
        assert!(has_text(&scene, "mail"));
        assert!(!has_text(&scene, "sync"), "sync should be filtered out");
    }

    #[test]
    fn a_filter_with_no_match_says_so() {
        let palette = Palette {
            filter: Some("zzz".to_string()),
            ..Palette::new()
        };
        let scene = layout(&demo_model(), &palette, 1200, 800, 2);
        assert!(has_text(&scene, "no match for 'zzz'"));
    }

    #[test]
    fn severable_channels_get_a_hit_and_dead_ones_do_not() {
        let m = demo_model();
        let scene = layout(&m, &idle(), 1200, 800, 2);
        for p in &m.principals {
            for c in &p.channels {
                let Some(g) = c.grant else { continue };
                let hit = scene.hits.iter().any(|h| h.action == Action::Sever(g));
                assert_eq!(
                    hit,
                    c.can_sever(),
                    "grant {g:?} hit={hit} can_sever={}",
                    c.can_sever()
                );
            }
        }
    }

    #[test]
    fn a_sever_hit_resolves_back_from_its_own_rect() {
        let m = demo_model();
        let scene = layout(&m, &idle(), 1200, 800, 2);
        let hit = scene.hits.first().expect("a severable channel exists");
        let action = scene.action_at(hit.x + 1, hit.y + 1);
        assert_eq!(action, Some(&hit.action));
    }
}
