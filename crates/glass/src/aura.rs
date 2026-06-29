// Aura's command line: turning a typed line into an intent, then resolving that
// intent against the live Model into something the shell can act on.
//
// This is the launcher and command palette behind the Glass intent line. It
// keeps to the same headless split as the rest of Glass: parsing is pure string
// work, resolution is a pure fold over the Model, and the editable buffer is
// plain state, so all three are tested here with no display. The only parts that
// need a screen sit above this: the key routing that feeds keystrokes in (the
// compositor reports them when no client holds focus) and the app spawn a
// `Launch` triggers (the shell).

use weave::GrantId;

use crate::model::{Channel, Model, PrincipalView};

// The hint shown when nothing is typed: the verbs on offer. Also the line the
// surface falls back to when the palette has no message of its own. `ask` leads
// because it is the headline: a natural-language intent Aura plans and brokers.
pub const HINT_IDLE: &str = "ask <intent>   launch <app>   sever <name>   type to filter   help";

/// A command parsed from the palette input: a verb and its argument. Pure string
/// work with no Model, so it is tested on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Nothing actionable typed (empty or whitespace only).
    Empty,
    /// Hand a natural-language intent to Aura: `ask <intent>` (also `do`).
    /// Glass cannot plan it (the model lives in the shell), so this only carries
    /// the intent text out; the shell runs the planner, previews the
    /// capabilities, and brokers the plan on confirm. ("aura" is not a verb: it
    /// is the principal's own name, so it stays usable as a filter query.)
    Ask(String),
    /// Launch an app: `launch <cmd>`, `run <cmd>`, or `open <cmd>`.
    Launch(String),
    /// Sever the live channels matching a query: `sever <query>` (also `revoke`,
    /// `kill`).
    Sever(String),
    /// List the commands: `help` or `?`.
    Help,
    /// Any other text: a bare query that filters the view.
    Filter(String),
}

/// Parse one input line into a [`Command`]. The first word is the verb; the rest
/// is its argument. An unknown verb is treated as a filter query, so plain text
/// narrows the view without a keyword.
pub fn parse(line: &str) -> Command {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Command::Empty;
    }
    let (verb, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((v, r)) => (v, r.trim()),
        None => (trimmed, ""),
    };
    match verb {
        "ask" | "do" => Command::Ask(rest.to_string()),
        "launch" | "run" | "open" => Command::Launch(rest.to_string()),
        "sever" | "revoke" | "kill" => Command::Sever(rest.to_string()),
        "help" | "?" => Command::Help,
        _ => Command::Filter(trimmed.to_string()),
    }
}

/// What pressing Enter on the current input will do, once resolved against the
/// model. The shell carries each of these out (spawning a process, severing
/// through Glass); resolution itself stays pure and screen-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaletteAction {
    /// Nothing to commit (empty, help, a bare filter, or no match).
    None,
    /// Hand this intent to Aura: the shell runs the planner, previews the
    /// capabilities the plan needs, and (on confirm) executes through the
    /// broker. Glass only classifies the line; the plan and the brokering live
    /// in the shell, the same way [`PaletteAction::Launch`] hands a command
    /// line out to be spawned.
    Ask(String),
    /// Spawn this command line as a client (ideally confined in a Cell).
    Launch(String),
    /// Revoke these grants, one Glass sever each.
    Sever(Vec<GrantId>),
}

/// The resolution of an input line against the model: what Enter does, how the
/// view should be filtered to preview it, and a one-line hint for the band.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    pub action: PaletteAction,
    pub filter: Option<String>,
    pub hint: String,
}

/// Parse and resolve a line in one step.
pub fn interpret(line: &str, model: &Model) -> Resolved {
    resolve(&parse(line), model)
}

/// Resolve a parsed command against the model. Pure: no I/O and no broker, so a
/// test drives a line and asserts the action, the filter, and the hint.
pub fn resolve(cmd: &Command, model: &Model) -> Resolved {
    match cmd {
        Command::Empty => Resolved {
            action: PaletteAction::None,
            filter: None,
            hint: HINT_IDLE.to_string(),
        },
        Command::Help => Resolved {
            action: PaletteAction::None,
            filter: None,
            hint: "ask <intent> plans and brokers through Aura   launch <app> spawns a client   \
                   sever <name> revokes matching channels   any other text filters the view"
                .to_string(),
        },
        Command::Ask(intent) => {
            let intent = intent.trim();
            if intent.is_empty() {
                Resolved {
                    action: PaletteAction::None,
                    filter: None,
                    hint: "ask: say what you want Aura to do".to_string(),
                }
            } else {
                Resolved {
                    action: PaletteAction::Ask(intent.to_string()),
                    filter: None,
                    hint: format!("Enter to ask Aura: {intent}"),
                }
            }
        }
        Command::Launch(program) => {
            let program = program.trim();
            if program.is_empty() {
                Resolved {
                    action: PaletteAction::None,
                    filter: None,
                    hint: "launch: name a program to run".to_string(),
                }
            } else {
                Resolved {
                    action: PaletteAction::Launch(program.to_string()),
                    filter: None,
                    hint: format!("Enter to launch {program}"),
                }
            }
        }
        Command::Filter(q) => {
            let n = model
                .principals
                .iter()
                .filter(|p| principal_matches(p, q))
                .count();
            let hint = if n == 0 {
                format!("no match for '{q}'")
            } else {
                format!(
                    "filtering '{q}': {n} {}",
                    plural(n, "principal", "principals")
                )
            };
            Resolved {
                action: PaletteAction::None,
                filter: Some(q.clone()),
                hint,
            }
        }
        Command::Sever(q) => {
            let q = q.trim();
            if q.is_empty() {
                return Resolved {
                    action: PaletteAction::None,
                    filter: None,
                    hint: "sever: name a principal or resource".to_string(),
                };
            }
            // Every live, severable channel the query touches (its principal,
            // resource, or kind). One grant can back several rows, so dedup.
            let mut grants: Vec<GrantId> = Vec::new();
            for c in model.principals.iter().flat_map(|p| &p.channels) {
                if c.can_sever() && channel_matches(c, q) {
                    if let Some(g) = c.grant {
                        if !grants.contains(&g) {
                            grants.push(g);
                        }
                    }
                }
            }
            let filter = Some(q.to_string());
            if grants.is_empty() {
                Resolved {
                    action: PaletteAction::None,
                    filter,
                    hint: format!("no live channel matches '{q}'"),
                }
            } else {
                let n = grants.len();
                Resolved {
                    action: PaletteAction::Sever(grants),
                    filter,
                    hint: format!("Enter to sever {n} {}", plural(n, "channel", "channels")),
                }
            }
        }
    }
}

/// Whether a principal is shown under a filter query: its name matches, or any of
/// its channels do. Used by both resolution and the surface layout, so the live
/// preview and the count agree.
pub fn principal_matches(p: &PrincipalView, q: &str) -> bool {
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    p.principal.0.to_lowercase().contains(&q) || p.channels.iter().any(|c| channel_contains(c, &q))
}

/// Whether a channel matches a query (by its principal, resource, or kind).
pub fn channel_matches(c: &Channel, q: &str) -> bool {
    let q = q.trim().to_lowercase();
    q.is_empty() || channel_contains(c, &q)
}

fn channel_contains(c: &Channel, q_lower: &str) -> bool {
    c.principal.0.to_lowercase().contains(q_lower)
        || c.resource.to_string().to_lowercase().contains(q_lower)
        || c.kind.label().contains(q_lower)
}

fn plural(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}

/// A plan Aura has proposed for an `ask` intent, reduced to what the surface
/// draws and the palette holds while it awaits a confirm. The shell builds this
/// from `aura::Preview` (which it cannot expose here without coupling Glass to
/// the model engine), so this is plain data: Glass renders it and computes the
/// confirm line from it, but never produces it. A confirm grants the missing
/// capabilities and runs the plan through the broker; an Esc dismisses it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Proposal {
    /// The natural-language intent the plan came from.
    pub intent: String,
    /// The tool calls the plan would make, in order.
    pub steps: Vec<ProposalStep>,
    /// Every tool is known, its arguments parse, and every capability it needs
    /// is already held: the plan runs as-is (a destructive step still wants the
    /// confirm, which is the same Enter).
    pub ready: bool,
    /// At least one step mutates irreversibly (a move or a delete), so the
    /// confirm is also the destructive confirmation.
    pub destructive: bool,
    /// Set when the planner could not turn the intent into a plan at all (an
    /// intent it cannot serve, or no model in this build): there is nothing to
    /// run, and the confirm just dismisses it.
    pub failed: Option<String>,
}

/// One tool call in a [`Proposal`]: which tool, why, what it would touch, and
/// the capabilities it needs (each marked held or missing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalStep {
    pub tool: String,
    pub rationale: String,
    /// The effect class: "read", "write", or "destructive".
    pub effect: String,
    /// The capabilities this step needs (resource + rights), each held or not.
    pub needs: Vec<ProposalNeed>,
    /// A hard reason the step cannot run (an unknown tool or bad arguments),
    /// which approving a capability would not fix. A merely-missing capability
    /// is carried on `needs`, not here.
    pub block: Option<String>,
}

/// One capability a [`ProposalStep`] needs: the resource and rights, and whether
/// Aura already holds a grant covering it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalNeed {
    /// The resource, as Weave displays it (e.g. "file:/etc/hosts").
    pub resource: String,
    /// The rights over it, as Weave displays them (e.g. "r", "rw").
    pub rights: String,
    /// True when Aura already holds a capability covering this need.
    pub held: bool,
}

impl Proposal {
    /// A planned proposal from its steps; `ready` and `destructive` are folded
    /// from them, so the shell hands over the per-step facts and Glass derives
    /// the rest (and tests it).
    pub fn new(intent: impl Into<String>, steps: Vec<ProposalStep>) -> Proposal {
        let destructive = steps.iter().any(|s| s.effect == "destructive");
        // Ready means nothing blocks the run: no hard block, and every need is
        // held. A destructive-but-held step is still ready (the confirm covers
        // it), exactly as `aura::Preview::ready` treats it.
        let ready = steps
            .iter()
            .all(|s| s.block.is_none() && s.needs.iter().all(|n| n.held));
        Proposal {
            intent: intent.into(),
            steps,
            ready,
            destructive,
            failed: None,
        }
    }

    /// A proposal the planner could not produce: nothing to run, only a reason
    /// to show.
    pub fn failed(intent: impl Into<String>, reason: impl Into<String>) -> Proposal {
        Proposal {
            intent: intent.into(),
            steps: Vec::new(),
            ready: false,
            destructive: false,
            failed: Some(reason.into()),
        }
    }

    /// The distinct capabilities the plan needs that Aura does not hold yet, the
    /// exact set a confirm would grant. De-duplicated by resource+rights, the way
    /// the preview's own `missing()` is.
    pub fn missing(&self) -> Vec<&ProposalNeed> {
        let mut out: Vec<&ProposalNeed> = Vec::new();
        for n in self.steps.iter().flat_map(|s| &s.needs) {
            if !n.held
                && !out
                    .iter()
                    .any(|m| m.resource == n.resource && m.rights == n.rights)
            {
                out.push(n);
            }
        }
        out
    }

    pub fn missing_count(&self) -> usize {
        self.missing().len()
    }

    /// Whether any step is hard-blocked (unknown tool or bad arguments), which a
    /// capability grant would not fix.
    pub fn has_hard_block(&self) -> bool {
        self.steps.iter().any(|s| s.block.is_some())
    }

    /// The one-line prompt under the plan: what Enter will do and that Esc
    /// cancels. Drives both the band footer and the palette message, so they
    /// always agree.
    pub fn confirm_hint(&self) -> String {
        if let Some(reason) = &self.failed {
            return format!("Aura could not plan that: {reason}   Esc to dismiss");
        }
        if self.has_hard_block() {
            return "some steps cannot run   Enter to run what can   Esc to cancel".to_string();
        }
        let missing = self.missing_count();
        if missing > 0 {
            return format!(
                "Enter to approve {missing} {} and run   Esc to cancel",
                plural(missing, "capability", "capabilities")
            );
        }
        if self.destructive {
            return "destructive   Enter to confirm and run   Esc to cancel".to_string();
        }
        "Enter to run   Esc to cancel".to_string()
    }
}

/// The command palette's editable state: the typed line, the text cursor (a char
/// index into it), the feedback line under it, and the view filter it currently
/// previews. The shell owns one, feeds it keystrokes, and re-resolves it after
/// each edit; [`surface::layout`](crate::surface::layout) draws it and narrows
/// the principal list by it.
#[derive(Clone, Debug, Default)]
pub struct Palette {
    pub input: String,
    pub cursor: usize,
    pub message: String,
    pub filter: Option<String>,
    /// A plan Aura proposed for an `ask` intent, awaiting a confirm. While it is
    /// set the surface draws it in place of the one-line feedback and the shell
    /// routes Enter to running it; the shell sets and clears it (Glass cannot
    /// produce one). None the rest of the time.
    pub proposal: Option<Proposal>,
}

impl Palette {
    pub fn new() -> Palette {
        Palette::default()
    }

    /// Characters in the input (the cursor's upper bound).
    pub fn len(&self) -> usize {
        self.input.chars().count()
    }

    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Insert a character at the cursor and step past it.
    pub fn insert(&mut self, c: char) {
        let at = self.byte_of(self.cursor);
        self.input.insert(at, c);
        self.cursor += 1;
    }

    /// Delete the character before the cursor (Backspace).
    pub fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let at = self.byte_of(self.cursor - 1);
        self.input.remove(at);
        self.cursor -= 1;
    }

    /// Delete the character under the cursor (Delete).
    pub fn delete(&mut self) {
        if self.cursor >= self.len() {
            return;
        }
        let at = self.byte_of(self.cursor);
        self.input.remove(at);
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.len());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.len();
    }

    /// Empty the input and reset the cursor, dropping any pending proposal (the
    /// plan belongs to the line being cleared). The caller resets the message and
    /// filter (which it derives by re-resolving the now-empty line).
    pub fn clear(&mut self) {
        self.input.clear();
        self.cursor = 0;
        self.proposal = None;
    }

    // Byte offset of char index `i` (or the end), for editing a UTF-8 String by
    // character position.
    fn byte_of(&self, i: usize) -> usize {
        self.input
            .char_indices()
            .nth(i)
            .map(|(b, _)| b)
            .unwrap_or(self.input.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::demo_model;

    #[test]
    fn parses_verbs_and_arguments() {
        assert_eq!(parse("launch firefox"), Command::Launch("firefox".into()));
        assert_eq!(
            parse("run  weston-terminal "),
            Command::Launch("weston-terminal".into())
        );
        assert_eq!(parse("open a b c"), Command::Launch("a b c".into()));
        assert_eq!(parse("sever mail"), Command::Sever("mail".into()));
        assert_eq!(parse("revoke sync"), Command::Sever("sync".into()));
        assert_eq!(parse("help"), Command::Help);
        assert_eq!(parse("?"), Command::Help);
        assert_eq!(parse(""), Command::Empty);
        assert_eq!(parse("   "), Command::Empty);
        // An unknown verb is a bare filter query, keeping the whole text.
        assert_eq!(parse("api.example"), Command::Filter("api.example".into()));
    }

    #[test]
    fn ask_parses_and_resolves_to_an_aura_intent() {
        assert_eq!(
            parse("ask what is in /etc/hosts"),
            Command::Ask("what is in /etc/hosts".into())
        );
        assert_eq!(
            parse("do find my notes"),
            Command::Ask("find my notes".into())
        );
        // "aura" is the principal's name, not a verb: it stays a filter query.
        assert_eq!(parse("aura"), Command::Filter("aura".into()));
        let r = interpret("ask read /etc/hosts", &demo_model());
        assert_eq!(r.action, PaletteAction::Ask("read /etc/hosts".into()));
        assert!(r.hint.contains("read /etc/hosts"));
        // An ask with no intent is inert, not an empty plan.
        assert_eq!(interpret("ask", &demo_model()).action, PaletteAction::None);
        assert_eq!(
            interpret("ask   ", &demo_model()).action,
            PaletteAction::None
        );
    }

    fn need(resource: &str, rights: &str, held: bool) -> ProposalNeed {
        ProposalNeed {
            resource: resource.into(),
            rights: rights.into(),
            held,
        }
    }

    fn step(tool: &str, effect: &str, needs: Vec<ProposalNeed>) -> ProposalStep {
        ProposalStep {
            tool: tool.into(),
            rationale: format!("{tool} something"),
            effect: effect.into(),
            needs,
            block: None,
        }
    }

    #[test]
    fn proposal_folds_ready_and_destructive_from_its_steps() {
        // A read whose capability is missing: not ready, one to approve.
        let p = Proposal::new(
            "read /etc/hosts",
            vec![step(
                "read_file",
                "read",
                vec![need("file:/etc/hosts", "r", false)],
            )],
        );
        assert!(!p.ready);
        assert!(!p.destructive);
        assert_eq!(p.missing_count(), 1);
        assert!(p.confirm_hint().contains("approve 1 capability"));

        // The same read with the capability held: ready, nothing to approve.
        let held = Proposal::new(
            "read /etc/hosts",
            vec![step(
                "read_file",
                "read",
                vec![need("file:/etc/hosts", "r", true)],
            )],
        );
        assert!(held.ready);
        assert_eq!(held.missing_count(), 0);
        assert_eq!(held.confirm_hint(), "Enter to run   Esc to cancel");

        // A destructive move with both capabilities held: ready, but the confirm
        // is the destructive confirmation.
        let mv = Proposal::new(
            "move a to b",
            vec![step(
                "move_file",
                "destructive",
                vec![need("file:/a", "rw", true), need("file:/b", "w", true)],
            )],
        );
        assert!(mv.ready);
        assert!(mv.destructive);
        assert!(mv.confirm_hint().contains("destructive"));
    }

    #[test]
    fn proposal_dedups_missing_and_reports_hard_blocks() {
        // Two steps needing the same capability count it once.
        let p = Proposal::new(
            "two reads",
            vec![
                step("read_file", "read", vec![need("file:/x", "r", false)]),
                step("list_dir", "read", vec![need("file:/x", "r", false)]),
            ],
        );
        assert_eq!(p.missing_count(), 1);

        // A hard-blocked step (unknown tool) takes precedence in the hint.
        let mut blocked = step("teleport", "read", vec![]);
        blocked.block = Some("unknown tool".into());
        let p = Proposal::new("teleport", vec![blocked]);
        assert!(p.has_hard_block());
        assert!(!p.ready);
        assert!(p.confirm_hint().contains("cannot run"));
    }

    #[test]
    fn a_failed_proposal_shows_its_reason() {
        let p = Proposal::failed("teleport to mars", "no rule for \"teleport\"");
        assert!(p.failed.is_some());
        assert!(!p.ready);
        assert_eq!(p.missing_count(), 0);
        assert!(p.confirm_hint().contains("could not plan"));
    }

    #[test]
    fn launch_resolves_to_a_spawn() {
        let r = interpret("launch firefox", &demo_model());
        assert_eq!(r.action, PaletteAction::Launch("firefox".into()));
        assert!(r.hint.contains("firefox"));
    }

    #[test]
    fn launch_without_a_program_is_inert() {
        assert_eq!(
            interpret("launch", &demo_model()).action,
            PaletteAction::None
        );
    }

    #[test]
    fn sever_by_name_finds_the_live_grant() {
        let m = demo_model();
        let mail = m
            .principals
            .iter()
            .find(|p| p.principal.0 == "mail")
            .unwrap();
        let live = mail.channels.iter().find(|c| c.can_sever()).unwrap();
        let r = interpret("sever mail", &m);
        assert_eq!(r.action, PaletteAction::Sever(vec![live.grant.unwrap()]));
        assert_eq!(r.filter.as_deref(), Some("mail"));
    }

    #[test]
    fn sever_an_already_dead_channel_matches_nothing() {
        // "sync"'s channel is already severed, so there is nothing live to sever.
        let r = interpret("sever sync", &demo_model());
        assert_eq!(r.action, PaletteAction::None);
        assert!(r.hint.contains("no live channel"));
    }

    #[test]
    fn sever_by_kind_targets_matching_live_channels() {
        // Only mail's network channel is live; sync's is severed already.
        match interpret("sever net", &demo_model()).action {
            PaletteAction::Sever(g) => assert_eq!(g.len(), 1),
            other => panic!("expected sever, got {other:?}"),
        }
    }

    #[test]
    fn sever_with_no_argument_is_inert() {
        assert_eq!(
            interpret("sever", &demo_model()).action,
            PaletteAction::None
        );
    }

    #[test]
    fn bare_text_filters_the_view() {
        let r = interpret("aura", &demo_model());
        assert_eq!(r.action, PaletteAction::None);
        assert_eq!(r.filter.as_deref(), Some("aura"));
        assert!(r.hint.contains("aura"));
    }

    #[test]
    fn empty_input_shows_the_idle_hint() {
        let r = interpret("", &demo_model());
        assert_eq!(r.action, PaletteAction::None);
        assert_eq!(r.filter, None);
        assert_eq!(r.hint, HINT_IDLE);
    }

    #[test]
    fn palette_edits_text_at_the_cursor() {
        let mut p = Palette::new();
        for c in "helo".chars() {
            p.insert(c);
        }
        assert_eq!(p.input, "helo");
        assert_eq!(p.cursor, 4);
        p.left(); // between 'l' and 'o'
        p.insert('l'); // "hello"
        assert_eq!(p.input, "hello");
        assert_eq!(p.cursor, 4);
        p.home();
        assert_eq!(p.cursor, 0);
        p.delete(); // remove 'h'
        assert_eq!(p.input, "ello");
        p.end();
        p.backspace(); // remove 'o'
        assert_eq!(p.input, "ell");
        p.clear();
        assert!(p.is_empty());
        assert_eq!(p.cursor, 0);
    }

    #[test]
    fn palette_handles_multibyte_chars() {
        let mut p = Palette::new();
        for c in "café".chars() {
            p.insert(c);
        }
        assert_eq!(p.len(), 4);
        p.backspace(); // remove the multibyte 'é'
        assert_eq!(p.input, "caf");
        assert_eq!(p.cursor, 3);
    }
}
