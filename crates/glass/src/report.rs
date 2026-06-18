// A plain-text rendering of the Glass model: the headless stand-in for the
// drawn surface, the same way `horizon weave audit` stands in for the log. It is
// pure (model in, string out) so it is testable, and it reads like a live
// dashboard: a header of totals, an activity sparkline over the window, then
// each principal with its channels and a kill-switch hint.

use crate::model::{Bucket, Channel, ChannelStatus, Model};

// Render the model as a text report.
pub fn text(m: &Model) -> String {
    let now = m.window.end_unix;
    let mut o = String::new();

    o.push_str(&format!(
        "glass   window {}   as of {}\n",
        span_label(m.window.span()),
        now
    ));
    let t = m.totals;
    o.push_str(&format!(
        "{} principals   {} live   {} network   {} blocked   {} severed\n\n",
        t.principals, t.live, t.network, t.blocked, t.severed
    ));

    o.push_str(&format!(
        "timeline   {}   grants {}   uses {}   denials {}   revokes {}\n",
        sparkline(&m.timeline),
        sum(&m.timeline, |b| b.grants),
        sum(&m.timeline, |b| b.uses),
        sum(&m.timeline, |b| b.denials),
        sum(&m.timeline, |b| b.revokes),
    ));

    if m.is_empty() {
        o.push_str("\nno activity\n");
        return o;
    }

    for p in &m.principals {
        o.push('\n');
        match p.last_unix {
            Some(t) => o.push_str(&format!("{}   {}\n", p.principal, ago(now, t))),
            None => o.push_str(&format!("{}\n", p.principal)),
        }
        for c in &p.channels {
            o.push_str(&channel_line(c));
            for a in c.accessed.iter().take(3) {
                o.push_str(&format!("                          {}\n", a));
            }
            if c.accessed.len() > 3 {
                o.push_str(&format!(
                    "                          +{} more\n",
                    c.accessed.len() - 3
                ));
            }
        }
    }
    o
}

fn channel_line(c: &Channel) -> String {
    let kill = match c.grant {
        Some(g) if c.can_sever() => format!("  {}", short(&g.to_hex())),
        Some(g) => format!("  ({})", short(&g.to_hex())),
        None => String::new(),
    };
    format!(
        "  {:<8} {:<4} {:<3} {}{}{}\n",
        c.status.label(),
        c.kind.label(),
        c.rights,
        c.resource,
        kill,
        counts(c),
    )
}

fn counts(c: &Channel) -> String {
    let mut s = String::new();
    if c.uses > 0 {
        s.push_str(&format!("   {} {}", c.uses, plural(c.uses, "use", "uses")));
    }
    if c.denials > 0 {
        s.push_str(&format!("   {} blocked", c.denials));
    }
    if c.status == ChannelStatus::Blocked {
        if let Some(r) = &c.last_reason {
            s.push_str(&format!("   ({})", r));
        }
    }
    s
}

// Time since `t`, coarse and human: now, 12s, 5m, 3h, 2d.
fn ago(now: u64, t: u64) -> String {
    let d = now.saturating_sub(t);
    if d == 0 {
        return "now".to_string();
    }
    if d < 60 {
        return format!("{d}s ago");
    }
    if d < 60 * 60 {
        return format!("{}m ago", d / 60);
    }
    if d < 24 * 60 * 60 {
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

fn sparkline(buckets: &[Bucket]) -> String {
    const BARS: [char; 8] = [
        '\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}',
        '\u{2588}',
    ];
    let max = buckets.iter().map(Bucket::total).max().unwrap_or(0);
    if buckets.is_empty() {
        return String::new();
    }
    buckets
        .iter()
        .map(|b| {
            if max == 0 {
                BARS[0]
            } else {
                let lvl = (b.total() as usize * (BARS.len() - 1)) / max as usize;
                BARS[lvl.min(BARS.len() - 1)]
            }
        })
        .collect()
}

fn sum(buckets: &[Bucket], f: impl Fn(&Bucket) -> u32) -> u32 {
    buckets.iter().map(f).sum()
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
