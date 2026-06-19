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
// surface falls back to when the palette has no message of its own.
pub const HINT_IDLE: &str = "type to filter   launch <app>   sever <name>   help";

/// A command parsed from the palette input: a verb and its argument. Pure string
/// work with no Model, so it is tested on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Nothing actionable typed (empty or whitespace only).
    Empty,
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
            hint: "launch <app> spawns a client   sever <name> revokes matching channels   \
                   any other text filters the view"
                .to_string(),
        },
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

    /// Empty the input and reset the cursor. The caller resets the message and
    /// filter (which it derives by re-resolving the now-empty line).
    pub fn clear(&mut self) {
        self.input.clear();
        self.cursor = 0;
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
