//! Aura: Horizon's on-device intent layer, and a principal in the Weave.
//!
//! Aura is not bolted onto the OS; it acts only through capabilities the broker
//! handed it, with every action scoped, previewed, audited, and reversible
//! (docs/05). This crate is the part of that which can be proven without a
//! model: a tool catalog ([`Catalog`]), a planner seam ([`Planner`]) the LLM
//! plugs into later, and a capability-checked, safety-railed executor
//! ([`Aura`]). An intent becomes a [`Plan`]; a [`Preview`] shows what each step
//! would touch and which capabilities are missing (never silently acquired); and
//! [`Aura::execute`] brokers each step's capability through the Weave (logging a
//! use) before the tool runs, gating destructive steps behind explicit
//! confirmation. The LLM that fills the planner is the weights-and-GPU-gated
//! shim, eye-verified later, the same split the compositor backends use.

mod error;
#[cfg(feature = "llama")]
mod llama;
mod plan;
mod semantic;
mod tool;

use std::collections::HashMap;

use weave::{Broker, Capability, GrantId, Limits, PrincipalId, Resource, Rights, Status};

pub use error::{Error, Result};
#[cfg(feature = "llama")]
pub use llama::{GgufEmbedder, LlmPlanner};
pub use plan::{Plan, Planner, RulePlanner, Step};
pub use semantic::{
    dot, normalize, Embedder, HashingEmbedder, Hit, SemanticIndex, VectorIndex, DEFAULT_DIM,
    INDEX_REF,
};
pub use tool::{Args, Catalog, Effect, Need, Outcome, ParamSpec, Tool};

// The name Aura acts under in the audit log. Everything it does shows up as this
// principal in Glass, distinct from any app it launches.
pub const PRINCIPAL: &str = "aura";

// Why a step would not run as things stand, the actionable half of a preview and
// the reason a skipped step carries in a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    UnknownTool,
    BadArgs(String),
    // At least one capability the step needs is not held. Surface it; do not
    // acquire it silently (docs/05 safety rail).
    NeedsCapability,
    // The step is destructive and was not confirmed.
    NeedsConfirmation,
}

impl Block {
    pub fn reason(&self) -> String {
        match self {
            Block::UnknownTool => "unknown tool".into(),
            Block::BadArgs(e) => format!("bad arguments: {e}"),
            Block::NeedsCapability => "needs a capability you have not granted".into(),
            Block::NeedsConfirmation => "needs confirmation (destructive)".into(),
        }
    }
}

// Whether Aura already holds authority for one of a step's needs.
#[derive(Clone, Debug)]
pub enum Authority {
    Held(GrantId),
    Missing,
}

// One required capability of a step, paired with whether Aura holds it.
#[derive(Clone, Debug)]
pub struct NeedStatus {
    pub resource: Resource,
    pub rights: Rights,
    pub authority: Authority,
}

impl NeedStatus {
    pub fn is_held(&self) -> bool {
        matches!(self.authority, Authority::Held(_))
    }
}

// The preview of one step: what it is, what it would touch, and why it would or
// would not run right now.
#[derive(Clone, Debug)]
pub struct StepPreview {
    pub index: usize,
    pub tool: String,
    pub rationale: String,
    pub effect: Option<Effect>,
    pub needs: Vec<NeedStatus>,
    pub block: Option<Block>,
}

// The preview of a whole plan: shown to the user before anything runs.
#[derive(Clone, Debug)]
pub struct Preview {
    pub intent: String,
    pub steps: Vec<StepPreview>,
}

impl Preview {
    // True when every step's tool is known, its arguments parse, and its
    // capabilities are held. Destructive steps still need a confirm at execute,
    // which is a separate gate, so a ready plan may still carry one.
    pub fn ready(&self) -> bool {
        self.steps.iter().all(|s| {
            !matches!(
                s.block,
                Some(Block::UnknownTool) | Some(Block::BadArgs(_)) | Some(Block::NeedsCapability)
            )
        })
    }

    pub fn has_destructive(&self) -> bool {
        self.steps
            .iter()
            .any(|s| s.effect == Some(Effect::Destructive))
    }

    // The capabilities the plan needs that Aura does not hold, de-duplicated, the
    // exact set a user would approve to make the plan runnable.
    pub fn missing(&self) -> Vec<Need> {
        let mut out: Vec<Need> = Vec::new();
        for s in &self.steps {
            for n in &s.needs {
                if !n.is_held()
                    && !out
                        .iter()
                        .any(|m| m.resource == n.resource && m.rights == n.rights)
                {
                    out.push(Need::new(n.resource.clone(), n.rights));
                }
            }
        }
        out
    }
}

// What became of one step after execute ran.
#[derive(Clone, Debug)]
pub enum StepStatus {
    Done(Outcome),
    Blocked(Block),
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct StepResult {
    pub index: usize,
    pub tool: String,
    pub status: StepStatus,
}

// The result of running a plan: one entry per step.
#[derive(Clone, Debug)]
pub struct Report {
    pub intent: String,
    pub results: Vec<StepResult>,
}

impl Report {
    pub fn ran(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r.status, StepStatus::Done(_)))
            .count()
    }
    pub fn all_done(&self) -> bool {
        !self.results.is_empty()
            && self
                .results
                .iter()
                .all(|r| matches!(r.status, StepStatus::Done(_)))
    }
}

// The executor: Aura as a principal over a Weave broker. It holds a wallet of
// capabilities granted to it and runs plans against the catalog, brokering every
// step before the tool acts.
pub struct Aura<'b> {
    principal: PrincipalId,
    broker: &'b mut Broker,
    catalog: Catalog,
    // The capabilities Aura has been granted. A capability is opaque (a grant id
    // and a session secret); the live grant table in the broker says what each
    // one covers, so authority is matched there and exercised through these.
    held: HashMap<GrantId, Capability>,
}

impl<'b> Aura<'b> {
    pub fn new(broker: &'b mut Broker) -> Aura<'b> {
        Aura::with_catalog(broker, Catalog::standard())
    }

    pub fn with_catalog(broker: &'b mut Broker, catalog: Catalog) -> Aura<'b> {
        Aura {
            principal: PrincipalId(PRINCIPAL.into()),
            broker,
            catalog,
            held: HashMap::new(),
        }
    }

    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    // The broker Aura runs against, for reading the audit log after a session.
    pub fn broker(&self) -> &Broker {
        self.broker
    }

    // Authorize Aura: grant it a capability and put it in its wallet. This is the
    // "you approve" step a Weave prompt resolves to in the running OS; the caller
    // (CLI, desktop) decides, never Aura itself.
    pub fn authorize(
        &mut self,
        resource: Resource,
        rights: Rights,
        limits: Limits,
    ) -> Result<GrantId> {
        let cap = self
            .broker
            .grant(self.principal.clone(), resource, rights, limits)?;
        let id = cap.grant_id();
        self.held.insert(id, cap);
        Ok(id)
    }

    // Grant every capability a preview reported missing, the bulk form of
    // approving a whole plan at once. Returns the ids granted.
    pub fn grant_missing(&mut self, preview: &Preview, limits: Limits) -> Result<Vec<GrantId>> {
        let mut ids = Vec::new();
        for need in preview.missing() {
            ids.push(self.authorize(need.resource, need.rights, limits)?);
        }
        Ok(ids)
    }

    pub fn plan(&self, planner: &dyn Planner, intent: &str) -> Result<Plan> {
        planner.plan(intent, &self.catalog)
    }

    // Examine a plan without running it: resolve each step's tool, compute the
    // capabilities it needs, and mark which are held. No side effects, no audit
    // entries, and no capabilities acquired.
    pub fn preview(&self, plan: &Plan) -> Preview {
        let steps = plan
            .steps
            .iter()
            .enumerate()
            .map(|(index, step)| self.preview_step(index, step))
            .collect();
        Preview {
            intent: plan.intent.clone(),
            steps,
        }
    }

    fn preview_step(&self, index: usize, step: &Step) -> StepPreview {
        let tool = match self.catalog.get(&step.tool) {
            Some(t) => t,
            None => {
                return StepPreview {
                    index,
                    tool: step.tool.clone(),
                    rationale: step.rationale.clone(),
                    effect: None,
                    needs: Vec::new(),
                    block: Some(Block::UnknownTool),
                }
            }
        };
        let effect = tool.effect();
        let needs = match tool.required(&step.args) {
            Ok(ns) => ns,
            Err(e) => {
                return StepPreview {
                    index,
                    tool: step.tool.clone(),
                    rationale: step.rationale.clone(),
                    effect: Some(effect),
                    needs: Vec::new(),
                    block: Some(Block::BadArgs(e.to_string())),
                }
            }
        };
        let statuses: Vec<NeedStatus> = needs
            .iter()
            .map(|n| NeedStatus {
                resource: n.resource.clone(),
                rights: n.rights,
                authority: match self.capability_for(n) {
                    Some((id, _)) => Authority::Held(id),
                    None => Authority::Missing,
                },
            })
            .collect();
        let any_missing = statuses.iter().any(|s| !s.is_held());
        let block = if any_missing {
            Some(Block::NeedsCapability)
        } else if effect.is_destructive() {
            Some(Block::NeedsConfirmation)
        } else {
            None
        };
        StepPreview {
            index,
            tool: step.tool.clone(),
            rationale: step.rationale.clone(),
            effect: Some(effect),
            needs: statuses,
            block,
        }
    }

    // Run a plan. Each step's capabilities are brokered (weave `access`, which
    // logs a use and enforces scope) before the tool runs; a step Aura lacks a
    // capability for is blocked, not run, and a destructive step is blocked
    // unless `confirm_destructive` is set. A failing or blocked step does not
    // stop the rest of the plan.
    pub fn execute(&mut self, plan: &Plan, confirm_destructive: bool) -> Report {
        let mut results = Vec::new();
        for (index, step) in plan.steps.iter().enumerate() {
            let status = self.run_step(step, confirm_destructive);
            results.push(StepResult {
                index,
                tool: step.tool.clone(),
                status,
            });
        }
        Report {
            intent: plan.intent.clone(),
            results,
        }
    }

    fn run_step(&mut self, step: &Step, confirm_destructive: bool) -> StepStatus {
        let needs = {
            let tool = match self.catalog.get(&step.tool) {
                Some(t) => t,
                None => return StepStatus::Blocked(Block::UnknownTool),
            };
            if tool.effect().is_destructive() && !confirm_destructive {
                return StepStatus::Blocked(Block::NeedsConfirmation);
            }
            match tool.required(&step.args) {
                Ok(ns) => ns,
                Err(e) => return StepStatus::Blocked(Block::BadArgs(e.to_string())),
            }
        };

        // Broker every need first. If any is not held or the broker refuses it
        // (out of scope, expired, used up), the step does not run at all.
        let mut leases = Vec::new();
        for need in &needs {
            let cap = match self.capability_for(need) {
                Some((_, cap)) => cap,
                None => return StepStatus::Blocked(Block::NeedsCapability),
            };
            match self.broker.access(&cap, &need.resource, need.rights) {
                Ok(lease) => leases.push(lease),
                Err(_) => return StepStatus::Blocked(Block::NeedsCapability),
            }
        }

        let tool = self.catalog.get(&step.tool).expect("tool resolved above");
        match tool.run(&step.args, &leases) {
            Ok(outcome) => StepStatus::Done(outcome),
            Err(e) => StepStatus::Failed(e.to_string()),
        }
    }

    // Find a held capability that covers a need: a live grant to Aura whose
    // resource covers and whose rights contain the need, and whose handle is in
    // the wallet. Returns the grant id and a usable handle.
    fn capability_for(&self, need: &Need) -> Option<(GrantId, Capability)> {
        for info in self.broker.grants() {
            if info.principal == self.principal
                && info.status == Status::Active
                && info.resource.covers(&need.resource)
                && info.rights.contains(need.rights)
            {
                if let Some(cap) = self.held.get(&info.id) {
                    return Some((info.id, cap.clone()));
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lifestream::Lifestream;
    use std::fs;
    use weave::Policy;

    fn broker() -> Broker {
        let dir = tempfile::tempdir().unwrap();
        let ls = Lifestream::init(dir.path().join("store"), &[7u8; 32]).unwrap();
        // Leak the tempdir: the store must outlive the broker for the test.
        std::mem::forget(dir);
        Broker::open(ls, Policy::DenyAll).unwrap()
    }

    // A directory with a couple of files for the file tools to act on.
    fn workdir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::write(d.path().join("cows.md"), "grazing rotations from spring").unwrap();
        fs::write(d.path().join("notes.txt"), "unrelated").unwrap();
        d
    }

    #[test]
    fn preview_marks_missing_capability_and_does_not_acquire_it() {
        let mut b = broker();
        let work = workdir();
        let aura = Aura::new(&mut b);
        let plan = aura
            .plan(&RulePlanner, &format!("list {}", work.path().display()))
            .unwrap();
        let pv = aura.preview(&plan);
        assert!(!pv.ready(), "no capability held yet");
        assert_eq!(pv.missing().len(), 1);
        assert!(matches!(pv.steps[0].block, Some(Block::NeedsCapability)));
        // Previewing acquired nothing: no grant to aura exists.
        drop(aura);
        assert!(b.grants().is_empty());
    }

    #[test]
    fn authorized_read_runs_and_logs_a_use() {
        let mut b = broker();
        let work = workdir();
        let mut aura = Aura::new(&mut b);
        let plan = aura
            .plan(&RulePlanner, &format!("list {}", work.path().display()))
            .unwrap();
        let pv = aura.preview(&plan);
        aura.grant_missing(&pv, Limits::none()).unwrap();
        let report = aura.execute(&plan, false);
        assert!(report.all_done());
        match &report.results[0].status {
            StepStatus::Done(Outcome::Listing(es)) => {
                assert!(es.iter().any(|e| e == "cows.md"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        // The access landed in the audit log as a Use.
        drop(aura);
        let audit = b.audit().unwrap();
        assert!(audit
            .iter()
            .any(|e| matches!(e.event, weave::Event::Use { .. })));
    }

    #[test]
    fn destructive_step_is_blocked_until_confirmed() {
        let mut b = broker();
        let work = workdir();
        let victim = work.path().join("notes.txt");
        let mut aura = Aura::new(&mut b);
        let plan = aura
            .plan(&RulePlanner, &format!("delete {}", victim.display()))
            .unwrap();
        let pv = aura.preview(&plan);
        aura.grant_missing(&pv, Limits::none()).unwrap();

        // Held the capability, but no confirmation: blocked, file still there.
        let blocked = aura.execute(&plan, false);
        assert!(matches!(
            blocked.results[0].status,
            StepStatus::Blocked(Block::NeedsConfirmation)
        ));
        assert!(victim.exists());

        // Confirmed: it runs and the file is gone.
        let done = aura.execute(&plan, true);
        assert!(done.all_done());
        assert!(!victim.exists());
    }

    #[test]
    fn a_grant_for_one_file_does_not_cover_a_sibling() {
        let mut b = broker();
        let work = workdir();
        let mut aura = Aura::new(&mut b);
        // Authorize only cows.md, then try to read notes.txt.
        aura.authorize(
            Resource::file(work.path().join("cows.md")),
            Rights::READ,
            Limits::none(),
        )
        .unwrap();
        let plan = aura
            .plan(
                &RulePlanner,
                &format!("read {}", work.path().join("notes.txt").display()),
            )
            .unwrap();
        let report = aura.execute(&plan, false);
        assert!(matches!(
            report.results[0].status,
            StepStatus::Blocked(Block::NeedsCapability)
        ));
    }

    #[test]
    fn a_directory_grant_covers_files_beneath_it() {
        let mut b = broker();
        let work = workdir();
        let mut aura = Aura::new(&mut b);
        // One grant on the directory authorizes find and read beneath it.
        aura.authorize(Resource::file(work.path()), Rights::READ, Limits::none())
            .unwrap();
        let plan = aura
            .plan(
                &RulePlanner,
                &format!("find cows in {}", work.path().display()),
            )
            .unwrap();
        let report = aura.execute(&plan, false);
        match &report.results[0].status {
            StepStatus::Done(Outcome::Matches(ms)) => {
                assert_eq!(ms.len(), 1);
                assert!(ms[0].ends_with("cows.md"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_verb_does_not_plan() {
        let mut b = broker();
        let aura = Aura::new(&mut b);
        assert!(aura.plan(&RulePlanner, "teleport to mars").is_err());
    }
}
