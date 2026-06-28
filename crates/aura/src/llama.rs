// The real model behind the seams: one llama.cpp engine, shared. This module is
// gated on the `llama` feature so the default build stays model-free and
// cross-platform; turning it on links llama.cpp (the sys crate builds it from
// source via cmake). It fills BOTH seams over the one engine: `GgufEmbedder`
// fills the `Embedder` seam with a GGUF embedding model (EmbeddingGemma), and
// `LlmPlanner` fills the `Planner` seam with a small instruct model that emits
// tool calls under a GBNF grammar, so its output is always valid JSON against the
// catalog's schema. That is the whole "one engine, both seams" plan.
//
// These are the weights-gated shims the rest of the crate is written around, the
// analog of identity's `HardwareKey` over the `SoftwareAuthenticator` or the
// compositor's display backends: the deterministic `HashingEmbedder` and
// `RulePlanner` prove the index, ranking, plan, and execute pipeline with no
// model, and a real model swaps in here to bring true meaning (it ties "cows" to
// "cattle", which the hashing stand-in cannot) and real language understanding
// (it plans "where do I keep the cattle notes" without a hand-written verb rule).

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::OnceLock;

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaChatTemplate, LlamaModel};
use llama_cpp_2::sampling::LlamaSampler;

use crate::error::{Error, Result};
use crate::plan::{Plan, Planner, Step};
use crate::semantic::{normalize, Embedder};
use crate::tool::{Args, Catalog, ParamSpec};

// llama.cpp's backend initializes a process-global (ggml's backend registry) and
// refuses a second init, so it is created once and shared for the life of the
// process. The guard is never dropped, which is what keeps the backend live for
// every model and context built against it.
fn backend() -> &'static LlamaBackend {
    static BACKEND: OnceLock<LlamaBackend> = OnceLock::new();
    BACKEND.get_or_init(|| {
        // Silence llama.cpp/ggml's own console chatter (device probe, graph
        // reservation, buffer sizes) before anything loads, so `horizon aura
        // search` prints only its ranked hits. This routes their logs into
        // `tracing` and then disables them, so with no subscriber installed they
        // go nowhere.
        llama_cpp_2::send_logs_to_tracing(
            llama_cpp_2::LogOptions::default().with_logs_enabled(false),
        );
        LlamaBackend::init().expect("initialize the llama.cpp backend")
    })
}

// The widest token sequence we embed. EmbeddingGemma is trained at a 2048-token
// context; a longer document is truncated to its head, the usual way a single
// vector summarizes an over-long text.
const MAX_TOKENS: usize = 2048;

// An [`Embedder`] backed by a real GGUF model over llama.cpp. It holds the model
// weights (read-only, shared) and embeds a string by running one forward pass and
// reading back the pooled, L2-normalized sequence embedding. A fresh context is
// built per call, so the embedder carries no mutable inference state and stays
// `Send + Sync` as the trait requires; reusing a context (or batching a whole
// directory in one decode) is a later throughput refinement, not a correctness
// one, at the scale this indexes.
pub struct GgufEmbedder {
    model: LlamaModel,
    dim: usize,
}

impl GgufEmbedder {
    /// Load a GGUF embedding model from `path`. The embedding width is read from
    /// the model itself (768 for EmbeddingGemma-300M), so the persisted index and
    /// the query are always the same shape.
    pub fn load(path: impl AsRef<Path>) -> Result<GgufEmbedder> {
        let path = path.as_ref();
        // Offload to the GPU when the engine was built with one (Metal on this
        // Mac); ignored on a CPU-only build, so the same call is correct either
        // way.
        let params = LlamaModelParams::default().with_n_gpu_layers(1000);
        let model = LlamaModel::load_from_file(backend(), path, &params)
            .map_err(|e| Error::model(format!("loading {}: {e}", path.display())))?;
        let dim = usize::try_from(model.n_embd()).map_err(Error::model)?;
        if dim == 0 {
            return Err(Error::Model("model reports a zero embedding width".into()));
        }
        Ok(GgufEmbedder { model, dim })
    }

    // One forward pass: tokenize (with the leading BOS the model expects),
    // truncate to the context, decode the sequence, and read back the pooled
    // embedding the model's metadata defines (EmbeddingGemma pools by mean). The
    // vector is L2-normalized, so a downstream dot product is cosine similarity,
    // exactly the contract the `HashingEmbedder` and the `VectorIndex` share.
    fn embed_one(&self, text: &str) -> Result<Vec<f32>> {
        let mut tokens = self
            .model
            .str_to_token(text, AddBos::Always)
            .map_err(Error::model)?;
        if tokens.is_empty() {
            // Featureless text embeds to zero, which has cosine 0 with everything
            // and so matches nothing, the same convention `normalize` keeps.
            return Ok(vec![0.0; self.dim]);
        }
        tokens.truncate(MAX_TOKENS);

        let threads = std::thread::available_parallelism()
            .map(|n| n.get() as i32)
            .unwrap_or(4);
        let ctx_params = LlamaContextParams::default()
            .with_embeddings(true)
            .with_n_ctx(NonZeroU32::new(MAX_TOKENS as u32))
            .with_n_threads(threads)
            .with_n_threads_batch(threads);
        let mut ctx = self
            .model
            .new_context(backend(), ctx_params)
            .map_err(Error::model)?;

        let mut batch = LlamaBatch::new(tokens.len(), 1);
        batch
            .add_sequence(&tokens, 0, false)
            .map_err(Error::model)?;
        ctx.decode(&mut batch).map_err(Error::model)?;

        let embedding = ctx.embeddings_seq_ith(0).map_err(Error::model)?;
        let mut v = embedding.to_vec();
        normalize(&mut v);
        Ok(v)
    }
}

impl Embedder for GgufEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    // The trait is infallible (the dev seam never fails), so a real engine error
    // on one document degrades to a featureless vector (matches nothing) with a
    // warning, rather than taking down a whole index build for one bad file.
    fn embed(&self, text: &str) -> Vec<f32> {
        match self.embed_one(text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("aura: embedding failed ({e}); treating as featureless");
                vec![0.0; self.dim]
            }
        }
    }
}

// The context window the planner runs in. The prompt (the tool catalog, a few
// examples, and the intent) is a few hundred tokens and the tool-call JSON is
// short, so this is generous; an over-long intent is refused rather than silently
// truncated, since a clipped intent would plan the wrong thing.
const PLANNER_CTX: u32 = 4096;
// A hard cap on generated tokens, the runaway guard. The grammar already forces
// the model to close the JSON array and then only emit end-of-generation, so this
// is only reached if a value string rambles; a real tool call is far shorter.
const PLANNER_MAX_TOKENS: usize = 1024;

// A [`Planner`] backed by a small instruct GGUF over the same llama.cpp engine as
// [`GgufEmbedder`]. It turns an intent into a [`Plan`] of catalog tool calls by
// prompting the model with the tool schema and decoding under a GBNF grammar
// generated from that same catalog, so the model's output is constrained to a
// JSON array of well-formed calls naming only real tools with their real argument
// keys. The grammar makes a malformed or hallucinated-tool call unrepresentable,
// rather than something to catch after the fact; the capability layer downstream
// (preview, broker) is what still decides whether a well-formed call may run.
//
// Like the embedder it holds the read-only weights and builds a fresh context per
// call, so it carries no mutable inference state and stays `Send + Sync`. It is
// not a member of the standard catalog: a caller wires it in where the
// `RulePlanner` stand-in sits (the CLI's `aura plan`), exactly as a real embedder
// is wired where the `HashingEmbedder` sits.
pub struct LlmPlanner {
    model: LlamaModel,
    template: LlamaChatTemplate,
}

impl LlmPlanner {
    /// Load a small instruct GGUF (Qwen2.5-1.5B/3B-Instruct, Llama-3.2-3B, or any
    /// chat model) as the planner. The model's own chat template is used to format
    /// the prompt; a model that ships none falls back to ChatML, which is what the
    /// Qwen and most instruct GGUFs use anyway.
    pub fn load(path: impl AsRef<Path>) -> Result<LlmPlanner> {
        let path = path.as_ref();
        // Offload to the GPU when the engine was built with one (Metal on this
        // Mac), ignored on a CPU-only build, exactly as the embedder does.
        let params = LlamaModelParams::default().with_n_gpu_layers(1000);
        let model = LlamaModel::load_from_file(backend(), path, &params)
            .map_err(|e| Error::model(format!("loading {}: {e}", path.display())))?;
        let template = model.chat_template(None).or_else(|_| {
            LlamaChatTemplate::new("chatml")
                .map_err(|e| Error::model(format!("chatml template: {e}")))
        })?;
        Ok(LlmPlanner { model, template })
    }

    // Format the system and user turns through the model's chat template, decode
    // the prompt, then generate under the grammar until the model ends generation
    // (the grammar lets it stop only once the JSON array is closed) or the runaway
    // cap is hit. Returns the raw decoded text, which the grammar guarantees is a
    // JSON array of tool calls.
    fn generate(&self, system: &str, user: &str, grammar: &str) -> Result<String> {
        let messages = [
            LlamaChatMessage::new("system".into(), system.into())
                .map_err(|e| Error::model(format!("system message: {e}")))?,
            LlamaChatMessage::new("user".into(), user.into())
                .map_err(|e| Error::model(format!("user message: {e}")))?,
        ];
        let prompt = self
            .model
            .apply_chat_template(&self.template, &messages, true)
            .map_err(|e| Error::model(format!("applying chat template: {e}")))?;

        // BOS handling is the model's own (AddBos maps to llama.cpp's add_special,
        // which adds a BOS only if the model is configured for one), so this is
        // correct for a Qwen GGUF (no BOS) and a Llama one (BOS) alike.
        let tokens = self
            .model
            .str_to_token(&prompt, AddBos::Always)
            .map_err(Error::model)?;
        if tokens.len() + 64 >= PLANNER_CTX as usize {
            return Err(Error::Plan(format!(
                "intent prompt is {} tokens, too long for the {PLANNER_CTX}-token planner context",
                tokens.len()
            )));
        }

        let threads = std::thread::available_parallelism()
            .map(|n| n.get() as i32)
            .unwrap_or(4);
        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(NonZeroU32::new(PLANNER_CTX))
            // Decode the whole prompt in one batch; it is well under the context.
            .with_n_batch(PLANNER_CTX)
            .with_n_threads(threads)
            .with_n_threads_batch(threads);
        let mut ctx = self
            .model
            .new_context(backend(), ctx_params)
            .map_err(Error::model)?;

        let mut batch = LlamaBatch::new(tokens.len().max(1), 1);
        let last = tokens.len() - 1;
        for (i, tok) in tokens.iter().enumerate() {
            batch
                .add(*tok, i as i32, &[0], i == last)
                .map_err(Error::model)?;
        }
        ctx.decode(&mut batch).map_err(Error::model)?;

        // grammar masks every token the JSON-tool-call grammar forbids, then greedy
        // takes the most likely of what survives. Greedy keeps the plan
        // reproducible for one intent (cosine-style float drift on Metal can only
        // flip a near-tie, which a constrained tool call rarely has). `sample`
        // accepts the token into the chain itself, advancing the grammar state, so
        // it must not be accepted again.
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::grammar(&self.model, grammar, "root")
                .map_err(|e| Error::model(format!("compiling the tool-call grammar: {e}")))?,
            LlamaSampler::greedy(),
        ]);

        // The position of the next token to decode, running on from the prompt; the
        // loop is also bounded by the runaway cap, so it counts positions and stops
        // at the cap or when the grammar lets the model end generation. Token pieces
        // are accumulated as bytes and decoded once at the end, so a multibyte
        // character split across two tokens still joins correctly.
        let mut out: Vec<u8> = Vec::new();
        for n_cur in (tokens.len() as i32..).take(PLANNER_MAX_TOKENS) {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            if self.model.is_eog_token(token) {
                break;
            }
            out.extend_from_slice(
                &self
                    .model
                    .token_to_piece_bytes(token, 32, true, None)
                    .map_err(Error::model)?,
            );
            batch.clear();
            batch.add(token, n_cur, &[0], true).map_err(Error::model)?;
            ctx.decode(&mut batch).map_err(Error::model)?;
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

impl Planner for LlmPlanner {
    fn plan(&self, intent: &str, catalog: &Catalog) -> Result<Plan> {
        let intent = intent.trim();
        if intent.is_empty() {
            return Err(Error::Plan("empty intent".into()));
        }
        let grammar = tool_call_grammar(catalog);
        let system = planner_system_prompt(catalog);
        let json = self.generate(&system, intent, &grammar)?;
        let steps = parse_tool_calls(&json, catalog)?;
        Ok(Plan {
            intent: intent.to_string(),
            steps,
        })
    }
}

// The system prompt: who Aura is, the catalog it may call (generated from the
// same `Catalog` the grammar is, so the prose and the grammar never drift), the
// shape of one call, and a few worked examples. The examples matter most for a
// small model: they teach it to copy paths verbatim and to keep the plan to the
// fewest steps, which the grammar cannot enforce (it constrains form, not choice).
fn planner_system_prompt(catalog: &Catalog) -> String {
    let mut tools = String::new();
    for t in catalog.tools() {
        let params: Vec<&str> = t.params().iter().map(|p| p.name).collect();
        tools.push_str(&format!(
            "- {}({}): {} [{}]\n",
            t.name(),
            params.join(", "),
            t.description(),
            t.effect().label()
        ));
    }
    format!(
        "You are Aura, the planner for an operating system. You convert the user's \
request into a JSON array of tool calls that carry it out. Output ONLY the JSON \
array, nothing else.\n\n\
Tools:\n{tools}\n\
Each element is {{\"tool\": <tool name>, \"args\": {{<arg>: <value>}}, \
\"rationale\": <short reason>}}. Use only the tools and argument names listed \
above. Copy paths, names, and search words from the request exactly. Choose \
read_file when the path names a single file and list_dir when it names a \
directory. Keep the array as short as possible, usually a single call.\n\n\
Examples:\n\
request: list what is in /var/log\n\
[{{\"tool\":\"list_dir\",\"args\":{{\"path\":\"/var/log\"}},\"rationale\":\"list the directory\"}}]\n\
request: open the file /home/me/todo.txt\n\
[{{\"tool\":\"read_file\",\"args\":{{\"path\":\"/home/me/todo.txt\"}},\"rationale\":\"read the file\"}}]\n\
request: what is inside /etc/hosts\n\
[{{\"tool\":\"read_file\",\"args\":{{\"path\":\"/etc/hosts\"}},\"rationale\":\"read the file\"}}]\n\
request: where are my notes about sailing under /home/me/docs\n\
[{{\"tool\":\"find\",\"args\":{{\"dir\":\"/home/me/docs\",\"query\":\"notes about sailing\"}},\"rationale\":\"semantic search\"}}]\n\
request: throw away /tmp/old.log\n\
[{{\"tool\":\"delete_file\",\"args\":{{\"path\":\"/tmp/old.log\"}},\"rationale\":\"delete the file\"}}]"
    )
}

// Build a GBNF grammar from the catalog that admits exactly a JSON array of one or
// more tool calls, where each call names one real tool and carries that tool's own
// required argument keys. The model literally cannot emit a call to a tool that is
// not in the catalog, or one missing a required argument key, or malformed JSON;
// the only freedom left to it is which tool and what string values, which is the
// decision we want the model to make. This is the planner analog of the index
// codec in `semantic`: a small, owned format with no serde.
//
// At least one call is required (the array is never empty): an intent the planner
// truly cannot serve still produces a call, which the capability layer then
// refuses, which is the docs/05 point the demo's `/etc/shadow` beat makes (the
// model planning a reach it is not granted, refused by the broker, not the model).
fn tool_call_grammar(catalog: &Catalog) -> String {
    let mut rules = String::new();
    let mut call_alts: Vec<String> = Vec::new();
    for t in catalog.tools() {
        let id = rule_id(t.name());
        let rule = format!("{id}-call");
        call_alts.push(rule.clone());
        rules.push_str(&format!(
            "{rule} ::= \"{{\" ws {tool_key} ws \":\" ws {tool_val} ws \",\" ws \
{args_key} ws \":\" ws {args} ws \",\" ws {rat_key} ws \":\" ws string ws \"}}\"\n",
            tool_key = lit("\"tool\""),
            tool_val = lit(&format!("\"{}\"", t.name())),
            args_key = lit("\"args\""),
            args = args_object_rule(t.params()),
            rat_key = lit("\"rationale\""),
        ));
    }
    format!(
        "root ::= ws \"[\" ws call ( ws \",\" ws call )* ws \"]\" ws\n\
call ::= {alts}\n\
{rules}\
string ::= \"\\\"\" char* \"\\\"\"\n\
char ::= [^\"\\\\] | \"\\\\\" ([\"\\\\/bfnrt] | \"u\" hex hex hex hex)\n\
hex ::= [0-9a-fA-F]\n\
ws ::= [ \\t\\n]*\n",
        alts = call_alts.join(" | "),
    )
}

// The args object for one tool: an open brace, then the tool's required keys in
// order (each `"key": string`), then any optional keys as optional trailing
// groups, then a close brace. A tool with no params is just `{}`. All the built-in
// tools have only required params, so the common path is the clean one; optional
// params are handled too so a future tool with one is representable.
fn args_object_rule(params: &[ParamSpec]) -> String {
    if params.is_empty() {
        return r#""{" ws "}""#.to_string();
    }
    let pair = |p: &ParamSpec| format!("{} ws \":\" ws string", lit(&format!("\"{}\"", p.name)));
    let required: Vec<&ParamSpec> = params.iter().filter(|p| p.required).collect();
    let optional: Vec<&ParamSpec> = params.iter().filter(|p| !p.required).collect();

    let mut body = String::from("\"{\" ws ");
    // Anchor on the required keys when there are any; otherwise the first optional
    // key anchors so the commas stay well-formed.
    let (anchor, rest_required): (&ParamSpec, &[&ParamSpec]) =
        if let Some((first, rest)) = required.split_first() {
            (first, rest)
        } else {
            let (first, _) = optional.split_first().expect("params is non-empty");
            // No required keys: anchor on the first optional, the rest stay optional.
            body.push_str(&format!("( {} ws ", pair(first)));
            for p in &optional[1..] {
                body.push_str(&format!("( \",\" ws {} ws )? ", pair(p)));
            }
            body.push_str(")? \"}\"");
            return body;
        };
    body.push_str(&format!("{} ws ", pair(anchor)));
    for p in rest_required {
        body.push_str(&format!("\",\" ws {} ws ", pair(p)));
    }
    for p in &optional {
        body.push_str(&format!("( \",\" ws {} ws )? ", pair(p)));
    }
    body.push_str("\"}\"");
    body
}

// A GBNF terminal that matches the exact text `s`: wrap it in quotes, escaping the
// backslash and quote so the literal is well-formed. Used to emit the JSON key and
// tool-name literals (which themselves contain quotes) into the grammar.
fn lit(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

// A GBNF rule name derived from a tool name: rule names are restricted to letters,
// digits, and dashes, so any other character (the underscore in `list_dir`)
// becomes a dash. Distinct tool names stay distinct because the only collision
// would need two names differing solely in a non-alnum character.
fn rule_id(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

// Parse the model's JSON array into plan steps, checking each names a real tool.
// The grammar guarantees the shape, but this is the seam where a generated plan
// becomes typed `Step`s, so it validates rather than trusts: a tool the catalog
// does not carry (impossible under the grammar, but cheap to assert) is a planning
// error, not an unrunnable step smuggled downstream.
fn parse_tool_calls(text: &str, catalog: &Catalog) -> Result<Vec<Step>> {
    let value = json::parse(text).map_err(|e| {
        Error::Plan(format!(
            "the planner did not return valid JSON ({e}): {text:?}"
        ))
    })?;
    let array = value
        .as_array()
        .ok_or_else(|| Error::Plan(format!("the planner did not return a JSON array: {text:?}")))?;
    let mut steps = Vec::new();
    for item in array {
        if item.as_object().is_none() {
            return Err(Error::Plan("a tool call was not an object".into()));
        }
        let tool = item
            .get("tool")
            .and_then(json::Value::as_str)
            .ok_or_else(|| Error::Plan("a tool call had no tool name".into()))?;
        if catalog.get(tool).is_none() {
            return Err(Error::Plan(format!(
                "the planner chose an unknown tool {tool:?}"
            )));
        }
        let mut args = Args::new();
        if let Some(map) = item.get("args").and_then(json::Value::as_object) {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    args.set(k.clone(), s.to_string());
                }
            }
        }
        let rationale = item
            .get("rationale")
            .and_then(json::Value::as_str)
            .unwrap_or("");
        steps.push(Step::new(tool, args, rationale));
    }
    Ok(steps)
}

// A minimal JSON reader, just enough to read the grammar-constrained tool-call
// array: objects, arrays, strings (with the standard escapes the grammar allows),
// and the scalars a stray value might be. The crate already owns its binary
// formats without serde (the index codec in `semantic`); this keeps the planner on
// the same footing rather than pulling a derive stack in for one small parse.
mod json {
    // Scalars carry no payload: a tool call's values are all strings (paths,
    // queries, rationales), so `null`, a bool, or a number can only appear as a
    // stray value the planner ignores. Keeping the variants lets such a value parse
    // without error; dropping their payload keeps the reader to what is read.
    pub enum Value {
        Null,
        Bool,
        Num,
        Str(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }
        pub fn as_array(&self) -> Option<&[Value]> {
            match self {
                Value::Array(a) => Some(a),
                _ => None,
            }
        }
        pub fn as_object(&self) -> Option<&[(String, Value)]> {
            match self {
                Value::Object(o) => Some(o),
                _ => None,
            }
        }
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
    }

    pub fn parse(s: &str) -> Result<Value, String> {
        let bytes = s.as_bytes();
        let mut p = Parser { bytes, pos: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        // Trailing content past the first complete value is tolerated (the model
        // ends generation at the close bracket, but a stray newline or token is
        // harmless), so the parse is not required to consume to the end.
        Ok(v)
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        pos: usize,
    }

    impl Parser<'_> {
        fn peek(&self) -> Option<u8> {
            self.bytes.get(self.pos).copied()
        }
        fn ws(&mut self) {
            while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
                self.pos += 1;
            }
        }
        fn value(&mut self) -> Result<Value, String> {
            match self.peek() {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => Ok(Value::Str(self.string()?)),
                Some(b't') => self.literal("true", Value::Bool),
                Some(b'f') => self.literal("false", Value::Bool),
                Some(b'n') => self.literal("null", Value::Null),
                Some(c) if c == b'-' || c.is_ascii_digit() => {
                    self.skip_number();
                    Ok(Value::Num)
                }
                _ => Err("expected a value".into()),
            }
        }
        fn literal(&mut self, word: &str, v: Value) -> Result<Value, String> {
            if self.bytes[self.pos..].starts_with(word.as_bytes()) {
                self.pos += word.len();
                Ok(v)
            } else {
                Err(format!("expected {word}"))
            }
        }
        fn skip_number(&mut self) {
            while matches!(self.peek(), Some(c) if c == b'-' || c == b'+' || c == b'.' || c == b'e' || c == b'E' || c.is_ascii_digit())
            {
                self.pos += 1;
            }
        }
        fn string(&mut self) -> Result<String, String> {
            // Opening quote.
            self.pos += 1;
            let mut out = String::new();
            loop {
                match self.peek() {
                    None => return Err("unterminated string".into()),
                    Some(b'"') => {
                        self.pos += 1;
                        return Ok(out);
                    }
                    Some(b'\\') => {
                        self.pos += 1;
                        match self.peek() {
                            Some(b'"') => out.push('"'),
                            Some(b'\\') => out.push('\\'),
                            Some(b'/') => out.push('/'),
                            Some(b'b') => out.push('\u{0008}'),
                            Some(b'f') => out.push('\u{000C}'),
                            Some(b'n') => out.push('\n'),
                            Some(b'r') => out.push('\r'),
                            Some(b't') => out.push('\t'),
                            Some(b'u') => {
                                let hex = self
                                    .bytes
                                    .get(self.pos + 1..self.pos + 5)
                                    .ok_or("short \\u escape")?;
                                let code = u32::from_str_radix(
                                    std::str::from_utf8(hex).map_err(|_| "bad \\u escape")?,
                                    16,
                                )
                                .map_err(|_| "bad \\u escape")?;
                                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                                self.pos += 4;
                            }
                            _ => return Err("bad escape".into()),
                        }
                        self.pos += 1;
                    }
                    Some(_) => {
                        // Copy one UTF-8 scalar by finding its byte length.
                        let rest = &self.bytes[self.pos..];
                        let ch_len = utf8_len(rest[0]);
                        let chunk = std::str::from_utf8(&rest[..ch_len.min(rest.len())])
                            .map_err(|_| "invalid utf-8 in string")?;
                        out.push_str(chunk);
                        self.pos += ch_len;
                    }
                }
            }
        }
        fn array(&mut self) -> Result<Value, String> {
            self.pos += 1; // [
            let mut items = Vec::new();
            self.ws();
            if self.peek() == Some(b']') {
                self.pos += 1;
                return Ok(Value::Array(items));
            }
            loop {
                self.ws();
                items.push(self.value()?);
                self.ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b']') => {
                        self.pos += 1;
                        return Ok(Value::Array(items));
                    }
                    _ => return Err("expected , or ] in array".into()),
                }
            }
        }
        fn object(&mut self) -> Result<Value, String> {
            self.pos += 1; // {
            let mut entries = Vec::new();
            self.ws();
            if self.peek() == Some(b'}') {
                self.pos += 1;
                return Ok(Value::Object(entries));
            }
            loop {
                self.ws();
                if self.peek() != Some(b'"') {
                    return Err("expected a string key in object".into());
                }
                let key = self.string()?;
                self.ws();
                if self.peek() != Some(b':') {
                    return Err("expected : in object".into());
                }
                self.pos += 1;
                self.ws();
                let val = self.value()?;
                entries.push((key, val));
                self.ws();
                match self.peek() {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => {
                        self.pos += 1;
                        return Ok(Value::Object(entries));
                    }
                    _ => return Err("expected , or } in object".into()),
                }
            }
        }
    }

    // The byte length of a UTF-8 scalar from its lead byte, so a multibyte
    // character inside a string is copied whole.
    fn utf8_len(lead: u8) -> usize {
        if lead < 0x80 {
            1
        } else if lead >> 5 == 0b110 {
            2
        } else if lead >> 4 == 0b1110 {
            3
        } else if lead >> 3 == 0b11110 {
            4
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::dot;

    // The model is a 334 MB download, so these run only when HORIZON_EMBED_MODEL
    // points at a readable GGUF, exactly as the FIDO2 hardware tests gate on a
    // real key and the multicast test gates on a working LAN. CI compiles this
    // module (clippy --features llama) but never runs it (no weights), so it stays
    // green; locally, `HORIZON_EMBED_MODEL=... cargo test -p aura --features llama`
    // exercises the real model.
    fn model() -> Option<GgufEmbedder> {
        let path = std::env::var("HORIZON_EMBED_MODEL").ok()?;
        if !Path::new(&path).is_file() {
            return None;
        }
        Some(GgufEmbedder::load(&path).expect("load the embedding model"))
    }

    #[test]
    fn embeds_normalized_vectors_of_the_model_width() {
        let Some(e) = model() else {
            eprintln!("skipping: set HORIZON_EMBED_MODEL to a GGUF to run");
            return;
        };
        assert!(e.dim() > 0);
        let v = e.embed("the cows graze on the spring pasture");
        assert_eq!(v.len(), e.dim());
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!(
            (norm - 1.0).abs() < 1e-3,
            "expected a unit vector, got {norm}"
        );
    }

    #[test]
    fn ranks_by_meaning_not_lexical_overlap() {
        let Some(e) = model() else {
            eprintln!("skipping: set HORIZON_EMBED_MODEL to a GGUF to run");
            return;
        };
        // The query shares no content word with either document, so the lexical
        // HashingEmbedder would tie them at zero. A real model must still place the
        // livestock note above the tax note. This is the whole point of the seam.
        let q = e.embed("bovine livestock and where they feed");
        let cattle = dot(&q, &e.embed("the herd moves to fresh grazing each morning"));
        let taxes = dot(&q, &e.embed("quarterly invoice totals and the tax return"));
        assert!(
            cattle > taxes,
            "meaning should win: cattle {cattle} vs taxes {taxes}"
        );
    }

    // The grammar generation and the JSON reader are pure code (no weights), so
    // they run in the normal suite. They are what guarantee a generated plan is
    // well-formed; the model-gated test below proves the model fills them.

    #[test]
    fn grammar_constrains_to_the_catalog_tools_and_their_keys() {
        let g = tool_call_grammar(&Catalog::standard());
        // The array root and a per-tool rule (underscores become dashes).
        assert!(g.contains("root ::="));
        assert!(g.contains("list-dir-call ::="));
        assert!(g.contains("delete-file-call ::="));
        // Each call pins the tool name and that tool's own argument keys as JSON
        // string literals, so a wrong tool or a missing key is unrepresentable.
        assert!(g.contains(r#""\"list_dir\"""#));
        assert!(g.contains(r#""\"path\"""#));
        assert!(g.contains(r#""\"find\"""#));
        assert!(g.contains(r#""\"dir\"""#));
        assert!(g.contains(r#""\"query\"""#));
        // The shared JSON terminals are present.
        assert!(g.contains("string ::="));
        assert!(g.contains("ws ::="));
    }

    #[test]
    fn json_reads_a_tool_call_array_with_escapes() {
        let v = json::parse(
            r#"[{"tool":"find","args":{"dir":"/a b","query":"line\none\ttwo"},"rationale":"why"}]"#,
        )
        .unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let call = &arr[0];
        assert_eq!(call.get("tool").and_then(json::Value::as_str), Some("find"));
        let args = call.get("args").unwrap();
        assert_eq!(args.get("dir").and_then(json::Value::as_str), Some("/a b"));
        // Escapes are decoded.
        assert_eq!(
            args.get("query").and_then(json::Value::as_str),
            Some("line\none\ttwo")
        );
    }

    #[test]
    fn parse_tool_calls_builds_steps_and_checks_the_tool() {
        let cat = Catalog::standard();
        let steps = parse_tool_calls(
            r#"[{"tool":"list_dir","args":{"path":"/var/log"},"rationale":"list it"}]"#,
            &cat,
        )
        .unwrap();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].tool, "list_dir");
        assert_eq!(steps[0].args.get("path"), Some("/var/log"));
        assert_eq!(steps[0].rationale, "list it");

        // A well-formed call to a tool the catalog does not carry is refused, not
        // passed downstream as an unrunnable step.
        assert!(
            parse_tool_calls(r#"[{"tool":"frobnicate","args":{},"rationale":"x"}]"#, &cat).is_err()
        );
        // Not even valid JSON is a planning error, not a panic.
        assert!(parse_tool_calls("not json", &cat).is_err());
    }

    // The planner model is a ~1 GB instruct GGUF, so this gates on HORIZON_PLAN_MODEL
    // exactly as the embedder tests gate on HORIZON_EMBED_MODEL: CI compiles it
    // (clippy --features llama) but never runs it (no weights), and locally
    // `HORIZON_PLAN_MODEL=... cargo test -p aura --features llama` exercises the
    // real model end to end.
    fn plan_model() -> Option<LlmPlanner> {
        let path = std::env::var("HORIZON_PLAN_MODEL").ok()?;
        if !Path::new(&path).is_file() {
            return None;
        }
        Some(LlmPlanner::load(&path).expect("load the planner model"))
    }

    #[test]
    fn plans_a_natural_language_intent_into_a_find_call() {
        let Some(p) = plan_model() else {
            eprintln!("skipping: set HORIZON_PLAN_MODEL to a GGUF to run");
            return;
        };
        let cat = Catalog::standard();
        // No verb grammar a RulePlanner could match; the model has to understand it
        // and extract the directory and the search words. The grammar forces the
        // call to be a real tool with real keys; the model chooses find and copies
        // the path.
        let plan = p
            .plan(
                "where do I keep my notes about the cattle under /home/me/farm",
                &cat,
            )
            .expect("the planner should return a plan");
        assert!(!plan.is_empty(), "expected at least one tool call");
        let step = &plan.steps[0];
        assert_eq!(step.tool, "find", "a search intent should plan a find");
        assert_eq!(
            step.args.get("dir"),
            Some("/home/me/farm"),
            "the directory should be copied verbatim from the intent"
        );
        assert!(
            !step.args.get("query").unwrap_or("").is_empty(),
            "find needs a query"
        );
    }

    #[test]
    fn plans_a_deletion_intent_into_a_destructive_call() {
        let Some(p) = plan_model() else {
            eprintln!("skipping: set HORIZON_PLAN_MODEL to a GGUF to run");
            return;
        };
        let cat = Catalog::standard();
        let plan = p
            .plan("get rid of the file /tmp/scratch/old.log", &cat)
            .expect("the planner should return a plan");
        assert!(!plan.is_empty());
        let step = &plan.steps[0];
        assert_eq!(step.tool, "delete_file");
        assert_eq!(step.args.get("path"), Some("/tmp/scratch/old.log"));
        // The catalog marks delete destructive, so the executor will gate it.
        assert!(cat.get("delete_file").unwrap().effect().is_destructive());
    }
}
