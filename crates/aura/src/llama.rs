// The real model behind the seams: one llama.cpp engine, shared. This module is
// gated on the `llama` feature so the default build stays model-free and
// cross-platform; turning it on links llama.cpp (the sys crate builds it from
// source via cmake). For now it fills the `Embedder` seam with a GGUF embedding
// model (EmbeddingGemma); the tool-calling planner that fills the `Planner` seam
// rides the same engine and lands next.
//
// This is the weights-gated shim the rest of `semantic` is written around, the
// analog of identity's `HardwareKey` over the `SoftwareAuthenticator` or the
// compositor's display backends: the deterministic `HashingEmbedder` proves the
// index, ranking, and persistence with no model, and a real model swaps in here
// to bring true meaning (it ties "cows" to "cattle", which the hashing stand-in
// cannot).

use std::num::NonZeroU32;
use std::path::Path;
use std::sync::OnceLock;

use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::{AddBos, LlamaModel};

use crate::error::{Error, Result};
use crate::semantic::{normalize, Embedder};

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
}
