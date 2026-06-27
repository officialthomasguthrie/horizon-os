// Semantic search: the embeddings + vector index that lets Aura find things by
// meaning rather than substring (docs/05's semantic memory). It sits on the same
// headless split as the rest of the system. The embedding MODEL is the
// weights-gated shim that plugs into the `Embedder` seam later (EmbeddingGemma
// over llama.cpp, the same engine the planner backend will use), eye-verified on
// hardware; the vector index, the cosine ranking, and the persistence are pure
// code, owned here and proven without a model.
//
// The default `HashingEmbedder` is the deterministic dev and test seam, the
// analog of the `RulePlanner` and identity's `SoftwareAuthenticator`: it turns
// text into a lexical-overlap feature vector (the hashing trick over words and
// character trigrams), which is enough to exercise the whole index and ranking
// pipeline end to end. It does not capture true meaning (it will not tie "cows"
// to "cattle"); that quality leap is exactly what the real model brings when it
// fills the seam.

use lifestream::{Lifestream, ObjectId};

use crate::error::{Error, Result};

// The default embedding width. Small enough to keep the brute-force search cheap
// and the persisted index compact, wide enough that feature-hash collisions are
// rare on ordinary text (a real EmbeddingGemma vector is 768-wide, comparable).
pub const DEFAULT_DIM: usize = 1024;

// The store ref the standing index lives under. Flat (no slash), since a ref is a
// single file under the store's refs/ directory.
pub const INDEX_REF: &str = "aura-index";

// L2-normalize a vector in place. A zero vector (empty or featureless text) is
// left as zeros, so it has cosine 0 with everything and matches nothing.
pub fn normalize(v: &mut [f32]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

// Dot product. For L2-normalized vectors this is the cosine similarity, which is
// what every embedding the crate produces is, so ranking is a plain dot.
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

// Turns text into an L2-normalized embedding. A zero vector is allowed and means
// "no features", which search treats as matching nothing.
pub trait Embedder: Send + Sync {
    fn dim(&self) -> usize;
    fn embed(&self, text: &str) -> Vec<f32>;
}

// So a caller can choose the embedder at runtime (the hashing stand-in or a real
// model behind the `llama` feature) and still drive one `SemanticIndex<Box<dyn
// Embedder>>`, rather than monomorphizing the whole CLI twice.
impl Embedder for Box<dyn Embedder> {
    fn dim(&self) -> usize {
        (**self).dim()
    }
    fn embed(&self, text: &str) -> Vec<f32> {
        (**self).embed(text)
    }
}

// The deterministic stand-in embedder: feature hashing over word tokens and
// their character trigrams into a fixed-width vector. Words give exact-term
// overlap; trigrams give a little morphological robustness (cow / cows share
// "cow"), which makes the ranking behave more like a real embedding than a raw
// substring match without pretending to understand meaning. Determinism matters:
// a persisted index is only valid if the same text embeds the same way on every
// run, so the hash is a fixed FNV-1a, not the std hasher (whose output is not
// guaranteed stable across builds).
pub struct HashingEmbedder {
    dim: usize,
}

impl HashingEmbedder {
    pub fn new(dim: usize) -> HashingEmbedder {
        assert!(dim > 0, "embedding dim must be positive");
        HashingEmbedder { dim }
    }
}

impl Default for HashingEmbedder {
    fn default() -> HashingEmbedder {
        HashingEmbedder::new(DEFAULT_DIM)
    }
}

impl Embedder for HashingEmbedder {
    fn dim(&self) -> usize {
        self.dim
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; self.dim];
        for token in tokens(text) {
            add_feature(&mut v, &token);
            for tri in trigrams(&token) {
                add_feature(&mut v, &tri);
            }
        }
        normalize(&mut v);
        v
    }
}

// Hash one feature into the vector: the low bit picks the sign (so unrelated
// features that collide tend to cancel rather than pile up), the rest picks the
// bucket. This is the standard signed feature-hashing trick.
fn add_feature(v: &mut [f32], feature: &str) {
    let h = fnv1a(feature.as_bytes());
    let bucket = (h >> 1) as usize % v.len();
    let sign = if h & 1 == 0 { 1.0 } else { -1.0 };
    v[bucket] += sign;
}

// Lowercase alphanumeric word tokens, with common function words dropped.
// Anything non-alphanumeric (punctuation, whitespace) is a separator, so
// "cows.md" yields "cows" and "md". Stopwording is what any bag-of-words search
// does and matters here: a natural-language query ("where do the cows graze")
// must match on its content words, not score every document that contains "the".
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            cur.extend(ch.to_lowercase());
        } else if !cur.is_empty() {
            push_token(&mut out, std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        push_token(&mut out, cur);
    }
    out
}

fn push_token(out: &mut Vec<String>, tok: String) {
    if !is_stopword(&tok) {
        out.push(tok);
    }
}

// A small set of English function words. Deliberately short: enough to keep the
// common filler from dominating, not a linguistics project. The real model has
// no such list; this is part of the stand-in.
fn is_stopword(tok: &str) -> bool {
    matches!(
        tok,
        "the"
            | "a"
            | "an"
            | "and"
            | "or"
            | "of"
            | "to"
            | "in"
            | "on"
            | "at"
            | "for"
            | "from"
            | "by"
            | "with"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "it"
            | "its"
            | "this"
            | "that"
            | "these"
            | "those"
            | "do"
            | "does"
            | "did"
            | "where"
            | "what"
            | "when"
            | "who"
            | "how"
            | "about"
            | "my"
            | "your"
            | "i"
            | "you"
    )
}

// The character trigrams of a token (already lowercased). Tokens shorter than 3
// chars contribute only their word feature.
fn trigrams(token: &str) -> Vec<String> {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() < 3 {
        return Vec::new();
    }
    chars
        .windows(3)
        .map(|w| w.iter().collect::<String>())
        .collect()
}

// FNV-1a, 64-bit. Small, fast, and crucially stable across builds, which a
// persisted index depends on.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// One ranked result: the document id, its cosine score against the query, and a
// short human-readable snippet carried alongside the vector.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub id: String,
    pub score: f32,
    pub snippet: String,
}

// One stored document: its id, its embedding, and a snippet for display.
#[derive(Clone, Debug, PartialEq)]
struct Entry {
    id: String,
    vector: Vec<f32>,
    snippet: String,
}

// A flat vector index: every document's embedding, searched by brute-force
// cosine. This is the docs/05 sqlite-vec approach at small scale (brute force is
// fine into the ~100k-vector range on a laptop); an approximate index (HNSW)
// is the swap-in beyond that, behind this same API. Owned in pure Rust with its
// own compact binary encoding, like the gpt/fat/cpio formats, so it is
// deterministic, dependency-free, and persists without dragging in serde.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VectorIndex {
    dim: usize,
    entries: Vec<Entry>,
}

impl VectorIndex {
    pub fn new(dim: usize) -> VectorIndex {
        VectorIndex {
            dim,
            entries: Vec::new(),
        }
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // Add or replace a document. A repeated id overwrites, so re-indexing is
    // idempotent rather than duplicating.
    pub fn add(&mut self, id: impl Into<String>, vector: Vec<f32>, snippet: impl Into<String>) {
        let id = id.into();
        let entry = Entry {
            id,
            vector,
            snippet: snippet.into(),
        };
        match self.entries.iter_mut().find(|e| e.id == entry.id) {
            Some(slot) => *slot = entry,
            None => self.entries.push(entry),
        }
    }

    // Drop a document by id; returns whether one was there.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.entries.len() != before
    }

    // The top-k documents by cosine similarity to the query, best first. A
    // non-positive `min_score` keeps everything; a small positive one (the
    // default the tools use) drops documents with no overlap, which is what gives
    // the lexical-grade precision the substring search had while adding ranking.
    pub fn search(&self, query: &[f32], k: usize, min_score: f32) -> Vec<Hit> {
        let mut hits: Vec<Hit> = self
            .entries
            .iter()
            .map(|e| Hit {
                id: e.id.clone(),
                score: dot(query, &e.vector),
                snippet: e.snippet.clone(),
            })
            .filter(|h| h.score > min_score)
            .collect();
        // Sort by score desc, breaking ties by id so the order is stable.
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.id.cmp(&b.id))
        });
        hits.truncate(k);
        hits
    }

    // The compact on-disk form: a magic tag, version, dim, count, then each
    // entry's id, snippet, and raw little-endian floats.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"AVIX");
        out.push(1); // version
        out.extend_from_slice(&(self.dim as u32).to_le_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            put_bytes(&mut out, e.id.as_bytes());
            put_bytes(&mut out, e.snippet.as_bytes());
            for x in &e.vector {
                out.extend_from_slice(&x.to_le_bytes());
            }
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<VectorIndex> {
        let mut r = Reader::new(buf);
        if r.take(4)? != b"AVIX" {
            return Err(Error::Index("bad magic"));
        }
        if r.u8()? != 1 {
            return Err(Error::Index("unsupported version"));
        }
        let dim = r.u32()? as usize;
        let count = r.u32()? as usize;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let id = r.string()?;
            let snippet = r.string()?;
            let mut vector = vec![0f32; dim];
            for x in vector.iter_mut() {
                *x = f32::from_le_bytes(r.take(4)?.try_into().unwrap());
            }
            entries.push(Entry {
                id,
                vector,
                snippet,
            });
        }
        Ok(VectorIndex { dim, entries })
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

// A small bounds-checked cursor over the encoded buffer, so a truncated or
// malformed index is a typed error, never a panic.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::Index("overflow"))?;
        if end > self.buf.len() {
            return Err(Error::Index("truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| Error::Index("non-utf8 string"))
    }
}

// A semantic index: an embedder and the vector index it fills, plus the
// persistence that puts the index inside the Lifestream (encrypted at rest,
// content-addressed, and referenced by name so it survives gc), exactly the way
// the Weave keeps its audit log. This is the "index over the Lifestream": the
// store both holds the documents and carries the index of them.
pub struct SemanticIndex<E: Embedder> {
    embedder: E,
    index: VectorIndex,
}

impl<E: Embedder> SemanticIndex<E> {
    pub fn new(embedder: E) -> SemanticIndex<E> {
        let dim = embedder.dim();
        SemanticIndex {
            embedder,
            index: VectorIndex::new(dim),
        }
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn index(&self) -> &VectorIndex {
        &self.index
    }

    pub fn embedder(&self) -> &E {
        &self.embedder
    }

    // Embed `text` and store it under `id`, with a short snippet kept for display.
    // Idempotent on `id`, so re-indexing a changed document replaces its vector.
    pub fn add(&mut self, id: impl Into<String>, text: &str) {
        let vector = self.embedder.embed(text);
        self.index.add(id, vector, snippet(text));
    }

    pub fn remove(&mut self, id: &str) -> bool {
        self.index.remove(id)
    }

    // Rank the indexed documents by meaning against a query, best first, dropping
    // those with no overlap (min_score 0).
    pub fn query(&self, text: &str, k: usize) -> Vec<Hit> {
        let q = self.embedder.embed(text);
        self.index.search(&q, k, 0.0)
    }

    // Persist the index into the store and point `refname` at it, so it is
    // reachable for gc and reloadable. Returns the object id of the stored index.
    pub fn save(&self, ls: &Lifestream, refname: &str) -> Result<ObjectId> {
        let id = ls
            .write_bytes(&self.index.encode())
            .map_err(Error::lifestream)?;
        ls.set_ref(refname, &id).map_err(Error::lifestream)?;
        Ok(id)
    }

    // Load the index `refname` points at, rebuilding it under `embedder`. A store
    // with no such ref yields an empty index (nothing indexed yet). A stored index
    // whose width does not match the embedder is refused rather than silently
    // mixing incompatible vectors.
    pub fn load(embedder: E, ls: &Lifestream, refname: &str) -> Result<SemanticIndex<E>> {
        let index = match ls.get_ref(refname).map_err(Error::lifestream)? {
            Some(id) => {
                let bytes = ls.read_bytes(&id).map_err(Error::lifestream)?;
                let index = VectorIndex::decode(&bytes)?;
                if index.dim() != embedder.dim() {
                    return Err(Error::Index("index width does not match the embedder"));
                }
                index
            }
            None => VectorIndex::new(embedder.dim()),
        };
        Ok(SemanticIndex { embedder, index })
    }
}

// A one-line, length-capped snippet of a document for display in results: the
// first non-empty line, trimmed.
fn snippet(text: &str) -> String {
    let line = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let trimmed = line.trim();
    let mut s: String = trimmed.chars().take(80).collect();
    if trimmed.chars().count() > 80 {
        s.push('\u{2026}');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_makes_unit_vectors_and_leaves_zero_alone() {
        let mut v = vec![3.0, 4.0];
        normalize(&mut v);
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-6);
        let mut z = vec![0.0, 0.0, 0.0];
        normalize(&mut z);
        assert_eq!(z, vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn identical_text_is_close_disjoint_text_is_not() {
        let e = HashingEmbedder::default();
        let a = e.embed("the cows graze in the north paddock");
        let b = e.embed("the cows graze in the north paddock");
        let c = e.embed("quarterly tax spreadsheet figures");
        assert!((dot(&a, &b) - 1.0).abs() < 1e-6, "identical => cosine 1");
        assert!(dot(&a, &c) < 0.2, "unrelated => low cosine");
    }

    #[test]
    fn embedding_is_deterministic_across_instances() {
        // A persisted index depends on this: the same text must embed the same
        // way on a later run.
        let a = HashingEmbedder::default().embed("grazing rotations from spring");
        let b = HashingEmbedder::default().embed("grazing rotations from spring");
        assert_eq!(a, b);
    }

    #[test]
    fn related_text_outranks_unrelated() {
        let e = HashingEmbedder::default();
        let q = e.embed("where do the cows graze");
        let near = dot(&q, &e.embed("the cows graze on the spring pasture"));
        let far = dot(&q, &e.embed("invoice totals for the quarter"));
        assert!(
            near > far,
            "related text should score higher: {near} vs {far}"
        );
    }

    #[test]
    fn index_search_orders_by_similarity_and_respects_k() {
        let e = HashingEmbedder::default();
        let mut idx = VectorIndex::new(e.dim());
        idx.add("a", e.embed("cattle grazing paddock rotation"), "a");
        idx.add("b", e.embed("cow pasture spring"), "b");
        idx.add("c", e.embed("annual budget spreadsheet"), "c");
        let hits = idx.search(&e.embed("where the cows graze"), 2, 0.0);
        assert_eq!(hits.len(), 2, "k caps the result count");
        assert!(hits[0].score >= hits[1].score, "ordered best first");
        assert!(
            hits.iter().all(|h| h.id != "c"),
            "the unrelated doc is dropped"
        );
    }

    #[test]
    fn min_score_drops_non_overlapping_documents() {
        let e = HashingEmbedder::default();
        let mut idx = VectorIndex::new(e.dim());
        idx.add("hit", e.embed("cows in the field"), "hit");
        idx.add("miss", e.embed("unrelated"), "miss");
        let hits = idx.search(&e.embed("cows"), 10, 0.0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "hit");
    }

    #[test]
    fn add_replaces_and_remove_drops() {
        let e = HashingEmbedder::default();
        let mut idx = VectorIndex::new(e.dim());
        idx.add("x", e.embed("first"), "first");
        idx.add("x", e.embed("second"), "second");
        assert_eq!(idx.len(), 1, "same id replaces, not duplicates");
        assert!(idx.remove("x"));
        assert!(!idx.remove("x"));
        assert!(idx.is_empty());
    }

    #[test]
    fn encode_decode_roundtrips_and_rejects_garbage() {
        let e = HashingEmbedder::default();
        let mut idx = VectorIndex::new(e.dim());
        idx.add("doc1", e.embed("the cows graze"), "the cows graze");
        idx.add("doc2", e.embed("spring rotations"), "spring rotations");
        let back = VectorIndex::decode(&idx.encode()).unwrap();
        assert_eq!(idx, back);
        assert!(VectorIndex::decode(b"not an index").is_err());
        assert!(VectorIndex::decode(&[]).is_err());
    }

    #[test]
    fn semantic_index_query_end_to_end() {
        let mut si = SemanticIndex::new(HashingEmbedder::default());
        si.add(
            "cattle.md",
            "grazing rotations from spring: moving the cows",
        );
        si.add("taxes.md", "quarterly figures and the budget spreadsheet");
        let hits = si.query("that thing about where the cows graze", 5);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].id, "cattle.md", "the cattle note ranks first");
        assert!(hits.iter().all(|h| h.id != "taxes.md"));
    }

    #[test]
    fn index_persists_through_the_lifestream() {
        let dir = tempfile::tempdir().unwrap();
        let ls = Lifestream::init(dir.path().join("store"), &[9u8; 32]).unwrap();

        let mut si = SemanticIndex::new(HashingEmbedder::default());
        si.add("cattle.md", "the cows graze on the spring pasture");
        si.add("taxes.md", "quarterly budget spreadsheet");
        si.save(&ls, INDEX_REF).unwrap();

        // A fresh load from the store reproduces the same ranking.
        let loaded = SemanticIndex::load(HashingEmbedder::default(), &ls, INDEX_REF).unwrap();
        assert_eq!(loaded.len(), 2);
        let hits = loaded.query("cows grazing", 5);
        assert_eq!(hits[0].id, "cattle.md");
    }

    #[test]
    fn load_with_no_ref_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let ls = Lifestream::init(dir.path().join("store"), &[1u8; 32]).unwrap();
        let si = SemanticIndex::load(HashingEmbedder::default(), &ls, INDEX_REF).unwrap();
        assert!(si.is_empty());
    }

    #[test]
    fn load_rejects_a_width_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let ls = Lifestream::init(dir.path().join("store"), &[2u8; 32]).unwrap();
        SemanticIndex::new(HashingEmbedder::new(256))
            .save(&ls, INDEX_REF)
            .unwrap();
        // A different embedding width cannot read the stored vectors.
        let err = SemanticIndex::load(HashingEmbedder::new(128), &ls, INDEX_REF);
        assert!(err.is_err());
    }
}
