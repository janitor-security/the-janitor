//! rkyv-backed FFI symbol registry with BLAKE3-hashed O(log N) lookup.
//!
//! ## Data model
//! Symbols are hashed with BLAKE3 and stored as a sorted `Vec<[u8; 32]>`.
//! A parallel `Vec<String>` preserves the original names at matching indices
//! for diagnostic output.  Sorting enables `binary_search` lookups.
//!
//! ## PHF note
//! True O(1) PHF requires the corpus at build time (`phf_codegen`/`build.rs`).
//! Since this engine extracts symbols at runtime, sorted-array binary search
//! is the most cache-efficient achievable alternative without a build step.
//!
//! ## Memory gate
//! If the estimated serialised size exceeds [`REGISTRY_MEMORY_LIMIT_BYTES`],
//! [`save_registry`] writes a sorted plaintext trie instead and appends an
//! architectural-failure notice to `.janitor/experiments.log`.

use std::io::Write as IoWrite;
use std::path::Path;

use anyhow::Result;
use memmap2::Mmap;

/// Serialised registry size threshold — triggers the Radix Trie fallback.
const REGISTRY_MEMORY_LIMIT_BYTES: usize = 20 * 1024 * 1024; // 20 MiB

// ---------------------------------------------------------------------------
// Serialisable registry struct
// ---------------------------------------------------------------------------

/// rkyv-serialisable FFI symbol corpus.
///
/// Stores BLAKE3 hashes of valid C++ exported symbol names, sorted ascending
/// for deterministic binary search.  The parallel `names` vec retains the
/// original strings at the same indices for human-readable diagnostics.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
pub struct FfiSymbolRegistry {
    /// BLAKE3 hashes of valid symbol names, sorted ascending.
    pub hashes: Vec<[u8; 32]>,
    /// Original symbol names at matching indices (for diagnostic output).
    pub names: Vec<String>,
}

impl FfiSymbolRegistry {
    /// Construct a registry from a list of exported symbol names.
    ///
    /// Hashes each name with BLAKE3, sorts the (hash, name) pairs by hash,
    /// deduplicates, and stores them in parallel vecs.
    pub fn build(symbols: &[String]) -> Self {
        let mut pairs: Vec<([u8; 32], String)> = symbols
            .iter()
            .map(|s| {
                let hash: [u8; 32] = blake3::hash(s.as_bytes()).into();
                (hash, s.clone())
            })
            .collect();
        pairs.sort_unstable_by_key(|(h, _)| *h);
        pairs.dedup_by_key(|(h, _)| *h);
        let (hashes, names) = pairs.into_iter().unzip();
        Self { hashes, names }
    }

    /// O(log N) membership test — does not allocate on the hot path.
    pub fn contains(&self, symbol: &str) -> bool {
        let hash: [u8; 32] = blake3::hash(symbol.as_bytes()).into();
        self.hashes.binary_search(&hash).is_ok()
    }

    /// Conservative estimate of serialised byte size.
    ///
    /// Used to gate against the 20 MiB memory limit before the (potentially
    /// expensive) `rkyv::to_bytes` call.
    fn estimated_size(&self) -> usize {
        // 32 bytes per hash + len + 16-byte heap overhead per name string.
        self.hashes.len() * 32 + self.names.iter().map(|n| n.len() + 16).sum::<usize>()
    }
}

// ---------------------------------------------------------------------------
// Serialisation / deserialisation
// ---------------------------------------------------------------------------

/// Serialise `registry` to an rkyv file at `path`.
///
/// If the estimated size exceeds [`REGISTRY_MEMORY_LIMIT_BYTES`]:
/// - Logs an architectural failure to `<janitor_dir>/experiments.log` (if
///   `janitor_dir` is `Some`).
/// - Writes a sorted plaintext trie to `<path>.trie` instead of the rkyv
///   archive.
///
/// # Errors
/// Returns `Err` on I/O failure or rkyv serialisation error.
pub fn save_registry(
    registry: &FfiSymbolRegistry,
    path: &Path,
    janitor_dir: Option<&Path>,
) -> Result<()> {
    if registry.estimated_size() > REGISTRY_MEMORY_LIMIT_BYTES {
        // ── Architectural failure: log and degrade ────────────────────────
        if let Some(dir) = janitor_dir {
            let log_path = dir.join("experiments.log");
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)?;
            writeln!(
                log,
                "[phantom_ffi_gate] DEGRADED: estimated registry size {} bytes \
                 exceeds 20 MiB gate. Falling back to sorted-plaintext radix \
                 trie at {}.trie",
                registry.estimated_size(),
                path.display()
            )?;
        }
        // Radix-trie fallback: sorted symbol names, one per line.
        let trie_path = path.with_extension("trie");
        let content = registry.names.join("\n");
        std::fs::write(trie_path, content.as_bytes())?;
        return Ok(());
    }

    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(registry)
        .map_err(|e| anyhow::anyhow!("rkyv serialisation failed: {e}"))?;
    std::fs::write(path, bytes.as_slice())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// mmap-backed zero-copy registry access
// ---------------------------------------------------------------------------

/// Zero-copy, mmap-backed FFI symbol registry for the evaluation pass.
///
/// Wraps a [`memmap2::Mmap`] and performs symbol lookups via binary search
/// directly on the archived hash slice — no heap allocation on the hot path.
pub struct RegistryMmap {
    mmap: Mmap,
}

impl RegistryMmap {
    /// Open `path` and memory-map the rkyv registry.
    ///
    /// # Safety (internal)
    /// [`lookup`][Self::lookup] calls `rkyv::access_unchecked` — the file at
    /// `path` **must** be a valid rkyv-serialised `FfiSymbolRegistry` produced
    /// by [`save_registry`].
    ///
    /// # Errors
    /// Returns `Err` if the file cannot be opened or the OS mmap call fails.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("Cannot open registry {}: {e}", path.display()))?;
        // SAFETY: the mmap region is read-only; the file is trusted (produced
        // by save_registry in this crate).
        let mmap = unsafe { Mmap::map(&file) }
            .map_err(|e| anyhow::anyhow!("mmap failed for {}: {e}", path.display()))?;
        Ok(Self { mmap })
    }

    /// Access the archived registry without deserialising to heap.
    ///
    /// # Safety
    /// The mmap contents must be a valid rkyv archive of `FfiSymbolRegistry`.
    unsafe fn archived(&self) -> &rkyv::Archived<FfiSymbolRegistry> {
        rkyv::access_unchecked::<rkyv::Archived<FfiSymbolRegistry>>(self.mmap.as_ref())
    }

    /// O(log N) symbol lookup with zero heap allocation.
    ///
    /// Hashes `symbol` with BLAKE3 and binary-searches the archived hash
    /// slice directly in the mmap region.
    pub fn lookup(&self, symbol: &str) -> bool {
        let hash: [u8; 32] = blake3::hash(symbol.as_bytes()).into();
        // SAFETY: mmap was populated by save_registry in this crate.
        let archived = unsafe { self.archived() };
        archived.hashes.binary_search(&hash).is_ok()
    }
}
