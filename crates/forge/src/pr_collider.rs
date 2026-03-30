//! # PR Collider — LSH-Based Cross-PR Deduplication
//!
//! Uses MinHash sketches and Locality-Sensitive Hashing (LSH) to detect when
//! two pull requests make structurally similar changes — a strong signal that
//! duplicate logic is being re-introduced from different branches.
//!
//! ## Algorithm
//! 1. Compute a 64-hash MinHash sketch ([`PrDeltaSignature`]) from byte 3-grams of
//!    the patch/diff content.
//! 2. Split the 64 hashes into bands; each band is hashed to a bucket key.
//! 3. Query the [`LshIndex`] — candidates sharing a bucket key are then verified
//!    with full Jaccard similarity.
//! 4. Signatures exceeding the similarity threshold are considered near-duplicate PRs.
//!
//! ## Thread Safety
//! [`LshIndex`] uses [`ArcSwap`][arc_swap::ArcSwap] for lock-free reads.
//! [`insert`][LshIndex::insert] and [`query`][LshIndex::query] are safe to call
//! concurrently from multiple tokio tasks.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;

// ---------------------------------------------------------------------------
// LSH parameters
// ---------------------------------------------------------------------------

/// Number of MinHash hashes per sketch.
const NUM_HASHES: usize = 64;
/// Number of LSH bands (each band covers `NUM_HASHES / NUM_BANDS` rows).
const NUM_BANDS: usize = 8;
/// Rows per LSH band.
const ROWS_PER_BAND: usize = NUM_HASHES / NUM_BANDS; // 8

// ---------------------------------------------------------------------------
// PrDeltaSignature
// ---------------------------------------------------------------------------

/// A 64-hash MinHash sketch of a pull-request diff.
///
/// Computed over byte 3-grams of the raw patch content.  Two sketches with
/// high Jaccard similarity represent structurally near-duplicate patches.
#[derive(Debug, Clone)]
pub struct PrDeltaSignature {
    pub min_hashes: [u64; NUM_HASHES],
}

impl PrDeltaSignature {
    /// Returns `true` if `data` yields at least [`MIN_SHINGLE_ENTROPY`] byte
    /// 3-gram windows, indicating sufficient entropy for swarm clustering.
    ///
    /// Patches below this threshold (single-word typo fixes, lone comment
    /// additions, pure whitespace edits) must not be inserted into or queried
    /// against the [`LshIndex`] — their MinHash sketches are too sparse to
    /// discriminate unrelated PRs and cause null-vector false collisions.
    pub fn has_entropy(data: &[u8]) -> bool {
        if data.len() < 3 {
            return false;
        }
        // windows(3).count() == data.len() - 2 for len >= 3.  O(1) — no
        // iteration required.
        (data.len() - 2) >= MIN_SHINGLE_ENTROPY
    }

    /// Compute a MinHash sketch from raw bytes (patch/diff content).
    ///
    /// Uses 64 independent hash seeds over byte 3-grams.  Falls back to
    /// single-byte shingles for inputs shorter than 3 bytes.
    ///
    /// Dispatches to the AVX-256 SIMD path on x86-64 when the `avx2` feature
    /// is detected at runtime, otherwise falls back to the scalar path.
    pub fn from_bytes(data: &[u8]) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: avx2 feature confirmed present by is_x86_feature_detected!
                return Self {
                    min_hashes: unsafe { from_bytes_avx256(data) },
                };
            }
        }
        from_bytes_scalar(data)
    }
}

/// Scalar (non-SIMD) MinHash implementation.
///
/// Reference path used both as the universal fallback and as the correctness
/// oracle in [`simd_matches_scalar`] tests.
fn from_bytes_scalar(data: &[u8]) -> PrDeltaSignature {
    let mut min_hashes = [u64::MAX; NUM_HASHES];

    if data.is_empty() {
        return PrDeltaSignature { min_hashes };
    }

    let window_size = if data.len() >= 3 { 3 } else { 1 };

    for window in data.windows(window_size) {
        for (i, &seed) in HASH_SEEDS.iter().enumerate() {
            let h = hash_shingle(window, seed);
            if h < min_hashes[i] {
                min_hashes[i] = h;
            }
        }
    }

    PrDeltaSignature { min_hashes }
}

// ---------------------------------------------------------------------------
// AVX-256 SIMD MinHash — x86-64 only
// ---------------------------------------------------------------------------
//
// Processes 4 MinHash seeds in parallel per SIMD call using 256-bit YMM
// registers (4 × u64 lanes).  Produces identical output to `from_bytes_scalar`
// but reduces inner-loop instruction count by 4× on AVX-256 runners.
//
// 64-bit multiply is not natively available in pure AVX-256 (that requires
// AVX-512VL `_mm256_mullo_epi64`).  We emulate it via two `_mm256_mul_epu32`
// calls using the identity:
//
//   (a_lo + a_hi·2³²) × (b_lo + b_hi·2³²) mod 2⁶⁴
//   = a_lo·b_lo + (a_lo·b_hi + a_hi·b_lo)·2³²
//
// Gate: `simd_matches_scalar` verifies bit-exact output for 100 random payloads.

/// Emulate 64-bit wrapping multiply for 4 u64 lanes in an AVX-256 register.
///
/// Uses two `_mm256_mul_epu32` calls per cross-term: O(8 instructions) vs the
/// single `_mm256_mullo_epi64` that would require AVX-512VL.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn mul64_avx2(
    a: std::arch::x86_64::__m256i,
    b: std::arch::x86_64::__m256i,
) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;
    // a_lo * b_lo (64-bit result per lane, using lower 32 bits of each operand)
    let lo_lo = _mm256_mul_epu32(a, b);
    // a_lo * b_hi: shift b right 32 to put b_hi into the low 32-bit position
    let b_hi = _mm256_srli_epi64(b, 32);
    let lo_hi = _mm256_mul_epu32(a, b_hi);
    // a_hi * b_lo: shift a right 32 to put a_hi into the low 32-bit position
    let a_hi = _mm256_srli_epi64(a, 32);
    let hi_lo = _mm256_mul_epu32(a_hi, b);
    // Sum the two cross-products, then shift into the high 32 bits
    let cross = _mm256_slli_epi64(_mm256_add_epi64(lo_hi, hi_lo), 32);
    _mm256_add_epi64(lo_lo, cross)
}

/// Compute a MinHash sketch using AVX-256 SIMD (4 seeds per register).
///
/// Requires the `avx2` target feature; caller MUST check
/// `is_x86_feature_detected!("avx2")` before calling.
///
/// Correctness invariant: `from_bytes_avx256(d).min_hashes == from_bytes_scalar(d).min_hashes`
/// for every input `d` — verified by the `simd_matches_scalar` unit test.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn from_bytes_avx256(data: &[u8]) -> [u64; NUM_HASHES] {
    use std::arch::x86_64::*;

    const M1: i64 = 0x6c62272e07bb0142u64 as i64;
    const M2: i64 = 0x94d049bb133111ebu64 as i64;
    const LANES: usize = 4; // 256-bit / 64-bit = 4 lanes

    let mut min_hashes = [u64::MAX; NUM_HASHES];

    if data.is_empty() {
        return min_hashes;
    }

    let window_size = if data.len() >= 3 { 3 } else { 1 };

    let m1 = _mm256_set1_epi64x(M1);
    let m2 = _mm256_set1_epi64x(M2);
    // Bias for unsigned comparison: XOR with 0x8000_0000_0000_0000 to convert
    // unsigned u64 ordering to signed i64 ordering so `_mm256_cmpgt_epi64` works.
    let bias = _mm256_set1_epi64x(i64::MIN);

    for window in data.windows(window_size) {
        // Process all 64 seeds in groups of LANES=4.
        let mut chunk_start = 0;
        while chunk_start < NUM_HASHES {
            // Load 4 seed values as the initial hash state for this window.
            // SAFETY: HASH_SEEDS has exactly NUM_HASHES=64 u64s; chunk_start
            // is a multiple of LANES=4 and chunk_start+LANES <= NUM_HASHES.
            let seeds_ptr = HASH_SEEDS.as_ptr().add(chunk_start) as *const __m256i;
            let mut lane = _mm256_loadu_si256(seeds_ptr);

            // Apply the hash mixing round for each byte in the 3-gram window.
            for &byte in window {
                let b = _mm256_set1_epi64x(byte as i64);
                lane = _mm256_xor_si256(lane, b);
                lane = mul64_avx2(lane, m1);
                lane = _mm256_xor_si256(lane, _mm256_srli_epi64(lane, 16));
                lane = mul64_avx2(lane, m2);
                lane = _mm256_xor_si256(lane, _mm256_srli_epi64(lane, 32));
            }

            // Lane-wise unsigned minimum: update min_hashes where lane < current.
            // Emulate _mm256_min_epu64 (requires AVX-512) via biased signed cmpgt.
            let min_ptr = min_hashes.as_ptr().add(chunk_start) as *const __m256i;
            let current = _mm256_loadu_si256(min_ptr);
            // Bias both operands: unsigned compare via signed comparison of (x XOR sign_bit)
            let lane_b = _mm256_xor_si256(lane, bias);
            let cur_b = _mm256_xor_si256(current, bias);
            // mask[i] = 0xFF...FF where current[i] > lane[i] (unsigned)
            let mask = _mm256_cmpgt_epi64(cur_b, lane_b);
            // Select lane where mask is true (current > lane), else keep current
            let new_min = _mm256_blendv_epi8(current, lane, mask);
            let min_mut_ptr = min_hashes.as_mut_ptr().add(chunk_start) as *mut __m256i;
            _mm256_storeu_si256(min_mut_ptr, new_min);

            chunk_start += LANES;
        }
    }

    min_hashes
}

/// Minimum number of byte 3-gram windows a patch must contain for its
/// [`PrDeltaSignature`] to be considered sufficiently entropic for swarm
/// clustering.
///
/// Patches below this threshold — single-word typo fixes, pure whitespace
/// edits, lone comment additions — produce MinHash sketches too sparse to
/// discriminate unrelated PRs and must bypass the [`LshIndex`].
const MIN_SHINGLE_ENTROPY: usize = 5;

/// Precomputed hash seeds for MinHash (64 independent seeds).
const HASH_SEEDS: [u64; NUM_HASHES] = {
    let mut seeds = [0u64; NUM_HASHES];
    let mut i = 0usize;
    while i < NUM_HASHES {
        seeds[i] = 0x517cc1b727220a95u64
            .wrapping_add(i as u64)
            .wrapping_mul(0x6c62272e07bb0142u64);
        i += 1;
    }
    seeds
};

/// Fast non-cryptographic hash for MinHash shingles.
fn hash_shingle(shingle: &[u8], seed: u64) -> u64 {
    let mut h = seed;
    for &byte in shingle {
        h ^= byte as u64;
        h = h.wrapping_mul(0x6c62272e07bb0142u64);
        h ^= h >> 16;
        h = h.wrapping_mul(0x94d049bb133111ebu64);
        h ^= h >> 32;
    }
    h
}

// ---------------------------------------------------------------------------
// LshIndex
// ---------------------------------------------------------------------------

/// Snapshot of the LSH index — held inside [`ArcSwap`] for lock-free swap.
#[derive(Debug, Clone, Default)]
struct IndexSnapshot {
    signatures: Vec<PrDeltaSignature>,
    /// PR numbers parallel to `signatures` — `pr_numbers[i]` is the PR that
    /// produced `signatures[i]`.  `0` is the sentinel for daemon-mode entries
    /// where no PR number is available.
    pr_numbers: Vec<u32>,
    /// Band buckets: `[band_index][bucket_key] = [signature_indices]`.
    buckets: Vec<HashMap<u64, Vec<usize>>>,
}

impl IndexSnapshot {
    fn new() -> Self {
        Self {
            signatures: Vec::new(),
            pr_numbers: Vec::new(),
            buckets: vec![HashMap::new(); NUM_BANDS],
        }
    }
}

/// Lock-free Locality-Sensitive Hashing index for [`PrDeltaSignature`]s.
///
/// Both [`insert`][Self::insert] and [`query`][Self::query] are wait-free for
/// readers; writers perform a clone-and-swap.
pub struct LshIndex {
    inner: ArcSwap<IndexSnapshot>,
}

impl LshIndex {
    /// Create an empty [`LshIndex`].
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(IndexSnapshot::new()),
        }
    }

    /// Insert a new [`PrDeltaSignature`] into the index, tagged with `pr_number`.
    ///
    /// `pr_number` is `0` when no PR context is available (daemon mode).
    /// Performs a full clone-and-swap of the snapshot — O(n) cost.
    /// Suitable for low-insert-rate workloads (one per PR bounce).
    pub fn insert(&self, sig: PrDeltaSignature, pr_number: u32) {
        let current = self.inner.load();
        let mut next = (**current).clone();

        let idx = next.signatures.len();
        next.signatures.push(sig.clone());
        next.pr_numbers.push(pr_number);

        for band in 0..NUM_BANDS {
            let band_slice = &sig.min_hashes[band * ROWS_PER_BAND..(band + 1) * ROWS_PER_BAND];
            let key = compute_band_hash(band_slice);
            next.buckets[band].entry(key).or_default().push(idx);
        }

        self.inner.store(Arc::new(next));
    }

    /// Query for signatures with Jaccard similarity ≥ `threshold`.
    ///
    /// Returns the PR numbers of matching entries (as supplied to [`insert`][Self::insert]).
    /// `0` entries indicate daemon-mode inserts where no PR number was available.
    /// Lock-free: takes a read-only guard with no blocking.
    pub fn query(&self, sig: &PrDeltaSignature, threshold: f64) -> Vec<u32> {
        let snap = self.inner.load();
        if snap.signatures.is_empty() {
            return Vec::new();
        }

        // Collect candidate indices from band bucket hits.
        let mut candidates: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for band in 0..NUM_BANDS {
            let band_slice = &sig.min_hashes[band * ROWS_PER_BAND..(band + 1) * ROWS_PER_BAND];
            let key = compute_band_hash(band_slice);
            if let Some(bucket) = snap.buckets[band].get(&key) {
                candidates.extend(bucket.iter().copied());
            }
        }

        // Verify candidates with full Jaccard similarity; return their PR numbers.
        candidates
            .into_iter()
            .filter(|&i| jaccard_similarity(&snap.signatures[i], sig) >= threshold)
            .map(|i| snap.pr_numbers[i])
            .collect()
    }

    /// Returns the number of signatures currently in the index.
    pub fn len(&self) -> usize {
        self.inner.load().signatures.len()
    }

    /// Returns `true` if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.load().signatures.is_empty()
    }
}

impl Default for LshIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Hash a band slice of min-hash values to a single `u64` bucket key.
fn compute_band_hash(band: &[u64]) -> u64 {
    let mut h: u64 = 0;
    for &v in band {
        h = h.rotate_left(7) ^ v;
    }
    h
}

/// Jaccard similarity estimate between two MinHash sketches.
///
/// Approximation: fraction of matching min-hash values.
fn jaccard_similarity(a: &PrDeltaSignature, b: &PrDeltaSignature) -> f64 {
    let matches = a
        .min_hashes
        .iter()
        .zip(b.min_hashes.iter())
        .filter(|(x, y)| x == y)
        .count();
    matches as f64 / NUM_HASHES as f64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_patches_have_high_jaccard() {
        let data = b"def foo():\n    return 42\n";
        let sig_a = PrDeltaSignature::from_bytes(data);
        let sig_b = PrDeltaSignature::from_bytes(data);
        let sim = jaccard_similarity(&sig_a, &sig_b);
        assert!(
            (sim - 1.0).abs() < 1e-9,
            "identical patches must have Jaccard=1.0, got {sim}"
        );
    }

    #[test]
    fn test_completely_different_patches_have_low_jaccard() {
        let data_a = b"def foo():\n    return 42\n";
        let data_b = b"SELECT * FROM users WHERE id=1 AND status='active' ORDER BY created_at;";
        let sig_a = PrDeltaSignature::from_bytes(data_a);
        let sig_b = PrDeltaSignature::from_bytes(data_b);
        let sim = jaccard_similarity(&sig_a, &sig_b);
        assert!(
            sim < 0.5,
            "very different patches should have low Jaccard similarity, got {sim}"
        );
    }

    #[test]
    fn test_lsh_index_insert_and_query() {
        let index = LshIndex::new();

        let patch = b"def add(a, b):\n    return a + b\n";
        let sig = PrDeltaSignature::from_bytes(patch);
        index.insert(sig.clone(), 42);
        assert_eq!(index.len(), 1);

        // Query with the same signature should find itself and return its PR number.
        let results = index.query(&sig, 0.9);
        assert!(
            !results.is_empty(),
            "query for inserted signature must return a hit"
        );
        assert_eq!(results[0], 42, "query must return the inserted PR number");
    }

    #[test]
    fn test_has_entropy_rejects_short_patches() {
        assert!(
            !PrDeltaSignature::has_entropy(&[]),
            "empty patch must have no entropy"
        );
        assert!(
            !PrDeltaSignature::has_entropy(b"hi"),
            "2-byte patch must have no entropy (len < 3)"
        );
        // Exactly at boundary: len=6 → 4 windows (len-2=4) < 5 → false.
        assert!(
            !PrDeltaSignature::has_entropy(b"abcdef"),
            "6-byte patch yields 4 windows, below threshold"
        );
    }

    #[test]
    fn test_has_entropy_accepts_code_patches() {
        // A real code patch is always far above the 5-window threshold.
        let patch = b"def foo():\n    return 42\n";
        assert!(
            PrDeltaSignature::has_entropy(patch),
            "real code patch must pass entropy gate"
        );
        // Minimal passing case: len=7 → 5 windows == threshold.
        assert!(
            PrDeltaSignature::has_entropy(b"abcdefg"),
            "7-byte patch yields exactly 5 windows, must pass"
        );
    }

    #[test]
    fn test_empty_input_does_not_panic() {
        let sig = PrDeltaSignature::from_bytes(&[]);
        let index = LshIndex::new();
        index.insert(sig.clone(), 0);
        let results = index.query(&sig, 0.5);
        // Empty signatures may or may not match — just verify no panic.
        let _ = results;
    }

    /// Verify that `from_bytes_avx256` produces bit-exact output identical to
    /// `from_bytes_scalar` for 100 deterministic random payloads.
    ///
    /// This test is the mathematical correctness gate for the SIMD path.  If it
    /// fails, the 64-bit multiply emulation or hash mixing steps are wrong.
    /// Skipped at runtime when AVX-256 is not available (e.g. QEMU, ARM CI).
    #[test]
    #[cfg(target_arch = "x86_64")]
    fn simd_matches_scalar() {
        if !std::is_x86_feature_detected!("avx2") {
            // AVX-256 not available on this host — test is a no-op.
            return;
        }

        /// Deterministic xorshift64 PRNG — no external deps.
        fn xorshift64(mut x: u64) -> u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }

        let mut state: u64 = 0xdead_beef_cafe_1234;

        for trial in 0..100usize {
            // Generate a payload of random length [1, 2048] bytes.
            state = xorshift64(state);
            let len = ((state % 2048) + 1) as usize;
            let mut payload = vec![0u8; len];
            for byte in payload.iter_mut() {
                state = xorshift64(state);
                *byte = state as u8;
            }

            let scalar = from_bytes_scalar(&payload);
            // SAFETY: avx2 confirmed present by is_x86_feature_detected! above.
            let simd = unsafe { from_bytes_avx256(&payload) };

            assert_eq!(
                scalar.min_hashes, simd,
                "SIMD/scalar mismatch on trial {trial} (payload length {len})"
            );
        }
    }
}
