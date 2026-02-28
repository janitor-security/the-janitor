//! # Agnostic Shield — Language-Agnostic Byte-Lattice Entropy Analysis
//!
//! Classifies arbitrary byte sequences as source code or anomalous binary blobs
//! **without** requiring a language-specific parser.  Acts as the fallback
//! analysis tier in the forge pipeline when no tree-sitter grammar is available
//! for a patched file's language.
//!
//! ## Algorithm
//! 1. **Shannon entropy** — computed over 512-byte sliding windows (stride 256).
//!    Code entropy typically falls in [2.0, 5.5]; compressed/encrypted data sits near 8.0.
//!    `max_window_entropy` tracks the highest single-window value across the entire input.
//! 2. **Bigram diagonal analysis** — builds a 256×256 byte-pair frequency matrix and
//!    measures how many counts fall on the main diagonal (byte pairs `(x, x)`).
//!    Human-written code has characteristic diagonal concentration patterns; random
//!    bytes do not.
//!
//! ## Classification
//! | Condition | Result |
//! |-----------|--------|
//! | Per-window entropy < 2.0 or > 5.5 | [`AnomalousBlob`] — degenerate byte distribution |
//! | Per-window diagonal density ≤ 0.05 | [`AnomalousBlob`] — no code-like bigram structure |
//! | `max_window_entropy` > 7.8 | [`AnomalousBlob`] — localized entropy spike; cloaked payload |
//! | Otherwise | [`ProbableCode`] |
//!
//! ## Cloaked-Payload Detection
//! A naive average-entropy check over the whole file can miss high-entropy payloads
//! (encrypted blobs, shellcode, base64-encoded secrets) hidden inside large, mostly
//! normal files — the low-entropy code dilutes the signal.  `max_window_entropy`
//! measures the *worst* 512-byte window; a spike above 7.8 flags the file regardless
//! of how benign the surrounding content is ("1Campaign"-style cloaking).

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Byte-content classification produced by [`ByteLatticeAnalyzer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextClass {
    /// Entropy and bigram structure are consistent with human-written source code.
    ProbableCode,
    /// High entropy or degenerate bigram structure — likely binary, compressed,
    /// or encrypted data embedded in a code patch.
    AnomalousBlob,
}

/// Language-agnostic byte-level classifier.
pub struct ByteLatticeAnalyzer;

impl ByteLatticeAnalyzer {
    /// Classify `bytes` as [`ProbableCode`] or [`AnomalousBlob`].
    ///
    /// Returns [`ProbableCode`] for empty inputs (no evidence of anomaly).
    pub fn classify(bytes: &[u8]) -> TextClass {
        if bytes.is_empty() {
            return TextClass::ProbableCode;
        }

        // Analyse in 512-byte sliding windows (stride 256).
        // `max_window_entropy` accumulates the highest per-window Shannon
        // entropy seen across the entire input — used for cloaked-payload
        // spike detection after the per-window structural checks pass.
        let window_size = 512;
        let stride = 256;
        let mut offset = 0;
        let mut max_window_entropy: f64 = 0.0;

        while offset < bytes.len() {
            let end = (offset + window_size).min(bytes.len());
            let window = &bytes[offset..end];

            let entropy = compute_entropy(window);
            // Track the highest single-window entropy seen across the whole input.
            if entropy > max_window_entropy {
                max_window_entropy = entropy;
            }

            let (diagonal, total_bigrams) = compute_bigram_diagonal(window);

            // Degenerate entropy: too low (constant bytes) or too high for code.
            if !(2.0..=5.5).contains(&entropy) {
                return TextClass::AnomalousBlob;
            }
            // Low diagonal density → no code-like bigram structure.
            // Only meaningful for windows with enough bigrams (≥ 64); skip for
            // short inputs where the statistic is too noisy to be reliable.
            if total_bigrams >= 64 {
                let diagonal_density = diagonal as f64 / total_bigrams as f64;
                if diagonal_density <= 0.05 {
                    return TextClass::AnomalousBlob;
                }
            }

            if offset + stride >= bytes.len() {
                break;
            }
            offset += stride;
        }

        // Cloaked-payload spike guard: a localized window with entropy > 7.8
        // indicates encrypted, compressed, or otherwise cloaked binary data
        // regardless of how benign the surrounding content appears.
        // This is a named invariant separate from the per-window range check
        // so that it survives future relaxation of the code-entropy bounds.
        if max_window_entropy > 7.8 {
            return TextClass::AnomalousBlob;
        }

        TextClass::ProbableCode
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute Shannon entropy over a byte window.
fn compute_entropy(window: &[u8]) -> f64 {
    if window.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &byte in window {
        freq[byte as usize] += 1;
    }
    let len = window.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Build a 256×256 bigram frequency matrix and return `(diagonal_count, total_bigrams)`.
///
/// The diagonal counts byte pairs `(x, x)` — consecutive identical bytes.
/// Typical code (lots of repeated characters like spaces, `e`, `;`) has measurably
/// higher diagonal concentration than random byte sequences.
fn compute_bigram_diagonal(window: &[u8]) -> (u16, u16) {
    if window.len() < 2 {
        return (0, 0);
    }
    let mut diagonal: u16 = 0;
    let total = (window.len() - 1) as u16;
    for pair in window.windows(2) {
        if pair[0] == pair[1] {
            diagonal = diagonal.saturating_add(1);
        }
    }
    (diagonal, total)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_is_probable_code() {
        assert_eq!(ByteLatticeAnalyzer::classify(&[]), TextClass::ProbableCode);
    }

    #[test]
    fn test_python_source_is_probable_code() {
        let src = b"def add(a, b):\n    return a + b\n\ndef sub(x, y):\n    return x - y\n";
        assert_eq!(
            ByteLatticeAnalyzer::classify(src),
            TextClass::ProbableCode,
            "Python source must classify as ProbableCode"
        );
    }

    #[test]
    fn test_high_entropy_bytes_are_anomalous() {
        // Pseudo-random high-entropy bytes (approximate encrypted/compressed data).
        let mut rng_bytes = Vec::with_capacity(512);
        let mut v: u64 = 0xdeadbeef_cafebabe;
        for _ in 0..512 {
            v ^= v << 13;
            v ^= v >> 7;
            v ^= v << 17;
            rng_bytes.push(v as u8);
        }
        assert_eq!(
            ByteLatticeAnalyzer::classify(&rng_bytes),
            TextClass::AnomalousBlob,
            "High-entropy pseudo-random bytes must classify as AnomalousBlob"
        );
    }

    #[test]
    fn test_entropy_calculation_sanity() {
        // All identical bytes → entropy = 0.
        let all_same = vec![0xFFu8; 64];
        let e = compute_entropy(&all_same);
        assert!(
            e < 0.01,
            "uniform bytes must have near-zero entropy, got {e}"
        );
    }

    /// Simulate a "1Campaign"-style cloaked payload: a large, structurally
    /// normal source file with a high-entropy binary blob injected mid-file.
    /// The surrounding code dilutes the *average* file entropy but the
    /// `max_window_entropy` spike must still be detected.
    #[test]
    fn test_cloaked_payload_in_normal_code_detected() {
        // ~3500 bytes of normal Rust-like source (entropy ≈ 4.5).
        let code_line = b"fn compute(x: u32, y: u32) -> u32 { x.wrapping_add(y) }\n";
        let mut normal_code = Vec::new();
        for _ in 0..60 {
            normal_code.extend_from_slice(code_line);
        }

        // 512 bytes of xorshift pseudo-random output (entropy ≈ 8.0).
        // Simulates an AES-encrypted blob or base64-decoded secret.
        let mut payload = Vec::with_capacity(512);
        let mut v: u64 = 0x1337c0de_deadbeef;
        for _ in 0..512 {
            v ^= v << 13;
            v ^= v >> 7;
            v ^= v << 17;
            payload.push(v as u8);
        }

        // Splice payload at the 1500-byte mark — surrounded by normal code.
        let mut cloaked = Vec::with_capacity(normal_code.len() + payload.len());
        cloaked.extend_from_slice(&normal_code[..1500]);
        cloaked.extend_from_slice(&payload);
        cloaked.extend_from_slice(&normal_code[1500..]);

        assert_eq!(
            ByteLatticeAnalyzer::classify(&cloaked),
            TextClass::AnomalousBlob,
            "high-entropy payload cloaked inside normal source code must be detected"
        );
    }
}
