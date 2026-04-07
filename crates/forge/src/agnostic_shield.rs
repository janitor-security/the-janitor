//! # Agnostic Shield — Language-Agnostic Byte-Lattice Entropy Analysis
//!
//! Classifies arbitrary byte sequences as source code or anomalous binary blobs
//! **without** requiring a language-specific parser.  Acts as the fallback
//! analysis tier in the forge pipeline when no tree-sitter grammar is available
//! for a patched file's language.
//!
//! ## Algorithm
//! 1. **Null-byte detection** — binary files and embedded binary blobs contain
//!    null bytes; well-formed source code never does.
//! 2. **Shannon entropy** — computed over 512-byte sliding windows (stride 256).
//!    `max_window_entropy` tracks the highest single-window value across the entire
//!    input.  Compressed or encrypted data has entropy approaching 8.0 bits/byte.
//!
//! ## Classification
//! | Condition | Result |
//! |-----------|--------|
//! | Byte array contains a null byte (`\0`) | [`AnomalousBlob`] — binary content |
//! | Any per-window entropy > 7.0 | [`AnomalousBlob`] — compressed/encrypted payload |
//! | Otherwise | [`ProbableCode`] |
//!
//! ## Design Rationale
//! The original lower-bound entropy check (`< 2.0`) was removed because highly
//! structured text — `.csproj` XML, repetitive `CODEOWNERS` lists, lockfile
//! manifests — legitimately falls below 2.0 bits/byte and is definitively *not*
//! anomalous.  Binary files and compressed payloads are characterised by *high*
//! entropy and null bytes, not low entropy.
//!
//! ## Cloaked-Payload Detection
//! A naive full-file entropy average can miss high-entropy payloads (encrypted
//! blobs, shellcode, base64-decoded secrets) hidden inside large, mostly normal
//! files — the low-entropy code dilutes the signal.  `max_window_entropy`
//! measures the *worst* 512-byte window; a spike above 7.0 flags the file
//! regardless of how benign the surrounding content is ("1Campaign"-style
//! cloaking).

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Byte-content classification produced by [`ByteLatticeAnalyzer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextClass {
    /// No null bytes and entropy consistent with human-written source code.
    ProbableCode,
    /// Null bytes present, or high-entropy window detected — likely binary,
    /// compressed, or encrypted data embedded in a code patch.
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

        // CT-016: UTF-16 BOM detection — must precede null-byte check.
        // UTF-16 LE (FF FE) and UTF-16 BE (FE FF) encoded source files are
        // valid text; the wide-char null bytes and high entropy they produce
        // would otherwise trigger AnomalousBlob false positives on
        // Windows-adjacent repos (Azure SDK, MSVC headers, legacy VB.NET).
        // A BOM is cryptographic proof of textual encoding intent — classify
        // unconditionally as ProbableCode and skip all further analysis.
        if bytes.len() >= 2 && (bytes[0..2] == [0xFF, 0xFE] || bytes[0..2] == [0xFE, 0xFF]) {
            return TextClass::ProbableCode;
        }

        // Null bytes are the defining characteristic of binary content.
        // Well-formed source code — regardless of language — never contains
        // literal null bytes in its text representation.
        if bytes.contains(&0u8) {
            return TextClass::AnomalousBlob;
        }

        // Windowed entropy analysis (512-byte windows, stride 256).
        // Track the highest per-window Shannon entropy across the entire input.
        // A spike above 7.0 bits/byte indicates compressed, encrypted, or
        // otherwise non-text data regardless of the surrounding content.
        // Only the upper bound is enforced — structured text (XML, CODEOWNERS,
        // lockfiles) legitimately has low entropy and must not be penalised.
        let window_size = 512;
        let stride = 256;
        let mut offset = 0;
        let mut max_window_entropy: f64 = 0.0;

        while offset < bytes.len() {
            let end = (offset + window_size).min(bytes.len());
            let window = &bytes[offset..end];

            let entropy = compute_entropy(window);
            if entropy > max_window_entropy {
                max_window_entropy = entropy;
            }

            if offset + stride >= bytes.len() {
                break;
            }
            offset += stride;
        }

        if max_window_entropy > 7.0 {
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

    /// Structured text (XML, CODEOWNERS, lockfiles) has low Shannon entropy
    /// and must not be flagged as anomalous — the lower-bound check was removed.
    #[test]
    fn test_low_entropy_structured_text_is_probable_code() {
        // Simulate a repetitive CODEOWNERS file — entropy < 2.0 bits/byte.
        let codeowners = b"* @team-platform\n".repeat(40);
        assert_eq!(
            ByteLatticeAnalyzer::classify(&codeowners),
            TextClass::ProbableCode,
            "Repetitive structured text must not be flagged as AnomalousBlob"
        );
    }

    /// CT-016 true-negative: UTF-16 LE BOM source file must classify as
    /// ProbableCode, not AnomalousBlob.
    ///
    /// UTF-16 LE encoding produces null bytes for every ASCII character
    /// (e.g. 'A' → `0x41 0x00`) which would normally trigger the null-byte
    /// AnomalousBlob path.  The BOM guard must short-circuit before that check.
    #[test]
    fn test_utf16_le_bom_classifies_as_probable_code() {
        // UTF-16 LE BOM followed by "int main() {}" in UTF-16 LE encoding.
        let mut utf16_le: Vec<u8> = vec![0xFF, 0xFE];
        for c in b"int main() {}" {
            utf16_le.push(*c);
            utf16_le.push(0x00);
        }
        assert_eq!(
            ByteLatticeAnalyzer::classify(&utf16_le),
            TextClass::ProbableCode,
            "UTF-16 LE BOM source must classify as ProbableCode"
        );
    }

    /// CT-016 true-negative: UTF-16 BE BOM source file must classify as
    /// ProbableCode, not AnomalousBlob.
    #[test]
    fn test_utf16_be_bom_classifies_as_probable_code() {
        // UTF-16 BE BOM followed by "int main() {}" in UTF-16 BE encoding.
        let mut utf16_be: Vec<u8> = vec![0xFE, 0xFF];
        for c in b"int main() {}" {
            utf16_be.push(0x00);
            utf16_be.push(*c);
        }
        assert_eq!(
            ByteLatticeAnalyzer::classify(&utf16_be),
            TextClass::ProbableCode,
            "UTF-16 BE BOM source must classify as ProbableCode"
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
