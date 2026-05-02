//! Cryptographic Protocol Correctness & Post-Quantum Completeness (P4-3).
//!
//! Detects two classes of cryptographic misuse:
//!
//! 1. **Nonce/IV reuse** — hardcoded or statically-derived initialization vectors
//!    passed to AES-GCM, ChaCha20-Poly1305, or similar AEAD ciphers.
//!    Emits `security:nonce_reuse` at `Critical`.
//!
//! 2. **PQC hybrid downgrade** — use of legacy asymmetric cryptography (RSA, ECC /
//!    ECDH / ECDSA) without a co-located post-quantum hybrid encapsulation layer.
//!    Emits `security:pqc_hybrid_downgrade` at `KevCritical`.
//!
//! ## Detection strategy
//!
//! AhoCorasick pre-screen: two automata scan for (a) AEAD cipher entry-points and
//! (b) legacy asymmetric primitives.  For nonce reuse, a ±15-line heuristic
//! window around each AEAD match is inspected for hardcoded IV literals
//! (`iv`, `nonce`, `0x`, hex digit sequences, `Buffer.from(`, `bytes.fromhex`).
//! For PQC downgrade, a ±40-line window is inspected for PQC sibling keywords;
//! absence triggers the finding.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// AhoCorasick automata
// ---------------------------------------------------------------------------

/// AEAD cipher entry-points (nonce/IV consumers).
fn aead_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"AES-GCM".as_ref(),
            b"AES_GCM",
            b"aes-gcm",
            b"aes_gcm",
            b"AesGcm",
            b"ChaCha20",
            b"chacha20",
            b"CHACHA20",
            b"ChaCha20Poly1305",
            b"chacha20poly1305",
            b"XChaCha20",
            b"xchacha20",
            b"AES-CCM",
            b"aes-ccm",
            b"AesCcm",
            b"createCipheriv",
            b"Cipher.getInstance",
            b"crypto.createCipher",
            b"EVP_EncryptInit",
            b"EVP_aead_aes_128_gcm",
            b"EVP_aead_aes_256_gcm",
        ])
        .expect("aead_ac: static patterns are valid")
    })
}

/// Hardcoded IV/nonce indicators in the window around an AEAD call.
fn hardcoded_iv_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"iv = b\"".as_ref(),
            b"iv = \"",
            b"iv=\"",
            b"nonce = b\"",
            b"nonce = \"",
            b"nonce=\"",
            b"iv = [",
            b"nonce = [",
            b"Buffer.from(\"",
            b"bytes.fromhex(\"",
            b"bytes.fromhex('",
            b"\\x00\\x00\\x00",
            b"0x000000",
        ])
        .expect("hardcoded_iv_ac: static patterns are valid")
    })
}

/// Legacy asymmetric primitives that lack post-quantum security.
fn legacy_asym_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"RSA.generate".as_ref(),
            b"RSA.new",
            b"rsa.generate_private_key",
            b"rsa.generate_key",
            b"Rsa::generate",
            b"generateKeyPair(\"rsa\"",
            b"generateKeyPair('rsa'",
            b"RSA_generate_key",
            b"ECDH.generateKeys",
            b"ec.generateKeyPair",
            b"EC_KEY_new",
            b"EC_KEY_generate",
            b"crypto.ECDH",
            b"ecdh.generateKeys",
            b"EllipticCurve.generate",
            b"EcdhKeyAgreement",
            b"EcKeyPairGenerator",
            b"KeyPairGenerator.getInstance(\"EC\"",
            b"KeyPairGenerator.getInstance(\"RSA\"",
            b"x25519_dalek::EphemeralSecret",
            b"x25519::StaticSecret",
        ])
        .expect("legacy_asym_ac: static patterns are valid")
    })
}

/// PQC hybrid sibling keywords — presence suppresses a downgrade finding.
fn pqc_hybrid_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"ml_kem".as_ref(),
            b"ML-KEM",
            b"mlkem",
            b"kyber",
            b"Kyber",
            b"KYBER",
            b"ml_dsa",
            b"ML-DSA",
            b"pqcrypto",
            b"liboqs",
            b"oqs",
            b"x-wing",
            b"xwing",
            b"hybrid_kem",
            b"hybrid_key",
            b"fips204",
            b"fips203",
            b"CRYSTALS",
        ])
        .expect("pqc_hybrid_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `source` for cryptographic protocol misuse.
///
/// Returns findings for:
/// - Hardcoded IV/nonce adjacent to AEAD cipher calls → `security:nonce_reuse`
/// - Legacy asymmetric key generation without PQC hybrid layer → `security:pqc_hybrid_downgrade`
pub fn detect_crypto_protocol_issues(source: &[u8]) -> Vec<SlopFinding> {
    let mut out = Vec::new();
    detect_nonce_reuse(source, &mut out);
    detect_pqc_downgrade(source, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Nonce/IV reuse detector
// ---------------------------------------------------------------------------

fn detect_nonce_reuse(source: &[u8], out: &mut Vec<SlopFinding>) {
    for mat in aead_ac().find_iter(source) {
        let sink_byte = mat.start();
        let sink_end = mat.end();

        let window_start = window_line_start(source, sink_byte, 15);
        let window_end = window_line_end(source, sink_end, 15);
        let window = &source[window_start..window_end];

        if hardcoded_iv_ac().is_match(window) {
            let line = byte_to_line(source, sink_byte);
            let pattern = std::str::from_utf8(&source[sink_byte..sink_end]).unwrap_or("?");
            out.push(SlopFinding {
                start_byte: sink_byte,
                end_byte: sink_end,
                description: format!(
                    "security:nonce_reuse — AEAD cipher `{pattern}` at line {line} \
                     uses a hardcoded or statically-derived IV/nonce; \
                     IV reuse with the same key destroys AEAD confidentiality \
                     and integrity (CWE-330, NIST SP 800-38D §8)"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// PQC hybrid downgrade detector
// ---------------------------------------------------------------------------

fn detect_pqc_downgrade(source: &[u8], out: &mut Vec<SlopFinding>) {
    for mat in legacy_asym_ac().find_iter(source) {
        let sink_byte = mat.start();
        let sink_end = mat.end();

        let window_start = window_line_start(source, sink_byte, 40);
        let window_end = window_line_end(source, sink_end, 40);
        let window = &source[window_start..window_end];

        if !pqc_hybrid_ac().is_match(window) {
            let line = byte_to_line(source, sink_byte);
            let pattern = std::str::from_utf8(&source[sink_byte..sink_end]).unwrap_or("?");
            out.push(SlopFinding {
                start_byte: sink_byte,
                end_byte: sink_end,
                description: format!(
                    "security:pqc_hybrid_downgrade — legacy asymmetric primitive `{pattern}` \
                     at line {line} is used without a co-located post-quantum hybrid \
                     encapsulation layer (ML-KEM / Kyber); quantum adversaries can \
                     retroactively decrypt all session keys harvested today \
                     (NIST PQC IR 8413, NSA CNSA 2.0)"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::KevCritical,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn window_line_start(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos > 0 {
        pos -= 1;
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
    }
    0
}

fn window_line_end(source: &[u8], byte: usize, lines: usize) -> usize {
    let mut count = 0;
    let mut pos = byte;
    while pos < source.len() {
        if source[pos] == b'\n' {
            count += 1;
            if count >= lines {
                return pos + 1;
            }
        }
        pos += 1;
    }
    source.len()
}

fn byte_to_line(source: &[u8], byte: usize) -> usize {
    source[..byte.min(source.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_hardcoded_iv_adjacent_to_aes_gcm() {
        let src = b"
const iv = \"000000000000000000000000\";
const cipher = crypto.createCipheriv('aes-gcm', key, iv);
";
        let findings = detect_crypto_protocol_issues(src);
        let nonce = findings
            .iter()
            .find(|f| f.description.contains("nonce_reuse"));
        assert!(
            nonce.is_some(),
            "hardcoded iv adjacent to aes-gcm must fire nonce_reuse"
        );
        assert_eq!(nonce.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn no_nonce_reuse_when_iv_is_random() {
        let src = b"
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv('aes-gcm', key, iv);
";
        let findings = detect_crypto_protocol_issues(src);
        let nonce = findings
            .iter()
            .find(|f| f.description.contains("nonce_reuse"));
        assert!(nonce.is_none(), "random IV must not trigger nonce_reuse");
    }

    #[test]
    fn flags_rsa_without_pqc_hybrid() {
        let src = b"
const { privateKey, publicKey } = crypto.generateKeyPair('rsa', {
  modulusLength: 4096,
});
";
        let findings = detect_crypto_protocol_issues(src);
        let pqc = findings
            .iter()
            .find(|f| f.description.contains("pqc_hybrid_downgrade"));
        assert!(pqc.is_some(), "RSA keygen without PQC hybrid must fire");
        assert_eq!(pqc.unwrap().severity, Severity::KevCritical);
    }

    #[test]
    fn suppresses_pqc_downgrade_when_hybrid_present() {
        let src = b"
// Key encapsulation: X25519 + ML-KEM-768 hybrid
let rsa_key = rsa.generate_private_key(65537, 2048, &mut rng);
let kem = ml_kem::MlKem768::encapsulate(&pk);
";
        let findings = detect_crypto_protocol_issues(src);
        let pqc = findings
            .iter()
            .find(|f| f.description.contains("pqc_hybrid_downgrade"));
        assert!(
            pqc.is_none(),
            "ml_kem in window must suppress pqc_hybrid_downgrade"
        );
    }

    #[test]
    fn flags_ecdh_without_pqc() {
        let src = b"
from cryptography.hazmat.primitives.asymmetric.ec import generate_key
private_key = ec.generateKeyPair(SECP256R1())
";
        let findings = detect_crypto_protocol_issues(src);
        let pqc = findings
            .iter()
            .find(|f| f.description.contains("pqc_hybrid_downgrade"));
        assert!(pqc.is_some(), "ECDH keygen without PQC hybrid must fire");
    }

    #[test]
    fn flags_chacha20_hardcoded_nonce() {
        let src = b"
nonce = bytes.fromhex(\"000000000000000000000000\")
cipher = ChaCha20Poly1305(key)
ct = cipher.encrypt(nonce, plaintext, aad)
";
        let findings = detect_crypto_protocol_issues(src);
        let nonce = findings
            .iter()
            .find(|f| f.description.contains("nonce_reuse"));
        assert!(
            nonce.is_some(),
            "hardcoded nonce adjacent to ChaCha20 must fire"
        );
    }
}
