//! Hardware Side-Channel Static Analyzer (P4-5).
//!
//! Detects non-constant-time comparisons of secret-derived values — the
//! primary source of timing side-channels in authentication, cryptographic,
//! and credential-handling code.
//!
//! ## Detection strategy
//!
//! Two AhoCorasick automata:
//!
//! 1. **Secret taint sources** — function calls or patterns that produce secret
//!    material (HMAC output, digest, token, password, key derivation, etc.).
//! 2. **Variable-time comparison sinks** — equality operators (`===`, `==`,
//!    `!=`, `!==`, `!=`, `ne`) applied to a variable named with a secret
//!    suffix or used in a ±20-line window around a secret-producing call.
//!
//! When a secret taint source is followed (within ±20 lines) by a variable-time
//! comparison that is NOT guarded by a constant-time helper (e.g.
//! `crypto.timingSafeEqual`, `hmac.compare_digest`, `constant_time_eq`,
//! `ct_eq`, `subtle::ConstantTimeEq`), the detector emits
//! `security:non_constant_time_comparison` at `Critical`.
//!
//! Plain string equality (`===`) on tokens or HMACs is the canonical
//! timing oracle — measurable remotely in <1 ms across a LAN.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

// ---------------------------------------------------------------------------
// AhoCorasick automata
// ---------------------------------------------------------------------------

/// Secret-producing taint sources.
fn secret_source_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"createHmac".as_ref(),
            b"hmac.digest",
            b"HMAC(",
            b"hmac(",
            b"computeHmac",
            b"hashlib.pbkdf2",
            b"hashlib.scrypt",
            b"bcrypt.hashpw",
            b"bcrypt.hash",
            b"Argon2",
            b"argon2",
            b"pbkdf2_hmac",
            b"scrypt(",
            b"derive_key",
            b"deriveKey",
            b"jwt.sign",
            b"jwt.encode",
            b"crypto.sign(",
            b"Ed25519.sign(",
            b"ed25519.sign(",
            b"password_hash",
            b"hash_password",
            b"make_password",
        ])
        .expect("secret_source_ac: static patterns are valid")
    })
}

/// Variable-time comparison operators / patterns that are unsafe for secrets.
fn vartime_cmp_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b" === ".as_ref(),
            b" !== ",
            b" == ",
            b" != ",
            b".equals(",
            b".compareTo(",
            b"str_eq(",
            b"strncmp(",
            b"strcmp(",
            b"memcmp(",
        ])
        .expect("vartime_cmp_ac: static patterns are valid")
    })
}

/// Constant-time comparison helpers — presence suppresses the finding.
fn consttime_ac() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new([
            b"timingSafeEqual".as_ref(),
            b"timing_safe_equal",
            b"compare_digest",
            b"hmac.compare_digest",
            b"constant_time_compare",
            b"constantTimeCompare",
            b"ct_eq",
            b"ConstantTimeEq",
            b"constant_time_eq",
            b"subtle_ct_eq",
            b"subtle::ConstantTimeEq",
            b"crypto.timingSafeEqual",
            b"secure_compare",
            b"secureCompare",
            b"safeEqual",
            b"safe_equal",
            b"crypto.subtle.timingSafeEqual",
        ])
        .expect("consttime_ac: static patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `source` for non-constant-time comparisons of secret-derived values.
///
/// Returns one finding per secret source whose ±20-line window contains a
/// variable-time comparison and no constant-time guard.
pub fn find_secret_dependent_branches(source: &[u8]) -> Vec<SlopFinding> {
    let mut out = Vec::new();

    for mat in secret_source_ac().find_iter(source) {
        let src_byte = mat.start();
        let src_end = mat.end();

        let window_start = window_line_start(source, src_byte, 20);
        let window_end = window_line_end(source, src_end, 20);
        let window = &source[window_start..window_end];

        // A constant-time guard in the window suppresses the finding.
        if consttime_ac().is_match(window) {
            continue;
        }

        // Variable-time comparison in the window → fire.
        if vartime_cmp_ac().is_match(window) {
            let line = byte_to_line(source, src_byte);
            let pattern = std::str::from_utf8(&source[src_byte..src_end]).unwrap_or("?");
            out.push(SlopFinding {
                start_byte: src_byte,
                end_byte: src_end,
                description: format!(
                    "security:non_constant_time_comparison — secret-producing call `{pattern}` \
                     at line {line} is compared with a variable-time operator in a ±20-line \
                     window and no constant-time guard (timingSafeEqual / compare_digest / \
                     ct_eq) was found; timing oracle enables remote secret recovery \
                     (CWE-208, CAPEC-462)"
                ),
                domain: DOMAIN_FIRST_PARTY,
                severity: Severity::Critical,
            });
        }
    }

    out
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
    fn flags_hmac_compared_with_equality() {
        let src = b"
const mac = createHmac('sha256', secret).update(data).digest('hex');
if (mac === req.headers['x-signature']) {
  processWebhook(req.body);
}
";
        let findings = find_secret_dependent_branches(src);
        assert!(
            !findings.is_empty(),
            "HMAC digest compared with === must fire non_constant_time_comparison"
        );
        assert!(findings[0]
            .description
            .contains("non_constant_time_comparison"));
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn suppressed_when_timing_safe_equal_present() {
        let src = b"
const mac = createHmac('sha256', secret).update(data).digest();
const sig = Buffer.from(req.headers['x-signature'], 'hex');
if (!crypto.timingSafeEqual(mac, sig)) {
  return res.status(403).end();
}
";
        let findings = find_secret_dependent_branches(src);
        assert!(
            findings.is_empty(),
            "timingSafeEqual guard must suppress the finding"
        );
    }

    #[test]
    fn flags_pbkdf2_with_equality_comparison() {
        let src = b"
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
if derived == stored_hash:
    grant_access()
";
        let findings = find_secret_dependent_branches(src);
        assert!(!findings.is_empty(), "pbkdf2 compared with == must fire");
    }

    #[test]
    fn suppressed_when_compare_digest_present() {
        let src = b"
import hmac, hashlib
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
if hmac.compare_digest(derived, stored_hash):
    grant_access()
";
        let findings = find_secret_dependent_branches(src);
        assert!(
            findings.is_empty(),
            "compare_digest must suppress the finding"
        );
    }

    #[test]
    fn flags_jwt_sign_result_with_strcmp() {
        let src = b"
token := jwt.sign(claims, secretKey)
if strcmp(token, expectedToken) != 0 {
    return errors.New(\"invalid token\")
}
";
        let findings = find_secret_dependent_branches(src);
        assert!(
            !findings.is_empty(),
            "jwt.sign result compared with strcmp/!= must fire"
        );
    }

    #[test]
    fn no_finding_when_no_secret_source() {
        let src = b"
const name = getUserName();
if (name === \"admin\") {
  grantAdmin();
}
";
        let findings = find_secret_dependent_branches(src);
        assert!(
            findings.is_empty(),
            "plain string equality without secret source must not fire"
        );
    }
}
