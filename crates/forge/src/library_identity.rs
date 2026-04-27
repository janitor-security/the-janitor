//! JWT library wrapper identity resolution (P1-5).
//!
//! Resolves whether a wrapper function that calls a JWT primitive performs
//! actual signature verification or silently decodes without checking.
//!
//! When a wrapper's cloned summary proves the underlying primitive is `decode`
//! (or `verify` with `algorithms: ["none"]` / `verify_signature: false`) at
//! an authorization-gate call site, this module emits
//! `security:jwt_wrapper_polymorphism` at `KevCritical`.

use common::slop::{ExploitWitness, StructuredFinding};

use crate::ifds::ArgEvidence;
use crate::sanitizer::SanitizerRegistry;

/// Canonical inner call-names that perform actual signature verification.
const VERIFY_PRIMITIVES: &[&str] = &[
    "verify",
    "verify_signature",
    "decode_verify",
    "validate_token",
    "parse_with_alg",
    "JWTVerifier.verify",
    "ParseWithClaims",
    "ValidateToken",
    "jwtVerify",
    "parse",
];

/// Canonical inner call-names that decode without verifying the signature.
const DECODE_PRIMITIVES: &[&str] = &[
    "decode",
    "decode_header",
    "DecodeOnly",
    "parseUnverified",
    "decodeJwt",
    "DecodeToken",
    "JWTParser.parseClaimsJwtWithBody",
];

/// Algorithm strings that bypass signature verification.
const NONE_ALGORITHMS: &[&str] = &["none", "NONE", "None", "RS256:none", "HS256:none"];

/// Resolution of a JWT wrapper call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapperResolution {
    /// Wrapper calls a verify primitive with a valid algorithm — safe.
    VerifiedSafe { algorithm: String },
    /// Wrapper calls a decode-only primitive — signature never verified.
    DecodedOnly { primitive: String },
    /// Wrapper calls a verify primitive but `verify_signature: false`.
    VerificationDisabled,
    /// Wrapper passes `algorithms: ["none"]` — server accepts unsigned tokens.
    NoneAlgorithm,
    /// Resolution could not be determined statically.
    Unresolved,
}

/// Resolve the effective JWT behavior of a wrapper call site.
///
/// * `callee` — inner function the wrapper calls.
/// * `algorithms_evidence` — [`ArgEvidence`] for the `algorithms` option field.
/// * `verify_evidence` — [`ArgEvidence`] for `verify_signature` / `complete`.
/// * `_registry` — consulted for additional conditional rules.
pub fn resolve_jwt_wrapper(
    callee: &str,
    algorithms_evidence: &ArgEvidence,
    verify_evidence: Option<&ArgEvidence>,
    _registry: &SanitizerRegistry,
) -> WrapperResolution {
    if DECODE_PRIMITIVES.iter().any(|p| callee.contains(p)) {
        return WrapperResolution::DecodedOnly {
            primitive: callee.to_string(),
        };
    }

    if !VERIFY_PRIMITIVES.iter().any(|p| callee.contains(p)) {
        return WrapperResolution::Unresolved;
    }

    // Verify primitive confirmed — inspect option arguments.
    if let Some(ArgEvidence::Constant(val)) = verify_evidence {
        if val == "false" || val == "0" {
            return WrapperResolution::VerificationDisabled;
        }
    }

    if let ArgEvidence::Constant(alg) = algorithms_evidence {
        if NONE_ALGORITHMS.iter().any(|a| alg.contains(a)) {
            return WrapperResolution::NoneAlgorithm;
        }
        return WrapperResolution::VerifiedSafe {
            algorithm: alg.clone(),
        };
    }

    WrapperResolution::Unresolved
}

/// Returns `true` when the resolution represents a dangerous JWT pattern.
pub fn is_dangerous_resolution(resolution: &WrapperResolution) -> bool {
    matches!(
        resolution,
        WrapperResolution::DecodedOnly { .. }
            | WrapperResolution::VerificationDisabled
            | WrapperResolution::NoneAlgorithm
    )
}

/// Emit a `security:jwt_wrapper_polymorphism` finding at `KevCritical`.
///
/// Called when a wrapper's cloned summary proves the underlying primitive is
/// unsafe at an authorization-gate call site.
pub fn emit_jwt_polymorphism(
    wrapper_name: &str,
    call_site_file: Option<&str>,
    call_site_line: Option<u32>,
    resolution: &WrapperResolution,
) -> StructuredFinding {
    let sanitizer_audit = match resolution {
        WrapperResolution::DecodedOnly { primitive } => format!(
            "wrapper `{wrapper_name}` internally calls `{primitive}` \
             (decode-only) — token signature is never verified"
        ),
        WrapperResolution::VerificationDisabled => format!(
            "wrapper `{wrapper_name}` passes `verify_signature: false` \
             — signature check bypassed at the authorization gate"
        ),
        WrapperResolution::NoneAlgorithm => format!(
            "wrapper `{wrapper_name}` specifies `algorithms: [\"none\"]` \
             — server accepts unsigned tokens"
        ),
        _ => format!("wrapper `{wrapper_name}` resolved to an unsafe JWT pattern"),
    };

    StructuredFinding {
        id: "security:jwt_wrapper_polymorphism".to_string(),
        file: call_site_file.map(str::to_string),
        line: call_site_line,
        fingerprint: String::new(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "Replace decode-only calls with a signature-verifying primitive \
             (e.g. `verify(token, key, { algorithms: [\"RS256\"] })`). \
             Audit all wrapper call sites for authorization-gate usage."
                .to_string(),
        ),
        docs_url: Some(
            "https://thejanitor.app/findings/security-jwt-wrapper-polymorphism".to_string(),
        ),
        exploit_witness: Some(ExploitWitness {
            source_function: wrapper_name.to_string(),
            sink_function: "authorization_gate".to_string(),
            sanitizer_audit: Some(sanitizer_audit),
            ..ExploitWitness::default()
        }),
        upstream_validation_absent: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifds::ArgEvidence;
    use crate::sanitizer::SanitizerRegistry;

    fn reg() -> SanitizerRegistry {
        SanitizerRegistry::with_defaults()
    }

    #[test]
    fn decode_only_wrapper_is_flagged() {
        let resolution = resolve_jwt_wrapper("decode", &ArgEvidence::Symbolic, None, &reg());
        assert_eq!(
            resolution,
            WrapperResolution::DecodedOnly {
                primitive: "decode".to_string()
            }
        );
        assert!(is_dangerous_resolution(&resolution));
        let finding = emit_jwt_polymorphism("verifyToken", Some("auth.ts"), Some(42), &resolution);
        assert_eq!(finding.id, "security:jwt_wrapper_polymorphism");
        assert_eq!(finding.severity.as_deref(), Some("KevCritical"));
        assert!(finding.upstream_validation_absent);
    }

    #[test]
    fn verify_with_rs256_is_safe() {
        let resolution = resolve_jwt_wrapper(
            "verify",
            &ArgEvidence::Constant("RS256".to_string()),
            Some(&ArgEvidence::Constant("true".to_string())),
            &reg(),
        );
        assert_eq!(
            resolution,
            WrapperResolution::VerifiedSafe {
                algorithm: "RS256".to_string()
            }
        );
        assert!(!is_dangerous_resolution(&resolution));
    }

    #[test]
    fn verify_signature_false_is_flagged() {
        let resolution = resolve_jwt_wrapper(
            "verify",
            &ArgEvidence::Constant("RS256".to_string()),
            Some(&ArgEvidence::Constant("false".to_string())),
            &reg(),
        );
        assert_eq!(resolution, WrapperResolution::VerificationDisabled);
        assert!(is_dangerous_resolution(&resolution));
    }

    #[test]
    fn none_algorithm_is_flagged() {
        let resolution = resolve_jwt_wrapper(
            "verify",
            &ArgEvidence::Constant("none".to_string()),
            None,
            &reg(),
        );
        assert_eq!(resolution, WrapperResolution::NoneAlgorithm);
        assert!(is_dangerous_resolution(&resolution));
    }

    #[test]
    fn parse_unverified_is_flagged() {
        let resolution =
            resolve_jwt_wrapper("parseUnverified", &ArgEvidence::Symbolic, None, &reg());
        assert!(matches!(resolution, WrapperResolution::DecodedOnly { .. }));
        assert!(is_dangerous_resolution(&resolution));
    }
}
