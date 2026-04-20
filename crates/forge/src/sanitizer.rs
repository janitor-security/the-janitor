//! Sanitizer / validator registry for interprocedural taint killing (P1-1).
//!
//! When a tainted value passes through a registered sanitizer function, the
//! corresponding [`TaintKind`] labels are killed, preventing false-positive
//! sink reports for that data flow path.
//!
//! ## Design contract
//!
//! - [`SanitizerRegistry::is_sanitizer`] answers "is this function a known
//!   sanitizer?" — used to suppress taint propagation past it.
//! - [`SanitizerRegistry::kills_taint`] answers "does calling this function
//!   neutralise a specific taint kind?" — used for precise label elimination.
//! - The default registry covers HTML escaping, URL encoding, SQL parameterization,
//!   and type-coercion functions across Python, JavaScript, Ruby, PHP, and Go.
//! - Users can extend the registry via [`SanitizerRegistry::push`].
//!
//! ## Conservative design
//!
//! A sanitizer that kills [`TaintKind::UserInput`] does NOT automatically
//! kill [`TaintKind::DatabaseResult`] or [`TaintKind::NetworkResponse`] — those
//! may carry injection-capable content even after a user-input sanitizer runs.
//! Each `kills` list is explicitly enumerated.

use common::taint::TaintKind;

// ---------------------------------------------------------------------------
// SanitizerSpec
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerRole {
    Sanitizer,
    Validator,
}

/// Describes one sanitizer or validator: its name and the taint labels it neutralises.
#[derive(Debug, Clone)]
pub struct SanitizerSpec {
    /// Bare function/method name as it appears in call expressions.
    /// Matching is case-sensitive.
    pub name: &'static str,
    /// Taint labels killed when a value passes through this function.
    pub kills: Vec<TaintKind>,
    /// Registry role: full sanitizer or upstream validation/typing guard.
    pub role: SanitizerRole,
}

// ---------------------------------------------------------------------------
// SanitizerRegistry
// ---------------------------------------------------------------------------

/// Registry of known sanitizer/validator functions.
pub struct SanitizerRegistry {
    specs: Vec<SanitizerSpec>,
}

impl SanitizerRegistry {
    /// Creates a registry pre-populated with the built-in cross-language
    /// sanitizer set.
    pub fn with_defaults() -> Self {
        Self {
            specs: default_specs(),
        }
    }

    /// Creates an empty registry.  Use [`push`][Self::push] to add custom specs.
    pub fn empty() -> Self {
        Self { specs: Vec::new() }
    }

    /// Appends a custom [`SanitizerSpec`] to the registry.
    pub fn push(&mut self, spec: SanitizerSpec) {
        self.specs.push(spec);
    }

    /// Returns `true` when `name` is a registered sanitizer that kills at least
    /// one [`TaintKind`].
    pub fn is_sanitizer(&self, name: &str) -> bool {
        self.specs
            .iter()
            .any(|s| s.name == name && s.role == SanitizerRole::Sanitizer && !s.kills.is_empty())
    }

    /// Returns `true` when `name` is a registered validation or sanitizer node
    /// that materially constrains upstream input.
    pub fn is_validation_function(&self, name: &str) -> bool {
        self.specs.iter().any(|s| {
            s.name == name && matches!(s.role, SanitizerRole::Validator | SanitizerRole::Sanitizer)
        })
    }

    /// Returns `true` when calling `name` kills a taint of `kind`.
    pub fn kills_taint(&self, name: &str, kind: TaintKind) -> bool {
        self.specs.iter().any(|s| {
            s.name == name
                && matches!(s.role, SanitizerRole::Sanitizer | SanitizerRole::Validator)
                && s.kills.contains(&kind)
        })
    }

    /// Returns all taint kinds killed by `name`.
    ///
    /// Returns an empty slice when `name` is not registered or kills nothing.
    pub fn killed_by(&self, name: &str) -> Vec<TaintKind> {
        self.specs
            .iter()
            .find(|s| s.name == name)
            .map(|s| s.kills.clone())
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Default sanitizer table
// ---------------------------------------------------------------------------

fn default_specs() -> Vec<SanitizerSpec> {
    use TaintKind::{FileRead, NetworkResponse, Unknown, UserInput};

    vec![
        // ── HTML / XSS sanitization ─────────────────────────────────────────
        sanitizer("escape_html", &[UserInput, Unknown]),
        sanitizer("escapeHtml", &[UserInput, Unknown]),
        sanitizer("html_escape", &[UserInput, Unknown]),
        sanitizer("escape", &[UserInput, Unknown]),
        sanitizer("sanitize", &[UserInput, Unknown]),
        sanitizer("sanitize_html", &[UserInput, Unknown]),
        sanitizer("strip_tags", &[UserInput, Unknown]),
        sanitizer("htmlspecialchars", &[UserInput, Unknown]),
        sanitizer("htmlentities", &[UserInput, Unknown]),
        // ── URL encoding ────────────────────────────────────────────────────
        sanitizer("encodeURIComponent", &[UserInput, Unknown]),
        sanitizer("encodeURI", &[UserInput, Unknown]),
        sanitizer("urlencode", &[UserInput, Unknown]),
        sanitizer("rawurlencode", &[UserInput, Unknown]),
        sanitizer("quote", &[UserInput, Unknown]),
        sanitizer("quote_plus", &[UserInput, Unknown]),
        sanitizer("url_encode", &[UserInput, Unknown]),
        // ── SQL parameterization ────────────────────────────────────────────
        // NOTE: These only kill UserInput, not DatabaseResult — a row value
        // fetched from the DB might still be injection-capable if re-inserted
        // into a raw query without parameterization.
        sanitizer("parameterize", &[UserInput]),
        sanitizer("quote_sql", &[UserInput]),
        sanitizer("mysql_real_escape_string", &[UserInput]),
        sanitizer("pg_escape_literal", &[UserInput]),
        sanitizer("pg_escape_string", &[UserInput]),
        sanitizer("sqlite_escape", &[UserInput]),
        // ── Path sanitization ───────────────────────────────────────────────
        sanitizer("basename", &[UserInput, Unknown]),
        sanitizer("normalize", &[UserInput, Unknown]),
        sanitizer("realpath", &[UserInput]),
        sanitizer("path_safe", &[UserInput, Unknown]),
        sanitizer("clean_path", &[UserInput, Unknown]),
        // ── Type coercion / numeric validation ──────────────────────────────
        // Integer/float coercion eliminates injection risk for numeric inputs.
        validator("parseInt", &[UserInput, Unknown, NetworkResponse]),
        validator("parseFloat", &[UserInput, Unknown, NetworkResponse]),
        validator("int", &[UserInput, Unknown, NetworkResponse]),
        validator("float", &[UserInput, Unknown, NetworkResponse]),
        validator("Number", &[UserInput, Unknown, NetworkResponse]),
        validator("abs", &[UserInput, Unknown, NetworkResponse]),
        // ── Regex / format validators ────────────────────────────────────────
        // These kill taint only when the value is the RESULT (return value) of
        // validation — not the input argument. The registry records name-level
        // killing; callers are responsible for applying only to return values.
        validator("validate_email", &[UserInput, Unknown]),
        validator("validate_uuid", &[UserInput, Unknown]),
        validator("is_numeric", &[UserInput, Unknown]),
        // ── Structural validation / typing guards ───────────────────────────
        validator("typeof_string", &[UserInput, Unknown, NetworkResponse]),
        validator("isString", &[UserInput, Unknown, NetworkResponse]),
        validator("Joi.string", &[UserInput, Unknown, NetworkResponse]),
        validator("express_validator_body", &[UserInput, Unknown]),
        validator("express_validator_query", &[UserInput, Unknown]),
        validator("express_validator_param", &[UserInput, Unknown]),
        // ── Cryptographic operations that neutralise file-read content ───────
        sanitizer("hash", &[FileRead, UserInput, Unknown]),
        sanitizer("sha256", &[FileRead, UserInput, Unknown]),
        sanitizer("blake3", &[FileRead, UserInput, Unknown]),
    ]
}

fn sanitizer(name: &'static str, kills: &[TaintKind]) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Sanitizer,
    }
}

fn validator(name: &'static str, kills: &[TaintKind]) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Validator,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::taint::TaintKind;

    #[test]
    fn default_registry_recognises_html_sanitizers() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.is_sanitizer("escape_html"));
        assert!(reg.is_sanitizer("escapeHtml"));
        assert!(reg.is_sanitizer("sanitize_html"));
        assert!(reg.is_sanitizer("htmlspecialchars"));
    }

    #[test]
    fn default_registry_recognises_url_encoders() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.is_sanitizer("encodeURIComponent"));
        assert!(reg.is_sanitizer("urlencode"));
        assert!(reg.is_sanitizer("quote_plus"));
    }

    #[test]
    fn html_sanitizer_kills_user_input() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.kills_taint("escape_html", TaintKind::UserInput));
        assert!(reg.kills_taint("escapeHtml", TaintKind::UserInput));
        assert!(reg.kills_taint("sanitize_html", TaintKind::UserInput));
    }

    #[test]
    fn sql_parameterize_kills_user_input_not_database_result() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.kills_taint("parameterize", TaintKind::UserInput));
        // DB result taint is NOT killed — a DB value could still be re-injected
        assert!(!reg.kills_taint("parameterize", TaintKind::DatabaseResult));
    }

    #[test]
    fn numeric_coercion_kills_user_input_and_network() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.kills_taint("parseInt", TaintKind::UserInput));
        assert!(reg.kills_taint("parseInt", TaintKind::NetworkResponse));
        assert!(reg.kills_taint("int", TaintKind::UserInput));
    }

    #[test]
    fn unregistered_function_is_not_sanitizer() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(!reg.is_sanitizer("random_helper"));
        assert!(!reg.is_sanitizer("process_data"));
        assert!(!reg.is_sanitizer(""));
    }

    #[test]
    fn empty_registry_has_no_sanitizers() {
        let reg = SanitizerRegistry::empty();
        assert!(!reg.is_sanitizer("escape_html"));
        assert!(!reg.kills_taint("escape_html", TaintKind::UserInput));
    }

    #[test]
    fn custom_spec_pushed_and_recognised() {
        let mut reg = SanitizerRegistry::empty();
        reg.push(SanitizerSpec {
            name: "my_domain_sanitizer",
            kills: vec![TaintKind::UserInput],
            role: SanitizerRole::Sanitizer,
        });
        assert!(reg.is_sanitizer("my_domain_sanitizer"));
        assert!(reg.kills_taint("my_domain_sanitizer", TaintKind::UserInput));
        assert!(!reg.kills_taint("my_domain_sanitizer", TaintKind::FileRead));
    }

    #[test]
    fn killed_by_returns_correct_set() {
        let reg = SanitizerRegistry::with_defaults();
        let killed = reg.killed_by("parameterize");
        assert!(killed.contains(&TaintKind::UserInput));
        assert!(!killed.contains(&TaintKind::DatabaseResult));
    }

    #[test]
    fn killed_by_unknown_name_returns_empty() {
        let reg = SanitizerRegistry::with_defaults();
        let killed = reg.killed_by("nonexistent_fn");
        assert!(killed.is_empty());
    }

    #[test]
    fn default_registry_recognises_validation_functions() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.is_validation_function("typeof_string"));
        assert!(reg.is_validation_function("Joi.string"));
        assert!(reg.is_validation_function("express_validator_body"));
        assert!(!reg.is_validation_function("random_helper"));
    }
}
