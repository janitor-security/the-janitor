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

/// Provenance of a registered sanitizer: where the guarantee originates and
/// therefore whose φ-lattice the Tier D audit must cite when triagers push
/// back with *"the framework already validates this"*.
///
/// The origin is a pure annotation — no behavior is conditioned on it beyond
/// the audit-string composition in [`crate::negtaint`]. It is, however, the
/// axis on which the Tier D non-bypassability argument hinges: a framework's
/// implicit validator must be named out loud so the triager understands the
/// engine evaluated it and the SMT solver still found a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizerOrigin {
    /// Built-in language / standard library (escape, parseInt, ...).
    Stdlib,
    /// Widely-used imported package (express-validator, Joi, ...).
    ThirdParty,
    /// Implicit validator emitted by a web framework's request-binding layer
    /// (Express `express.json()` body parser, Spring `@RequestBody` Jackson
    /// coercion, Flask `request.get_json()`). Paired with
    /// [`SanitizerSpec::framework_label`] to name the framework in reports.
    FrameworkImplicit,
    /// Registered at runtime by calling code (custom policy, test harness).
    UserDefined,
}

/// Logical constraint that a sanitizer enforces on its return value, expressed
/// as an SMT-LIB2 assertion body.
///
/// This predicate is the `φ_sanitizer` term in the weakest-precondition
/// falsification `wp(sanitizer, φ_required)`.  The [`crate::negtaint`] Tier C
/// falsifier asserts `sanitizer_predicate ∧ ¬sink_predicate` and asks z3 for a
/// concrete counterexample: an `output` value that the sanitizer would return
/// yet that still violates the sink's safety contract.
///
/// The `output` binding is the canonical name used by both sanitizer and sink
/// predicates.  Callers must declare this constant in the solver session
/// before asserting either predicate body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizerPredicate {
    /// SMT-LIB2 sort of the sanitizer's return value — `"String"`, `"Int"`,
    /// `"Bool"`, or `"(_ BitVec N)"`.
    pub output_sort: &'static str,
    /// SMT-LIB2 assertion body describing what the sanitizer guarantees about
    /// its `output` binding.  Example (HTML escaper):
    /// `"(not (str.contains output \"<\"))"` — the sanitizer ensures no
    /// less-than byte appears in the returned value.
    pub smt_assertion: &'static str,
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
    /// Optional logical constraint the sanitizer enforces on its return value.
    /// Populated for sanitizers whose guarantee can be expressed as a concrete
    /// SMT-LIB2 predicate — enables Tier C weakest-precondition falsification
    /// via [`crate::negtaint::NegTaintSolver::falsify_sanitizer_against_sink`].
    pub predicate: Option<SanitizerPredicate>,
    /// Provenance tag for Tier D audit-string composition.
    pub origin: SanitizerOrigin,
    /// Human-readable framework name (`"Express.js"`, `"Spring"`, `"Flask"`).
    /// Populated iff `origin == SanitizerOrigin::FrameworkImplicit`; elsewhere
    /// left `None`. Audit strings only embed the label when this is `Some`.
    pub framework_label: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// JwtConditionalSpec
// ---------------------------------------------------------------------------

/// Conditional suppression rule for JWT library wrappers.
///
/// A JWT function is a valid verifier only when its option arguments satisfy
/// safety conditions:
/// - `algorithms_arg` resolves to a non-`["none"]` algorithm list, AND
/// - `verify_arg` (if present) resolves to `true`.
///
/// When either condition fails, `library_identity::resolve_jwt_wrapper` returns
/// a dangerous resolution and the engine emits `security:jwt_wrapper_polymorphism`.
#[derive(Debug, Clone)]
pub struct JwtConditionalSpec {
    /// Bare function name as it appears in call expressions.
    pub name: &'static str,
    /// Name of the options field that specifies allowed algorithms
    /// (e.g. `"algorithms"` for jsonwebtoken, `"alg"` for jose).
    pub algorithms_arg: &'static str,
    /// Name of the options field that enables or disables signature
    /// verification. `None` when the library always verifies if invoked via
    /// the canonical verify entry-point.
    pub verify_arg: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// SanitizerRegistry
// ---------------------------------------------------------------------------

/// Registry of known sanitizer/validator functions.
pub struct SanitizerRegistry {
    specs: Vec<SanitizerSpec>,
    jwt_conditionals: Vec<JwtConditionalSpec>,
}

impl SanitizerRegistry {
    /// Creates a registry pre-populated with the built-in cross-language
    /// sanitizer set.
    pub fn with_defaults() -> Self {
        Self {
            specs: default_specs(),
            jwt_conditionals: default_jwt_conditionals(),
        }
    }

    /// Creates an empty registry.  Use [`push`][Self::push] to add custom specs.
    pub fn empty() -> Self {
        Self {
            specs: Vec::new(),
            jwt_conditionals: Vec::new(),
        }
    }

    /// Appends a custom [`SanitizerSpec`] to the registry.
    pub fn push(&mut self, spec: SanitizerSpec) {
        self.specs.push(spec);
    }

    /// Appends a [`JwtConditionalSpec`] to the JWT conditional registry.
    pub fn push_jwt_conditional(&mut self, spec: JwtConditionalSpec) {
        self.jwt_conditionals.push(spec);
    }

    /// Returns `true` when `name` is a registered JWT conditional verifier.
    pub fn is_jwt_conditional(&self, name: &str) -> bool {
        self.jwt_conditionals.iter().any(|s| s.name == name)
    }

    /// Returns the [`JwtConditionalSpec`] for `name`, if registered.
    pub fn jwt_conditional_for(&self, name: &str) -> Option<&JwtConditionalSpec> {
        self.jwt_conditionals.iter().find(|s| s.name == name)
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

    /// Returns a stable, human-readable sample of registered validation names
    /// suitable for audit strings.
    pub fn audit_examples(&self, limit: usize) -> Vec<&'static str> {
        self.specs
            .iter()
            .filter(|spec| {
                matches!(
                    spec.role,
                    SanitizerRole::Sanitizer | SanitizerRole::Validator
                )
            })
            .map(|spec| spec.name)
            .take(limit)
            .collect()
    }

    /// Returns the [`SanitizerPredicate`] registered for `name`, if any.
    ///
    /// Present only for sanitizers whose guarantee is expressible as a concrete
    /// SMT-LIB2 assertion — Tier C falsification skips any sanitizer whose
    /// predicate is `None`, preserving the conservative "unknown → keep the
    /// finding" default.
    pub fn predicate_for(&self, name: &str) -> Option<SanitizerPredicate> {
        self.specs
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.predicate)
    }

    /// Returns the full [`SanitizerSpec`] for `name`, if registered.
    ///
    /// Tier D audit composition needs both the predicate and the origin /
    /// framework label to decide whether to emit a framework-citation clause.
    pub fn spec_for(&self, name: &str) -> Option<&SanitizerSpec> {
        self.specs.iter().find(|s| s.name == name)
    }
}

// ---------------------------------------------------------------------------
// Default sanitizer table
// ---------------------------------------------------------------------------

fn default_specs() -> Vec<SanitizerSpec> {
    use TaintKind::{FileRead, NetworkResponse, Unknown, UserInput};

    // Canonical predicate: HTML escapers guarantee the literal `<` byte is
    // absent from the output, but do NOT prove the output is safe as a URL
    // attribute context (e.g. `javascript:` inside an href).  That gap is the
    // falsification target for Tier C.
    let html_predicate = SanitizerPredicate {
        output_sort: "String",
        smt_assertion: r#"(not (str.contains output "<"))"#,
    };
    // URL encoders guarantee the literal space byte is absent, but do not
    // prevent dangerous scheme prefixes (`javascript:`, `data:`).
    let url_predicate = SanitizerPredicate {
        output_sort: "String",
        smt_assertion: r#"(not (str.contains output " "))"#,
    };
    // SQL single-quote escapers guarantee raw `'` is absent; they do not
    // prevent comment sequences or stacked-query separators.
    let sql_quote_predicate = SanitizerPredicate {
        output_sort: "String",
        smt_assertion: r#"(not (str.contains output "'"))"#,
    };
    // Framework implicit validators (Express body parsers, Spring Jackson
    // binding, Flask `request.get_json`) all share the same weak shape
    // guarantee: the request body is a well-formed String (no stronger
    // constraint on content). Encoded as the trivial tautology
    // `(>= (str.len output) 0)` so Z3 resolves the conjunction without
    // contradiction and the sink's `(not φ_required)` alone drives the
    // entailment query — yielding the counterexample the triager needs.
    let framework_binding_predicate = SanitizerPredicate {
        output_sort: "String",
        smt_assertion: r#"(>= (str.len output) 0)"#,
    };

    vec![
        // ── HTML / XSS sanitization ─────────────────────────────────────────
        sanitizer_with_predicate("escape_html", &[UserInput, Unknown], html_predicate),
        sanitizer_with_predicate("escapeHtml", &[UserInput, Unknown], html_predicate),
        sanitizer_with_predicate("html_escape", &[UserInput, Unknown], html_predicate),
        sanitizer("escape", &[UserInput, Unknown]),
        sanitizer("sanitize", &[UserInput, Unknown]),
        sanitizer_with_predicate("sanitize_html", &[UserInput, Unknown], html_predicate),
        sanitizer("strip_tags", &[UserInput, Unknown]),
        sanitizer_with_predicate("htmlspecialchars", &[UserInput, Unknown], html_predicate),
        sanitizer_with_predicate("htmlentities", &[UserInput, Unknown], html_predicate),
        // ── URL encoding ────────────────────────────────────────────────────
        sanitizer_with_predicate("encodeURIComponent", &[UserInput, Unknown], url_predicate),
        sanitizer_with_predicate("encodeURI", &[UserInput, Unknown], url_predicate),
        sanitizer_with_predicate("urlencode", &[UserInput, Unknown], url_predicate),
        sanitizer_with_predicate("rawurlencode", &[UserInput, Unknown], url_predicate),
        sanitizer("quote", &[UserInput, Unknown]),
        sanitizer_with_predicate("quote_plus", &[UserInput, Unknown], url_predicate),
        sanitizer_with_predicate("url_encode", &[UserInput, Unknown], url_predicate),
        // ── SQL parameterization ────────────────────────────────────────────
        // NOTE: These only kill UserInput, not DatabaseResult — a row value
        // fetched from the DB might still be injection-capable if re-inserted
        // into a raw query without parameterization.
        sanitizer_with_predicate("parameterize", &[UserInput], sql_quote_predicate),
        sanitizer_with_predicate("quote_sql", &[UserInput], sql_quote_predicate),
        sanitizer_with_predicate(
            "mysql_real_escape_string",
            &[UserInput],
            sql_quote_predicate,
        ),
        sanitizer_with_predicate("pg_escape_literal", &[UserInput], sql_quote_predicate),
        sanitizer_with_predicate("pg_escape_string", &[UserInput], sql_quote_predicate),
        sanitizer_with_predicate("sqlite_escape", &[UserInput], sql_quote_predicate),
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
        // ── Framework-implicit validators (Tier D) ──────────────────────────
        // Each binding parser coerces the request body into a typed object;
        // the triager's "the framework already validates this" claim is
        // answered by Z3 proving the framework's φ does NOT entail the
        // sink-specific safety contract.
        framework_implicit(
            "express.json",
            &[UserInput, Unknown],
            framework_binding_predicate,
            "Express.js",
        ),
        framework_implicit(
            "express.urlencoded",
            &[UserInput, Unknown],
            framework_binding_predicate,
            "Express.js",
        ),
        framework_implicit(
            "springRequestBody",
            &[UserInput, Unknown],
            framework_binding_predicate,
            "Spring",
        ),
        framework_implicit(
            "request.get_json",
            &[UserInput, Unknown],
            framework_binding_predicate,
            "Flask",
        ),
    ]
}

fn sanitizer(name: &'static str, kills: &[TaintKind]) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Sanitizer,
        predicate: None,
        origin: SanitizerOrigin::Stdlib,
        framework_label: None,
    }
}

fn sanitizer_with_predicate(
    name: &'static str,
    kills: &[TaintKind],
    predicate: SanitizerPredicate,
) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Sanitizer,
        predicate: Some(predicate),
        origin: SanitizerOrigin::Stdlib,
        framework_label: None,
    }
}

fn validator(name: &'static str, kills: &[TaintKind]) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Validator,
        predicate: None,
        origin: SanitizerOrigin::Stdlib,
        framework_label: None,
    }
}

fn framework_implicit(
    name: &'static str,
    kills: &[TaintKind],
    predicate: SanitizerPredicate,
    framework: &'static str,
) -> SanitizerSpec {
    SanitizerSpec {
        name,
        kills: kills.to_vec(),
        role: SanitizerRole::Sanitizer,
        predicate: Some(predicate),
        origin: SanitizerOrigin::FrameworkImplicit,
        framework_label: Some(framework),
    }
}

// ---------------------------------------------------------------------------
// Default JWT conditional table
// ---------------------------------------------------------------------------

fn default_jwt_conditionals() -> Vec<JwtConditionalSpec> {
    vec![
        // jsonwebtoken (Node.js) — `jwt.verify(token, secret, { algorithms: [...] })`
        JwtConditionalSpec {
            name: "verify",
            algorithms_arg: "algorithms",
            verify_arg: None,
        },
        // jose (Node.js) — `jwtVerify(token, key, { algorithms: [...] })`
        JwtConditionalSpec {
            name: "jwtVerify",
            algorithms_arg: "algorithms",
            verify_arg: None,
        },
        // PyJWT — `jwt.decode(token, key, algorithms=[...], options={...})`
        JwtConditionalSpec {
            name: "decode",
            algorithms_arg: "algorithms",
            verify_arg: Some("verify_signature"),
        },
        // golang-jwt/jwt — `ParseWithClaims(token, claims, keyFunc)`
        JwtConditionalSpec {
            name: "ParseWithClaims",
            algorithms_arg: "alg",
            verify_arg: None,
        },
        // Microsoft.IdentityModel.Tokens — `ValidateToken(token, params, out _)`
        JwtConditionalSpec {
            name: "ValidateToken",
            algorithms_arg: "ValidAlgorithms",
            verify_arg: Some("RequireSignedTokens"),
        },
        // nimbus-jose-jwt — `JWTParser.parse(token).verify(verifier)`
        JwtConditionalSpec {
            name: "parse",
            algorithms_arg: "expectedJWSAlgorithm",
            verify_arg: None,
        },
        // Auth0 java-jwt — `JWT.require(algorithm).build().verify(token)`
        JwtConditionalSpec {
            name: "verify",
            algorithms_arg: "algorithm",
            verify_arg: None,
        },
    ]
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
            predicate: None,
            origin: SanitizerOrigin::UserDefined,
            framework_label: None,
        });
        assert!(reg.is_sanitizer("my_domain_sanitizer"));
        assert!(reg.kills_taint("my_domain_sanitizer", TaintKind::UserInput));
        assert!(!reg.kills_taint("my_domain_sanitizer", TaintKind::FileRead));
    }

    #[test]
    fn framework_implicit_express_json_carries_framework_label() {
        let reg = SanitizerRegistry::with_defaults();
        let spec = reg
            .spec_for("express.json")
            .expect("express.json must be registered");
        assert_eq!(spec.origin, SanitizerOrigin::FrameworkImplicit);
        assert_eq!(spec.framework_label, Some("Express.js"));
        assert!(spec.predicate.is_some());
    }

    #[test]
    fn framework_implicit_spring_flask_registered() {
        let reg = SanitizerRegistry::with_defaults();
        let spring = reg.spec_for("springRequestBody").expect("spring spec");
        assert_eq!(spring.origin, SanitizerOrigin::FrameworkImplicit);
        assert_eq!(spring.framework_label, Some("Spring"));
        let flask = reg.spec_for("request.get_json").expect("flask spec");
        assert_eq!(flask.origin, SanitizerOrigin::FrameworkImplicit);
        assert_eq!(flask.framework_label, Some("Flask"));
    }

    #[test]
    fn stdlib_sanitizer_has_stdlib_origin() {
        let reg = SanitizerRegistry::with_defaults();
        let spec = reg.spec_for("escape_html").expect("escape_html spec");
        assert_eq!(spec.origin, SanitizerOrigin::Stdlib);
        assert!(spec.framework_label.is_none());
    }

    #[test]
    fn html_sanitizer_has_predicate_for_tier_c_falsification() {
        let reg = SanitizerRegistry::with_defaults();
        let pred = reg
            .predicate_for("escape_html")
            .expect("html escaper must expose a predicate for wp falsification");
        assert_eq!(pred.output_sort, "String");
        assert!(pred.smt_assertion.contains("str.contains"));
    }

    #[test]
    fn unpredicated_sanitizer_returns_none() {
        let reg = SanitizerRegistry::with_defaults();
        assert!(reg.predicate_for("strip_tags").is_none());
        assert!(reg.predicate_for("random_helper").is_none());
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
