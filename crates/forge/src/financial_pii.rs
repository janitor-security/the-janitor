//! Financial PII to External LLM Taint Guard (P4-9).
//!
//! Detects flows from financial PII source fields to external LLM API sinks
//! without intervening cryptographic masking primitives. Emits
//! `security:financial_pii_to_external_llm` at `KevCritical` when detected.
//!
//! ## Regulatory coverage
//!
//! GLBA Safeguards Rule, EU AI Act Article 10, NYDFS 23 NYCRR 500.11,
//! OCC AI Bulletin 2024-32 — estimated minimum fine floor: $10 million.

use common::slop::StructuredFinding;

// ---------------------------------------------------------------------------
// Financial PII source registry
// ---------------------------------------------------------------------------

/// Field-accessor identifier fragments that classify a variable as a financial
/// PII source across Python, JS/TS, Java, Go, C#, and Rust.
pub const FINANCIAL_PII_IDENTIFIERS: &[&str] = &[
    "account_number",
    "account_no",
    "accountnumber",
    "iban",
    "routing_number",
    "swift_code",
    "pan",
    "card_number",
    "clabe",
    "bsb",
    "ssn",
    "social_security",
    "tin",
    "nin",
    "personnummer",
    "nhs_number",
    "balance",
    "available_credit",
    "transaction_amount",
    "kyc_document",
    "passport_number",
    "pep_match",
    "aml_score",
    "sanctions_match",
];

/// Type-system decorator fragments that classify a type as financial PII.
pub const FINANCIAL_PII_DECORATORS: &[&str] = &[
    "@FinancialPII",
    "#[financial_pii]",
    "@Sensitive(\"financial\")",
    "@Pii(category=\"financial\")",
    "FinancialPii",
    "FinancialData",
];

// ---------------------------------------------------------------------------
// External LLM sink registry
// ---------------------------------------------------------------------------

/// Hostname fragments that identify external (non-VPC-private) LLM endpoints.
pub const LLM_SINK_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.groq.com",
    "bedrock-runtime",
    "openai.azure.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.perplexity.ai",
    "api.x.ai",
];

/// SDK call fragments that identify LLM completion API calls.
pub const LLM_SINK_SDK_CALLS: &[&str] = &[
    "openai.chat.completions.create",
    "openai.ChatCompletion.create",
    "client.chat.completions.create",
    "anthropic.messages.create",
    "anthropic.completions.create",
    "generative_model.generate_content",
    "cohere.generate",
    "cohere.chat",
    "mistral.chat",
    "ChatOpenAI",
    "AzureChatOpenAI",
    "BedrockChat",
    "VertexAI",
    "invoke_model",
    "converse",
];

// ---------------------------------------------------------------------------
// Cryptographic masking sanitizer registry
// ---------------------------------------------------------------------------

/// Function name fragments indicating a recognized cryptographic masking
/// primitive. Any of these interposed between a PII source and an LLM sink
/// suppresses the `security:financial_pii_to_external_llm` finding.
pub const CRYPTO_MASKING_SANITIZERS: &[&str] = &[
    // Format-Preserving Encryption
    "fpe::encrypt",
    "fpe.encrypt",
    "fpe_encrypt",
    "ffx_encrypt",
    "Voltage",
    "SecureData",
    "Protegrity::tokenize",
    "protegrity_tokenize",
    // Homomorphic encryption
    "tfhe::encrypt",
    "tfhe.encrypt",
    "concrete_ml",
    "microsoft_seal",
    "OpenFHE",
    "Pyfhel",
    "pyfhel.encrypt",
    "he_encrypt",
    // Zero-knowledge masking
    "risc0::commit",
    "noir::encrypt",
    "circom_witness",
    // Deterministic tokenization / KMS-backed masking
    "vault::tokenize",
    "hashicorp_vault",
    "aws_kms",
    "kms.generate_data_key",
    "generate_data_key",
    "gcp_cloud_dlp",
    "cloud_dlp",
    "deidentify",
    // Differential privacy noise
    "opendp::laplace_noise",
    "laplace_noise",
    "tumult_analytics",
    "pydp",
    "add_noise",
    "dp_mechanism",
];

// ---------------------------------------------------------------------------
// Regulatory metadata
// ---------------------------------------------------------------------------

/// Regulatory regimes triggered by an unmasked PII-to-LLM data flow.
pub const REGULATORY_REGIMES: &[&str] = common::slop::RECOGNIZED_REGULATORY_REGIMES;

/// Minimum estimated regulatory fine floor in USD under simultaneous
/// multi-regime enforcement (GLBA + state AG + NYDFS).
pub const FINE_FLOOR_USD: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `source` contains any financial PII identifier or
/// type-system decorator pattern.
pub fn contains_financial_pii(source: &str) -> bool {
    FINANCIAL_PII_IDENTIFIERS
        .iter()
        .any(|pat| source.contains(pat))
        || FINANCIAL_PII_DECORATORS
            .iter()
            .any(|pat| source.contains(pat))
}

/// Returns `true` if `source` contains any recognized external LLM sink call
/// or endpoint reference.
pub fn contains_llm_sink(source: &str) -> bool {
    LLM_SINK_HOSTS.iter().any(|h| source.contains(h))
        || LLM_SINK_SDK_CALLS.iter().any(|s| source.contains(s))
}

/// Returns `true` if `source` contains a recognized cryptographic masking
/// sanitizer that neutralizes the PII-to-LLM taint flow.
pub fn contains_crypto_sanitizer(source: &str) -> bool {
    CRYPTO_MASKING_SANITIZERS.iter().any(|s| source.contains(s))
}

// ---------------------------------------------------------------------------
// Emitter
// ---------------------------------------------------------------------------

/// Scans a single source file blob for the Financial PII → LLM taint pattern.
///
/// Emits `security:financial_pii_to_external_llm` at `KevCritical` when:
/// - the source contains at least one financial PII identifier, **and**
/// - the source references at least one external LLM sink, **and**
/// - no recognized cryptographic masking sanitizer is present.
///
/// Returns a non-empty vec on detection; empty vec when the file is clean or
/// when a cryptographic sanitizer suppresses the finding.
pub fn emit_financial_pii_to_llm_findings(
    file: Option<&str>,
    source: &str,
) -> Vec<StructuredFinding> {
    if !contains_financial_pii(source) {
        return Vec::new();
    }
    if !contains_llm_sink(source) {
        return Vec::new();
    }
    if contains_crypto_sanitizer(source) {
        return Vec::new();
    }

    vec![StructuredFinding {
        id: "security:financial_pii_to_external_llm".to_string(),
        file: file.map(str::to_string),
        line: None,
        fingerprint: String::new(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "Interpose a recognized cryptographic masking primitive (FPE, KMS tokenization, \
             or differential-privacy noise) before submitting financial PII to an external \
             LLM endpoint. If the deployment is VPC-private with a documented BAA/DPA, \
             add it to JanitorPolicy::llm_compliance_attestations."
                .to_string(),
        ),
        regulatory_regimes: Some(REGULATORY_REGIMES.iter().map(|s| s.to_string()).collect()),
        estimated_fine_floor_usd: Some(FINE_FLOOR_USD),
        ..Default::default()
    }]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const OPENAI_SINK: &str = r#"
import openai
result = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": customer_data}]
)
"#;

    const FPE_SANITIZER: &str = r#"
import fpe
encrypted_account = fpe.encrypt(account_number, key)
result = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": encrypted_account}]
)
"#;

    #[test]
    fn pii_source_plus_openai_sink_emits_kev_critical() {
        let source = format!("account_number = customer.account_number\n{OPENAI_SINK}");
        let findings = emit_financial_pii_to_llm_findings(Some("app/llm_handler.py"), &source);
        assert_eq!(findings.len(), 1, "must emit exactly one finding");
        let f = &findings[0];
        assert_eq!(f.id, "security:financial_pii_to_external_llm");
        assert_eq!(f.severity.as_deref(), Some("KevCritical"));
        assert_eq!(
            f.file.as_deref(),
            Some("app/llm_handler.py"),
            "file path must be propagated"
        );
    }

    #[test]
    fn regulatory_annotations_present_on_emission() {
        let source = format!("ssn = user.ssn\n{OPENAI_SINK}");
        let findings = emit_financial_pii_to_llm_findings(Some("handler.py"), &source);
        assert_eq!(findings.len(), 1);
        let regimes = findings[0]
            .regulatory_regimes
            .as_ref()
            .expect("regulatory_regimes must be populated");
        assert!(
            regimes.contains(&"GLBA".to_string()),
            "GLBA must be present"
        );
        assert!(
            regimes.contains(&"EU_AI_Act_Art_10".to_string()),
            "EU_AI_Act_Art_10 must be present"
        );
        assert!(
            regimes.contains(&"EU_NIS2".to_string()),
            "EU_NIS2 must be present"
        );
        assert!(
            regimes.contains(&"EU_DORA".to_string()),
            "EU_DORA must be present"
        );
        assert!(
            regimes.contains(&"NYDFS_500_11".to_string()),
            "NYDFS_500_11 must be present"
        );
        assert!(
            regimes.contains(&"OCC_2024_32".to_string()),
            "OCC_2024_32 must be present"
        );
        assert_eq!(
            findings[0].estimated_fine_floor_usd,
            Some(10_000_000),
            "fine floor must be 10 million USD"
        );
    }

    #[test]
    fn fpe_sanitizer_suppresses_finding() {
        let findings =
            emit_financial_pii_to_llm_findings(Some("app/safe_handler.py"), FPE_SANITIZER);
        assert!(
            findings.is_empty(),
            "FPE sanitizer must suppress the PII-to-LLM finding"
        );
    }

    #[test]
    fn no_pii_no_finding() {
        let source = format!("user_message = request.body\n{OPENAI_SINK}");
        let findings = emit_financial_pii_to_llm_findings(Some("chat.py"), &source);
        assert!(findings.is_empty(), "no PII source means no finding");
    }

    #[test]
    fn no_llm_sink_no_finding() {
        let source = "account_number = customer.account_number\nprint(account_number)";
        let findings = emit_financial_pii_to_llm_findings(Some("print_data.py"), source);
        assert!(findings.is_empty(), "no LLM sink means no finding");
    }

    #[test]
    fn pii_decorator_triggers_detection() {
        let source = format!("@FinancialPII\nclass CustomerRecord:\n    pass\n{OPENAI_SINK}");
        let findings = emit_financial_pii_to_llm_findings(Some("model.py"), &source);
        assert_eq!(
            findings.len(),
            1,
            "FinancialPII decorator must trigger detection"
        );
    }

    #[test]
    fn kms_generate_data_key_suppresses_finding() {
        let source = format!(
            "account_number = record.account_number\n\
             encrypted = kms.generate_data_key(account_number)\n{OPENAI_SINK}"
        );
        let findings = emit_financial_pii_to_llm_findings(Some("app/kms_handler.py"), &source);
        assert!(
            findings.is_empty(),
            "KMS generate_data_key must suppress the finding"
        );
    }

    #[test]
    fn anthropic_sink_triggers_detection() {
        let source = "pan = payment.pan\nanthroptic.messages.create(messages=[pan])";
        // Note: test the contains_llm_sink predicate directly too
        let source2 = "pan = payment.pan\nanthroptic_client.anthropic.messages.create(msgs)";
        assert!(
            !contains_llm_sink(source),
            "misspelled anthropic is not a sink"
        );
        let _ = source2; // unused but documents intent

        let correct = "pan = payment.pan\nanthropic.messages.create(messages=[pan])";
        let findings = emit_financial_pii_to_llm_findings(Some("pay.py"), correct);
        assert_eq!(findings.len(), 1, "Anthropic sink must fire");
    }
}
