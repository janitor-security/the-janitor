//! Probabilistic IFDS taint extensions for LLM execution sinks.
//!
//! This module does not attempt stochastic runtime exploitation. It adds a
//! bounded Bayesian scoring lane that marks LLM prompt flows as risky when
//! attacker-controlled text reaches a model call without strict system-prompt
//! isolation or prompt sanitization.

use common::slop::{ExploitWitness, StructuredFinding};

const LLM_SINKS: &[&[u8]] = &[
    b"openai.chat",
    b"openai.ChatCompletion",
    b"chat.completions.create",
    b"client.chat.completions.create",
    b"anthropic.messages.create",
    b"messages.create",
];

const USER_INPUT_SOURCES: &[&[u8]] = &[
    b"req.body",
    b"req.query",
    b"request.json",
    b"request.form",
    b"user_input",
    b"userInput",
    b"prompt_input",
    b"input(",
];

const STRICT_ISOLATION_GUARDS: &[&[u8]] = &[
    b"strict_system_prompt",
    b"system_prompt_isolated",
    b"PromptInjectionDetector",
    b"sanitizePrompt",
    b"sanitize_prompt",
    b"llm_guard",
    b"rebuff",
];

/// Probabilistic taint fact carried by IFDS summaries for LLM outputs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbabilisticTaint {
    /// Posterior probability that prompt influence survives into model output.
    pub probability: f64,
    /// Symmetric confidence interval width for the posterior estimate.
    pub confidence_interval: f64,
}

impl ProbabilisticTaint {
    /// Construct a bounded taint value.
    pub fn new(probability: f64, confidence_interval: f64) -> Self {
        Self {
            probability: clamp_unit(probability),
            confidence_interval: clamp_unit(confidence_interval),
        }
    }

    /// Return true when the posterior crosses the hijack emission threshold.
    pub fn is_hijack_threshold(&self) -> bool {
        self.probability > 0.85
    }
}

/// System-prompt isolation evidence at an LLM sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptIsolation {
    /// System prompt and user prompt are structurally separated and sanitized.
    Strict,
    /// A system prompt exists, but untrusted text can share instruction context.
    Weak,
    /// No system-prompt isolation or sanitizer evidence was detected.
    Absent,
}

/// LLM transition node projected into the probabilistic IFDS lattice.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmTransitionNode {
    /// Detected SDK or framework call.
    pub model_api: String,
    /// Incoming taint reaching the prompt argument.
    pub input_taint: ProbabilisticTaint,
    /// Prompt isolation evidence at the call site.
    pub isolation: PromptIsolation,
}

impl LlmTransitionNode {
    /// Propagate input taint through the LLM transition.
    pub fn output_taint(&self) -> ProbabilisticTaint {
        propagate_llm_taint(self.input_taint, self.isolation)
    }
}

/// Propagate a taint fact through an LLM call using bounded Bayesian weights.
pub fn propagate_llm_taint(
    input: ProbabilisticTaint,
    isolation: PromptIsolation,
) -> ProbabilisticTaint {
    let multiplier = match isolation {
        PromptIsolation::Strict => 0.18,
        PromptIsolation::Weak => 0.74,
        PromptIsolation::Absent => 0.96,
    };
    let confidence = match isolation {
        PromptIsolation::Strict => input.confidence_interval * 0.50,
        PromptIsolation::Weak => input.confidence_interval + 0.08,
        PromptIsolation::Absent => input.confidence_interval + 0.14,
    };
    ProbabilisticTaint::new(input.probability * multiplier, confidence)
}

/// Emit `security:probabilistic_llm_hijack` findings for unsafe LLM prompt flows.
pub fn find_probabilistic_llm_hijacks(source: &[u8]) -> Vec<StructuredFinding> {
    if !contains_any(source, USER_INPUT_SOURCES) || !contains_any(source, LLM_SINKS) {
        return Vec::new();
    }

    let isolation = if contains_any(source, STRICT_ISOLATION_GUARDS) {
        PromptIsolation::Strict
    } else if contains_role_system(source) {
        PromptIsolation::Weak
    } else {
        PromptIsolation::Absent
    };
    let node = LlmTransitionNode {
        model_api: detected_sink(source).unwrap_or("llm.chat").to_string(),
        input_taint: ProbabilisticTaint::new(0.95, 0.07),
        isolation,
    };
    let output = node.output_taint();
    if !output.is_hijack_threshold() {
        return Vec::new();
    }

    let sink_offset = LLM_SINKS
        .iter()
        .find_map(|needle| find_bytes(source, needle))
        .unwrap_or(0);
    vec![StructuredFinding {
        id: "security:probabilistic_llm_hijack".to_string(),
        file: None,
        line: Some(byte_to_line(source, sink_offset)),
        fingerprint: fingerprint("security:probabilistic_llm_hijack", source, sink_offset),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "User-controlled prompt content reaches an LLM call without strict system-prompt isolation. Split system/user roles, sanitize retrieved context, and gate tool calls behind explicit policy checks.".to_string(),
        ),
        exploit_witness: Some(ExploitWitness {
            source_function: "llm_prompt_source".to_string(),
            source_label: "param:user_prompt".to_string(),
            sink_function: node.model_api,
            sink_label: "sink:llm_completion".to_string(),
            call_chain: vec!["user_input".to_string(), "llm_prompt".to_string()],
            path_proof: Some(format!(
                "posterior={:.2}; ci={:.2}; isolation={:?}",
                output.probability, output.confidence_interval, isolation
            )),
            upstream_validation_absent: true,
            ..ExploitWitness::default()
        }),
        upstream_validation_absent: true,
        ..StructuredFinding::default()
    }]
}

fn clamp_unit(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    value.clamp(0.0, 1.0)
}

fn contains_any(haystack: &[u8], needles: &[&[u8]]) -> bool {
    needles
        .iter()
        .any(|needle| find_bytes(haystack, needle).is_some())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn detected_sink(source: &[u8]) -> Option<&'static str> {
    LLM_SINKS
        .iter()
        .find(|needle| find_bytes(source, needle).is_some())
        .and_then(|needle| std::str::from_utf8(needle).ok())
}

fn contains_role_system(source: &[u8]) -> bool {
    find_bytes(source, br#""role": "system""#).is_some()
        || find_bytes(source, br#"role: "system""#).is_some()
        || find_bytes(source, br#"role='system'"#).is_some()
}

fn byte_to_line(source: &[u8], offset: usize) -> u32 {
    let capped = offset.min(source.len());
    source[..capped]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u32
        + 1
}

fn fingerprint(rule: &str, source: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(64);
    let end = source.len().min(offset.saturating_add(128));
    let mut hasher = blake3::Hasher::new();
    hasher.update(rule.as_bytes());
    hasher.update(b":");
    hasher.update(&source[start..end]);
    hasher.finalize().to_hex().to_string()
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn probabilistic_taint_constructor_clamps_unit_interval() {
        let raw_probability = kani::any::<u8>();
        let raw_ci = kani::any::<u8>();
        let taint =
            ProbabilisticTaint::new(f64::from(raw_probability) / 10.0, f64::from(raw_ci) / 10.0);
        assert!(taint.probability >= 0.0 && taint.probability <= 1.0);
        assert!(taint.confidence_interval >= 0.0 && taint.confidence_interval <= 1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn llm_output_crosses_hijack_threshold_without_isolation() {
        let input = ProbabilisticTaint::new(0.95, 0.07);
        let output = propagate_llm_taint(input, PromptIsolation::Absent);
        assert!(output.probability > 0.85);
        assert!(output.is_hijack_threshold());
    }

    #[test]
    fn strict_prompt_isolation_suppresses_hijack_finding() {
        let source = br#"
const prompt = req.body.prompt;
const strict_system_prompt = true;
client.chat.completions.create({
  messages: [{ role: "system", content: "fixed" }, { role: "user", content: prompt }]
});
"#;
        assert!(find_probabilistic_llm_hijacks(source).is_empty());
    }

    #[test]
    fn user_prompt_to_openai_chat_emits_probabilistic_hijack() {
        let source = br#"
const prompt = req.body.prompt;
openai.chat.completions.create({ messages: [{ role: "user", content: prompt }] });
"#;
        let findings = find_probabilistic_llm_hijacks(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:probabilistic_llm_hijack");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }
}
