//! RAG source and sink catalog for indirect prompt-injection taint.

use crate::ifds::external_rag_flow_reaches_llm_sink;
use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

/// Detect external-content flows into LLM context sinks without an explicit
/// prompt-injection sanitizer.
pub fn find_rag_context_poisoning(source: &[u8]) -> Vec<SlopFinding> {
    if !external_rag_flow_reaches_llm_sink(source) {
        return Vec::new();
    }

    vec![SlopFinding {
        start_byte: 0,
        end_byte: source.len(),
        description: "security:rag_context_poisoning — external RAG content flows into an LLM context sink without an explicit PromptInjectionDetector-style sanitizer; indirect prompt injection can steer model/tool behavior — P6-10".to_string(),
        domain: DOMAIN_FIRST_PARTY,
        severity: Severity::KevCritical,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_flowing_into_openai_chat_triggers_rag_poisoning() {
        let source = br#"
async function answer(url) {
  const doc = await fetch(url).then((r) => r.text());
  return openai.chat.completions.create({
    messages: [{ role: "user", content: doc }]
  });
}
"#;

        let findings = find_rag_context_poisoning(source);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("security:rag_context_poisoning")),
            "RAG context poisoning detector must fire"
        );
    }

    #[test]
    fn prompt_injection_detector_suppresses_rag_poisoning() {
        let source = br#"
async function answer(url) {
  const doc = await fetch(url).then((r) => r.text());
  const clean = PromptInjectionDetector.sanitize(doc);
  return openai.chat.completions.create({
    messages: [{ role: "user", content: clean }]
  });
}
"#;

        assert!(find_rag_context_poisoning(source).is_empty());
    }
}
