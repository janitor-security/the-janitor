//! Bare-metal agentic loop detector.
//!
//! This module catches agent loops that do not use LangChain, AutoGen, CrewAI,
//! or other scaffold frameworks. The detector stays bounded: it parses source
//! with tree-sitter, inspects loop subtrees only, and emits only when an LLM
//! network invocation appears before a dynamic execution sink in the same loop.

use common::slop::StructuredFinding;
use tree_sitter::{Language, Node, Parser};

const MAX_LOOP_BYTES: usize = 256 * 1024;

const LLM_MARKERS: &[&str] = &[
    "openai.chat",
    "openai.chat.completions.create",
    "chat.completions.create",
    "openai.com/v1/chat",
    "api.openai.com",
    "anthropic.messages",
    "api.anthropic.com",
    "client.chat",
    "llm.invoke",
    "model.generate",
    "fetch(",
];

const EXEC_MARKERS: &[&str] = &[
    "subprocess.run",
    "subprocess.popen",
    "subprocess.check_output",
    "os.system",
    "eval(",
    "exec(",
    "child_process.exec",
    "child_process.spawn",
    "execsync",
    "spawn(",
    "std::process::command",
    "process::command",
];

/// Detect bare-metal agentic loops where an LLM result can drive dynamic code
/// execution inside the same loop body.
pub fn find_bare_metal_agentic_loops(
    language: &str,
    source: &[u8],
    label: &str,
) -> Vec<StructuredFinding> {
    if !has_required_markers(source) {
        return Vec::new();
    }

    let Some(lang) = language_for(language) else {
        return Vec::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    collect_loop_findings(tree.root_node(), source, label, &mut findings);
    findings
}

fn has_required_markers(source: &[u8]) -> bool {
    contains_ascii_case_insensitive(source, b"openai")
        || contains_ascii_case_insensitive(source, b"api.openai.com")
        || contains_ascii_case_insensitive(source, b"anthropic")
        || contains_ascii_case_insensitive(source, b"llm")
}

fn language_for(language: &str) -> Option<Language> {
    match language {
        "py" | "pyi" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "jsx" | "ts" | "tsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        _ => None,
    }
}

fn collect_loop_findings(
    node: Node<'_>,
    source: &[u8],
    label: &str,
    findings: &mut Vec<StructuredFinding>,
) {
    if is_loop_node(node) && loop_has_llm_to_exec_flow(node, source) {
        let line = byte_to_line(source, node.start_byte());
        let material = format!(
            "security:bare_metal_agentic_loop:{label}:{}:{}:{}",
            node.kind(),
            node.start_byte(),
            node.end_byte()
        );
        findings.push(StructuredFinding {
            id: "security:bare_metal_agentic_loop".to_string(),
            file: Some(label.to_string()),
            line: Some(line),
            fingerprint: short_fingerprint(material.as_bytes()),
            severity: Some("KevCritical".to_string()),
            remediation: Some(
                "Break the autonomous loop with a policy gate: never route raw LLM output into eval, exec, subprocess, or process-spawn sinks without an allowlist and human approval boundary."
                    .to_string(),
            ),
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: true,
            ..Default::default()
        });
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_loop_findings(child, source, label, findings);
    }
}

fn is_loop_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "while_statement"
            | "for_statement"
            | "do_statement"
            | "while_expression"
            | "loop_expression"
            | "for_expression"
    )
}

fn loop_has_llm_to_exec_flow(node: Node<'_>, source: &[u8]) -> bool {
    let span_len = node.end_byte().saturating_sub(node.start_byte());
    if span_len > MAX_LOOP_BYTES {
        return false;
    }
    let Ok(text) = node.utf8_text(source) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    let Some(llm_pos) = first_marker_pos(&lower, LLM_MARKERS) else {
        return false;
    };
    let Some(exec_pos) = first_marker_pos(&lower, EXEC_MARKERS) else {
        return false;
    };
    exec_pos > llm_pos
}

fn first_marker_pos(haystack: &str, markers: &[&str]) -> Option<usize> {
    markers
        .iter()
        .filter_map(|marker| haystack.find(marker))
        .min()
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn byte_to_line(source: &[u8], byte: usize) -> u32 {
    source[..source.len().min(byte)]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_python_while_true_openai_to_subprocess_emits_bare_metal_loop() {
        let source = br#"
import openai
import subprocess

while True:
    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "next command"}],
    )
    command = response.choices[0].message.content
    subprocess.run(command, shell=True)
"#;

        let findings = find_bare_metal_agentic_loops("py", source, "agent.py");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:bare_metal_agentic_loop");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn openai_loop_without_dynamic_execution_is_clean() {
        let source = br#"
import openai

while True:
    response = openai.chat.completions.create(model="gpt-4o-mini", messages=[])
    print(response)
"#;

        let findings = find_bare_metal_agentic_loops("py", source, "agent.py");

        assert!(findings.is_empty());
    }

    #[test]
    fn execution_before_llm_call_is_clean() {
        let source = br#"
import openai
import subprocess

while True:
    subprocess.run(["echo", "ready"])
    response = openai.chat.completions.create(model="gpt-4o-mini", messages=[])
"#;

        let findings = find_bare_metal_agentic_loops("py", source, "agent.py");

        assert!(findings.is_empty());
    }
}
