//! Intent-vs-implementation divergence detector.
//!
//! This module uses bounded AST structure and lexical cues only. It deliberately
//! avoids embeddings or model inference so the detector stays deterministic and
//! inside the 8GB Law.

use tree_sitter::Node;

use crate::metadata::DOMAIN_FIRST_PARTY;
use crate::slop_hunter::{Severity, SlopFinding};

const SECURITY_VERBS: &[&str] = &["verify", "authenticate", "sanitize", "check"];

/// Detect Rust functions whose security-signaling name or doc comment
/// contradicts a vacuous implementation body.
pub fn find_rust_intent_divergence(root: Node<'_>, source: &[u8]) -> Vec<SlopFinding> {
    let mut findings = Vec::new();
    find_rust_functions(root, source, &mut findings);
    findings
}

fn find_rust_functions(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "function_item" {
        if let (Some(name), Some(body)) = (
            node.child_by_field_name("name"),
            node.child_by_field_name("body"),
        ) {
            let name_text = name.utf8_text(source).unwrap_or("");
            let leading_doc = leading_doc_window(node, source);
            if (has_security_intent(name_text) || has_security_intent(&leading_doc))
                && is_vacuous_rust_body(body, source)
            {
                findings.push(SlopFinding {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    description: format!(
                        "security:intent_divergence — function `{name_text}` claims a security responsibility but its AST body is vacuous (`return true`, `return obj`, or empty block); this matches LLM-assisted supply-chain backdoor structure"
                    ),
                    domain: DOMAIN_FIRST_PARTY,
                    severity: Severity::Critical,
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_rust_functions(child, source, findings);
    }
}

fn has_security_intent(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECURITY_VERBS.iter().any(|verb| lower.contains(verb))
}

fn leading_doc_window(node: Node<'_>, source: &[u8]) -> String {
    let start = node.start_byte();
    let window_start = start.saturating_sub(512);
    String::from_utf8_lossy(&source[window_start..start]).into_owned()
}

fn is_vacuous_rust_body(body: Node<'_>, source: &[u8]) -> bool {
    let body_text = body.utf8_text(source).unwrap_or("");
    let normalized: String = body_text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !matches!(c, '{' | '}' | ';'))
        .collect();

    if normalized.is_empty() {
        return true;
    }
    matches!(
        normalized.as_str(),
        "returntrue" | "true" | "returnobj" | "obj"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rust(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("rust grammar loads");
        parser.parse(source, None).expect("rust source parses")
    }

    #[test]
    fn verify_signature_return_true_backdoor_fires() {
        let source = b"fn verify_signature() -> bool { return true; }\n";
        let tree = parse_rust(source);
        let findings = find_rust_intent_divergence(tree.root_node(), source);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("security:intent_divergence")),
            "security-named vacuous verifier must fire"
        );
    }

    #[test]
    fn doc_comment_security_intent_empty_body_fires() {
        let source = b"/// Authenticate the caller.\nfn handler() {}\n";
        let tree = parse_rust(source);
        let findings = find_rust_intent_divergence(tree.root_node(), source);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("security:intent_divergence")),
            "security docstring with empty implementation must fire"
        );
    }

    #[test]
    fn non_security_helper_return_true_is_clean() {
        let source = b"fn feature_enabled() -> bool { return true; }\n";
        let tree = parse_rust(source);
        let findings = find_rust_intent_divergence(tree.root_node(), source);
        assert!(
            findings
                .iter()
                .all(|f| !f.description.contains("security:intent_divergence")),
            "non-security helpers must not trigger intent divergence"
        );
    }
}
