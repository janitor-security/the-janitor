//! Bounded intra-procedural memory safety proof lane.
//!
//! The proof lane is deliberately local and deterministic. It inspects a single
//! tree-sitter subtree, derives attacker-controlled parameter names, and proves
//! only simple dominance facts that appear before a memory sink in the same
//! function body.

use common::slop::ExploitWitness;
use tree_sitter::{Language, Node, Parser};

const MAX_PROOF_BYTES: usize = 256 * 1024;

/// Result of a bounded local memory proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofStatus {
    /// The local invariant was proven by a dominating guard.
    ProvenSafe,
    /// The local invariant is violated by an attacker-controlled value.
    Vulnerable,
    /// The proof lane found a memory sink but could not prove either side.
    Unknown,
}

/// Evidence produced by the intra-procedural proof lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProofEvidence {
    /// Final proof status.
    pub status: ProofStatus,
    /// Memory sink that triggered the proof.
    pub sink: String,
    /// Attacker-controlled variable participating in the sink.
    pub variable: String,
    /// 1-indexed line number of the memory sink.
    pub line: u32,
    /// Human-readable deterministic proof summary.
    pub rationale: String,
}

/// Prove local memory-safety facts for a single tree-sitter node.
///
/// The function returns `ProofStatus::Vulnerable` when an attacker-controlled
/// index, size, or pointer is used in a memory sink without a dominating local
/// bounds/null guard. It never allocates proportional to repository size; the
/// inspected subtree is capped by `MAX_PROOF_BYTES`.
pub fn prove_intraprocedural_memory_safety(node: Node<'_>, source: &[u8]) -> ProofStatus {
    match prove_node(node, source) {
        Some(evidence) => evidence.status,
        None => ProofStatus::Unknown,
    }
}

/// Parse a source file and return every vulnerable local memory-proof artifact.
pub fn find_vulnerable_memory_proofs(
    language: &str,
    source: &[u8],
    label: &str,
) -> Vec<ExploitWitness> {
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

    let mut proofs = Vec::new();
    collect_vulnerable_proofs(tree.root_node(), source, label, &mut proofs);
    proofs
}

/// Build an exploit witness for an existing unsafe memory finding span.
pub fn witness_for_memory_finding(
    language: &str,
    source: &[u8],
    label: &str,
    finding_line: u32,
) -> Option<ExploitWitness> {
    find_vulnerable_memory_proofs(language, source, label)
        .into_iter()
        .find(|witness| {
            witness
                .path_proof
                .as_deref()
                .is_some_and(|proof| proof.contains(&format!("line {finding_line}")))
        })
}

fn collect_vulnerable_proofs(
    node: Node<'_>,
    source: &[u8],
    label: &str,
    proofs: &mut Vec<ExploitWitness>,
) {
    if is_function_node(node) {
        if let Some(evidence) = prove_node(node, source) {
            if evidence.status == ProofStatus::Vulnerable {
                proofs.push(ExploitWitness {
                    source_function: function_name(node, source)
                        .unwrap_or_else(|| "unknown_function".to_string()),
                    source_label: format!("attacker-controlled {}", evidence.variable),
                    sink_function: function_name(node, source)
                        .unwrap_or_else(|| "unknown_function".to_string()),
                    sink_label: evidence.sink.clone(),
                    call_chain: vec![label.to_string()],
                    path_proof: Some(format!(
                        "ProofStatus::Vulnerable at line {}: {}",
                        evidence.line, evidence.rationale
                    )),
                    upstream_validation_absent: true,
                    ..Default::default()
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_vulnerable_proofs(child, source, label, proofs);
    }
}

fn prove_node(node: Node<'_>, source: &[u8]) -> Option<MemoryProofEvidence> {
    let span_len = node.end_byte().saturating_sub(node.start_byte());
    if span_len > MAX_PROOF_BYTES {
        return Some(MemoryProofEvidence {
            status: ProofStatus::Unknown,
            sink: "oversized_function".to_string(),
            variable: "unknown".to_string(),
            line: byte_to_line(source, node.start_byte()),
            rationale: "function exceeds bounded proof budget".to_string(),
        });
    }
    let text = node.utf8_text(source).ok()?;
    let params = extract_parameter_like_names(text);
    let sinks = extract_memory_sinks(text);
    for sink in sinks {
        let Some(variable) = sink
            .variables
            .iter()
            .find(|candidate| params.iter().any(|param| param == *candidate))
            .cloned()
        else {
            continue;
        };
        let prefix = &text[..sink.offset.min(text.len())];
        if has_dominating_guard(prefix, &variable) {
            return Some(MemoryProofEvidence {
                status: ProofStatus::ProvenSafe,
                sink: sink.kind,
                variable,
                line: byte_to_line(source, node.start_byte() + sink.offset),
                rationale: "dominating bounds/null guard found before memory sink".to_string(),
            });
        }
        return Some(MemoryProofEvidence {
            status: ProofStatus::Vulnerable,
            sink: sink.kind.clone(),
            variable: variable.clone(),
            line: byte_to_line(source, node.start_byte() + sink.offset),
            rationale: format!(
                "`{variable}` reaches `{}` without a dominating bounds/null guard",
                sink.kind
            ),
        });
    }
    None
}

#[derive(Debug, Clone)]
struct MemorySink {
    kind: String,
    variables: Vec<String>,
    offset: usize,
}

fn extract_memory_sinks(text: &str) -> Vec<MemorySink> {
    let mut sinks = Vec::new();
    for name in [
        "strcpy", "strcat", "sprintf", "vsprintf", "memcpy", "memmove",
    ] {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(name) {
            let absolute = search_from + pos;
            let args = call_args_after(&text[absolute + name.len()..]);
            let variables = args.as_deref().map(extract_identifiers).unwrap_or_default();
            sinks.push(MemorySink {
                kind: name.to_string(),
                variables,
                offset: absolute,
            });
            search_from = absolute + name.len();
        }
    }
    for pattern in ["*ptr", "*p", ".add(", ".offset("] {
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(pattern) {
            let absolute = search_from + pos;
            let window_start = absolute.saturating_sub(96);
            let window_end = (absolute + 160).min(text.len());
            sinks.push(MemorySink {
                kind: "raw_pointer_deref".to_string(),
                variables: extract_identifiers(&text[window_start..window_end]),
                offset: absolute,
            });
            search_from = absolute + pattern.len();
        }
    }
    for (absolute, variables) in indexed_accesses(text) {
        sinks.push(MemorySink {
            kind: "array_index".to_string(),
            variables,
            offset: absolute,
        });
    }
    sinks.sort_by_key(|sink| sink.offset);
    sinks
}

fn indexed_accesses(text: &str) -> Vec<(usize, Vec<String>)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            let start = i + 1;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b']' && end - start < 128 {
                end += 1;
            }
            if end < bytes.len() && bytes[end] == b']' {
                let vars = extract_identifiers(&text[start..end]);
                if !vars.is_empty() {
                    out.push((i, vars));
                }
                i = end;
            }
        }
        i += 1;
    }
    out
}

fn call_args_after(text: &str) -> Option<String> {
    let open = text.find('(')?;
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in text[open..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    end = Some(open + idx);
                    break;
                }
            }
            _ => {}
        }
    }
    end.map(|idx| text[open + 1..idx].to_string())
}

fn extract_parameter_like_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Some(open) = text.find('(') else {
        return names;
    };
    let Some(close_rel) = text[open + 1..].find(')') else {
        return names;
    };
    let params = &text[open + 1..open + 1 + close_rel];
    for param in params.split(',') {
        let ids = extract_identifiers(param);
        if let Some(last) = ids.last() {
            names.push(last.clone());
        }
    }
    names.extend(
        ["argc", "argv", "input", "idx", "len", "size"]
            .iter()
            .map(|s| s.to_string()),
    );
    names.sort();
    names.dedup();
    names
}

fn extract_identifiers(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch == '_' || ch.is_ascii_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            push_identifier(&mut names, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        push_identifier(&mut names, &current);
    }
    names
}

fn push_identifier(names: &mut Vec<String>, candidate: &str) {
    if candidate
        .chars()
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && !matches!(
            candidate,
            "if" | "for"
                | "while"
                | "return"
                | "let"
                | "mut"
                | "const"
                | "char"
                | "int"
                | "size_t"
                | "usize"
                | "u8"
                | "unsafe"
                | "null"
                | "NULL"
                | "std"
                | "ptr"
        )
    {
        names.push(candidate.to_string());
    }
}

fn has_dominating_guard(prefix: &str, variable: &str) -> bool {
    let compact = prefix.split_whitespace().collect::<String>();
    let guards = [
        format!("{variable}<"),
        format!("{variable}<="),
        format!("{variable}.len()>"),
        format!("len>{variable}"),
        format!("size>{variable}"),
        format!("{variable}!=NULL"),
        format!("{variable}.is_null()==false"),
        format!("!{variable}.is_null()"),
        format!("{variable}.is_some()"),
    ];
    guards.iter().any(|guard| compact.contains(guard))
}

fn is_function_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "function_declarator" | "function_item"
    )
}

fn function_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    let open = text.find('(')?;
    let head = &text[..open];
    extract_identifiers(head).last().cloned()
}

fn language_for(language: &str) -> Option<Language> {
    match language {
        "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        _ => None,
    }
}

fn byte_to_line(source: &[u8], byte: usize) -> u32 {
    source[..source.len().min(byte)]
        .iter()
        .filter(|&&b| b == b'\n')
        .count() as u32
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rust(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("rust grammar loads");
        parser.parse(source, None).expect("source parses")
    }

    #[test]
    fn raw_pointer_without_bounds_checks_yields_vulnerable_memory_proof() {
        let source = br#"
pub unsafe fn read_at(ptr: *const u8, idx: usize) -> u8 {
    *ptr.add(idx)
}
"#;
        let tree = parse_rust(source);

        let status = prove_intraprocedural_memory_safety(tree.root_node(), source);

        assert_eq!(status, ProofStatus::Vulnerable);
    }

    #[test]
    fn guarded_index_is_proven_safe() {
        let source = br#"
pub fn read_at(buf: &[u8], idx: usize) -> u8 {
    if idx < buf.len() {
        return buf[idx];
    }
    0
}
"#;
        let tree = parse_rust(source);

        let status = prove_intraprocedural_memory_safety(tree.root_node(), source);

        assert_eq!(status, ProofStatus::ProvenSafe);
    }
}
