//! Solidity/Web3 structural security detectors.
//!
//! This module establishes the P2-2 parser lane without folding it into the
//! language-agnostic slop hunter yet.  The detector performs a tree-sitter parse
//! first, then uses bounded byte-slice inspection over the parsed source to emit
//! deterministic Web3 findings.

use alloy_primitives::Address;
use common::slop::StructuredFinding;
use tree_sitter::{Node, Tree};

const ZERO_ADDRESS: Address = Address::ZERO;

/// Find Solidity/Web3 security findings in a single Solidity source buffer.
pub fn find_solidity_slop(source: &[u8]) -> Vec<StructuredFinding> {
    let Some(tree) = parse_solidity(source) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    let _ = ZERO_ADDRESS;
    find_reentrancy(source, &tree, &mut findings);
    find_unprotected_selfdestruct(source, &tree, &mut findings);
    findings
}

fn parse_solidity(source: &[u8]) -> Option<Tree> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_solidity::LANGUAGE;
    parser.set_language(&language.into()).ok()?;
    let tree = parser.parse(source, None)?;
    if tree.root_node().has_error() {
        return None;
    }
    Some(tree)
}

fn find_reentrancy(source: &[u8], tree: &Tree, findings: &mut Vec<StructuredFinding>) {
    let text = std::str::from_utf8(source).unwrap_or("");
    let lower = text.to_ascii_lowercase();
    let Some(call_offset) = find_value_call(&lower) else {
        return;
    };
    let tail = &lower[call_offset..];
    let Some(write_offset) = find_state_write_after_external_call(tail) else {
        return;
    };

    let start = call_offset + write_offset;
    let line = byte_to_line(source, start);
    findings.push(StructuredFinding {
        id: "security:reentrancy".to_string(),
        file: None,
        line: Some(line),
        fingerprint: fingerprint("security:reentrancy", source, start),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "External value transfer is followed by a state mutation. Move state changes before the call or apply a nonReentrant guard.".to_string(),
        ),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: false,
    });

    let _ = first_named_descendant(tree.root_node());
}

fn find_unprotected_selfdestruct(
    source: &[u8],
    tree: &Tree,
    findings: &mut Vec<StructuredFinding>,
) {
    let text = std::str::from_utf8(source).unwrap_or("");
    let lower = text.to_ascii_lowercase();
    let Some(offset) = lower
        .find("selfdestruct(")
        .or_else(|| lower.find("suicide("))
    else {
        return;
    };
    let function_start = lower[..offset].rfind("function ").unwrap_or(0);
    let body = &lower[function_start..offset];
    let protected = body.contains("onlyowner")
        || body.contains("onlyrole")
        || body.contains("requiresauth")
        || body.contains("auth")
        || body.contains("require(msg.sender")
        || body.contains("require (msg.sender")
        || body.contains("if (msg.sender")
        || body.contains("if(msg.sender");
    if protected {
        return;
    }

    findings.push(StructuredFinding {
        id: "security:unprotected_selfdestruct".to_string(),
        file: None,
        line: Some(byte_to_line(source, offset)),
        fingerprint: fingerprint("security:unprotected_selfdestruct", source, offset),
        severity: Some("KevCritical".to_string()),
        remediation: Some(
            "Selfdestruct is reachable without an owner, role, or explicit msg.sender authorization guard.".to_string(),
        ),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: false,
    });

    let _ = first_named_descendant(tree.root_node());
}

fn find_value_call(lower: &str) -> Option<usize> {
    lower
        .find(".call.value(")
        .or_else(|| lower.find(".call{value:"))
        .or_else(|| lower.find(".call{ value:"))
}

fn find_state_write_after_external_call(tail: &str) -> Option<usize> {
    let mut cursor = 0usize;
    for line in tail.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty()
            && !trimmed.starts_with("//")
            && !trimmed.starts_with("require")
            && !trimmed.starts_with("emit ")
            && !trimmed.starts_with("return")
            && (trimmed.contains(" = ")
                || trimmed.contains("+=")
                || trimmed.contains("-=")
                || trimmed.contains("++")
                || trimmed.contains("--"))
        {
            return Some(cursor);
        }
        cursor += line.len() + 1;
    }
    None
}

fn first_named_descendant(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.is_named() && node != root {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    None
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

fn byte_to_line(source: &[u8], offset: usize) -> u32 {
    let capped = offset.min(source.len());
    source[..capped]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u32
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solidity_parser_initializes() {
        let src = br#"
pragma solidity ^0.8.20;
contract Vault {
    function balance() external pure returns (uint256) { return 1; }
}
"#;
        assert!(parse_solidity(src).is_some());
    }

    #[test]
    fn detects_reentrancy_value_call_before_state_write() {
        let src = br#"
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) external {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"#;
        let findings = find_solidity_slop(src);
        assert!(findings.iter().any(|f| f.id == "security:reentrancy"));
    }

    #[test]
    fn detects_unprotected_selfdestruct() {
        let src = br#"
pragma solidity ^0.8.20;
contract KillSwitch {
    function kill() external {
        selfdestruct(payable(msg.sender));
    }
}
"#;
        let findings = find_solidity_slop(src);
        assert!(findings
            .iter()
            .any(|f| f.id == "security:unprotected_selfdestruct"));
    }
}
