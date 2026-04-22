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
    find_cross_function_reentrancy(source, &tree, &mut findings);
    find_unprotected_authority_transitions(source, &tree, &mut findings);
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

#[derive(Debug, Clone)]
struct SolidityFunction {
    name: String,
    start: usize,
    end: usize,
    lower: String,
}

impl SolidityFunction {
    fn line(&self, source: &[u8]) -> u32 {
        byte_to_line(source, self.start)
    }

    fn has_external_value_call(&self) -> bool {
        find_value_call(&self.lower).is_some()
    }

    fn has_non_reentrant_lock(&self) -> bool {
        self.lower.contains("nonreentrant")
    }

    fn has_authority_guard(&self) -> bool {
        has_authority_guard(&self.lower)
    }

    fn reads_state_var(&self, var: &str) -> bool {
        contains_identifier(&self.lower, var)
    }

    fn writes_state_var(&self, var: &str) -> bool {
        let Some(first) = self.lower.find(var) else {
            return false;
        };
        let tail = &self.lower[first..];
        tail.contains(&format!("{var}[")) && contains_assignment_operator(tail)
            || tail.contains(&format!("{var}.")) && contains_assignment_operator(tail)
            || tail.contains(&format!("{var} ="))
            || tail.contains(&format!("{var} +="))
            || tail.contains(&format!("{var} -="))
            || tail.contains(&format!("{var}++"))
            || tail.contains(&format!("{var}--"))
    }
}

fn find_cross_function_reentrancy(
    source: &[u8],
    tree: &Tree,
    findings: &mut Vec<StructuredFinding>,
) {
    let functions = collect_functions(source, tree);
    if functions.len() < 2 {
        return;
    }
    let state_vars = collect_state_variables(source, &functions);
    if state_vars.is_empty() {
        return;
    }

    for caller in functions
        .iter()
        .filter(|function| function.has_external_value_call())
    {
        for var in state_vars
            .iter()
            .filter(|var| caller.reads_state_var(var.as_str()))
        {
            for writer in functions.iter().filter(|function| {
                function.name != caller.name && function.writes_state_var(var.as_str())
            }) {
                if caller.has_non_reentrant_lock() && writer.has_non_reentrant_lock() {
                    continue;
                }
                findings.push(StructuredFinding {
                    id: "security:cross_function_reentrancy".to_string(),
                    file: None,
                    line: Some(caller.line(source)),
                    fingerprint: fingerprint(
                        "security:cross_function_reentrancy",
                        source,
                        caller.start,
                    ),
                    severity: Some("KevCritical".to_string()),
                    remediation: Some(format!(
                        "Function `{}` performs an external value call while reading state `{}`; function `{}` mutates the same state without a shared nonReentrant lock.",
                        caller.name, var, writer.name
                    )),
                    docs_url: None,
                    exploit_witness: None,
                    upstream_validation_absent: false,
                });
                return;
            }
        }
    }
}

fn find_unprotected_authority_transitions(
    source: &[u8],
    tree: &Tree,
    findings: &mut Vec<StructuredFinding>,
) {
    let text = std::str::from_utf8(source).unwrap_or("");
    let lower = text.to_ascii_lowercase();
    for (offset, sink) in dangerous_evm_sink_offsets(&lower) {
        let function = function_for_sink(source, tree, offset);
        let protected = function
            .as_ref()
            .is_some_and(|function| function.has_authority_guard());
        if protected {
            continue;
        }

        findings.push(StructuredFinding {
            id: "security:unprotected_authority_transition".to_string(),
            file: None,
            line: Some(byte_to_line(source, offset)),
            fingerprint: fingerprint("security:unprotected_authority_transition", source, offset),
            severity: Some("KevCritical".to_string()),
            remediation: Some(format!(
                "`{sink}` is reachable without onlyOwner, onlyRole, or an explicit msg.sender authority guard."
            )),
            docs_url: None,
            exploit_witness: None,
            upstream_validation_absent: false,
        });
    }

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

fn collect_functions(source: &[u8], tree: &Tree) -> Vec<SolidityFunction> {
    let mut out = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if is_function_node(node) {
            if let Some(function) = function_from_node(source, node) {
                out.push(function);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out.extend(collect_functions_text(source));
    out.sort_by_key(|function| function.start);
    out.dedup_by(|left, right| left.start == right.start && left.end == right.end);
    out
}

fn function_for_sink(source: &[u8], tree: &Tree, offset: usize) -> Option<SolidityFunction> {
    let node = tree
        .root_node()
        .descendant_for_byte_range(offset, offset.saturating_add(1))?;
    let mut cursor = Some(node);
    while let Some(current) = cursor {
        if is_function_node(current) {
            return function_from_node(source, current);
        }
        cursor = current.parent();
    }
    collect_functions_text(source)
        .into_iter()
        .find(|function| offset >= function.start && offset <= function.end)
}

fn is_function_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_definition" | "function_declaration" | "constructor_definition"
    )
}

fn function_from_node(source: &[u8], node: Node<'_>) -> Option<SolidityFunction> {
    let text = node.utf8_text(source).ok()?.to_string();
    let lower = text.to_ascii_lowercase();
    let name = extract_function_name(&text).unwrap_or_else(|| "<constructor>".to_string());
    Some(SolidityFunction {
        name,
        start: node.start_byte(),
        end: node.end_byte(),
        lower,
    })
}

fn collect_functions_text(source: &[u8]) -> Vec<SolidityFunction> {
    let text = std::str::from_utf8(source).unwrap_or("");
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search_start = 0usize;
    while let Some(rel) = lower[search_start..].find("function ") {
        let start = search_start + rel;
        let Some(open_rel) = lower[start..].find('{') else {
            break;
        };
        let open = start + open_rel;
        let Some(end) = matching_brace(source, open) else {
            break;
        };
        let function_text = text[start..=end].to_string();
        let name =
            extract_function_name(&function_text).unwrap_or_else(|| "<anonymous>".to_string());
        out.push(SolidityFunction {
            name,
            start,
            end,
            lower: function_text.to_ascii_lowercase(),
        });
        search_start = end + 1;
    }
    out
}

fn matching_brace(source: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, byte) in source.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_function_name(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with("constructor") {
        return Some("<constructor>".to_string());
    }
    let after_function = trimmed.strip_prefix("function ")?;
    let name = after_function
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .next()?;
    (!name.is_empty()).then(|| name.to_string())
}

fn collect_state_variables(source: &[u8], functions: &[SolidityFunction]) -> Vec<String> {
    let text = std::str::from_utf8(source).unwrap_or("");
    let mut vars = Vec::new();
    for line in text.lines() {
        let line_start = line.as_ptr() as usize - text.as_ptr() as usize;
        if functions
            .iter()
            .any(|function| line_start >= function.start && line_start <= function.end)
        {
            continue;
        }
        let stripped = line.split("//").next().unwrap_or("").trim();
        if !stripped.ends_with(';')
            || stripped.contains(" function ")
            || stripped.starts_with("function ")
            || stripped.starts_with("event ")
            || stripped.starts_with("modifier ")
            || stripped.starts_with("using ")
        {
            continue;
        }
        if !(stripped.contains("mapping")
            || stripped.contains("uint")
            || stripped.contains("int")
            || stripped.contains("address")
            || stripped.contains("bool"))
        {
            continue;
        }
        if let Some(name) = state_var_name(stripped) {
            vars.push(name.to_ascii_lowercase());
        }
    }
    if vars.is_empty() {
        for line in text.lines() {
            let stripped = line.split("//").next().unwrap_or("").trim();
            if stripped.ends_with(';')
                && (stripped.contains("mapping")
                    || stripped.contains("uint")
                    || stripped.contains("int")
                    || stripped.contains("address")
                    || stripped.contains("bool"))
            {
                if let Some(name) = state_var_name(stripped) {
                    vars.push(name.to_ascii_lowercase());
                }
            }
        }
    }
    vars.sort();
    vars.dedup();
    vars
}

fn state_var_name(line: &str) -> Option<String> {
    let without_init = line.split(" = ").next().unwrap_or(line);
    let before_semicolon = without_init.trim_end_matches(';').trim();
    before_semicolon
        .split_whitespace()
        .rev()
        .find(|token| {
            !matches!(
                *token,
                "public"
                    | "private"
                    | "internal"
                    | "external"
                    | "immutable"
                    | "constant"
                    | "payable"
            )
        })
        .map(|token| token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'))
        .filter(|token| !token.is_empty())
        .map(str::to_string)
}

fn dangerous_evm_sink_offsets(lower: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for (needle, sink) in [
        ("selfdestruct(", "selfdestruct"),
        ("suicide(", "suicide"),
        (".delegatecall(", "delegatecall"),
        (".delegatecall{", "delegatecall"),
        ("function upgradeto(", "upgradeTo"),
        ("function upgradetoandcall(", "upgradeToAndCall"),
    ] {
        let mut search_start = 0usize;
        while let Some(rel) = lower[search_start..].find(needle) {
            let offset = search_start + rel;
            out.push((offset, sink));
            search_start = offset + needle.len();
        }
    }
    out.sort_by_key(|(offset, _)| *offset);
    out
}

fn has_authority_guard(lower_function: &str) -> bool {
    lower_function.contains("onlyowner")
        || lower_function.contains("onlyrole")
        || lower_function.contains("requiresauth")
        || lower_function.contains("require(msg.sender")
        || lower_function.contains("require (msg.sender")
        || lower_function.contains("if (msg.sender")
        || lower_function.contains("if(msg.sender")
        || lower_function.contains("_checkowner(")
        || lower_function.contains("_authorizeupgrade(")
}

fn contains_identifier(haystack: &str, ident: &str) -> bool {
    haystack
        .match_indices(ident)
        .any(|(idx, _)| identifier_boundary(haystack, idx, ident.len()))
}

fn identifier_boundary(haystack: &str, idx: usize, len: usize) -> bool {
    let before = idx
        .checked_sub(1)
        .and_then(|pos| haystack.as_bytes().get(pos))
        .copied();
    let after = haystack.as_bytes().get(idx + len).copied();
    !before.is_some_and(is_identifier_byte) && !after.is_some_and(is_identifier_byte)
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn contains_assignment_operator(text: &str) -> bool {
    text.contains(" = ")
        || text.contains("+=")
        || text.contains("-=")
        || text.contains("++")
        || text.contains("--")
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
            .any(|f| f.id == "security:unprotected_authority_transition"));
    }

    #[test]
    fn detects_cross_function_reentrancy_shared_state_without_lock() {
        let src = br#"
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public balances;

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }

    function credit(address user, uint256 amount) external {
        balances[user] += amount;
    }
}
"#;
        let findings = find_solidity_slop(src);
        assert!(findings
            .iter()
            .any(|f| f.id == "security:cross_function_reentrancy"));
    }

    #[test]
    fn detects_unprotected_delegatecall_authority_transition() {
        let src = br#"
pragma solidity ^0.8.20;
contract Proxy {
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"#;
        let findings = find_solidity_slop(src);
        assert!(findings
            .iter()
            .any(|f| f.id == "security:unprotected_authority_transition"));
    }

    #[test]
    fn guarded_delegatecall_is_not_authority_transition() {
        let src = br#"
pragma solidity ^0.8.20;
contract Proxy {
    modifier onlyOwner() {
        _;
    }

    function execute(address target, bytes calldata data) external onlyOwner {
        (bool ok,) = target.delegatecall(data);
        require(ok);
    }
}
"#;
        let findings = find_solidity_slop(src);
        assert!(findings
            .iter()
            .all(|f| f.id != "security:unprotected_authority_transition"));
    }
}
