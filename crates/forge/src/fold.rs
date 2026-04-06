//! Bounded AST constant folding for sink-adjacent string concatenation.
//!
//! This module deliberately folds only deterministic string-literal `+` chains.
//! It is not a general evaluator.

use tree_sitter::Node;

const MAX_FOLD_DEPTH: usize = 10;
const MAX_FOLDED_BYTES: usize = 4096;

/// Fold an AST expression into a single contiguous string when it is composed
/// solely of nested string-literal concatenations.
pub fn fold_string_concat(node: Node<'_>, source: &[u8]) -> Option<String> {
    fold_string_concat_inner(node, source, 0)
}

fn fold_string_concat_inner(node: Node<'_>, source: &[u8], depth: usize) -> Option<String> {
    if depth > MAX_FOLD_DEPTH {
        return None;
    }

    if let Some(inner) = unwrap_container(node) {
        return fold_string_concat_inner(inner, source, depth + 1);
    }

    if let Some(lit) = extract_string_literal(node, source) {
        return Some(lit);
    }

    if !matches!(node.kind(), "binary_expression" | "binary_operator") {
        return None;
    }

    let op = node.child_by_field_name("operator")?;
    if op.utf8_text(source).ok()? != "+" {
        return None;
    }

    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let left = fold_string_concat_inner(left, source, depth + 1)?;
    let right = fold_string_concat_inner(right, source, depth + 1)?;

    let total = left.len() + right.len();
    if total > MAX_FOLDED_BYTES {
        return None;
    }

    let mut out = String::with_capacity(total);
    out.push_str(&left);
    out.push_str(&right);
    Some(out)
}

fn unwrap_container(node: Node<'_>) -> Option<Node<'_>> {
    if !matches!(
        node.kind(),
        "expression_statement" | "parenthesized_expression"
    ) {
        return None;
    }

    let mut cursor = node.walk();
    let inner = node.named_children(&mut cursor).next();
    inner
}

fn extract_string_literal(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "string" | "string_literal" | "interpreted_string_literal" => {
            let text = node.utf8_text(source).ok()?;
            unquote(text)
        }
        "string_fragment" | "string_content" => Some(node.utf8_text(source).ok()?.to_string()),
        _ => {
            let mut cursor = node.walk();
            let named: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            if named.is_empty() {
                return None;
            }
            let mut out = String::new();
            for child in named {
                match child.kind() {
                    "string_fragment" | "string_content" => {
                        out.push_str(child.utf8_text(source).ok()?)
                    }
                    "escape_sequence" => out.push_str(child.utf8_text(source).ok()?),
                    _ => return None,
                }
                if out.len() > MAX_FOLDED_BYTES {
                    return None;
                }
            }
            (!out.is_empty()).then_some(out)
        }
    }
}

fn unquote(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if !matches!(first, b'\'' | b'"' | b'`') || first != last {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    (inner.len() <= MAX_FOLDED_BYTES).then(|| inner.to_string())
}

#[cfg(test)]
mod tests {
    use super::fold_string_concat;
    use tree_sitter::Parser;

    #[test]
    fn folds_js_string_concat_chain() {
        let source = br#""Y29uc2" + "9sZS5" + "sb2co" + "J2hhY2tlZCcp""#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let expr = tree.root_node().named_child(0).unwrap();
        let folded = fold_string_concat(expr, source).unwrap();
        assert_eq!(folded, "Y29uc29sZS5sb2coJ2hhY2tlZCcp");
    }

    #[test]
    fn folds_parenthesized_js_string_concat_chain() {
        let source = br#"("Y29uc2" + "9sZS5" + "sb2co" + "J2hhY2tlZCcp")"#;
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let expr = tree.root_node().named_child(0).unwrap();
        let folded = fold_string_concat(expr, source).unwrap();
        assert_eq!(folded, "Y29uc29sZS5sb2coJ2hhY2tlZCcp");
    }

    #[test]
    fn non_string_binary_expression_stays_unfolded() {
        let source = b"1 + 2";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let expr = tree.root_node().named_child(0).unwrap();
        assert!(fold_string_concat(expr, source).is_none());
    }
}
