//! Semantic CST diff extraction for subtree-local patch analysis.
//!
//! Resolves added patch line ranges against a parsed source unit and returns
//! the tightest enclosing AST nodes that contain those mutations.

use crate::slop_hunter::ParsedUnit;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddedLineRange {
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutatedSubtree {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub end_line: usize,
}

pub fn added_line_ranges_from_patch(patch: &str) -> Vec<AddedLineRange> {
    let mut ranges = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut added_line_no = 1usize;

    for line in patch.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            current_start.get_or_insert(added_line_no);
            added_line_no += 1;
            continue;
        }

        if let Some(start_line) = current_start.take() {
            ranges.push(AddedLineRange {
                start_line,
                end_line: added_line_no.saturating_sub(1),
            });
        }
    }

    if let Some(start_line) = current_start.take() {
        ranges.push(AddedLineRange {
            start_line,
            end_line: added_line_no.saturating_sub(1),
        });
    }

    ranges
}

pub fn resolve_mutated_subtrees(
    parsed: &ParsedUnit<'_>,
    ranges: &[AddedLineRange],
) -> Vec<MutatedSubtree> {
    let Some(tree) = parsed.tree() else {
        return Vec::new();
    };

    let root = tree.root_node();
    let mut dedup = HashSet::new();
    let mut out = Vec::new();

    for range in ranges {
        let node = tightest_enclosing_node(root, range.start_line, range.end_line);
        let start_byte = node.start_byte();
        let end_byte = node.end_byte();
        if start_byte >= end_byte || !dedup.insert((start_byte, end_byte)) {
            continue;
        }

        out.push(MutatedSubtree {
            start_byte,
            end_byte,
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        });
    }

    out.sort_by_key(|subtree| (subtree.start_byte, subtree.end_byte));
    out
}

fn tightest_enclosing_node(node: Node<'_>, start_line: usize, end_line: usize) -> Node<'_> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if covers_line_range(child, start_line, end_line) && should_descend(child) {
            return tightest_enclosing_node(child, start_line, end_line);
        }
    }
    node
}

fn covers_line_range(node: Node<'_>, start_line: usize, end_line: usize) -> bool {
    let node_start = node.start_position().row + 1;
    let node_end = node.end_position().row + 1;
    node_start <= start_line && node_end >= end_line
}

fn should_descend(node: Node<'_>) -> bool {
    node.named_child_count() > 0
        && !matches!(
            node.kind(),
            "identifier"
                | "string"
                | "string_literal"
                | "string_fragment"
                | "string_content"
                | "escape_sequence"
                | "interpreted_string_literal"
                | "arguments"
                | "argument_list"
        )
}

#[cfg(test)]
mod tests {
    use super::{added_line_ranges_from_patch, resolve_mutated_subtrees};
    use crate::slop_hunter::ParsedUnit;
    use tree_sitter::Parser;

    #[test]
    fn parses_added_line_ranges_from_patch() {
        let patch = "\
diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,0 +1,5 @@
+function demo() {
+
+  eval(\"boom\");
+}
+";
        let ranges = added_line_ranges_from_patch(patch);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_line, 1);
        assert_eq!(ranges[0].end_line, 5);
    }

    #[test]
    fn resolves_tightest_js_subtree_for_added_lines() {
        let source = b"function demo() {\n  eval(\"boom\");\n}\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let parsed = ParsedUnit::new(
            source,
            Some(tree),
            Some(tree_sitter_javascript::LANGUAGE.into()),
        );
        let subtrees = resolve_mutated_subtrees(
            &parsed,
            &[super::AddedLineRange {
                start_line: 2,
                end_line: 2,
            }],
        );
        assert_eq!(subtrees.len(), 1);
        let slice = &source[subtrees[0].start_byte..subtrees[0].end_byte];
        let text = std::str::from_utf8(slice).unwrap();
        assert!(text.contains("eval"));
    }
}
