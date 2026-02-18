//! PR Slop Filter — detect dead-code additions and logic clones in patches.
//!
//! [`PRBouncer`] is a trait for patch quality gatekeepers.
//! [`PatchBouncer`] is the default implementation: it parses a unified diff,
//! extracts added Python source, and uses structural hashing to detect
//! duplication and re-introduction of known symbols.
//!
//! ## Scoring Formula
//! ```text
//! SlopScore = (dead_symbols_added * 10) + (logic_clones_found * 5)
//! ```
//! Dead-symbol additions are penalised more heavily (×10) than structural
//! duplication (×5) because re-introducing dead code degrades signal quality.

use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tree_sitter::StreamingIterator;

use common::registry::SymbolRegistry;

// ---------------------------------------------------------------------------
// SlopScore
// ---------------------------------------------------------------------------

/// Score representing the amount of "slop" detected in a patch.
///
/// ## Formula
/// ```text
/// score = (dead_symbols_added × 10) + (logic_clones_found × 5)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlopScore {
    /// Number of added functions whose names already appear in the registry.
    ///
    /// Signals that the patch re-introduces or duplicates a known symbol —
    /// a common source of dead code accumulation.
    pub dead_symbols_added: u32,
    /// Number of structurally identical function pairs within the added code.
    ///
    /// Each "extra" clone beyond the first occurrence in a hash group counts
    /// as one clone (N functions sharing a hash → N−1 clones).
    pub logic_clones_found: u32,
}

impl SlopScore {
    /// Returns the weighted aggregate slop score.
    ///
    /// Higher scores indicate lower patch quality. A score of zero means the
    /// patch passes all checks cleanly.
    pub fn score(&self) -> u32 {
        self.dead_symbols_added * 10 + self.logic_clones_found * 5
    }

    /// Returns `true` when no slop was detected.
    pub fn is_clean(&self) -> bool {
        self.dead_symbols_added == 0 && self.logic_clones_found == 0
    }
}

// ---------------------------------------------------------------------------
// PRBouncer trait
// ---------------------------------------------------------------------------

/// Trait for patch-quality gatekeepers.
///
/// Implementors inspect a unified diff patch against an existing symbol registry
/// and return a [`SlopScore`] characterising the quality of the added code.
pub trait PRBouncer {
    /// Analyse `patch` (unified diff format) against `registry` and return a
    /// [`SlopScore`] quantifying dead-symbol additions and logic clones.
    ///
    /// # Errors
    /// Returns `Err` if the grammar fails to load or the patch cannot be parsed.
    fn bounce(&self, patch: &str, registry: &SymbolRegistry) -> Result<SlopScore>;
}

// ---------------------------------------------------------------------------
// PatchBouncer (default implementation)
// ---------------------------------------------------------------------------

/// Default [`PRBouncer`] implementation — analyses added Python functions in a
/// unified diff.
///
/// # Algorithm
/// 1. Extract all `+`-prefixed lines (excluding `+++` header lines) to
///    reconstruct the virtual added source.
/// 2. Parse the added source with `tree-sitter-python` to locate function
///    definitions and compute their structural hashes via
///    [`compute_structural_hash`][crate::compute_structural_hash].
/// 3. **`dead_symbols_added`**: functions whose names already exist in the
///    registry — likely re-introductions of known symbols.
/// 4. **`logic_clones_found`**: for each hash group with N > 1 members,
///    contribute N − 1 to the clone count (each extra copy beyond the first).
#[derive(Debug, Default)]
pub struct PatchBouncer;

impl PRBouncer for PatchBouncer {
    fn bounce(&self, patch: &str, registry: &SymbolRegistry) -> Result<SlopScore> {
        // Step 1: Reconstruct added source from `+` diff lines.
        let added: String = patch
            .lines()
            .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
            .map(|l| &l[1..]) // strip the leading '+'
            .collect::<Vec<_>>()
            .join("\n");

        if added.trim().is_empty() {
            return Ok(SlopScore::default());
        }

        // Step 2: Parse added source with tree-sitter-python.
        let source = added.as_bytes();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|e| anyhow::anyhow!("Failed to load Python grammar: {e}"))?;

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Ok(SlopScore::default()),
        };

        // Query: capture function name and body block.
        let query = tree_sitter::Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            "(function_definition name: (identifier) @fn.name body: (block) @fn.body)",
        )?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        let cap_names = query.capture_names();

        // Collect (name, structural_hash) pairs for added functions.
        let mut fn_hashes: Vec<(String, u64)> = Vec::new();
        while let Some(m) = matches.next() {
            let name_cap = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.name");
            let body_cap = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.body");

            if let (Some(name_c), Some(body_c)) = (name_cap, body_cap) {
                if let Ok(name) = name_c.node.utf8_text(source) {
                    let hash = crate::compute_structural_hash(body_c.node, source);
                    fn_hashes.push((name.to_string(), hash));
                }
            }
        }

        // Step 3: Dead symbols added — name already exists in registry.
        let registry_names: HashSet<&str> =
            registry.entries.iter().map(|e| e.name.as_str()).collect();
        let dead_symbols_added = fn_hashes
            .iter()
            .filter(|(name, _)| registry_names.contains(name.as_str()))
            .count() as u32;

        // Step 4: Logic clones — structural hash collisions within added code.
        // For a group of N functions sharing the same hash, contribute N − 1
        // (each clone beyond the first is counted once).
        let mut hash_counts: HashMap<u64, u32> = HashMap::new();
        for (_, hash) in &fn_hashes {
            *hash_counts.entry(*hash).or_insert(0) += 1;
        }
        let logic_clones_found: u32 = hash_counts
            .values()
            .filter(|&&c| c > 1)
            .map(|&c| c - 1)
            .sum();

        Ok(SlopScore {
            dead_symbols_added,
            logic_clones_found,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::registry::{SymbolEntry, SymbolRegistry};

    fn empty_registry() -> SymbolRegistry {
        SymbolRegistry::new()
    }

    fn registry_with(names: &[&str]) -> SymbolRegistry {
        let mut r = SymbolRegistry::new();
        for (i, &name) in names.iter().enumerate() {
            r.entries.push(SymbolEntry {
                id: i as u64,
                name: name.to_string(),
                qualified_name: name.to_string(),
                file_path: "test.py".to_string(),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                end_line: 3,
                entity_type: 0,
                structural_hash: 0,
                protected_by: None,
            });
        }
        r
    }

    fn make_patch(added_lines: &str) -> String {
        let mut patch = String::from("--- a/test.py\n+++ b/test.py\n@@ -0,0 +1 @@\n");
        for line in added_lines.lines() {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        patch
    }

    #[test]
    fn test_empty_patch_is_clean() {
        let bouncer = PatchBouncer;
        let score = bouncer.bounce("", &empty_registry()).unwrap();
        assert!(score.is_clean());
        assert_eq!(score.score(), 0);
    }

    #[test]
    fn test_new_symbol_clean_registry() {
        let patch = make_patch("def brand_new():\n    return 42\n");
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(score.dead_symbols_added, 0);
        assert_eq!(score.logic_clones_found, 0);
    }

    #[test]
    fn test_dead_symbol_detected() {
        let patch = make_patch("def old_helper():\n    return 1\n");
        let registry = registry_with(&["old_helper"]);
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &registry).unwrap();
        assert_eq!(score.dead_symbols_added, 1);
        assert_eq!(score.score(), 10);
    }

    #[test]
    fn test_logic_clone_detected() {
        // Two functions with identical logic but different names.
        let patch =
            make_patch("def add(a, b):\n    return a + b\ndef plus(x, y):\n    return x + y\n");
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(score.logic_clones_found, 1);
        assert_eq!(score.score(), 5);
    }

    #[test]
    fn test_score_formula() {
        let s = SlopScore {
            dead_symbols_added: 2,
            logic_clones_found: 3,
        };
        assert_eq!(s.score(), 2 * 10 + 3 * 5); // 35
    }
}
