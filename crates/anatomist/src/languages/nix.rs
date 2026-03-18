//! # Nix Grammar Router — Attribute Binding Entity Extraction and Protection
//!
//! Provides the Tree-sitter S-expression query for Nix source files and a
//! post-extraction shield that prevents Nix attribute bindings from appearing
//! in the dead-symbol report.
//!
//! ## Why all Nix entities are pre-protected
//!
//! Nix is a purely functional configuration language.  Every attribute binding
//! (`name = expr;`) is active configuration that is evaluated at build time.
//! The dead-symbol pipeline — designed for Python / Rust application code —
//! has no concept of a "Nix call graph" and would incorrectly flag all Nix
//! bindings as dead.  [`shield_all`] applies [`crate::Protection::WisdomRule`]
//! to every extracted entity, routing them permanently out of the dead-symbol
//! surface.
//!
//! ## Grammar coverage
//!
//! The `(binding attrpath: ...)` pattern in [`ENTITY_S_EXPR`] captures:
//! - Simple bindings:  `curl = callPackage ./curl {};`
//! - Dotted bindings:  `meta.license = licenses.mit;` (captures `meta`)
//! - Deep `let … in` bindings at any nesting level
//! - `mkDerivation { pname = "curl"; ... }` attribute arguments

use crate::{Entity, EntityType, Protection};

/// S-expression for Nix grammar entity extraction.
///
/// Captures attribute bindings (`name = expr;`) at all nesting levels.
/// The first `identifier` component of each `attrpath` is recorded as the
/// entity name, covering both simple (`foo = ...`) and dotted
/// (`foo.bar = ...`, captures `foo`) forms.
pub const ENTITY_S_EXPR: &str = r#"
    (binding
      attrpath: (attrpath
        attr: (identifier) @bind.name)) @bind.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for the Nix grammar.
///
/// Index 0: `binding` node → [`EntityType::Assignment`] entity.
pub const PATTERNS: &[(&str, &str, EntityType)] =
    &[("bind.def", "bind.name", EntityType::Assignment)];

/// Mark every extracted Nix entity as [`Protection::WisdomRule`].
///
/// Nix attribute bindings are active build-time configuration, not dead code.
/// Pre-protecting them prevents false positives in the dead-symbol pipeline.
pub fn shield_all(entities: &mut [Entity]) {
    for e in entities.iter_mut() {
        e.protected_by = Some(Protection::WisdomRule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parser::ParserHost, Protection};

    #[test]
    fn nix_entities_are_pre_protected() {
        let source = b"{ pkgs }:\n{\n  curl = pkgs.callPackage ./curl {};\n  wget = pkgs.callPackage ./wget {};\n}";
        let mut entities = ParserHost::extract_nix_entities(source, "default.nix").unwrap();
        assert_eq!(entities.len(), 2, "expected 2 binding entities");
        // shield_all is called inside extract_nix_entities; all entities must carry WisdomRule.
        shield_all(&mut entities); // idempotent second call — still WisdomRule
        for e in &entities {
            assert_eq!(
                e.protected_by,
                Some(Protection::WisdomRule),
                "Nix entity '{}' must be pre-protected with WisdomRule",
                e.name
            );
        }
    }

    #[test]
    fn shield_all_sets_wisdom_rule_on_each_entity() {
        let source = b"{\n  pname = \"curl\";\n  version = \"8.0.0\";\n  meta.license = null;\n}";
        let entities = ParserHost::extract_nix_entities(source, "default.nix").unwrap();
        assert!(
            !entities.is_empty(),
            "must extract at least one binding from attrset"
        );
        for e in &entities {
            assert_eq!(
                e.protected_by,
                Some(Protection::WisdomRule),
                "every Nix entity must carry WisdomRule protection"
            );
        }
    }
}
