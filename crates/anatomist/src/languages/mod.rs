/// Language-specific grammar routing helpers.
///
/// Each module provides:
/// - `ENTITY_S_EXPR` — the Tree-sitter S-expression query for entity extraction
/// - `PATTERNS` — pattern-index to (def_cap, name_cap, entity_type) mapping
/// - Optional post-extraction transformation functions (e.g., `shield_all`)
pub mod nix;
