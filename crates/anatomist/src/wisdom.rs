//! Stage 2 + Stage 4 classifier: per-file sequential heuristic pass.
//!
//! Processes one file's entities against its source bytes in a single linear scan,
//! assigning `protected_by` for entities that match a protection rule.
//!
//! **Stage 2**: WisdomRegistry heuristics — decorators, names, framework patterns.
//! **Stage 4**: Package export detection — `__all__` and `__init__.py` top-level symbols.
//!
//! Both stages share pre-computed file-level flags extracted in **one combined
//! Aho-Corasick pass** over the full source bytes. Total cost: O(file_size + entity_count).

use crate::{Entity, Protection};
use aho_corasick::AhoCorasick;
use std::collections::HashSet;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Combined Aho-Corasick automaton for file-level flag extraction.
//
// One AC pass over the full source bytes simultaneously tests for all 7 file-level
// boolean flags. Each pattern is tagged with a bitmask; scanning stops as soon as
// all 7 bits are set (short-circuits on highly idiomatic files).
// ---------------------------------------------------------------------------

/// Bit positions for the 7 file-level flags extracted by the combined AC.
const FLAG_DI: u8 = 1 << 0; // has FastAPI DI (`Depends(`, `Security(`, `dependency_overrides`)
const FLAG_ORM: u8 = 1 << 1; // has ORM base class (`(Model)`, `(Base)`, …)
const FLAG_SQLA: u8 = 1 << 2; // has SQLAlchemy (`sqlalchemy`, `SQLAlchemy`)
const FLAG_QT: u8 = 1 << 3; // has Qt widget (`QWidget`, `QMainWindow`, `QObject`)
const FLAG_META: u8 = 1 << 4; // has metaprogramming (`getattr(`, `eval(`, …)
const FLAG_ACTX: u8 = 1 << 5; // has `asynccontextmanager`
const FLAG_PYDA: u8 = 1 << 6; // has pydantic imports (`BaseModel`, `pydantic`)
const FLAG_ALL: u8 = 0b0111_1111; // all flags set — used for early-exit

/// (pattern, flag_bitmask) pairs for the combined file-level AC.
///
/// Patterns appear in roughly frequency order so the AC DFA has good locality.
#[rustfmt::skip]
static FILE_PATTERNS: &[(&[u8], u8)] = &[
    // Pydantic (very common in modern Python codebases)
    (b"BaseModel",              FLAG_PYDA),
    (b"pydantic",               FLAG_PYDA),
    // FastAPI DI
    (b"Depends(",               FLAG_DI),
    (b"Security(",              FLAG_DI),
    (b"dependency_overrides",   FLAG_DI),
    // ORM
    (b"(Model)",                FLAG_ORM),
    (b"(Base)",                 FLAG_ORM),
    (b"(Document)",             FLAG_ORM),
    (b"(db.Model)",             FLAG_ORM),
    // SQLAlchemy
    (b"sqlalchemy",             FLAG_SQLA),
    (b"SQLAlchemy",             FLAG_SQLA),
    // Qt
    (b"QWidget",                FLAG_QT),
    (b"QMainWindow",            FLAG_QT),
    (b"QObject",                FLAG_QT),
    // Metaprogramming
    (b"getattr(",               FLAG_META),
    (b"setattr(",               FLAG_META),
    (b"hasattr(",               FLAG_META),
    (b"delattr(",               FLAG_META),
    (b"eval(",                  FLAG_META),
    (b"exec(",                  FLAG_META),
    (b"__import__(",            FLAG_META),
    (b"importlib.",             FLAG_META),
    (b".__dict__",              FLAG_META),
    (b"type(",                  FLAG_META),
    // Async context manager
    (b"asynccontextmanager",    FLAG_ACTX),
];

/// Returns (automaton, per-pattern flag array). Compiled once at first call.
fn get_file_ac() -> Option<&'static (AhoCorasick, Vec<u8>)> {
    static FILE_AC: OnceLock<Option<(AhoCorasick, Vec<u8>)>> = OnceLock::new();
    FILE_AC
        .get_or_init(|| {
            let pats: Vec<&[u8]> = FILE_PATTERNS.iter().map(|(p, _)| *p).collect();
            let flags: Vec<u8> = FILE_PATTERNS.iter().map(|(_, f)| *f).collect();
            match AhoCorasick::new(pats) {
                Ok(ac) => Some((ac, flags)),
                Err(e) => {
                    eprintln!("wisdom: FILE_AC build failed (compile-time bug): {e}");
                    None
                }
            }
        })
        .as_ref()
}

/// Scans `source` once with the combined automaton and returns the 7-bit flag word.
///
/// Short-circuits as soon as all 7 flags are set (common for framework-heavy files).
/// Returns 0 if the automaton failed to build (should never happen in practice).
#[inline]
fn file_flags(source: &[u8]) -> u8 {
    let Some((ac, flags)) = get_file_ac() else {
        return 0;
    };
    let mut found: u8 = 0;
    for mat in ac.find_iter(source) {
        found |= flags[mat.pattern().as_usize()];
        if found == FLAG_ALL {
            break;
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Per-pattern-group AhoCorasick automata for entity/decorator-level scans.
//
// Decorator bodies are typically ≤ 128 bytes, so a pre-compiled AC is still
// faster than calling `AhoCorasick::new` per invocation.
// ---------------------------------------------------------------------------

/// Pre-compiled AC for route decorator patterns.
fn get_route_dec_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(ROUTE_DEC)
            .map_err(|e| eprintln!("wisdom: ROUTE_DEC_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

/// Pre-compiled AC for CLI decorator patterns.
fn get_cli_dec_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(CLI_DEC)
            .map_err(|e| eprintln!("wisdom: CLI_DEC_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

/// Pre-compiled AC for Pydantic validator decorator patterns.
fn get_pydantic_dec_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(PYDANTIC_DEC)
            .map_err(|e| eprintln!("wisdom: PYDANTIC_DEC_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

/// Pre-compiled AC for SQLAlchemy decorator patterns.
fn get_sqlalchemy_dec_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(SQLALCHEMY_DEC)
            .map_err(|e| eprintln!("wisdom: SQLALCHEMY_DEC_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

/// Pre-compiled AC for DI patterns (entity-body scan).
fn get_di_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(DI_PATTERNS)
            .map_err(|e| eprintln!("wisdom: DI_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

/// Pre-compiled AC for metaprogramming patterns (entity-body scan).
fn get_metaprog_ac() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::new(METAPROG)
            .map_err(|e| eprintln!("wisdom: METAPROG_AC build failed: {e}"))
            .ok()
    })
    .as_ref()
}

// --- Directory-level protection ---

/// Directories whose files are implicitly entry points via dynamic/plugin loading.
///
/// Files in these directories are discovered and executed by frameworks (Scrapy, Django,
/// Celery, etc.) without being explicitly imported, so all their public symbols must be
/// treated as entry points.
///
/// `migrations/` is intentionally omitted here — it is already caught by Stage 0
/// (`PROTECTED_DIRS` in `pipeline.rs`) which marks the entire directory as `Directory`.
static PLUGIN_DIRS: &[&str] = &["spiders", "plugins", "commands", "handlers", "tasks"];

// --- Global shield: framework-agnostic lifecycle / entry-point names ---

/// Names that are protected regardless of language or framework.
///
/// Covers game-engine lifecycle methods (Unity, Godot), generic entry points, and
/// framework-invoked hooks that are never explicitly called from user code.
///
/// **Godot C++ note**: `GDCLASS(ClassName, Parent)` registers lifecycle methods via
/// function pointers — `_bind_methods`, `_notification`, etc. are stored in a
/// `ClassInfo` struct and called indirectly. No string literal of the method name
/// is emitted in the macro expansion, so grep_shield cannot protect them. They must
/// be explicitly shielded here.
static GLOBAL_SHIELD_NAMES: &[&str] = &[
    // Universal entry points
    "main",
    "Main",
    "init",
    "update",
    "draw",
    "act",
    // Unity lifecycle
    "Start",
    "FixedUpdate",
    "Awake",
    "OnEnable",
    "OnTriggerEnter",
    // Godot C++ GDCLASS-registered methods (registered via function pointer, not string)
    "_bind_methods",
    "_notification",
    "_get_property_list",
    "_validate_property",
    "_property_can_revert",
    "_get_property_revert",
    "_get_configuration_warnings",
    // Godot reflection / scripting API virtual overrides (invoked via Object::get/set)
    "_get",
    "_set",
    "_property_get_revert",
];

// --- Byte pattern tables (compile-time constants) ---

/// FastAPI/Flask/Starlette route decorator patterns (without leading `@`).
static ROUTE_DEC: &[&[u8]] = &[
    b"app.get",
    b"app.post",
    b"app.put",
    b"app.delete",
    b"app.patch",
    b"app.websocket",
    b"app.options",
    b"app.head",
    b"router.get",
    b"router.post",
    b"router.put",
    b"router.delete",
    b"router.patch",
    b"router.websocket",
];

/// FastAPI dependency injection patterns (file-level scan).
static DI_PATTERNS: &[&[u8]] = &[b"Depends(", b"Security(", b"dependency_overrides"];

/// CLI entry-point decorator patterns.
static CLI_DEC: &[&[u8]] = &[
    b"app.command",
    b"app.callback",
    b"cli.command",
    b"click.command",
    b"typer.command",
];

/// ORM lifecycle method names that are called by the framework, not user code.
static ORM_LIFECYCLE_NAMES: &[&str] = &[
    "save",
    "delete",
    "update",
    "create",
    "get",
    "filter",
    "pre_save",
    "post_save",
    "pre_delete",
    "post_delete",
    "before_insert",
    "after_insert",
];

/// SQLAlchemy decorator patterns (entity-level scan).
static SQLALCHEMY_DEC: &[&[u8]] = &[b"declared_attr", b"hybrid_property", b"hybrid_method"];

/// SQLAlchemy special class attribute names.
static SQLALCHEMY_NAMES: &[&str] = &[
    "__tablename__",
    "__table_args__",
    "__abstract__",
    "__mapper_args__",
];

/// Pydantic validator decorator patterns.
static PYDANTIC_DEC: &[&[u8]] = &[
    b"validator",
    b"field_validator",
    b"model_validator",
    b"root_validator",
];

/// Metaprogramming danger patterns (entity-level scan).
static METAPROG: &[&[u8]] = &[
    b"getattr(",
    b"setattr(",
    b"hasattr(",
    b"delattr(",
    b"eval(",
    b"exec(",
    b"__import__(",
    b"importlib.",
    b".__dict__",
    b"type(",
];

// ---------------------------------------------------------------------------

/// Classifies entities in-place using Stages 2 and 4 of the pipeline.
///
/// Modifies `entity.protected_by` for each entity that matches a rule.
/// Entities already protected (e.g., `PytestFixture` from the parser pass) are skipped.
///
/// # Arguments
/// - `entities`: Mutable slice of entities belonging to a single file.
/// - `source`: Raw bytes of that file (used for byte-level pattern scanning).
/// - `file_path`: Normalized file path (UTF-8, forward slashes).
pub fn classify(entities: &mut [Entity], source: &[u8], file_path: &str) {
    // Pre-compute file-level flags — single combined Aho-Corasick pass over source.
    let flags = file_flags(source);
    let has_di = flags & FLAG_DI != 0;
    let has_orm = flags & FLAG_ORM != 0;
    let has_sqlalchemy = flags & FLAG_SQLA != 0;
    let has_qt = flags & FLAG_QT != 0;
    let has_metaprog = flags & FLAG_META != 0;
    let has_asyncctx = flags & FLAG_ACTX != 0;
    let has_pydantic_imports = flags & FLAG_PYDA != 0;
    let is_init = file_path.ends_with("__init__.py");

    // Plugin directory flag: file lives in a framework-managed directory.
    let is_plugin_dir = PLUGIN_DIRS
        .iter()
        .any(|d| file_path.split('/').any(|seg| seg == *d));

    // Stage 4: extract __all__ exports (single scan, result is &str slices into `source`).
    let all_exports = extract_all_exports(source);

    // Pre-compute lifespan teardown identifiers and Pydantic forward reference names.
    // Both require scanning the entity list before the mutable classification pass.
    let post_yield_names = if has_asyncctx {
        extract_post_yield_names(entities, source)
    } else {
        HashSet::new()
    };
    let forward_ref_names = if has_pydantic_imports {
        extract_pydantic_forward_refs(source)
    } else {
        HashSet::new()
    };

    for entity in entities.iter_mut() {
        // Already protected by a prior pass (e.g., PytestFixture from parser).
        if entity.protected_by.is_some() {
            continue;
        }

        // --- Stage 2: WisdomRegistry ---

        // 2a-pre. Plugin directory: public symbols are implicit framework entry points.
        // Spiders, task handlers, command modules, etc. are discovered dynamically —
        // they are never explicitly imported, so the reference graph has no edges to them.
        if is_plugin_dir && !entity.is_private() {
            entity.protected_by = Some(Protection::EntryPoint);
            continue;
        }

        // 2a. Dunder methods: always lifecycle-critical.
        if entity.is_dunder() {
            entity.protected_by = Some(Protection::LifecycleMethod);
            continue;
        }

        // 2b-global. Global shield: framework-agnostic lifecycle / entry-point names.
        // Protects game-engine callbacks (Unity, Godot) and universal entry points.
        if GLOBAL_SHIELD_NAMES.contains(&entity.name.as_str()) {
            entity.protected_by = Some(Protection::EntryPoint);
            continue;
        }

        // 2b. Entry points: CLI decorator (main already covered by GLOBAL_SHIELD_NAMES).
        if entity
            .decorators
            .iter()
            .any(|d| get_cli_dec_ac().is_some_and(|ac| ac.is_match(d.as_bytes())))
        {
            entity.protected_by = Some(Protection::EntryPoint);
            continue;
        }

        // 2c. FastAPI / Flask / Starlette route decorators.
        if entity
            .decorators
            .iter()
            .any(|d| get_route_dec_ac().is_some_and(|ac| ac.is_match(d.as_bytes())))
        {
            entity.protected_by = Some(Protection::MetaprogrammingDanger);
            continue;
        }

        // 2c-lifespan. FastAPI lifespan function: @asynccontextmanager + yield.
        // The function itself is an entry point; entities called in its post-yield
        // teardown block are also immortal (resolved in `post_yield_names`).
        if has_asyncctx {
            if entity
                .decorators
                .iter()
                .any(|d| bytes_contain(d.as_bytes(), b"asynccontextmanager"))
            {
                entity.protected_by = Some(Protection::FastApiOverride);
                continue;
            }
            if !post_yield_names.is_empty() && post_yield_names.contains(entity.name.as_str()) {
                entity.protected_by = Some(Protection::FastApiOverride);
                continue;
            }
        }

        // 2d. Pydantic validator decorators.
        if entity
            .decorators
            .iter()
            .any(|d| get_pydantic_dec_ac().is_some_and(|ac| ac.is_match(d.as_bytes())))
        {
            entity.protected_by = Some(Protection::PydanticAlias);
            continue;
        }

        // 2d-fwdref. Pydantic forward reference: class referenced as a string literal
        // in type annotations, e.g. `items: List['MyModel']`. Only applies when the
        // file imports pydantic / BaseModel, reducing noise.
        if has_pydantic_imports
            && !forward_ref_names.is_empty()
            && forward_ref_names.contains(entity.name.as_str())
        {
            entity.protected_by = Some(Protection::PydanticAlias);
            continue;
        }

        // 2e. SQLAlchemy special attribute names.
        if SQLALCHEMY_NAMES.contains(&entity.name.as_str()) {
            entity.protected_by = Some(Protection::SqlAlchemyMeta);
            continue;
        }

        // 2f. SQLAlchemy decorator on this entity.
        if has_sqlalchemy {
            let es = entity_src(source, entity);
            if get_sqlalchemy_dec_ac().is_some_and(|ac| ac.is_match(es)) {
                entity.protected_by = Some(Protection::SqlAlchemyMeta);
                continue;
            }
        }

        // 2g. ORM lifecycle method (method inside a class, file uses ORM bases).
        if has_orm
            && entity.parent_class.is_some()
            && ORM_LIFECYCLE_NAMES.contains(&entity.name.as_str())
        {
            entity.protected_by = Some(Protection::OrmLifecycle);
            continue;
        }

        // 2h. FastAPI dependency injection in entity body.
        if has_di {
            let es = entity_src(source, entity);
            if get_di_ac().is_some_and(|ac| ac.is_match(es)) {
                entity.protected_by = Some(Protection::FastApiOverride);
                continue;
            }
        }

        // 2i. Qt auto-connection slot: `on_<widget>_<signal>` in Qt-using file.
        if has_qt && is_qt_auto_slot(&entity.name) {
            entity.protected_by = Some(Protection::QtAutoSlot);
            continue;
        }

        // 2j. General metaprogramming in this entity's body.
        if has_metaprog {
            let es = entity_src(source, entity);
            if get_metaprog_ac().is_some_and(|ac| ac.is_match(es)) {
                entity.protected_by = Some(Protection::MetaprogrammingDanger);
                continue;
            }
        }

        // --- Stage 4: Package Export ---

        // 4a. Symbol name appears in `__all__`.
        if !all_exports.is_empty() && all_exports.contains(entity.name.as_str()) {
            entity.protected_by = Some(Protection::PackageExport);
            continue;
        }

        // 4b. `__init__.py`: every non-private, non-dunder top-level symbol is an export.
        if is_init && entity.parent_class.is_none() && !entity.is_private() {
            entity.protected_by = Some(Protection::PackageExport);
            continue;
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns true if `name` matches Qt's `on_<widget>_<signal>` auto-slot convention.
fn is_qt_auto_slot(name: &str) -> bool {
    name.starts_with("on_") && name.len() > 3 && name[3..].contains('_')
}

/// Returns the source bytes for an entity's byte range (clamped to file bounds).
fn entity_src<'a>(source: &'a [u8], entity: &Entity) -> &'a [u8] {
    let start = entity.start_byte as usize;
    let end = (entity.end_byte as usize).min(source.len());
    if start < end {
        &source[start..end]
    } else {
        b""
    }
}

/// Returns true if `needle` is a substring of `haystack`.
///
/// Used only for small haystacks (single decorator strings, ≤128 bytes) where
/// the AC startup cost exceeds the linear scan cost. All large file-level scans
/// use the combined [`file_flags`] AC automaton instead.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Extracts PascalCase string literals from `source` — Pydantic forward reference targets.
///
/// Scans for `'ClassName'` or `"ClassName"` where the content starts with an uppercase
/// letter and consists only of identifier characters. Matches forward references like
/// `items: List['MyModel']` without requiring a full CST pass.
///
/// Only called when the file is known to import pydantic / BaseModel, keeping false
/// positive noise low.
fn extract_pydantic_forward_refs(source: &[u8]) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut i = 0;
    while i < source.len() {
        let q = source[i];
        if q == b'\'' || q == b'"' {
            i += 1;
            let content_start = i;
            // Consume valid identifier characters.
            while i < source.len() && (source[i].is_ascii_alphanumeric() || source[i] == b'_') {
                i += 1;
            }
            let content_end = i;
            // Accept: non-empty, ends with matching quote, starts with uppercase.
            if content_end > content_start
                && i < source.len()
                && source[i] == q
                && source[content_start].is_ascii_uppercase()
            {
                if let Ok(name) = std::str::from_utf8(&source[content_start..content_end]) {
                    names.insert(name.to_string());
                }
                i += 1; // skip closing quote
            }
        } else {
            i += 1;
        }
    }
    names
}

/// Collects identifier names appearing after the first `yield` in each
/// `@asynccontextmanager`-decorated entity's source bytes.
///
/// FastAPI lifespan teardown code runs after `yield`. Any function called there
/// may appear dead to the reference graph if it has no other callers. This
/// pre-pass harvests those names so they can be shielded in the classify loop.
fn extract_post_yield_names(entities: &[Entity], source: &[u8]) -> HashSet<String> {
    let mut names = HashSet::new();
    for entity in entities {
        if !entity
            .decorators
            .iter()
            .any(|d| bytes_contain(d.as_bytes(), b"asynccontextmanager"))
        {
            continue;
        }
        let es = entity_src(source, entity);
        let yield_kw = b"yield";
        let Some(yield_pos) = es.windows(yield_kw.len()).position(|w| w == yield_kw) else {
            continue;
        };
        // Scan post-yield portion for identifier-like tokens.
        let post = &es[yield_pos + yield_kw.len()..];
        let mut i = 0;
        while i < post.len() {
            if post[i].is_ascii_alphabetic() || post[i] == b'_' {
                let start = i;
                while i < post.len() && (post[i].is_ascii_alphanumeric() || post[i] == b'_') {
                    i += 1;
                }
                if let Ok(name) = std::str::from_utf8(&post[start..i]) {
                    if name.len() > 2 && !is_python_keyword(name) {
                        names.insert(name.to_string());
                    }
                }
            } else {
                i += 1;
            }
        }
    }
    names
}

/// Returns true if `name` is a Python keyword or common builtin that should be
/// excluded from the post-yield identifier set.
fn is_python_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "else"
            | "elif"
            | "for"
            | "while"
            | "in"
            | "not"
            | "and"
            | "or"
            | "True"
            | "False"
            | "None"
            | "return"
            | "yield"
            | "async"
            | "await"
            | "def"
            | "class"
            | "import"
            | "from"
            | "as"
            | "with"
            | "pass"
            | "raise"
            | "try"
            | "except"
            | "finally"
            | "del"
            | "lambda"
            | "self"
            | "cls"
            | "super"
            | "print"
            | "len"
            | "range"
            | "type"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "set"
            | "tuple"
    )
}

/// Extracts names listed in `__all__ = [...]` or `__all__ = (...)`.
///
/// Single linear scan: finds the `__all__` marker, then collects quoted identifiers
/// until the closing `]` or `)`. Returns `&str` slices into `source`.
fn extract_all_exports(source: &[u8]) -> HashSet<&str> {
    let mut exports = HashSet::new();
    let marker = b"__all__";

    let Some(pos) = source.windows(marker.len()).position(|w| w == marker) else {
        return exports;
    };

    let rest = &source[pos + marker.len()..];
    let mut in_list = false;
    let mut i = 0;

    while i < rest.len() {
        match rest[i] {
            b'[' | b'(' => {
                in_list = true;
                i += 1;
            }
            b']' | b')' if in_list => break,
            b'"' | b'\'' if in_list => {
                let quote = rest[i];
                i += 1;
                let start = i;
                while i < rest.len() && rest[i] != quote {
                    i += 1;
                }
                if i < rest.len() {
                    if let Ok(name) = std::str::from_utf8(&rest[start..i]) {
                        let name = name.trim();
                        if !name.is_empty()
                            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                        {
                            exports.insert(name);
                        }
                    }
                }
                i += 1; // skip closing quote
            }
            _ => {
                i += 1;
            }
        }
    }

    exports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Entity, EntityType, Protection};

    fn make_entity(name: &str, decorators: Vec<String>, parent: Option<String>) -> Entity {
        Entity {
            name: name.into(),
            entity_type: EntityType::FunctionDefinition,
            start_byte: 0,
            end_byte: 0,
            start_line: 1,
            end_line: 1,
            file_path: "src/mod.py".into(),
            qualified_name: name.into(),
            parent_class: parent,
            base_classes: vec![],
            protected_by: None,
            decorators,
            structural_hash: None,
        }
    }

    #[test]
    fn test_dunder_protected() {
        let mut entities = vec![make_entity("__init__", vec![], None)];
        classify(&mut entities, b"", "src/mod.py");
        assert_eq!(entities[0].protected_by, Some(Protection::LifecycleMethod));
    }

    #[test]
    fn test_main_entry_point() {
        let mut entities = vec![make_entity("main", vec![], None)];
        classify(&mut entities, b"", "src/mod.py");
        assert_eq!(entities[0].protected_by, Some(Protection::EntryPoint));
    }

    #[test]
    fn test_fastapi_route_decorator() {
        let mut entities = vec![make_entity(
            "get_items",
            vec!["app.get(\"/items\")".into()],
            None,
        )];
        classify(&mut entities, b"", "src/routes.py");
        assert_eq!(
            entities[0].protected_by,
            Some(Protection::MetaprogrammingDanger)
        );
    }

    #[test]
    fn test_pydantic_validator() {
        let mut entities = vec![make_entity(
            "validate_name",
            vec!["field_validator(\"name\")".into()],
            None,
        )];
        classify(&mut entities, b"", "src/schemas.py");
        assert_eq!(entities[0].protected_by, Some(Protection::PydanticAlias));
    }

    #[test]
    fn test_all_exports() {
        let source =
            b"__all__ = [\"foo\", \"bar\"]\ndef foo(): pass\ndef bar(): pass\ndef _private(): pass";
        let mut entities = vec![
            make_entity("foo", vec![], None),
            make_entity("bar", vec![], None),
            make_entity("_private", vec![], None),
        ];
        classify(&mut entities, source, "src/mod.py");
        assert_eq!(entities[0].protected_by, Some(Protection::PackageExport));
        assert_eq!(entities[1].protected_by, Some(Protection::PackageExport));
        assert_eq!(entities[2].protected_by, None); // private, not in __all__
    }

    #[test]
    fn test_init_py_public_export() {
        let source = b"def public(): pass\ndef _private(): pass";
        let mut entities = vec![
            make_entity("public", vec![], None),
            make_entity("_private", vec![], None),
        ];
        classify(&mut entities, source, "pkg/__init__.py");
        assert_eq!(entities[0].protected_by, Some(Protection::PackageExport));
        assert_eq!(entities[1].protected_by, None);
    }

    #[test]
    fn test_already_protected_skipped() {
        let mut entity = make_entity("fixture_db", vec![], None);
        entity.protected_by = Some(Protection::PytestFixture);
        let mut entities = vec![entity];
        classify(&mut entities, b"", "tests/conftest.py");
        // Should remain PytestFixture, not overwritten
        assert_eq!(entities[0].protected_by, Some(Protection::PytestFixture));
    }

    #[test]
    fn test_qt_auto_slot() {
        let source = b"from PyQt5.QtWidgets import QWidget\nclass W(QWidget):\n    def on_button_clicked(self): pass";
        let mut entities = vec![make_entity("on_button_clicked", vec![], Some("W".into()))];
        classify(&mut entities, source, "src/ui.py");
        assert_eq!(entities[0].protected_by, Some(Protection::QtAutoSlot));
    }

    #[test]
    fn test_extract_all_single_quotes() {
        let source = b"__all__ = ('alpha', 'beta')";
        let exports = extract_all_exports(source);
        assert!(exports.contains("alpha"));
        assert!(exports.contains("beta"));
    }

    #[test]
    fn test_no_all_returns_empty() {
        let source = b"def foo(): pass";
        let exports = extract_all_exports(source);
        assert!(exports.is_empty());
    }

    #[test]
    fn test_plugin_dir_protects_public_symbols() {
        let mut entities = vec![
            make_entity("MySpider", vec![], None),
            make_entity("_helper", vec![], None),
        ];
        classify(&mut entities, b"", "myproject/spiders/my_spider.py");
        // Public class in spiders/ → EntryPoint
        assert_eq!(entities[0].protected_by, Some(Protection::EntryPoint));
        // Private helper in spiders/ → NOT protected by plugin rule
        assert_eq!(entities[1].protected_by, None);
    }

    #[test]
    fn test_handlers_dir_protects_public() {
        let mut entities = vec![make_entity("handle_event", vec![], None)];
        classify(&mut entities, b"", "app/handlers/webhook.py");
        assert_eq!(entities[0].protected_by, Some(Protection::EntryPoint));
    }

    #[test]
    fn test_non_plugin_dir_not_affected() {
        let mut entities = vec![make_entity("some_func", vec![], None)];
        classify(&mut entities, b"", "app/utils/helpers.py");
        // Regular file — no plugin protection
        assert_eq!(entities[1 - 1].protected_by, None);
    }

    #[test]
    fn test_asynccontextmanager_lifespan_protected() {
        let source = b"from contextlib import asynccontextmanager\n\
            @asynccontextmanager\n\
            async def lifespan(app):\n\
                db.connect()\n\
                yield\n\
                db.disconnect()\n";
        let mut entities = vec![make_entity(
            "lifespan",
            vec!["asynccontextmanager".into()],
            None,
        )];
        classify(&mut entities, source, "app/main.py");
        assert_eq!(entities[0].protected_by, Some(Protection::FastApiOverride));
    }

    #[test]
    fn test_post_yield_teardown_protected() {
        // `shutdown_worker` is only called after yield — it must be shielded.
        let source = b"from contextlib import asynccontextmanager\n\
            @asynccontextmanager\n\
            async def lifespan(app):\n\
                yield\n\
                shutdown_worker()\n";
        // Entity for the lifespan function (occupies whole source range so entity_src
        // returns the full source).
        let lifespan = Entity {
            name: "lifespan".into(),
            entity_type: EntityType::FunctionDefinition,
            start_byte: 0,
            end_byte: source.len() as u32,
            start_line: 1,
            end_line: 6,
            file_path: "app/main.py".into(),
            qualified_name: "lifespan".into(),
            parent_class: None,
            base_classes: vec![],
            protected_by: None,
            decorators: vec!["asynccontextmanager".into()],
            structural_hash: None,
        };
        let mut entities = vec![lifespan, make_entity("shutdown_worker", vec![], None)];
        classify(&mut entities, source, "app/main.py");
        assert_eq!(entities[1].protected_by, Some(Protection::FastApiOverride));
    }

    #[test]
    fn test_pydantic_forward_ref_protected() {
        // `UserModel` is only referenced as `'UserModel'` in a type annotation.
        let source = b"from pydantic import BaseModel\ndef get_users() -> List['UserModel']: ...\n";
        let mut entities = vec![make_entity("UserModel", vec![], None)];
        classify(&mut entities, source, "app/models.py");
        assert_eq!(entities[0].protected_by, Some(Protection::PydanticAlias));
    }

    #[test]
    fn test_pydantic_forward_ref_no_false_positive_without_pydantic() {
        // Same quoted name, but file has no pydantic import — should NOT be protected.
        let source = b"def get_users() -> List['UserModel']: ...\n";
        let mut entities = vec![make_entity("UserModel", vec![], None)];
        classify(&mut entities, source, "app/models.py");
        assert_eq!(entities[0].protected_by, None);
    }
}
