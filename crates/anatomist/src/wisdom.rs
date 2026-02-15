//! Stage 2 + Stage 4 classifier: per-file sequential heuristic pass.
//!
//! Processes one file's entities against its source bytes in a single linear scan,
//! assigning `protected_by` for entities that match a protection rule.
//!
//! **Stage 2**: WisdomRegistry heuristics — decorators, names, framework patterns.
//! **Stage 4**: Package export detection — `__all__` and `__init__.py` top-level symbols.
//!
//! Both stages share pre-computed file-level flags (one linear pass each),
//! then iterate entities once. Total cost: O(file_size + entity_count).

use crate::{Entity, Protection};
use std::collections::HashSet;

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

/// ORM base class patterns (file-level: indicates ORM usage).
static ORM_BASE: &[&[u8]] = &[b"(Model)", b"(Base)", b"(Document)", b"(db.Model)"];

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
    // Pre-compute file-level flags — one linear scan each, amortised over all entities.
    let has_di = any_in(source, DI_PATTERNS);
    let has_orm = any_in(source, ORM_BASE);
    let has_sqlalchemy =
        bytes_contain(source, b"sqlalchemy") || bytes_contain(source, b"SQLAlchemy");
    let has_qt = bytes_contain(source, b"QWidget")
        || bytes_contain(source, b"QMainWindow")
        || bytes_contain(source, b"QObject");
    let has_metaprog = any_in(source, METAPROG);
    let is_init = file_path.ends_with("__init__.py");

    // Plugin directory flag: file lives in a framework-managed directory.
    let is_plugin_dir = PLUGIN_DIRS
        .iter()
        .any(|d| file_path.split('/').any(|seg| seg == *d));

    // Stage 4: extract __all__ exports (single scan, result is &str slices into `source`).
    let all_exports = extract_all_exports(source);

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

        // 2b. Entry points: `main` function or CLI decorator.
        if entity.name == "main"
            || entity.decorators.iter().any(|d| {
                let b = d.as_bytes();
                CLI_DEC.iter().any(|p| bytes_contain(b, p))
            })
        {
            entity.protected_by = Some(Protection::EntryPoint);
            continue;
        }

        // 2c. FastAPI / Flask / Starlette route decorators.
        if entity.decorators.iter().any(|d| {
            let b = d.as_bytes();
            ROUTE_DEC.iter().any(|p| bytes_contain(b, p))
        }) {
            entity.protected_by = Some(Protection::MetaprogrammingDanger);
            continue;
        }

        // 2d. Pydantic validator decorators.
        if entity.decorators.iter().any(|d| {
            let b = d.as_bytes();
            PYDANTIC_DEC.iter().any(|p| bytes_contain(b, p))
        }) {
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
            if any_in(es, SQLALCHEMY_DEC) {
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
            if any_in(es, DI_PATTERNS) {
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
            if any_in(es, METAPROG) {
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

/// Returns true if any pattern in `patterns` is found in `haystack`.
fn any_in(haystack: &[u8], patterns: &[&[u8]]) -> bool {
    patterns.iter().any(|p| bytes_contain(haystack, p))
}

/// Returns true if `needle` is a substring of `haystack` (naive O(n·m) scan).
///
/// Fast enough for decorator regions (<512 bytes) and entity-body checks.
/// For large file-level scans, call once per flag and cache the result.
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
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
    use crate::{EntityType, Protection};

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
}
