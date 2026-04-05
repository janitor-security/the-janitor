pub mod deps;
pub mod physarum;
pub mod policy;
pub mod pqc;
pub mod registry;
pub mod scm;
pub mod slop;
pub mod taint;
pub mod wisdom;

use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use std::fmt;

/// Reason why a symbol was protected from deletion by the 6-stage pipeline.
///
/// Stored in `SymbolEntry::protected_by` in the disk-backed registry so that
/// downstream tools (dashboard, oracle) can reason about protection rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(u8)]
pub enum Protection {
    /// Stage 0: symbol lives inside a protected directory (tests/, migrations/, etc.).
    Directory = 0,
    /// Stage 1: symbol has at least one incoming reference edge in the call graph.
    Referenced = 1,
    /// Stage 2: generic wisdom-rule match (fallback bucket).
    WisdomRule = 2,
    /// Stage 3: library mode — all public symbols are protected.
    LibraryMode = 3,
    /// Stage 4: symbol is exported via `__all__` or lives in `__init__.py`.
    PackageExport = 4,
    /// Stage 2: referenced from a config file (e.g., `settings.py`, `celery.py`).
    ConfigReference = 5,
    /// Stage 2: metaprogramming danger (`__init_subclass__`, `__class_getitem__`, etc.).
    MetaprogrammingDanger = 6,
    /// Stage 2: lifecycle dunder method (`__enter__`, `__exit__`, `__repr__`, etc.).
    LifecycleMethod = 7,
    /// Stage 2: CLI / application entry-point (`main`, `run`, `cli`, etc.).
    EntryPoint = 8,
    /// Stage 2: Qt auto-slot (`on_<widget>_<signal>` convention).
    QtAutoSlot = 9,
    /// Stage 2: SQLAlchemy model/table metadata method.
    SqlAlchemyMeta = 10,
    /// Stage 2: ORM lifecycle hook (`save`, `delete`, `pre_save`, `post_save`, etc.).
    OrmLifecycle = 11,
    /// Stage 2: Pydantic validator or field alias.
    PydanticAlias = 12,
    /// Stage 2: FastAPI dependency injection override.
    FastApiOverride = 13,
    /// Heuristic: pytest fixture or conftest symbol.
    PytestFixture = 14,
    /// Stage 5: symbol name found in non-Python files (templates, configs, etc.).
    GrepShield = 15,
    /// Post-pipeline: symbol is directly referenced by a test node ID.
    TestReference = 16,
    /// Stage 2: single-underscore lifecycle hook in a dynamic language (Python, JS, TS).
    ///
    /// Methods named `_foo` (single leading underscore, not dunder) in Python/JS/TS
    /// files are frequently invoked by frameworks without any static import chain.
    LifecycleHook = 17,
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Protection::Directory => "protected-dir",
            Protection::Referenced => "referenced",
            Protection::WisdomRule => "wisdom-rule",
            Protection::LibraryMode => "library-mode",
            Protection::PackageExport => "package-export",
            Protection::ConfigReference => "config-reference",
            Protection::MetaprogrammingDanger => "metaprogramming",
            Protection::LifecycleMethod => "lifecycle-method",
            Protection::EntryPoint => "entry-point",
            Protection::QtAutoSlot => "qt-auto-slot",
            Protection::SqlAlchemyMeta => "sqlalchemy-meta",
            Protection::OrmLifecycle => "orm-lifecycle",
            Protection::PydanticAlias => "pydantic-alias",
            Protection::FastApiOverride => "fastapi-override",
            Protection::PytestFixture => "pytest-fixture",
            Protection::GrepShield => "grep-shield",
            Protection::TestReference => "test-reference",
            Protection::LifecycleHook => "lifecycle-hook-dynamic",
        };
        f.write_str(label)
    }
}
