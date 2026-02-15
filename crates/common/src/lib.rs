pub mod registry;
pub mod wisdom;

use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

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
}

// THE ATOM: CLR FACT
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, PartialEq)]
#[repr(u8)]
pub enum ClrFact {
    Definition { id: u64, file_id: u64 },
    Reference { caller: u64, callee: u64 },
    SlopMarker { id: u64, entropy: f32 },
}

// THE CONTAINER: CLR GRAPH
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, PartialEq)]
#[repr(C)]
pub struct ClrGraph {
    pub facts: Vec<ClrFact>,
    pub symbol_attestation_hash: [u8; 32],
}

impl ClrGraph {
    pub fn from_facts(facts: Vec<ClrFact>, symbol_attestation_hash: [u8; 32]) -> Self {
        Self {
            facts,
            symbol_attestation_hash,
        }
    }
}

// TEMPORAL DEBT BOND
// SSOT: Internal storage = rkyv. Serde is for dashboards only.
#[derive(Archive, Deserialize, Serialize, CheckBytes, Debug, Clone)]
#[repr(C)]
pub struct TemporalDebtBond {
    pub id: Uuid,
    pub original_checksum: [u8; 32],
    pub creation_timestamp: u64,
    pub entropy_score: f32,
}

// TRAITS

pub struct Candidate {
    pub id: u64,
    pub path: std::path::PathBuf,
}

pub trait Anatomist {
    fn dissect(&self, path: &Path) -> anyhow::Result<ClrGraph>;
}

pub trait Reaper {
    fn execute(&self, candidate: &Candidate) -> anyhow::Result<bool>;
}

pub trait Oracle {
    fn attest(&self, graph: &ClrGraph) -> bool;
}
