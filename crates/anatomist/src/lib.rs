//! # The Anatomist: CST Parsing & Entity Extraction
//!
//! **Role**: Converts Python source into zero-copy `Entity` facts for Datalog ingestion.
//!
//! **Core Types**:
//! - `Entity`: Zero-copy representation of Python symbols (functions, classes, methods).
//! - `EntityType`: 7 Python definition types (FunctionDefinition, ClassDefinition, etc.).
//! - `Protection`: Enumeration of 16 pipeline protection gates (e.g., PytestFixture, FastApiOverride).
//!
//! **Design**:
//! - Stores byte ranges (`start_byte..end_byte`) instead of full text for memory efficiency.
//! - Uses `rkyv` for zero-copy serialization to Oracle's Datalog engine.
//! - All public types derive `Archive, Deserialize, Serialize, CheckBytes` for cross-process IPC.

pub mod graph;
pub mod heuristics;
pub mod imports;
pub mod parser;
pub mod path_util;
pub mod pipeline;
pub mod scan;
pub mod wisdom;

pub use pipeline::ScanResult;

pub use heuristics::Heuristic;
pub use parser::ParserHost;

// Protection is defined in `common` and re-exported here so that all
// intra-crate modules that write `use crate::Protection` continue to
// compile without modification.
pub use common::Protection;

use rkyv::{Archive, Deserialize, Serialize};

/// Python definition types recognized by the Anatomist.
///
/// Maps to Tree-sitter node types: `function_definition`, `async_function_definition`,
/// `class_definition`, `decorated_definition`, `assignment`, `type_alias`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[repr(u8)]
pub enum EntityType {
    /// `def foo(): ...`
    FunctionDefinition = 0,
    /// `async def foo(): ...`
    AsyncFunctionDefinition = 1,
    /// `class Foo: ...`
    ClassDefinition = 2,
    /// `def method(self): ...` (inside a class)
    MethodDefinition = 3,
    /// `@decorator\ndef foo(): ...` or `@decorator\nclass Foo: ...`
    DecoratedDefinition = 4,
    /// `x = 42` (module or class-level)
    Assignment = 5,
    /// `type Alias = int` (PEP 613)
    TypeAlias = 6,
}

/// Core Entity representing a Python symbol (function, class, method, etc.).
///
/// **Zero-Copy Design**:
/// - `start_byte`/`end_byte`: Index into source buffer (`&source[start_byte..end_byte]`).
/// - Avoids storing full text (`full_text: String`) to reduce memory overhead.
/// - All strings are UTF-8 normalized with forward slashes (Windows `\` -> `/`).
///
/// **Serialization**:
/// - Derives `Archive, Deserialize, Serialize` for `rkyv` zero-copy IPC to Oracle.
/// - Derives `CheckBytes` for safe deserialization (validates pointers/lengths).
#[derive(Debug, Clone, PartialEq, Eq, Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct Entity {
    /// Symbol name (e.g., `"foo"`, `"MyClass"`, `"method_name"`).
    pub name: String,

    /// Entity type (function, class, method, etc.).
    pub entity_type: EntityType,

    /// Byte offset of the first character of the definition in the source file.
    pub start_byte: u32,

    /// Byte offset of the last character of the definition in the source file (exclusive).
    pub end_byte: u32,

    /// Line number of the first line of the definition (1-indexed).
    pub start_line: u32,

    /// Line number of the last line of the definition (1-indexed).
    pub end_line: u32,

    /// Normalized file path (UTF-8, forward slashes). Example: `"src/api/handlers.py"`.
    pub file_path: String,

    /// Fully qualified name (e.g., `"ClassName.method_name"`, `"module.function"`).
    pub qualified_name: String,

    /// Parent class name for methods (e.g., `"MyClass"` for `def MyClass.foo(self)`).
    pub parent_class: Option<String>,

    /// Base class names for class definitions (e.g., `["BaseClass", "Mixin"]`).
    pub base_classes: Vec<String>,

    /// Protection reason (if entity survived the pipeline). `None` = candidate for deletion.
    pub protected_by: Option<Protection>,

    /// Decorator names (e.g., `["staticmethod", "pytest.fixture"]`).
    pub decorators: Vec<String>,

    /// Deterministic structural fingerprint (alpha-normalized BLAKE3 over the function body).
    ///
    /// `Some(hash)` for functions and methods; `None` for classes and assignments.
    /// Two functions with identical control-flow but different variable names produce the same hash.
    pub structural_hash: Option<u64>,
}

impl Entity {
    /// Generates a unique symbol identifier: `"{file_path}::{qualified_name}"`.
    ///
    /// # Example
    /// ```
    /// # use anatomist::{Entity, EntityType};
    /// let entity = Entity {
    ///     name: "foo".into(),
    ///     entity_type: EntityType::FunctionDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "src/api.py".into(),
    ///     qualified_name: "api.foo".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert_eq!(entity.symbol_id(), "src/api.py::api.foo");
    /// ```
    pub fn symbol_id(&self) -> String {
        format!("{}::{}", self.file_path, self.qualified_name)
    }

    /// Returns the byte length of the entity's source code.
    ///
    /// # Example
    /// ```
    /// # use anatomist::{Entity, EntityType};
    /// let entity = Entity {
    ///     name: "foo".into(),
    ///     entity_type: EntityType::FunctionDefinition,
    ///     start_byte: 100,
    ///     end_byte: 250,
    ///     start_line: 1,
    ///     end_line: 5,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "foo".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert_eq!(entity.byte_len(), 150);
    /// ```
    pub fn byte_len(&self) -> u32 {
        self.end_byte.saturating_sub(self.start_byte)
    }

    /// Returns `true` if the entity name is a dunder (e.g., `__init__`, `__str__`).
    ///
    /// # Example
    /// ```
    /// # use anatomist::{Entity, EntityType};
    /// let dunder = Entity {
    ///     name: "__init__".into(),
    ///     entity_type: EntityType::MethodDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "__init__".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert!(dunder.is_dunder());
    ///
    /// let normal = Entity {
    ///     name: "foo".into(),
    ///     entity_type: EntityType::FunctionDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "foo".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert!(!normal.is_dunder());
    /// ```
    pub fn is_dunder(&self) -> bool {
        self.name.starts_with("__") && self.name.ends_with("__") && self.name.len() > 4
    }

    /// Returns `true` if the entity name is private (single leading underscore, not dunder).
    ///
    /// # Example
    /// ```
    /// # use anatomist::{Entity, EntityType};
    /// let private = Entity {
    ///     name: "_helper".into(),
    ///     entity_type: EntityType::FunctionDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "_helper".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert!(private.is_private());
    ///
    /// let public = Entity {
    ///     name: "helper".into(),
    ///     entity_type: EntityType::FunctionDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "helper".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert!(!public.is_private());
    ///
    /// let dunder = Entity {
    ///     name: "__init__".into(),
    ///     entity_type: EntityType::MethodDefinition,
    ///     start_byte: 0,
    ///     end_byte: 10,
    ///     start_line: 1,
    ///     end_line: 3,
    ///     file_path: "test.py".into(),
    ///     qualified_name: "__init__".into(),
    ///     parent_class: None,
    ///     base_classes: vec![],
    ///     protected_by: None,
    ///     decorators: vec![],
    ///     structural_hash: None,
    /// };
    /// assert!(!dunder.is_private()); // Dunders are NOT considered private
    /// ```
    pub fn is_private(&self) -> bool {
        self.name.starts_with('_') && !self.name.starts_with("__")
    }
}

/// Errors produced by the Anatomist crate.
#[derive(Debug, thiserror::Error)]
pub enum AnatomistError {
    /// Tree-sitter parsing failed.
    #[error("Parse failure: {0}")]
    ParseFailure(String),

    /// I/O error (file read/write).
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Byte range exceeds u32::MAX (file too large).
    #[error("Byte range overflow: file size exceeds 4GB limit")]
    ByteRangeOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_entity(name: &str, qname: Option<&str>) -> Entity {
        Entity {
            name: name.into(),
            entity_type: EntityType::FunctionDefinition,
            start_byte: 100,
            end_byte: 250,
            start_line: 10,
            end_line: 20,
            file_path: "src/test.py".into(),
            qualified_name: qname.unwrap_or(name).into(),
            parent_class: None,
            base_classes: vec![],
            protected_by: None,
            decorators: vec![],
            structural_hash: None,
        }
    }

    #[test]
    fn test_symbol_id_with_qualified_name() {
        let entity = make_test_entity("foo", Some("module.foo"));
        assert_eq!(entity.symbol_id(), "src/test.py::module.foo");
    }

    #[test]
    fn test_symbol_id_without_qualified_name() {
        let entity = make_test_entity("foo", None);
        assert_eq!(entity.symbol_id(), "src/test.py::foo");
    }

    #[test]
    fn test_byte_len() {
        let entity = make_test_entity("foo", None);
        assert_eq!(entity.byte_len(), 150);
    }

    #[test]
    fn test_byte_len_zero() {
        let mut entity = make_test_entity("foo", None);
        entity.start_byte = 100;
        entity.end_byte = 100;
        assert_eq!(entity.byte_len(), 0);
    }

    #[test]
    fn test_byte_len_overflow_protection() {
        let mut entity = make_test_entity("foo", None);
        entity.start_byte = 200;
        entity.end_byte = 100;
        assert_eq!(entity.byte_len(), 0); // saturating_sub prevents underflow
    }

    #[test]
    fn test_is_dunder() {
        assert!(make_test_entity("__init__", None).is_dunder());
        assert!(make_test_entity("__str__", None).is_dunder());
        assert!(make_test_entity("__tablename__", None).is_dunder());
        assert!(!make_test_entity("__", None).is_dunder()); // Too short
        assert!(!make_test_entity("___", None).is_dunder()); // Too short
        assert!(!make_test_entity("_private", None).is_dunder());
        assert!(!make_test_entity("foo", None).is_dunder());
    }

    #[test]
    fn test_is_private() {
        assert!(make_test_entity("_helper", None).is_private());
        assert!(make_test_entity("_internal", None).is_private());
        assert!(!make_test_entity("__init__", None).is_private()); // Dunder, not private
        assert!(!make_test_entity("foo", None).is_private());
        assert!(!make_test_entity("__", None).is_private()); // Dunder (even if short)
    }

    #[test]
    fn test_protection_enum_size() {
        // Ensure Protection serializes as 1 byte
        assert_eq!(std::mem::size_of::<Protection>(), 1);
    }

    #[test]
    fn test_entity_type_enum_size() {
        // Ensure EntityType serializes as 1 byte
        assert_eq!(std::mem::size_of::<EntityType>(), 1);
    }

    #[test]
    fn test_rkyv_roundtrip() {
        let entity = Entity {
            name: "test_func".into(),
            entity_type: EntityType::FunctionDefinition,
            start_byte: 0,
            end_byte: 42,
            start_line: 1,
            end_line: 5,
            file_path: "src/lib.py".into(),
            qualified_name: "lib.test_func".into(),
            parent_class: None,
            base_classes: vec![],
            protected_by: Some(Protection::PytestFixture),
            decorators: vec!["pytest.fixture".into()],
            structural_hash: None,
        };

        // Serialize with rkyv
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&entity).unwrap();

        // Deserialize
        let archived = rkyv::access::<ArchivedEntity, rkyv::rancor::Error>(&bytes).unwrap();
        assert_eq!(archived.name.as_str(), "test_func");
        assert_eq!(archived.start_byte, 0);
        assert_eq!(archived.end_byte, 42);
        assert_eq!(archived.file_path.as_str(), "src/lib.py");
    }
}
