//! Tree-sitter based Python parser with entity extraction and heuristic protection detection.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::OnceLock;

use memmap2::MmapOptions;
use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

use crate::path_util::normalize_path;
use crate::{AnatomistError, Entity, EntityType, Heuristic};
use forge::compute_structural_hash;

/// Pattern indices for the entity query.
const PATTERN_FN: usize = 0; // Standalone function_definition
const PATTERN_CLASS: usize = 1; // Standalone class_definition
const PATTERN_DECORATED: usize = 2; // decorated_definition wrapping function or class
const PATTERN_ASSIGNMENT: usize = 3; // Module-level assignments

/// Static cache for the tree-sitter query.
///
/// The query is compiled once on first use and reused for all subsequent parses.
/// This is safe because tree-sitter queries are immutable once compiled.
static ENTITY_QUERY: OnceLock<Query> = OnceLock::new();

/// Returns the compiled entity extraction query, initializing it on first call.
///
/// # Query Patterns
/// - Pattern 0: Standalone `function_definition`
/// - Pattern 1: Standalone `class_definition` (with optional superclasses)
/// - Pattern 2: `decorated_definition` wrapping function or class
/// - Pattern 3: Module-level assignments (e.g., `__all__ = [...]`)
///
/// # Panic
/// Panics if the query S-expression is malformed. This is a compile-time bug,
/// not a runtime condition — the query is a hardcoded string literal.
fn get_entity_query() -> &'static Query {
    ENTITY_QUERY.get_or_init(|| {
        Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            r#"
            ; Pattern 0: Standalone function definitions
            (function_definition
              name: (identifier) @fn.name) @fn.def

            ; Pattern 1: Standalone class definitions
            (class_definition
              name: (identifier) @class.name
              superclasses: (argument_list)? @class.bases) @class.def

            ; Pattern 2: Decorated definitions (functions or classes)
            (decorated_definition
              (decorator)+ @dec_expr
              definition: [
                (function_definition
                  name: (identifier) @decorated.name)
                (class_definition
                  name: (identifier) @decorated.name)
              ] @decorated.inner) @decorated.def

            ; Pattern 3: Module-level assignments
            (assignment
              left: (identifier) @assign.name
              right: (_) @assign.value) @assign.stmt
            "#,
        )
        .expect("Entity query compilation failed — this is a bug in the hardcoded S-expression")
    })
}

/// The main parser host for extracting entities from Python source files.
///
/// # Architecture
/// - Uses memory-mapped file I/O for zero-copy parsing of large files
/// - Applies registered heuristics during entity extraction (single-pass)
/// - Performs two-pass deduplication to handle decorated entities correctly
///
/// # Example
/// ```no_run
/// use anatomist::{ParserHost, heuristics::pytest::PytestFixtureHeuristic};
/// use std::path::Path;
///
/// let mut host = ParserHost::new().unwrap();
/// host.register_heuristic(Box::new(PytestFixtureHeuristic));
///
/// let entities = host.dissect(Path::new("test_example.py")).unwrap();
/// for entity in entities {
///     println!("{}: {:?}", entity.name, entity.entity_type);
/// }
/// ```
pub struct ParserHost {
    parser: Parser,
    heuristics: Vec<Box<dyn Heuristic>>,
}

impl ParserHost {
    /// Creates a new parser host with the Python grammar loaded.
    ///
    /// # Errors
    /// Returns `AnatomistError::ParseFailure` if the tree-sitter parser
    /// fails to initialize with the Python language.
    pub fn new() -> Result<Self, AnatomistError> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .map_err(|e| {
                AnatomistError::ParseFailure(format!("Failed to load Python grammar: {}", e))
            })?;

        Ok(Self {
            parser,
            heuristics: Vec::new(),
        })
    }

    /// Registers a heuristic for entity protection detection.
    ///
    /// Heuristics are applied in registration order. The first heuristic
    /// to return `Some(Protection)` wins for each entity.
    ///
    /// # Example
    /// ```no_run
    /// use anatomist::{ParserHost, heuristics::pytest::PytestFixtureHeuristic};
    ///
    /// let mut host = ParserHost::new().unwrap();
    /// host.register_heuristic(Box::new(PytestFixtureHeuristic));
    /// ```
    pub fn register_heuristic(&mut self, heuristic: Box<dyn Heuristic>) {
        self.heuristics.push(heuristic);
    }

    /// Extracts entities from a Python source file using memory-mapped I/O.
    ///
    /// # Process
    /// 1. Opens file and validates size (must fit in u32 for tree-sitter byte ranges)
    /// 2. Memory-maps file for zero-copy parsing
    /// 3. Parses source into CST (Concrete Syntax Tree)
    /// 4. Executes entity extraction query
    /// 5. Performs two-pass deduplication for decorated entities
    /// 6. Applies registered heuristics for protection classification
    ///
    /// # Errors
    /// - `IoError`: File not found, permission denied, mmap failure
    /// - `ByteRangeOverflow`: File larger than 4GB (tree-sitter u32 limit)
    /// - `ParseFailure`: Tree-sitter parse returned `None` (severe syntax errors)
    ///
    /// # Example
    /// ```no_run
    /// use anatomist::ParserHost;
    /// use std::path::Path;
    ///
    /// let mut host = ParserHost::new().unwrap();
    /// let entities = host.dissect(Path::new("main.py")).unwrap();
    /// ```
    pub fn dissect(&mut self, path: &Path) -> Result<Vec<Entity>, AnatomistError> {
        // Open and validate file size
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_len = metadata.len();

        if file_len > u32::MAX as u64 {
            return Err(AnatomistError::ByteRangeOverflow);
        }

        // Handle empty files
        if file_len == 0 {
            return Ok(Vec::new());
        }

        // Memory-map the file for zero-copy parsing
        // SAFETY: The file handle is held for the duration of the mmap lifetime.
        // We validate the file length above to ensure it fits in addressable memory.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let source = &mmap[..];

        // Normalize path once for all entities
        let normalized_path = normalize_path(path)?;

        self.dissect_impl(source, &normalized_path)
    }

    /// Internal implementation shared by `dissect()` and `dissect_bytes()`.
    fn dissect_impl(
        &mut self,
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        // Parse source into CST
        let tree = self.parser.parse(source, None).ok_or_else(|| {
            AnatomistError::ParseFailure("Tree-sitter parse returned None".to_string())
        })?;

        let root = tree.root_node();
        let query = get_entity_query();

        // Two-pass deduplication: Track inner node IDs from decorated_definition
        let mut inner_node_ids = HashSet::new();

        // Pass 1: Collect inner node IDs from decorated definitions
        // Note: QueryMatches uses StreamingIterator, not standard Iterator
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, root, source);
        while let Some(m) = matches.next() {
            if m.pattern_index == PATTERN_DECORATED {
                if let Some(inner_capture) = m
                    .captures
                    .iter()
                    .find(|c| query.capture_names()[c.index as usize] == "decorated.inner")
                {
                    inner_node_ids.insert(inner_capture.node.id());
                }
            }
        }

        // Pass 2: Extract entities, skipping duplicates
        let mut entities = Vec::new();
        cursor = QueryCursor::new(); // Reset cursor
        let mut matches = cursor.matches(query, root, source);
        while let Some(m) = matches.next() {
            let pattern_idx = m.pattern_index;

            // Skip Pattern 0/1 if this node is the inner part of a decorated definition
            if pattern_idx == PATTERN_FN || pattern_idx == PATTERN_CLASS {
                if let Some(def_capture) = m.captures.first() {
                    if inner_node_ids.contains(&def_capture.node.id()) {
                        continue; // Skip — will be processed via PATTERN_DECORATED
                    }
                }
            }

            match pattern_idx {
                PATTERN_FN | PATTERN_CLASS | PATTERN_DECORATED => {
                    if let Some(entity) =
                        self.extract_function_or_class(source, m, query, file_path, pattern_idx)?
                    {
                        entities.push(entity);
                    }
                }
                PATTERN_ASSIGNMENT => {
                    // Module-level assignments (future work: extract __all__, etc.)
                }
                _ => {}
            }
        }

        Ok(entities)
    }

    /// Extracts a function or class entity from a query match.
    ///
    /// # Returns
    /// `Some(Entity)` if extraction succeeds, `None` if required captures are missing.
    fn extract_function_or_class(
        &self,
        source: &[u8],
        m: &tree_sitter::QueryMatch<'_, '_>,
        query: &Query,
        file_path: &str,
        pattern_idx: usize,
    ) -> Result<Option<Entity>, AnatomistError> {
        let capture_names = query.capture_names();

        // Determine the primary node and name capture based on pattern
        let (primary_node, name_suffix) = match pattern_idx {
            PATTERN_FN => {
                let def_node = m
                    .captures
                    .iter()
                    .find(|c| capture_names[c.index as usize] == "fn.def");
                (def_node.map(|c| c.node), "fn.name")
            }
            PATTERN_CLASS => {
                let def_node = m
                    .captures
                    .iter()
                    .find(|c| capture_names[c.index as usize] == "class.def");
                (def_node.map(|c| c.node), "class.name")
            }
            PATTERN_DECORATED => {
                let def_node = m
                    .captures
                    .iter()
                    .find(|c| capture_names[c.index as usize] == "decorated.def");
                (def_node.map(|c| c.node), "decorated.name")
            }
            _ => return Ok(None),
        };

        let primary_node = match primary_node {
            Some(node) => node,
            None => return Ok(None),
        };

        // Extract entity name
        let name_capture = m
            .captures
            .iter()
            .find(|c| capture_names[c.index as usize] == name_suffix);
        let name = match name_capture {
            Some(c) => {
                let start = c.node.start_byte();
                let end = c.node.end_byte();
                std::str::from_utf8(&source[start..end])
                    .map_err(|_| AnatomistError::ParseFailure("Non-UTF-8 identifier".to_string()))?
                    .to_string()
            }
            None => return Ok(None),
        };

        // Determine entity type
        let entity_type = self.determine_entity_type(source, &primary_node, pattern_idx);

        // Extract decorators
        let decorators = if pattern_idx == PATTERN_DECORATED {
            m.captures
                .iter()
                .filter(|c| capture_names[c.index as usize] == "dec_expr")
                .map(|c| {
                    let start = c.node.start_byte();
                    let end = c.node.end_byte();
                    let text = std::str::from_utf8(&source[start..end]).unwrap_or("");
                    // Strip leading '@' if present
                    text.strip_prefix('@').unwrap_or(text).to_string()
                })
                .collect()
        } else {
            Vec::new()
        };

        // Extract base classes (for classes only)
        let base_classes = if pattern_idx == PATTERN_CLASS || pattern_idx == PATTERN_DECORATED {
            m.captures
                .iter()
                .find(|c| capture_names[c.index as usize] == "class.bases")
                .map(|bases_capture| {
                    let mut base_names = Vec::new();
                    let mut cursor = bases_capture.node.walk();
                    for child in bases_capture.node.children(&mut cursor) {
                        if child.kind() == "identifier" || child.kind() == "attribute" {
                            let start = child.start_byte();
                            let end = child.end_byte();
                            if let Ok(text) = std::str::from_utf8(&source[start..end]) {
                                base_names.push(text.to_string());
                            }
                        }
                    }
                    base_names
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        // Determine parent class (for methods)
        let (parent_class, qualified_name) =
            if let Some(class_name) = find_enclosing_class(&primary_node, source) {
                let qualified = format!("{}.{}", class_name, name);
                (Some(class_name), qualified)
            } else {
                (None, name.clone())
            };

        // Byte range and line numbers
        let start_byte = primary_node.start_byte() as u32;
        let end_byte = primary_node.end_byte() as u32;
        let start_line = (primary_node.start_position().row + 1) as u32; // tree-sitter uses 0-based rows
        let end_line = (primary_node.end_position().row + 1) as u32;

        // Apply heuristics
        let protected_by = self
            .heuristics
            .iter()
            .find_map(|h| h.apply(source, &primary_node, file_path));

        // Compute structural hash for functions/methods (alpha-normalized BLAKE3 over body block).
        let structural_hash = match entity_type {
            EntityType::FunctionDefinition
            | EntityType::AsyncFunctionDefinition
            | EntityType::MethodDefinition => {
                // For decorated definitions the logic node is the inner definition.
                let func_node = if pattern_idx == PATTERN_DECORATED {
                    primary_node
                        .child_by_field_name("definition")
                        .unwrap_or(primary_node)
                } else {
                    primary_node
                };
                func_node
                    .child_by_field_name("body")
                    .map(|body| compute_structural_hash(body, source))
            }
            _ => None,
        };

        Ok(Some(Entity {
            name,
            qualified_name,
            entity_type,
            file_path: file_path.to_string(),
            start_byte,
            end_byte,
            start_line,
            end_line,
            parent_class,
            decorators,
            base_classes,
            protected_by,
            structural_hash,
        }))
    }

    /// Determines the specific entity type based on node kind and context.
    fn determine_entity_type(
        &self,
        source: &[u8],
        node: &tree_sitter::Node,
        pattern_idx: usize,
    ) -> EntityType {
        // For decorated definitions, inspect the inner definition
        let target_node = if pattern_idx == PATTERN_DECORATED {
            node.child_by_field_name("definition").unwrap_or(*node)
        } else {
            *node
        };

        match target_node.kind() {
            "function_definition" => {
                // Check for async keyword
                let is_async = target_node
                    .children(&mut target_node.walk())
                    .any(|c| c.kind() == "async");

                if is_async {
                    EntityType::AsyncFunctionDefinition
                } else {
                    // Check if inside a class (method vs function)
                    if find_enclosing_class(&target_node, source).is_some() {
                        EntityType::MethodDefinition
                    } else {
                        EntityType::FunctionDefinition
                    }
                }
            }
            "class_definition" => EntityType::ClassDefinition,
            // Fallback for unexpected node kinds (should not happen with correct query)
            _ => EntityType::FunctionDefinition,
        }
    }

    /// Test helper: parses bytes directly without file I/O.
    #[cfg(test)]
    pub(crate) fn dissect_bytes(
        &mut self,
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        self.dissect_impl(source, file_path)
    }
}

/// Finds the enclosing class name for a given node by walking up the tree.
///
/// # Returns
/// `Some(class_name)` if the node is inside a class definition, `None` otherwise.
fn find_enclosing_class(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            // Extract class name from the 'name' field
            if let Some(name_node) = parent.child_by_field_name("name") {
                let start = name_node.start_byte();
                let end = name_node.end_byte();
                if let Ok(class_name) = std::str::from_utf8(&source[start..end]) {
                    return Some(class_name.to_string());
                }
            }
        }
        current = parent.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heuristics::pytest::PytestFixtureHeuristic;
    use crate::Protection;

    #[test]
    fn test_simple_function() {
        let mut host = ParserHost::new().unwrap();
        let source = b"def hello():\n    pass";
        let entities = host.dissect_bytes(source, "test.py").unwrap();

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "hello");
        assert_eq!(entities[0].entity_type, EntityType::FunctionDefinition);
        assert_eq!(entities[0].qualified_name, "hello");
        assert!(entities[0].parent_class.is_none());
    }

    #[test]
    fn test_async_function() {
        let mut host = ParserHost::new().unwrap();
        let source = b"async def fetch():\n    pass";
        let entities = host.dissect_bytes(source, "test.py").unwrap();

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "fetch");
        assert_eq!(entities[0].entity_type, EntityType::AsyncFunctionDefinition);
    }

    #[test]
    fn test_class_with_bases() {
        let mut host = ParserHost::new().unwrap();
        let source = b"class Derived(Base, Mixin):\n    pass";
        let entities = host.dissect_bytes(source, "test.py").unwrap();

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "Derived");
        assert_eq!(entities[0].entity_type, EntityType::ClassDefinition);
        assert_eq!(entities[0].base_classes.len(), 2);
        assert!(entities[0].base_classes.contains(&"Base".to_string()));
        assert!(entities[0].base_classes.contains(&"Mixin".to_string()));
    }

    #[test]
    fn test_method_inside_class() {
        let mut host = ParserHost::new().unwrap();
        let source = b"class MyClass:\n    def my_method(self):\n        pass";
        let entities = host.dissect_bytes(source, "test.py").unwrap();

        assert_eq!(entities.len(), 2); // Class + Method
        let method = entities.iter().find(|e| e.name == "my_method").unwrap();
        assert_eq!(method.entity_type, EntityType::MethodDefinition);
        assert_eq!(method.parent_class, Some("MyClass".to_string()));
        assert_eq!(method.qualified_name, "MyClass.my_method");
    }

    #[test]
    fn test_decorated_function() {
        let mut host = ParserHost::new().unwrap();
        let source = b"@decorator\ndef decorated():\n    pass";
        let entities = host.dissect_bytes(source, "test.py").unwrap();

        assert_eq!(entities.len(), 1); // Should NOT be 2 (no duplicate)
        assert_eq!(entities[0].name, "decorated");
        assert_eq!(entities[0].decorators.len(), 1);
        assert_eq!(entities[0].decorators[0], "decorator");
        // Byte range should span from @ to end of function
        assert_eq!(entities[0].start_byte, 0);
    }

    #[test]
    fn test_empty_file() {
        let mut host = ParserHost::new().unwrap();
        let source = b"";
        let entities = host.dissect_bytes(source, "empty.py").unwrap();

        assert_eq!(entities.len(), 0);
    }

    #[test]
    fn test_syntax_error_recovery() {
        let mut host = ParserHost::new().unwrap();
        // Missing colon - syntax error, but tree-sitter recovers
        let source = b"def broken()\n    pass\ndef valid():\n    pass";
        let entities = host.dissect_bytes(source, "broken.py").unwrap();

        // Should still extract the valid function (tree-sitter error recovery)
        assert!(!entities.is_empty());
    }

    #[test]
    fn test_pytest_fixture_decorator() {
        let mut host = ParserHost::new().unwrap();
        host.register_heuristic(Box::new(PytestFixtureHeuristic));

        let source = b"@pytest.fixture\ndef my_fixture():\n    pass";
        let entities = host.dissect_bytes(source, "test_example.py").unwrap();

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].protected_by, Some(Protection::PytestFixture));
    }

    #[test]
    fn test_conftest_auto_protection() {
        let mut host = ParserHost::new().unwrap();
        host.register_heuristic(Box::new(PytestFixtureHeuristic));

        let source = b"import pytest\ndef any_function():\n    pass";
        let entities = host.dissect_bytes(source, "conftest.py").unwrap();

        assert_eq!(entities.len(), 1);
        // All functions in conftest.py should be protected
        assert_eq!(entities[0].protected_by, Some(Protection::PytestFixture));
    }
}
