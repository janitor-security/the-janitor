//! Tree-sitter based polyglot parser with entity extraction and heuristic protection detection.
//!
//! Supports Python (primary), Rust, JavaScript, and TypeScript. File extension determines
//! which grammar is used. Python entities receive full heuristic classification; other
//! languages receive name + location extraction only.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::OnceLock;

use memmap2::MmapOptions;
use tree_sitter::{
    Language, ParseOptions, ParseState, Parser, Query, QueryCursor, StreamingIterator,
};

use crate::induce;
use crate::path_util::normalize_path;
use crate::{AnatomistError, Entity, EntityType, Heuristic, Protection};
use forge::compute_structural_hash;

/// Pattern indices for the entity query.
const PATTERN_FN: usize = 0; // Standalone function_definition
const PATTERN_CLASS: usize = 1; // Standalone class_definition
const PATTERN_DECORATED: usize = 2; // decorated_definition wrapping function or class
const PATTERN_ASSIGNMENT: usize = 3; // Module-level assignments

/// Maximum time tree-sitter is allowed to spend on a single parse (100 ms).
///
/// Adversarial inputs ("parser bombs") can trigger super-linear parse time in
/// certain grammars. Aborting after 100 ms returns `None` from `parse()`, which
/// the caller maps to `ParseFailure` — the file is skipped and the daemon
/// continues processing the next blob.
const PARSE_TIMEOUT_MICROS: u64 = 100_000;

/// Static cache for the Python entity extraction query.
static ENTITY_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the Rust entity extraction query.
static RUST_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the JavaScript entity extraction query.
static JS_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the TypeScript (.ts) entity extraction query.
static TS_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the TypeScript JSX (.tsx) entity extraction query.
static TSX_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the C++ entity extraction query.
static CPP_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the C entity extraction query.
static C_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the Java entity extraction query.
static JAVA_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the C# entity extraction query.
static CSHARP_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the Go entity extraction query.
static GO_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the GLSL entity extraction query.
static GLSL_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the Objective-C entity extraction query.
static OBJC_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();
/// Static cache for the Nix entity extraction query.
static NIX_QUERY: OnceLock<Result<Query, String>> = OnceLock::new();

/// S-expression for JS / JSX grammars.
const JS_ENTITY_S_EXPR: &str = r#"
    (function_declaration
      name: (identifier) @fn.name) @fn.def

    (class_declaration
      name: (identifier) @class.name) @class.def

    (method_definition
      name: (property_identifier) @method.name) @method.def
"#;

/// S-expression for TypeScript / TSX grammars.
///
/// Uses `type_identifier` for class names (TypeScript grammar differs from JS here).
const TS_ENTITY_S_EXPR: &str = r#"
    (function_declaration
      name: (identifier) @fn.name) @fn.def

    (class_declaration
      name: (type_identifier) @class.name) @class.def

    (method_definition
      name: (property_identifier) @method.name) @method.def
"#;

/// S-expression for Rust grammar entity extraction.
const RUST_ENTITY_S_EXPR: &str = r#"
    (function_item
      name: (identifier) @fn.name) @fn.def

    (struct_item
      name: (type_identifier) @struct.name) @struct.def

    (enum_item
      name: (type_identifier) @enum.name) @enum.def

    (trait_item
      name: (type_identifier) @trait.name) @trait.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for Rust grammar.
const RUST_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("struct.def", "struct.name", EntityType::ClassDefinition),
    ("enum.def", "enum.name", EntityType::ClassDefinition),
    ("trait.def", "trait.name", EntityType::ClassDefinition),
];

/// S-expression for C++ grammar entity extraction.
///
/// Captures simple (non-template, non-pointer) function definitions and class/struct specifiers.
const CPP_ENTITY_S_EXPR: &str = r#"
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @fn.name)) @fn.def

    (class_specifier
      name: (type_identifier) @class.name) @class.def

    (struct_specifier
      name: (type_identifier) @struct.name) @struct.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for C++ grammar.
const CPP_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("class.def", "class.name", EntityType::ClassDefinition),
    ("struct.def", "struct.name", EntityType::ClassDefinition),
];

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for JS/TS grammars.
const JS_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("class.def", "class.name", EntityType::ClassDefinition),
    ("method.def", "method.name", EntityType::MethodDefinition),
];

fn get_rust_query() -> Result<&'static Query, AnatomistError> {
    RUST_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_rust::LANGUAGE.into(), RUST_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_js_query() -> Result<&'static Query, AnatomistError> {
    JS_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_javascript::LANGUAGE.into(), JS_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_ts_query() -> Result<&'static Query, AnatomistError> {
    TS_QUERY
        .get_or_init(|| {
            Query::new(
                &tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                TS_ENTITY_S_EXPR,
            )
            .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_tsx_query() -> Result<&'static Query, AnatomistError> {
    TSX_QUERY
        .get_or_init(|| {
            Query::new(
                &tree_sitter_typescript::LANGUAGE_TSX.into(),
                TS_ENTITY_S_EXPR,
            )
            .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_cpp_query() -> Result<&'static Query, AnatomistError> {
    CPP_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_cpp::LANGUAGE.into(), CPP_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

/// S-expression for C grammar entity extraction.
const C_ENTITY_S_EXPR: &str = r#"
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @fn.name)) @fn.def

    (struct_specifier
      name: (type_identifier) @struct.name
      body: (field_declaration_list)) @struct.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for C grammar.
const C_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("struct.def", "struct.name", EntityType::ClassDefinition),
];

/// S-expression for Java grammar entity extraction.
const JAVA_ENTITY_S_EXPR: &str = r#"
    (method_declaration
      name: (identifier) @fn.name) @fn.def

    (class_declaration
      name: (identifier) @class.name) @class.def

    (interface_declaration
      name: (identifier) @class.name) @class.def

    (enum_declaration
      name: (identifier) @class.name) @class.def

    (constructor_declaration
      name: (identifier) @fn.name) @fn.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for Java grammar.
///
/// Indices must align exactly with the pattern order in `JAVA_ENTITY_S_EXPR`:
/// 0=method_declaration, 1=class_declaration, 2=interface_declaration,
/// 3=enum_declaration, 4=constructor_declaration.
const JAVA_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition), // method_declaration
    ("class.def", "class.name", EntityType::ClassDefinition), // class_declaration
    ("class.def", "class.name", EntityType::ClassDefinition), // interface_declaration
    ("class.def", "class.name", EntityType::ClassDefinition), // enum_declaration
    ("fn.def", "fn.name", EntityType::FunctionDefinition), // constructor_declaration
];

/// S-expression for C# grammar entity extraction.
const CSHARP_ENTITY_S_EXPR: &str = r#"
    (method_declaration
      name: (identifier) @fn.name) @fn.def

    (class_declaration
      name: (identifier) @class.name) @class.def

    (interface_declaration
      name: (identifier) @class.name) @class.def

    (constructor_declaration
      name: (identifier) @fn.name) @fn.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for C# grammar.
const CSHARP_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("class.def", "class.name", EntityType::ClassDefinition),
    ("class.def", "class.name", EntityType::ClassDefinition), // interface
    ("fn.def", "fn.name", EntityType::FunctionDefinition),    // constructor
];

/// S-expression for Go grammar entity extraction.
const GO_ENTITY_S_EXPR: &str = r#"
    (function_declaration
      name: (identifier) @fn.name) @fn.def

    (method_declaration
      name: (field_identifier) @fn.name) @fn.def

    (type_declaration
      (type_spec
        name: (type_identifier) @type.name)) @type.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for Go grammar.
const GO_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("fn.def", "fn.name", EntityType::MethodDefinition),
    ("type.def", "type.name", EntityType::ClassDefinition),
];

/// S-expression for GLSL (OpenGL Shading Language) entity extraction.
///
/// GLSL syntax is C-like; only `function_definition` nodes are captured.
const GLSL_ENTITY_S_EXPR: &str = r#"
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @fn.name)) @fn.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for GLSL grammar.
const GLSL_PATTERNS: &[(&str, &str, EntityType)] =
    &[("fn.def", "fn.name", EntityType::FunctionDefinition)];

/// S-expression for Objective-C grammar entity extraction.
///
/// Captures C-style `function_definition` nodes, `@interface`/`@implementation`
/// class declarations, and **simple unary** Objective-C method definitions.
///
/// ## Method Selector Coverage
/// In tree-sitter-objc 3.0.2, `method_definition` has no `selector:` field.
/// The method name appears as a direct `identifier` child only for unary (zero-arg)
/// methods: `- (void)dealloc`, `+ (instancetype)sharedInstance`, etc.  Multi-keyword
/// selectors (`doSomething:withArg:`) store the keyword inside `keyword_declarator`
/// sub-nodes and are excluded here — they are not patterns in the dead-code hot path.
const OBJC_ENTITY_S_EXPR: &str = r#"
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @fn.name)) @fn.def

    (class_interface . (identifier) @class.name) @class.def

    (class_implementation . (identifier) @class.name) @class.def

    (method_definition (identifier) @method.name) @method.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for Objective-C grammar.
///
/// Pattern 3 captures unary ObjC method names via the direct `identifier` child
/// of `method_definition` (e.g. `"dealloc"`, `"sharedInstance"`).
const OBJC_PATTERNS: &[(&str, &str, EntityType)] = &[
    ("fn.def", "fn.name", EntityType::FunctionDefinition),
    ("class.def", "class.name", EntityType::ClassDefinition), // class_interface
    ("class.def", "class.name", EntityType::ClassDefinition), // class_implementation
    ("method.def", "method.name", EntityType::MethodDefinition), // unary ObjC method
];

/// S-expression for Nix grammar entity extraction.
///
/// Captures top-level attribute bindings (`name = expr;`) from Nix source files.
/// The first simple identifier in each attrpath is recorded as the entity name.
/// This covers both `foo = ...;` (simple) and `foo.bar = ...;` (nested, captures `foo`).
///
/// Note: bindings inside `mkDerivation { ... }` calls are also captured; the grep
/// shield (Stage 5) will rescue any that are referenced elsewhere.
const NIX_ENTITY_S_EXPR: &str = r#"
    (binding
      attrpath: (attrpath
        attr: (identifier) @bind.name)) @bind.def
"#;

/// Pattern-index → (def_cap, name_cap, entity_type) mapping for Nix grammar.
const NIX_PATTERNS: &[(&str, &str, EntityType)] =
    &[("bind.def", "bind.name", EntityType::Assignment)];

fn get_c_query() -> Result<&'static Query, AnatomistError> {
    C_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_c::LANGUAGE.into(), C_ENTITY_S_EXPR).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_java_query() -> Result<&'static Query, AnatomistError> {
    JAVA_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_java::LANGUAGE.into(), JAVA_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_csharp_query() -> Result<&'static Query, AnatomistError> {
    CSHARP_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_c_sharp::LANGUAGE.into(), CSHARP_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_go_query() -> Result<&'static Query, AnatomistError> {
    GO_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_go::LANGUAGE.into(), GO_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_glsl_query() -> Result<&'static Query, AnatomistError> {
    GLSL_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_glsl::LANGUAGE_GLSL.into(), GLSL_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_objc_query() -> Result<&'static Query, AnatomistError> {
    OBJC_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_objc::LANGUAGE.into(), OBJC_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

fn get_nix_query() -> Result<&'static Query, AnatomistError> {
    NIX_QUERY
        .get_or_init(|| {
            Query::new(&tree_sitter_nix::LANGUAGE.into(), NIX_ENTITY_S_EXPR)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
}

/// Returns the compiled entity extraction query, initializing it on first call.
///
/// # Query Patterns
/// - Pattern 0: Standalone `function_definition`
/// - Pattern 1: Standalone `class_definition` (with optional superclasses)
/// - Pattern 2: `decorated_definition` wrapping function or class
/// - Pattern 3: Module-level assignments (e.g., `__all__ = [...]`)
///
/// # Errors
/// Returns `AnatomistError::ParseFailure` if the hardcoded S-expression is malformed
/// (compile-time bug — should never happen in a correct build).
fn get_entity_query() -> Result<&'static Query, AnatomistError> {
    ENTITY_QUERY
        .get_or_init(|| {
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
            .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| AnatomistError::ParseFailure(e.clone()))
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
                AnatomistError::ParseFailure(format!("Failed to load Python grammar: {e}"))
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

    /// Extracts entities from a source file using memory-mapped I/O.
    ///
    /// Dispatches to the appropriate grammar based on file extension:
    /// - `.py` (default): Full Python extraction with heuristic classification.
    /// - `.rs`: Rust functions, structs, enums, and traits.
    /// - `.js` / `.jsx`: JavaScript functions, classes, and methods.
    /// - `.ts` / `.tsx`: TypeScript functions, classes, and methods.
    /// - `.cpp` / `.cxx` / `.cc` / `.hpp`: C++ functions, classes, and structs.
    /// - `.c` / `.h`: C functions and structs.
    /// - `.java`: Java methods, classes, interfaces, enums, and constructors.
    /// - `.cs`: C# methods, classes, interfaces, and constructors.
    /// - `.go`: Go functions, methods, and type declarations.
    /// - `.glsl` / `.vert` / `.frag`: GLSL shader functions.
    /// - `.m` / `.mm`: Objective-C functions, `@interface`/`@implementation` classes, and
    ///   instance/class method selectors (full selector string used as entity name).
    ///
    /// # Errors
    /// - `IoError`: File not found, permission denied, mmap failure
    /// - `ByteRangeOverflow`: File larger than 4GB (tree-sitter u32 limit)
    /// - `ParseFailure`: Tree-sitter parse returned `None` (severe syntax errors)
    pub fn dissect(&mut self, path: &Path) -> Result<Vec<Entity>, AnatomistError> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_len = metadata.len();

        if file_len > u32::MAX as u64 {
            return Err(AnatomistError::ByteRangeOverflow);
        }
        if file_len == 0 {
            return Ok(Vec::new());
        }

        // SAFETY: The file handle is held for the duration of the mmap lifetime.
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        let source = &mmap[..];
        let normalized_path = normalize_path(path)?;

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            // Explicit Python arm — keeps the built-in 14-language list exhaustive.
            "py" | "pyi" => self.dissect_impl(source, &normalized_path),
            "rs" => Self::extract_rust_entities(source, &normalized_path),
            "js" | "jsx" => Self::extract_js_entities(source, &normalized_path),
            "ts" => extract_named_entities(
                source,
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
                get_ts_query()?,
                &normalized_path,
                JS_PATTERNS,
            ),
            "tsx" => extract_named_entities(
                source,
                tree_sitter_typescript::LANGUAGE_TSX.into(),
                get_tsx_query()?,
                &normalized_path,
                JS_PATTERNS,
            ),
            "cpp" | "cxx" | "cc" | "h" | "hpp" => {
                Self::extract_cpp_entities(source, &normalized_path)
            }
            "c" => Self::extract_c_entities(source, &normalized_path),
            "java" => Self::extract_java_entities(source, &normalized_path),
            "cs" => Self::extract_csharp_entities(source, &normalized_path),
            "go" => Self::extract_go_entities(source, &normalized_path),
            "glsl" | "vert" | "frag" => Self::extract_glsl_entities(source, &normalized_path),
            "m" | "mm" => Self::extract_objc_entities(source, &normalized_path),
            // Nix: attribute-binding entity extraction.
            "nix" => Self::extract_nix_entities(source, &normalized_path),
            // Polyglot-registered grammars without a dedicated entity extractor.
            // Parsing happens locally (grammar is in the registry); we return an
            // empty entity list rather than falling through to the Induction Bridge
            // and triggering a cloud POST.
            "yaml" | "yml" | "sh" | "bash" | "tf" | "hcl" | "gd" | "kt" | "kts" => Ok(vec![]),
            _ => {
                // Unknown extension: attempt to learn via the Induction Bridge.
                //
                // 1. Look up the extension in the on-disk cache (.janitor/learned_wisdom.rkyv).
                // 2. On cache miss, POST to the Governor API; persist the result if successful.
                // 3. Use the returned `language_hint` to select an existing grammar.
                // 4. If the API call fails or the hint is unsupported, skip the file (Ok(vec![])).
                let janitor_dir = induce::find_janitor_dir(path);
                let mut cache = janitor_dir
                    .as_deref()
                    .map(induce::load_cache)
                    .unwrap_or_default();

                let lang_hint: Option<String> = if let Some(entry) = cache.get(ext) {
                    Some(entry.language_hint.clone())
                } else if let Some(entry) = induce::induce(source, ext) {
                    let hint = entry.language_hint.clone();
                    cache.insert(ext.to_string(), entry);
                    if let Some(dir) = &janitor_dir {
                        induce::save_cache(dir, &cache);
                    }
                    Some(hint)
                } else {
                    None
                };

                match lang_hint.as_deref() {
                    Some("python") => self.dissect_impl(source, &normalized_path),
                    Some(hint) => {
                        // Future: map additional hints to registered grammars.
                        eprintln!(
                            "induce: unsupported language_hint '{hint}' for .{ext} — skipping"
                        );
                        Ok(vec![])
                    }
                    None => {
                        // API unavailable or timed out — skip this file gracefully.
                        Ok(vec![])
                    }
                }
            }
        }
    }

    /// Extracts `fn`, `struct`, `enum`, and `trait` entities from a Rust source buffer.
    ///
    /// Functions annotated with `#[test]` are immediately shielded as
    /// `Protection::PytestFixture` so the dead-symbol pipeline never flags them.
    pub fn extract_rust_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        let mut entities = extract_named_entities(
            source,
            tree_sitter_rust::LANGUAGE.into(),
            get_rust_query()?,
            file_path,
            RUST_PATTERNS,
        )?;
        // Post-process: protect any `fn` item preceded by `#[test]`.
        // `extract_named_entities` captures the `fn_item` node start (not its
        // attribute siblings), so we inspect raw bytes to detect the attribute.
        for entity in &mut entities {
            if entity.entity_type == EntityType::FunctionDefinition
                && entity.protected_by.is_none()
                && rust_has_test_attr(source, entity.start_byte as usize)
            {
                entity.protected_by = Some(Protection::PytestFixture);
            }
        }
        Ok(entities)
    }

    /// Extracts `function`, `class`, and `method` entities from a JavaScript source buffer.
    ///
    /// Uses the JavaScript grammar. For TypeScript files use `dissect()` which dispatches
    /// automatically. `protected_by` is `None` for all returned entities.
    pub fn extract_js_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_javascript::LANGUAGE.into(),
            get_js_query()?,
            file_path,
            JS_PATTERNS,
        )
    }

    /// Extracts `function_definition`, `class_specifier`, and `struct_specifier` entities
    /// from a C++ source buffer.
    ///
    /// Only captures simple (non-template, non-pointer-returning) functions. `protected_by`
    /// is `None` for all returned entities; protection is assigned by later pipeline stages.
    pub fn extract_cpp_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_cpp::LANGUAGE.into(),
            get_cpp_query()?,
            file_path,
            CPP_PATTERNS,
        )
    }

    /// Extracts `function_definition` and `struct_specifier` entities from a C source buffer.
    ///
    /// Captures named struct types with bodies. `protected_by` is `None` for all returned entities.
    pub fn extract_c_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_c::LANGUAGE.into(),
            get_c_query()?,
            file_path,
            C_PATTERNS,
        )
    }

    /// Extracts method, class, interface, enum, and constructor entities from a Java source buffer.
    ///
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_java_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_java::LANGUAGE.into(),
            get_java_query()?,
            file_path,
            JAVA_PATTERNS,
        )
    }

    /// Extracts method, class, interface, and constructor entities from a C# source buffer.
    ///
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_csharp_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_c_sharp::LANGUAGE.into(),
            get_csharp_query()?,
            file_path,
            CSHARP_PATTERNS,
        )
    }

    /// Extracts function, method, and type declaration entities from a Go source buffer.
    ///
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_go_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_go::LANGUAGE.into(),
            get_go_query()?,
            file_path,
            GO_PATTERNS,
        )
    }

    /// Extracts `function_definition` entities from a GLSL source buffer.
    ///
    /// Captures all named shader functions (vertex, fragment, geometry, compute, etc.).
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_glsl_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_glsl::LANGUAGE_GLSL.into(),
            get_glsl_query()?,
            file_path,
            GLSL_PATTERNS,
        )
    }

    /// Extracts C-style function and `@interface`/`@implementation` class entities from
    /// an Objective-C source buffer.
    ///
    /// Method selectors are not captured due to their complex multi-keyword grammar.
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_objc_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_objc::LANGUAGE.into(),
            get_objc_query()?,
            file_path,
            OBJC_PATTERNS,
        )
    }

    /// Extracts attribute-binding entities from a Nix source buffer.
    ///
    /// Captures `name = expr;` bindings (simple and dotted attrpaths) at any
    /// depth in the expression tree. The first identifier component of each
    /// attrpath is recorded as the entity name with [`EntityType::Assignment`].
    ///
    /// This provides the symbol surface for nixpkgs-style repos where packages
    /// are defined as top-level attribute-set bindings (e.g., `curl = callPackage ./curl {};`).
    /// `protected_by` is `None` for all returned entities; protection is assigned by later stages.
    pub fn extract_nix_entities(
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        extract_named_entities(
            source,
            tree_sitter_nix::LANGUAGE.into(),
            get_nix_query()?,
            file_path,
            NIX_PATTERNS,
        )
    }

    /// Internal implementation shared by `dissect()` and `dissect_bytes()`.
    fn dissect_impl(
        &mut self,
        source: &[u8],
        file_path: &str,
    ) -> Result<Vec<Entity>, AnatomistError> {
        // Parse source into CST — abort after 100 ms (adversarial-input shield).
        let tree = timed_parse(&mut self.parser, source)?;

        let root = tree.root_node();
        let query = get_entity_query()?;

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
                let qualified = format!("{class_name}.{name}");
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

/// Generic entity extractor for non-Python languages.
///
/// Returns `true` if `#[test]` appears in the attribute lines immediately
/// preceding the Rust item whose first byte is at `fn_start`.
///
/// Walks backward through horizontal whitespace and `#[…]` attribute lines
/// (e.g. `#[should_panic]`, `#[ignore]`) until it either matches `#[test]`
/// (returns `true`) or hits a non-attribute, non-blank line (returns `false`).
fn rust_has_test_attr(source: &[u8], fn_start: usize) -> bool {
    let mut cur = fn_start;
    loop {
        // Skip horizontal whitespace (indentation) preceding `cur`.
        while cur > 0 && matches!(source[cur - 1], b' ' | b'\t') {
            cur -= 1;
        }
        // No preceding newline — we are at the start of the first line.
        if cur == 0 || source[cur - 1] != b'\n' {
            return false;
        }
        cur -= 1; // step past the '\n'
                  // Locate the start of this previous line.
        let line_start = source[..cur]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0);
        let line = source[line_start..=cur].trim_ascii();
        if line.is_empty() {
            cur = line_start;
            continue;
        }
        if line == b"#[test]" {
            return true;
        }
        if line.starts_with(b"#[") {
            // Another attribute (e.g. `#[ignore]`) — keep scanning.
            cur = line_start;
            continue;
        }
        return false;
    }
}

/// Coerces a closure to satisfy `for<'a> FnMut(&'a ParseState) -> ControlFlow<()>`.
///
/// Rust's inference sometimes fails to make closures higher-ranked when the
/// argument is unused. Routing through this function forces the HRTB check.
fn coerce_progress_cb<F>(f: F) -> F
where
    F: for<'a> FnMut(&'a ParseState) -> std::ops::ControlFlow<()>,
{
    f
}

/// Runs a timed parse with panic shielding.
///
/// Limits parse time to [`PARSE_TIMEOUT_MICROS`] via the tree-sitter 0.26
/// `ParseOptions` progress callback — returns `Break` when the wall-clock
/// deadline is exceeded, causing `parse_with_options` to return `None`.
///
/// Also wraps the call in `catch_unwind` so a grammar-level Rust panic is
/// caught and converted to `ParseFailure` rather than crashing the daemon.
/// (A C-level segfault in a grammar is unrecoverable regardless.)
fn timed_parse(parser: &mut Parser, source: &[u8]) -> Result<tree_sitter::Tree, AnatomistError> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_micros(PARSE_TIMEOUT_MICROS);
    // `move` copies `deadline` (Instant: Copy) into the closure.
    // `coerce_progress_cb` forces the HRTB `for<'a> FnMut(&'a ParseState)`.
    let mut progress_cb = coerce_progress_cb(move |_: &ParseState| {
        if std::time::Instant::now() >= deadline {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    });
    let opts = ParseOptions::default().progress_callback(&mut progress_cb);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        parser.parse_with_options(
            &mut |i, _| source.get(i..).unwrap_or_default(),
            None,
            Some(opts),
        )
    }))
    .unwrap_or(None)
    .ok_or_else(|| {
        AnatomistError::ParseFailure("Parse returned None (timeout or bad input)".to_string())
    })
}

/// Parses `source` with `language`, runs `query`, and maps pattern indices to entity
/// metadata via `patterns: &[(def_cap, name_cap, entity_type)]`.
///
/// Creates a local `Parser` per call — avoids mutating the host's Python parser state.
fn extract_named_entities(
    source: &[u8],
    language: Language,
    query: &Query,
    file_path: &str,
    patterns: &[(&str, &str, EntityType)],
) -> Result<Vec<Entity>, AnatomistError> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|e| AnatomistError::ParseFailure(format!("Grammar load failed: {e}")))?;

    let tree = timed_parse(&mut parser, source)?;

    let root = tree.root_node();
    let capture_names = query.capture_names();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, root, source);
    let mut entities = Vec::new();

    while let Some(m) = matches.next() {
        let idx = m.pattern_index;
        if idx >= patterns.len() {
            continue;
        }
        let (def_cap_name, name_cap_name, entity_type) = patterns[idx];

        let def_node = m
            .captures
            .iter()
            .find(|c| capture_names[c.index as usize] == def_cap_name)
            .map(|c| c.node);
        let name_node = m
            .captures
            .iter()
            .find(|c| capture_names[c.index as usize] == name_cap_name)
            .map(|c| c.node);

        let (Some(def_node), Some(name_node)) = (def_node, name_node) else {
            continue;
        };

        let name = match name_node.utf8_text(source) {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };

        entities.push(Entity {
            name: name.clone(),
            qualified_name: name,
            entity_type,
            file_path: file_path.to_string(),
            start_byte: def_node.start_byte() as u32,
            end_byte: def_node.end_byte() as u32,
            start_line: (def_node.start_position().row + 1) as u32,
            end_line: (def_node.end_position().row + 1) as u32,
            parent_class: None,
            base_classes: vec![],
            decorators: vec![],
            protected_by: None,
            structural_hash: None,
        });
    }

    Ok(entities)
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

    #[test]
    fn test_rust_entity_extraction() {
        let source = b"fn hello() {}\nstruct Foo {}\nenum Bar { A, B }\ntrait Baz {}";
        let entities = ParserHost::extract_rust_entities(source, "src/lib.rs").unwrap();

        let names: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hello"), "should extract function 'hello'");
        assert!(names.contains(&"Foo"), "should extract struct 'Foo'");
        assert!(names.contains(&"Bar"), "should extract enum 'Bar'");
        assert!(names.contains(&"Baz"), "should extract trait 'Baz'");

        let fn_entity = entities.iter().find(|e| e.name == "hello").unwrap();
        assert_eq!(fn_entity.entity_type, EntityType::FunctionDefinition);
        assert_eq!(fn_entity.file_path, "src/lib.rs");
        assert!(fn_entity.protected_by.is_none());
    }

    #[test]
    fn test_rust_test_fn_shielded() {
        // A function annotated with `#[test]` must be classified as PytestFixture
        // (the shared "test symbol" protection) so the scanner never flags it dead.
        let source = b"#[test]\nfn my_test() { assert!(true); }\n";
        let entities = ParserHost::extract_rust_entities(source, "src/lib.rs").unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "my_test");
        assert_eq!(entities[0].protected_by, Some(Protection::PytestFixture));
    }

    #[test]
    fn test_rust_non_test_fn_unshielded() {
        // A plain function without `#[test]` must NOT be auto-protected.
        let source = b"fn plain() { }\n";
        let entities = ParserHost::extract_rust_entities(source, "src/lib.rs").unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].protected_by, None);
    }

    #[test]
    fn test_rust_test_fn_with_extra_attr_shielded() {
        // #[test] mixed with other attrs (e.g. #[ignore]) must still be shielded.
        let source = b"#[ignore]\n#[test]\nfn slow_test() { }\n";
        let entities = ParserHost::extract_rust_entities(source, "src/lib.rs").unwrap();
        let fn_e = entities.iter().find(|e| e.name == "slow_test").unwrap();
        assert_eq!(fn_e.protected_by, Some(Protection::PytestFixture));
    }

    #[test]
    fn test_js_entity_extraction() {
        let source = b"function greet(name) {}\nclass Animal {}\n";
        let entities = ParserHost::extract_js_entities(source, "src/app.js").unwrap();

        let names: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"greet"), "should extract function 'greet'");
        assert!(names.contains(&"Animal"), "should extract class 'Animal'");

        let fn_entity = entities.iter().find(|e| e.name == "greet").unwrap();
        assert_eq!(fn_entity.entity_type, EntityType::FunctionDefinition);
        assert!(fn_entity.protected_by.is_none());
    }

    #[test]
    fn test_cpp_entity_extraction() {
        let source = b"int add(int a, int b) { return a + b; }\nclass Foo {};\nstruct Bar {};\n";
        let entities = ParserHost::extract_cpp_entities(source, "src/math.cpp").unwrap();

        let names: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"add"), "should extract function 'add'");
        assert!(names.contains(&"Foo"), "should extract class 'Foo'");
        assert!(names.contains(&"Bar"), "should extract struct 'Bar'");

        let fn_entity = entities.iter().find(|e| e.name == "add").unwrap();
        assert_eq!(fn_entity.entity_type, EntityType::FunctionDefinition);
        assert_eq!(fn_entity.file_path, "src/math.cpp");
        assert!(fn_entity.protected_by.is_none());
        // u32 byte ranges must fit without overflow
        assert!(fn_entity.end_byte > fn_entity.start_byte);
    }

    // ---------------------------------------------------------------------------
    // Fuzz-proofing: binary garbage must never panic or crash the process.
    // ---------------------------------------------------------------------------

    #[test]
    fn test_garbage_bytes_python_no_panic() {
        let mut host = ParserHost::new().unwrap();
        // 4 KiB of repeating 0x00–0xFF — adversarial binary noise.
        let garbage: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        // Must not panic; result may be Ok([]) or Err(ParseFailure) — both safe.
        let _ = host.dissect_bytes(&garbage, "adversarial.py");
    }

    #[test]
    fn test_garbage_bytes_rust_no_panic() {
        let garbage: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let _ = ParserHost::extract_rust_entities(&garbage, "adversarial.rs");
    }

    #[test]
    fn test_garbage_bytes_js_no_panic() {
        let garbage: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let _ = ParserHost::extract_js_entities(&garbage, "adversarial.js");
    }

    // ---------------------------------------------------------------------------
    // Polyglot-registered extensions must return Ok(vec![]) locally — never
    // fall through to the Induction Bridge (cloud POST).
    // ---------------------------------------------------------------------------

    #[test]
    fn test_polyglot_new_exts_parsed_locally() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Minimal valid source for each new polyglot grammar.
        // Note: "nix" is excluded here — it now has a real entity extractor and
        // is covered by test_nix_binding_entities below.
        let cases: &[(&str, &[u8])] = &[
            ("tf", b"resource \"aws_instance\" \"web\" {}"),
            ("hcl", b"variable \"region\" { default = \"us-east-1\" }"),
            ("yaml", b"key: value\n"),
            ("sh", b"#!/bin/bash\necho hello\n"),
            ("gd", b"func _ready():\n  pass\n"),
            ("kt", b"fun main() { println(\"hi\") }"),
        ];

        for (ext, src) in cases {
            let mut f = NamedTempFile::new().unwrap();
            f.write_all(src).unwrap();
            // Rename to give the correct extension.
            let dst = f.path().with_extension(ext);
            std::fs::copy(f.path(), &dst).unwrap();

            let mut host = ParserHost::new().unwrap();
            let result = host.dissect(&dst);
            std::fs::remove_file(&dst).ok();

            assert!(
                result.is_ok(),
                ".{ext} dissect must return Ok, not trigger induce"
            );
            assert!(
                result.unwrap().is_empty(),
                ".{ext} must return empty entity list (no extractor yet)"
            );
        }
    }

    #[test]
    fn test_nix_binding_entities() {
        // A Nix attrset with two top-level bindings should yield two Assignment entities.
        let source = b"{ pkgs }:\n{\n  curl = pkgs.callPackage ./curl {};\n  wget = pkgs.callPackage ./wget {};\n}";
        let entities = ParserHost::extract_nix_entities(source, "pkgs/default.nix").unwrap();
        assert_eq!(
            entities.len(),
            2,
            "expected 2 bindings; got {}",
            entities.len()
        );
        let names: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"curl"), "missing 'curl' binding");
        assert!(names.contains(&"wget"), "missing 'wget' binding");
        for e in &entities {
            assert_eq!(e.entity_type, EntityType::Assignment);
            assert_eq!(e.file_path, "pkgs/default.nix");
            assert!(e.end_byte > e.start_byte);
        }
    }

    #[test]
    fn test_nix_function_no_bindings() {
        // A bare Nix function expression (no attrset bindings) yields no entities.
        let source = b"{ pkgs }: pkgs.hello";
        let entities = ParserHost::extract_nix_entities(source, "shell.nix").unwrap();
        assert!(
            entities.is_empty(),
            "bare function should yield no binding entities"
        );
    }

    #[test]
    fn test_nix_mkderivation_binding() {
        // mkDerivation-style file: pname, version, etc. are captured as bindings.
        let source =
            b"{ stdenv }:\nstdenv.mkDerivation {\n  pname = \"curl\";\n  version = \"8.0.0\";\n}";
        let entities = ParserHost::extract_nix_entities(source, "pkgs/curl/default.nix").unwrap();
        assert!(
            !entities.is_empty(),
            "mkDerivation bindings must be extracted"
        );
        let names: Vec<&str> = entities.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"pname"), "expected 'pname' binding");
        assert!(names.contains(&"version"), "expected 'version' binding");
    }
}
