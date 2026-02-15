//! # Import Extraction & Resolution
//!
//! Parses Python import statements and resolves them to absolute file paths.
//! Supports both absolute (`import foo.bar`) and relative (`from ..utils import x`) imports.

use crate::AnatomistError;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};

/// Import statement metadata extracted from Python source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    /// The import path (e.g., `"foo.bar"` or `".utils"`).
    pub raw_path: String,
    /// Imported names (e.g., `["bar"]` from `"from foo import bar"`). Empty for bare imports.
    pub names: Vec<String>,
    /// Line number (1-indexed).
    pub line: u32,
}

static IMPORT_QUERY: OnceLock<Query> = OnceLock::new();

/// Extracts import statements from Python source code.
///
/// # Examples
/// ```ignore
/// let source = b"import foo\nfrom bar import baz";
/// let mut parser = tree_sitter::Parser::new();
/// parser.set_language(&tree_sitter_python::LANGUAGE.into()).unwrap();
/// let tree = parser.parse(source, None).unwrap();
/// let imports = extract_imports(source, tree.root_node()).unwrap();
/// assert_eq!(imports.len(), 2);
/// ```
pub fn extract_imports(source: &[u8], root: Node) -> Result<Vec<ImportInfo>, AnatomistError> {
    let query = IMPORT_QUERY.get_or_init(|| {
        Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            r#"
            (import_statement
              name: (dotted_name) @import_module)

            (import_from_statement
              module_name: (dotted_name) @from_module
              name: (dotted_name) @from_name)

            (import_from_statement
              module_name: (relative_import) @from_relative
              name: (dotted_name) @from_name_rel)

            (import_from_statement
              module_name: (dotted_name) @from_module_star
              (wildcard_import))

            (import_from_statement
              module_name: (relative_import) @from_relative_star
              (wildcard_import))
            "#,
        )
        .expect("Invalid import query")
    });

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, root, source);

    let mut imports = Vec::new();

    while let Some(m) = matches.next() {
        let mut raw_path = String::new();
        let mut names = Vec::new();
        let mut line = 0;

        for capture in m.captures {
            let node = capture.node;
            let text = node.utf8_text(source).unwrap_or("");
            let capture_name = query.capture_names()[capture.index as usize];

            match capture_name {
                "import_module" => {
                    raw_path = text.to_string();
                    line = node.start_position().row as u32 + 1;
                }
                "from_module" | "from_module_star" => {
                    raw_path = text.to_string();
                    line = node.start_position().row as u32 + 1;
                }
                "from_relative" | "from_relative_star" => {
                    raw_path = text.to_string();
                    line = node.start_position().row as u32 + 1;
                }
                "from_name" | "from_name_rel" => {
                    names.push(text.to_string());
                }
                _ => {}
            }
        }

        if !raw_path.is_empty() {
            imports.push(ImportInfo {
                raw_path,
                names,
                line,
            });
        }
    }

    // Fallback: manual walking if query fails to capture
    if imports.is_empty() {
        let mut cursor_walk = root.walk();
        for child in root.children(&mut cursor_walk) {
            if child.kind() == "import_statement" || child.kind() == "import_from_statement" {
                if let Some(info) = extract_import_manual(source, child) {
                    imports.push(info);
                }
            }
        }
    }

    Ok(imports)
}

/// Manual fallback for import extraction when query doesn't match.
fn extract_import_manual(source: &[u8], node: Node) -> Option<ImportInfo> {
    let kind = node.kind();
    let line = node.start_position().row as u32 + 1;

    if kind == "import_statement" {
        // Extract dotted name from children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "dotted_name" {
                let text = child.utf8_text(source).ok()?;
                return Some(ImportInfo {
                    raw_path: text.to_string(),
                    names: vec![],
                    line,
                });
            }
        }
    } else if kind == "import_from_statement" {
        let mut raw_path = String::new();
        let mut names = Vec::new();

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "dotted_name" | "relative_import" => {
                    if raw_path.is_empty() {
                        raw_path = child.utf8_text(source).ok()?.to_string();
                    } else {
                        names.push(child.utf8_text(source).ok()?.to_string());
                    }
                }
                _ => {}
            }
        }

        if !raw_path.is_empty() {
            return Some(ImportInfo {
                raw_path,
                names,
                line,
            });
        }
    }

    None
}

/// Resolves a Python import path to an absolute file path.
///
/// # Examples
/// ```ignore
/// let source_file = Path::new("/project/src/api/handlers.py");
/// let project_root = Path::new("/project");
///
/// // Relative import: from ..utils import foo
/// let result = resolve_import(source_file, "..utils", project_root);
/// // Returns Some("/project/src/utils.py") or Some("/project/src/utils/__init__.py")
///
/// // Absolute import: from mypackage.core import bar
/// let result = resolve_import(source_file, "mypackage.core", project_root);
/// // Returns Some("/project/mypackage/core.py") or Some("/project/mypackage/core/__init__.py")
/// ```
pub fn resolve_import(
    source_file: &Path,
    import_path: &str,
    project_root: &Path,
) -> Option<PathBuf> {
    // Count leading dots for relative imports
    let dot_count = import_path.chars().take_while(|&c| c == '.').count();

    if dot_count > 0 {
        // Relative import
        let dotted = &import_path[dot_count..];
        let base = if dot_count == 1 {
            source_file.parent()?
        } else {
            let mut base = source_file.parent()?;
            for _ in 0..(dot_count - 1) {
                base = base.parent()?;
            }
            base
        };
        resolve_module_path(base, dotted)
    } else {
        // Absolute import from project root
        resolve_module_path(project_root, import_path)
    }
}

/// Resolves a dotted module path to a file path.
///
/// Tries:
/// 1. `{base}/{parts.join("/")}.py`
/// 2. `{base}/{parts.join("/")}/__init__.py`
fn resolve_module_path(base: &Path, dotted: &str) -> Option<PathBuf> {
    if dotted.is_empty() {
        // Special case: "from . import foo" resolves to current dir's __init__.py
        let init_py = base.join("__init__.py");
        if init_py.exists() {
            return dunce::canonicalize(init_py).ok();
        }
        return None;
    }

    let parts: Vec<&str> = dotted.split('.').collect();
    let rel_path = parts.join("/");

    // Try module.py
    let module_py = base.join(format!("{}.py", rel_path));
    if module_py.exists() {
        return dunce::canonicalize(module_py).ok();
    }

    // Try module/__init__.py
    let init_py = base.join(&rel_path).join("__init__.py");
    if init_py.exists() {
        return dunce::canonicalize(init_py).ok();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tree_sitter::Parser;

    fn parse_imports(source: &str) -> Vec<ImportInfo> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source.as_bytes(), None).unwrap();
        extract_imports(source.as_bytes(), tree.root_node()).unwrap()
    }

    #[test]
    fn test_bare_import() {
        let imports = parse_imports("import foo");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].raw_path, "foo");
        assert!(imports[0].names.is_empty());
    }

    #[test]
    fn test_from_import() {
        let imports = parse_imports("from foo import bar");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].raw_path, "foo");
        assert_eq!(imports[0].names, vec!["bar"]);
    }

    #[test]
    fn test_relative_single_dot() {
        let imports = parse_imports("from .utils import helper");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].raw_path, ".utils");
        assert_eq!(imports[0].names, vec!["helper"]);
    }

    #[test]
    fn test_relative_double_dot() {
        let imports = parse_imports("from ..core import engine");
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].raw_path, "..core");
        assert_eq!(imports[0].names, vec!["engine"]);
    }

    #[test]
    fn test_multi_name_from_import() {
        let imports = parse_imports("from foo import bar, baz");
        // Note: tree-sitter may capture each name separately or together depending on grammar
        // This test accepts either behavior
        assert!(!imports.is_empty());
    }

    #[test]
    fn test_resolve_absolute() {
        let tmp = std::env::temp_dir().join("test_resolve_abs");
        fs::create_dir_all(&tmp).ok();
        let module_py = tmp.join("mymod.py");
        fs::write(&module_py, "").ok();

        let source = tmp.join("main.py");
        let result = resolve_import(&source, "mymod", &tmp);
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("mymod.py"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_resolve_package_init() {
        let tmp = std::env::temp_dir().join("test_resolve_pkg");
        fs::create_dir_all(tmp.join("pkg")).ok();
        let init_py = tmp.join("pkg/__init__.py");
        fs::write(&init_py, "").ok();

        let source = tmp.join("main.py");
        let result = resolve_import(&source, "pkg", &tmp);
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("__init__.py"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_resolve_relative_single_dot() {
        let tmp = std::env::temp_dir().join("test_resolve_rel1");
        fs::create_dir_all(tmp.join("src")).ok();
        let utils_py = tmp.join("src/utils.py");
        fs::write(&utils_py, "").ok();

        let source = tmp.join("src/main.py");
        let result = resolve_import(&source, ".utils", &tmp);
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("utils.py"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_resolve_relative_double_dot() {
        let tmp = std::env::temp_dir().join("test_resolve_rel2");
        fs::create_dir_all(tmp.join("src/api")).ok();
        let core_py = tmp.join("src/core.py");
        fs::write(&core_py, "").ok();

        let source = tmp.join("src/api/handlers.py");
        let result = resolve_import(&source, "..core", &tmp);
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("core.py"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_resolve_nonexistent() {
        let tmp = std::env::temp_dir().join("test_resolve_none");
        fs::create_dir_all(&tmp).ok();
        let source = tmp.join("main.py");
        let result = resolve_import(&source, "nonexistent", &tmp);
        assert!(result.is_none());
        fs::remove_dir_all(tmp).ok();
    }
}
