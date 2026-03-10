//! # Polyglot — Lazy Grammar Registry
//!
//! Thread-safe singleton registry of tree-sitter grammars, loaded on demand via
//! [`OnceLock`] globals. Each grammar is initialised once on first request and
//! pinned for the process lifetime — zero re-compilation overhead.
//!
//! ## Supported Languages
//! Python, Rust, TypeScript, TSX, JavaScript, JSX, C++, C, Java, C#, Go,
//! GLSL (vertex/fragment shaders), Objective-C/C++, YAML, Bash, Scala,
//! Ruby, PHP, Swift, Lua, HCL/Terraform, Nix, GDScript, Kotlin.
//!
//! ## Usage
//! ```ignore
//! if let Some(lang) = polyglot::LazyGrammarRegistry::get("py") {
//!     parser.set_language(lang).unwrap();
//! }
//! ```

use std::sync::OnceLock;
use tree_sitter::Language;

// ---------------------------------------------------------------------------
// Module-level OnceLock statics — one per supported grammar.
// Must be module-level: Rust does not permit `static` items inside `impl` blocks.
// Empty OnceLock<Language> costs one pointer-sized word (8 bytes on 64-bit) until
// first use; the Language value itself is a thin wrapper around a raw pointer.
// ---------------------------------------------------------------------------

static PYTHON: OnceLock<Language> = OnceLock::new();
static RUST: OnceLock<Language> = OnceLock::new();
static TYPESCRIPT: OnceLock<Language> = OnceLock::new();
static TSX: OnceLock<Language> = OnceLock::new();
static JAVASCRIPT: OnceLock<Language> = OnceLock::new();
static CPP: OnceLock<Language> = OnceLock::new();
static C: OnceLock<Language> = OnceLock::new();
static JAVA: OnceLock<Language> = OnceLock::new();
static CSHARP: OnceLock<Language> = OnceLock::new();
static GO: OnceLock<Language> = OnceLock::new();
static GLSL: OnceLock<Language> = OnceLock::new();
static OBJC: OnceLock<Language> = OnceLock::new();
static YAML: OnceLock<Language> = OnceLock::new();
static BASH: OnceLock<Language> = OnceLock::new();
static SCALA: OnceLock<Language> = OnceLock::new();
static RUBY: OnceLock<Language> = OnceLock::new();
static PHP: OnceLock<Language> = OnceLock::new();
static SWIFT: OnceLock<Language> = OnceLock::new();
static LUA: OnceLock<Language> = OnceLock::new();
static HCL: OnceLock<Language> = OnceLock::new();
static NIX: OnceLock<Language> = OnceLock::new();
static GDSCRIPT: OnceLock<Language> = OnceLock::new();
static KOTLIN: OnceLock<Language> = OnceLock::new();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Lazy singleton registry for tree-sitter grammars.
///
/// All grammars are loaded on first access and cached for the process lifetime.
/// Thread-safe: multiple concurrent calls for the same extension are safe —
/// only one will perform the initialisation; the rest observe the cached result.
pub struct LazyGrammarRegistry;

impl LazyGrammarRegistry {
    /// Returns the tree-sitter [`Language`] for the given file extension, or
    /// `None` if the extension is not supported.
    ///
    /// The grammar is initialised exactly once (on first call for that extension)
    /// and pinned globally.
    pub fn get(extension: &str) -> Option<&'static Language> {
        match extension {
            "py" => Some(PYTHON.get_or_init(|| tree_sitter_python::LANGUAGE.into())),
            "rs" => Some(RUST.get_or_init(|| tree_sitter_rust::LANGUAGE.into())),
            "ts" => {
                Some(TYPESCRIPT.get_or_init(|| tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()))
            }
            "tsx" => Some(TSX.get_or_init(|| tree_sitter_typescript::LANGUAGE_TSX.into())),
            "js" | "jsx" | "mjs" | "cjs" => {
                Some(JAVASCRIPT.get_or_init(|| tree_sitter_javascript::LANGUAGE.into()))
            }
            "cpp" | "cxx" | "cc" | "hpp" | "hxx" => {
                Some(CPP.get_or_init(|| tree_sitter_cpp::LANGUAGE.into()))
            }
            "c" | "h" => Some(C.get_or_init(|| tree_sitter_c::LANGUAGE.into())),
            "java" => Some(JAVA.get_or_init(|| tree_sitter_java::LANGUAGE.into())),
            "cs" => Some(CSHARP.get_or_init(|| tree_sitter_c_sharp::LANGUAGE.into())),
            "go" => Some(GO.get_or_init(|| tree_sitter_go::LANGUAGE.into())),
            "glsl" | "vert" | "frag" => {
                Some(GLSL.get_or_init(|| tree_sitter_glsl::LANGUAGE_GLSL.into()))
            }
            "m" | "mm" => Some(OBJC.get_or_init(|| tree_sitter_objc::LANGUAGE.into())),
            "yaml" | "yml" => Some(YAML.get_or_init(|| tree_sitter_yaml::LANGUAGE.into())),
            "sh" | "bash" | "cmd" | "zsh" => {
                Some(BASH.get_or_init(|| tree_sitter_bash::LANGUAGE.into()))
            }
            "scala" => Some(SCALA.get_or_init(|| tree_sitter_scala::LANGUAGE.into())),
            "rb" => Some(RUBY.get_or_init(|| tree_sitter_ruby::LANGUAGE.into())),
            "php" => Some(PHP.get_or_init(|| tree_sitter_php::LANGUAGE_PHP.into())),
            "swift" => Some(SWIFT.get_or_init(|| tree_sitter_swift::LANGUAGE.into())),
            "lua" => Some(LUA.get_or_init(|| tree_sitter_lua::LANGUAGE.into())),
            "tf" | "hcl" => Some(HCL.get_or_init(|| tree_sitter_hcl::LANGUAGE.into())),
            "nix" => Some(NIX.get_or_init(|| tree_sitter_nix::LANGUAGE.into())),
            "gd" => Some(GDSCRIPT.get_or_init(|| tree_sitter_gdscript::LANGUAGE.into())),
            "kt" | "kts" => Some(KOTLIN.get_or_init(|| tree_sitter_kotlin_ng::LANGUAGE.into())),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_grammar_loads() {
        let lang = LazyGrammarRegistry::get("py");
        assert!(lang.is_some(), "Python grammar must load");
    }

    #[test]
    fn test_rust_grammar_loads() {
        let lang = LazyGrammarRegistry::get("rs");
        assert!(lang.is_some(), "Rust grammar must load");
    }

    #[test]
    fn test_unknown_ext_returns_none() {
        let lang = LazyGrammarRegistry::get("unknown_extension_xyz");
        assert!(lang.is_none());
    }

    #[test]
    fn test_get_is_idempotent() {
        // Calling get() twice returns the same static reference.
        let a = LazyGrammarRegistry::get("py");
        let b = LazyGrammarRegistry::get("py");
        assert_eq!(
            a.map(|l| l as *const _),
            b.map(|l| l as *const _),
            "get() must return the same pointer on repeated calls"
        );
    }

    #[test]
    fn test_all_supported_extensions() {
        let supported = [
            "py", "rs", "ts", "tsx", "js", "jsx", "cpp", "cxx", "cc", "h", "hpp", "c", "java",
            "cs", "go", "glsl", "vert", "frag", "m", "mm", "yaml", "yml", "sh", "bash", "cmd",
            "zsh", "scala", // Tier-1 mobile / legacy enterprise
            "rb", "php", "swift", "lua", // Gauntlet grammars
            "tf", "hcl", "nix", "gd", "kt", "kts",
        ];
        for ext in supported {
            assert!(
                LazyGrammarRegistry::get(ext).is_some(),
                "extension '.{ext}' must be supported"
            );
        }
    }
}
