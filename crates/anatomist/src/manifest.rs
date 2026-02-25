//! Manifest scanning and zombie dependency detection.
//!
//! Parses package manifest files (`package.json`, `Cargo.toml`,
//! `requirements.txt`, `pyproject.toml`) to build a `DependencyRegistry`,
//! then cross-references declared deps against actual import statements in
//! source files via Aho-Corasick substring matching.
//!
//! ## Zombie dependency
//! A dependency is a **zombie** when it is declared in a manifest but its
//! package name never appears in any source file in the project.
//!
//! ## Algorithm
//! 1. Walk project root for known manifest filenames (non-recursive beyond
//!    one level for nested workspaces).
//! 2. Parse each manifest with the appropriate parser.
//! 3. Build one Aho-Corasick automaton over all declared dep names.
//! 4. Walk source files, scan each byte slice — O(N) total.
//! 5. Any dep not found in step 4 is a zombie.

use aho_corasick::AhoCorasick;
use common::deps::{DependencyEcosystem, DependencyEntry, DependencyRegistry};
use std::path::Path;
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Manifest filenames
// ---------------------------------------------------------------------------

const NPM_MANIFEST: &str = "package.json";
const CARGO_MANIFEST: &str = "Cargo.toml";
const PIP_REQUIREMENTS: &str = "requirements.txt";
const PIP_PYPROJECT: &str = "pyproject.toml";

/// Scans `project_root` for manifest files and builds a `DependencyRegistry`.
///
/// Walks at most 3 directory levels deep to handle monorepos with nested
/// manifests (e.g., `packages/*/package.json`) without traversing `node_modules`
/// or `target` directories.
pub fn scan_manifests(project_root: &Path) -> DependencyRegistry {
    let mut registry = DependencyRegistry::new();

    let walker = WalkDir::new(project_root)
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Always allow the root entry (depth 0) — it may have any name.
            // Only apply exclusion filters to descendants.
            if e.depth() == 0 {
                return true;
            }
            // Skip hidden dirs and known build/cache dirs.
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.')
                && name != "node_modules"
                && name != "target"
                && name != "__pycache__"
                && name != ".venv"
                && name != "venv"
        });

    for entry in walker.flatten() {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        match name {
            NPM_MANIFEST => parse_package_json(path, &mut registry),
            CARGO_MANIFEST => parse_cargo_toml(path, &mut registry),
            PIP_REQUIREMENTS => parse_requirements_txt(path, &mut registry),
            PIP_PYPROJECT => parse_pyproject_toml(path, &mut registry),
            _ => {}
        }
    }

    registry
}

/// Cross-references declared dependencies against actual imports in source files.
///
/// Returns the names of zombie dependencies — declared in a manifest but whose
/// package name was not found anywhere in the project's source files.
///
/// # Algorithm
/// Builds a single Aho-Corasick automaton from all declared dep names, then
/// scans every non-manifest source file.  A dep is alive if its name appears
/// as a substring in any source file (covers `import X`, `require("X")`,
/// `use X::`, etc.).
pub fn find_zombie_deps(project_root: &Path, registry: &DependencyRegistry) -> Vec<String> {
    if registry.is_empty() {
        return Vec::new();
    }

    let names: Vec<String> = registry.entries.iter().map(|e| e.name.clone()).collect();

    if names.is_empty() {
        return Vec::new();
    }

    let ac = match AhoCorasick::builder()
        .ascii_case_insensitive(false)
        .build(&names)
    {
        Ok(ac) => ac,
        Err(_) => return Vec::new(),
    };

    let mut seen = vec![false; names.len()];

    let walker = WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
            let n = e.file_name().to_string_lossy();
            !n.starts_with('.') && n != "node_modules" && n != "target" && n != "__pycache__"
        });

    for entry in walker.flatten() {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        // Skip manifest files themselves (they obviously contain the dep name).
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if matches!(
            filename,
            NPM_MANIFEST | CARGO_MANIFEST | PIP_REQUIREMENTS | PIP_PYPROJECT
        ) {
            continue;
        }
        // Only scan known source extensions.
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !is_source_ext(ext) {
            continue;
        }

        // Skip binary-like files by checking size (> 4 MB is likely not source).
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        if meta.len() > 4 * 1024 * 1024 {
            continue;
        }

        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };

        for mat in ac.find_iter(&bytes) {
            seen[mat.pattern().as_usize()] = true;
        }

        // Early exit if all deps found.
        if seen.iter().all(|&s| s) {
            break;
        }
    }

    names
        .into_iter()
        .zip(seen)
        .filter(|(_, found)| !found)
        .map(|(name, _)| name)
        .collect()
}

// ---------------------------------------------------------------------------
// Source extension filter
// ---------------------------------------------------------------------------

fn is_source_ext(ext: &str) -> bool {
    matches!(
        ext,
        "py" | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "rs"
            | "java"
            | "cs"
            | "go"
            | "cpp"
            | "cc"
            | "cxx"
            | "c"
            | "h"
            | "hpp"
    )
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

/// Parse `package.json` — extracts `dependencies` and `devDependencies`.
fn parse_package_json(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };

    let obj = match json.as_object() {
        Some(o) => o,
        None => return,
    };

    for (section_key, dev) in &[("dependencies", false), ("devDependencies", true)] {
        if let Some(deps) = obj.get(*section_key).and_then(|v| v.as_object()) {
            for (name, version) in deps {
                registry.insert(DependencyEntry {
                    name: name.clone(),
                    version: version.as_str().unwrap_or("*").to_owned(),
                    ecosystem: DependencyEcosystem::Npm,
                    dev: *dev,
                });
            }
        }
    }
}

/// Parse `Cargo.toml` — extracts `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`.
fn parse_cargo_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = toml::from_str::<toml::Value>(&content) else {
        return;
    };

    for (section, dev) in &[
        ("dependencies", false),
        ("dev-dependencies", true),
        ("build-dependencies", false),
    ] {
        let Some(table) = val.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, spec) in table {
            // Skip workspace-level `[workspace]` virtual manifests.
            if name == "workspace" {
                continue;
            }
            let version = match spec {
                toml::Value::String(s) => s.clone(),
                toml::Value::Table(t) => t
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*")
                    .to_owned(),
                _ => "*".to_owned(),
            };
            registry.insert(DependencyEntry {
                name: name.clone(),
                version,
                ecosystem: DependencyEcosystem::Cargo,
                dev: *dev,
            });
        }
    }
}

/// Parse `requirements.txt` — one package per line.
///
/// Handles common formats:
/// - `package==1.0.0`
/// - `package>=1.0,<2.0`
/// - `package`
/// - Lines starting with `#` or `-r` are skipped.
fn parse_requirements_txt(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        // Strip extras: `package[extra]>=1.0` → `package`
        let base = line
            .split_once(['=', '>', '<', '!', '[', ';', ' '])
            .map(|(n, _)| n)
            .unwrap_or(line)
            .trim();
        if !base.is_empty() {
            let version = line
                .split_once("==")
                .map(|(_, v)| v.split_whitespace().next().unwrap_or("*").to_owned())
                .unwrap_or_else(|| "*".to_owned());
            registry.insert(DependencyEntry {
                name: base.to_owned(),
                version,
                ecosystem: DependencyEcosystem::Pip,
                dev: false,
            });
        }
    }
}

/// Parse `pyproject.toml` — supports PEP 621 `[project.dependencies]` and
/// Poetry `[tool.poetry.dependencies]`.
fn parse_pyproject_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = toml::from_str::<toml::Value>(&content) else {
        return;
    };

    // PEP 621: [project] dependencies = ["requests>=2.0"]
    if let Some(arr) = val
        .get("project")
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        for item in arr {
            if let Some(s) = item.as_str() {
                let name = s
                    .split_once(['=', '>', '<', '!', '[', ';', ' '])
                    .map(|(n, _)| n)
                    .unwrap_or(s)
                    .trim();
                if !name.is_empty() {
                    registry.insert(DependencyEntry {
                        name: name.to_owned(),
                        version: "*".to_owned(),
                        ecosystem: DependencyEcosystem::Pip,
                        dev: false,
                    });
                }
            }
        }
    }

    // Poetry: [tool.poetry.dependencies] package = "^1.0"
    for (section, dev) in &[
        ("dependencies", false),
        ("dev-dependencies", true),
        ("group.dev.dependencies", false), // Poetry 1.2+ groups
    ] {
        let table = val.get("tool").and_then(|t| t.get("poetry")).and_then(|p| {
            // Handle dotted keys like "group.dev.dependencies"
            let mut cur = p;
            for key in section.split('.') {
                cur = cur.get(key)?;
            }
            cur.as_table()
        });

        if let Some(table) = table {
            for (name, spec) in table {
                if name == "python" {
                    continue;
                }
                let version = match spec {
                    toml::Value::String(s) => s.clone(),
                    toml::Value::Table(t) => t
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_owned(),
                    _ => "*".to_owned(),
                };
                registry.insert(DependencyEntry {
                    name: name.clone(),
                    version,
                    ecosystem: DependencyEcosystem::Pip,
                    dev: *dev,
                });
            }
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
    fn test_parse_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = serde_json::json!({
            "name": "my-app",
            "dependencies": {"lodash": "^4.17.21", "axios": "^1.0.0"},
            "devDependencies": {"jest": "^29.0.0"}
        });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();

        let registry = scan_manifests(dir.path());
        let names: Vec<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"axios"));
        assert!(names.contains(&"jest"));

        let jest = registry.entries.iter().find(|e| e.name == "jest").unwrap();
        assert!(jest.dev);
    }

    #[test]
    fn test_parse_requirements_txt() {
        let dir = tempfile::tempdir().unwrap();
        let content = "requests==2.28.0\nflask>=2.0\n# comment\nnumpy\n-r other.txt\n";
        std::fs::write(dir.path().join("requirements.txt"), content).unwrap();

        let registry = scan_manifests(dir.path());
        let names: Vec<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"flask"));
        assert!(names.contains(&"numpy"));
        assert!(!names.contains(&"-r"));
    }

    #[test]
    fn test_parse_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
[package]
name = "my-crate"
version = "1.0.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"

[dev-dependencies]
tempfile = "3"
"#;
        std::fs::write(dir.path().join("Cargo.toml"), content).unwrap();

        let registry = scan_manifests(dir.path());
        let names: Vec<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"anyhow"));
        assert!(names.contains(&"tempfile"));

        let tempfile_entry = registry
            .entries
            .iter()
            .find(|e| e.name == "tempfile")
            .unwrap();
        assert!(tempfile_entry.dev);
    }

    #[test]
    fn test_find_zombie_deps() {
        let dir = tempfile::tempdir().unwrap();
        // manifest declares lodash and axios
        let pkg = serde_json::json!({
            "dependencies": {"lodash": "^4.17.21", "axios": "^1.0.0"}
        });
        std::fs::write(dir.path().join("package.json"), pkg.to_string()).unwrap();
        // Source file only uses lodash
        std::fs::write(
            dir.path().join("app.js"),
            b"const _ = require('lodash');\nconsole.log('hello');\n",
        )
        .unwrap();

        let registry = scan_manifests(dir.path());
        let zombies = find_zombie_deps(dir.path(), &registry);
        assert!(zombies.contains(&"axios".to_owned()), "axios is zombie");
        assert!(!zombies.contains(&"lodash".to_owned()), "lodash is used");
    }
}
