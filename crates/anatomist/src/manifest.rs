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
//! ## Algorithms
//!
//! ### Full-project scan (`find_zombie_deps`)
//! 1. Walk project root for known manifest filenames (depth ≤ 3).
//! 2. Parse each manifest with the appropriate parser.
//! 3. Build one Aho-Corasick automaton over all declared dep names.
//! 4. Walk source files, scan each byte slice — O(N) total.
//! 5. Any dep not found in step 4 is a zombie.
//!
//! ### PR-scoped scan (`find_zombie_deps_in_blobs`)
//! Identical algorithm, but bounded to the files actually changed in a PR:
//! 1. Parse manifests present in the blob map (no WalkDir).
//! 2. Build one Aho-Corasick automaton.
//! 3. Scan only non-manifest source blobs in the map.
//! 4. Return names with zero hits.
//!
//! The PR-scoped variant runs in O(B) where B = total bytes in changed files,
//! eliminating the per-PR full-repository traversal that made the Grand Slam
//! script O(N × M) (N PRs × M repo source files).

use aho_corasick::AhoCorasick;
use common::deps::{DependencyEcosystem, DependencyEntry, DependencyRegistry};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ---------------------------------------------------------------------------
// Manifest filenames
// ---------------------------------------------------------------------------

const NPM_MANIFEST: &str = "package.json";
const CARGO_MANIFEST: &str = "Cargo.toml";
const PIP_REQUIREMENTS: &str = "requirements.txt";
const PIP_PYPROJECT: &str = "pyproject.toml";
const SPIN_MANIFEST: &str = "spin.toml";
const WRANGLER_MANIFEST: &str = "wrangler.toml";

/// All manifest filenames — used to skip manifest blobs during source scanning.
const MANIFEST_NAMES: &[&str] = &[
    NPM_MANIFEST,
    CARGO_MANIFEST,
    PIP_REQUIREMENTS,
    PIP_PYPROJECT,
    SPIN_MANIFEST,
    WRANGLER_MANIFEST,
];

/// Scans `project_root` for manifest files and builds a `DependencyRegistry`.
///
/// Walks at most 6 directory levels deep to handle deep monorepos and
/// package-collection repositories (e.g., NixOS/nixpkgs where package manifests
/// live at `pkgs/development/tools/<name>/package.json`).
/// `node_modules`, `target`, and virtualenv directories are always pruned.
pub fn scan_manifests(project_root: &Path) -> DependencyRegistry {
    let mut registry = DependencyRegistry::new();

    let walker = WalkDir::new(project_root)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() == 0 {
                return true;
            }
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
            SPIN_MANIFEST => parse_spin_toml(path, &mut registry),
            WRANGLER_MANIFEST => parse_wrangler_toml(path, &mut registry),
            _ => {
                if path.extension() == Some(OsStr::new("sh"))
                    || path.extension() == Some(OsStr::new("bash"))
                {
                    parse_shell_script(path, &mut registry);
                }
            }
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
///
/// For PR-scoped analysis use [`find_zombie_deps_in_blobs`] instead — it
/// eliminates the full-tree WalkDir traversal and runs in O(PR-diff bytes).
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
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if MANIFEST_NAMES.contains(&filename) {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !is_source_ext(ext) {
            continue;
        }

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

/// PR-scoped zombie dependency detection.
///
/// Accepts the blob map from a `MergeSnapshot` or `extract_patch_blobs` and
/// operates **without any filesystem traversal**.  Only files present in `blobs`
/// are inspected:
///
/// 1. Manifest files in `blobs` are parsed to build the dep registry.
/// 2. Non-manifest source files in `blobs` are scanned for dep name occurrences.
/// 3. Dep names with zero occurrences across all source blobs are returned.
///
/// **Performance**: O(B) where B = total bytes in `blobs`.  For a typical PR
/// (< 1 MiB changed), this completes in microseconds — vs. the full-project
/// WalkDir scan which traverses 1,200+ Godot source files per PR invocation.
pub fn find_zombie_deps_in_blobs(blobs: &HashMap<PathBuf, Vec<u8>>) -> Vec<String> {
    // Step 1: parse any manifests that appear in the PR diff.
    let mut registry = DependencyRegistry::new();
    for (path, bytes) in blobs {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let Ok(content) = std::str::from_utf8(bytes) else {
            continue;
        };
        match name {
            NPM_MANIFEST => parse_package_json_content(content, &mut registry),
            CARGO_MANIFEST => parse_cargo_toml_content(content, &mut registry),
            PIP_REQUIREMENTS => parse_requirements_txt_content(content, &mut registry),
            PIP_PYPROJECT => parse_pyproject_toml_content(content, &mut registry),
            SPIN_MANIFEST => parse_spin_toml_content(content, &mut registry),
            WRANGLER_MANIFEST => parse_wrangler_toml_content(content, &mut registry),
            _ => {
                if let Some("sh" | "bash") = path.extension().and_then(|e| e.to_str()) {
                    parse_shell_script_content(content, &mut registry);
                }
            }
        }
    }

    if registry.is_empty() {
        // No manifest was touched in this PR — nothing to check.
        return Vec::new();
    }

    // Step 2: build Aho-Corasick automaton over declared dep names.
    let names: Vec<String> = registry.entries.iter().map(|e| e.name.clone()).collect();
    if names.is_empty() {
        return Vec::new();
    }

    let Ok(ac) = AhoCorasick::builder()
        .ascii_case_insensitive(false)
        .build(&names)
    else {
        return Vec::new();
    };

    // Step 3: scan only non-manifest source blobs in the PR.
    let mut seen = vec![false; names.len()];
    for (path, bytes) in blobs {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        // Manifests contain dep names by definition — skip.
        if MANIFEST_NAMES.contains(&filename) {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !is_source_ext(ext) {
            continue;
        }
        if bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        for mat in ac.find_iter(bytes) {
            seen[mat.pattern().as_usize()] = true;
        }
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
            | "sh"
            | "bash"
    )
}

// ---------------------------------------------------------------------------
// Path-based parsers (read file, delegate to content parsers)
// ---------------------------------------------------------------------------

/// Parse `package.json` — extracts `dependencies` and `devDependencies`.
fn parse_package_json(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_package_json_content(&content, registry);
}

/// Parse `Cargo.toml` — extracts `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`.
fn parse_cargo_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_cargo_toml_content(&content, registry);
}

/// Parse `requirements.txt` — one package per line.
fn parse_requirements_txt(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_requirements_txt_content(&content, registry);
}

/// Parse `pyproject.toml` — supports PEP 621 `[project.dependencies]` and
/// Poetry `[tool.poetry.dependencies]`.
fn parse_pyproject_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_pyproject_toml_content(&content, registry);
}

/// Parse `spin.toml` — Fermyon Spin WebAssembly application manifest.
fn parse_spin_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_spin_toml_content(&content, registry);
}

/// Parse a shell script (`.sh`, `.bash`) — extracts system tools declared via
/// package manager install commands (`apt-get install`, `apt install`,
/// `brew install`).
///
/// Declared tools that are never actually invoked anywhere in the project
/// are flagged as zombie dependencies.
fn parse_shell_script(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_shell_script_content(&content, registry);
}

/// Parse `wrangler.toml` — Cloudflare Workers deployment manifest.
fn parse_wrangler_toml(path: &Path, registry: &mut DependencyRegistry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    parse_wrangler_toml_content(&content, registry);
}

// ---------------------------------------------------------------------------
// Content-based parsers (accept &str — used by find_zombie_deps_in_blobs)
// ---------------------------------------------------------------------------

/// Parse `package.json` content — extracts `dependencies` and `devDependencies`.
fn parse_package_json_content(content: &str, registry: &mut DependencyRegistry) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(obj) = json.as_object() else {
        return;
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

/// Parse `Cargo.toml` content — extracts `[dependencies]`, `[dev-dependencies]`,
/// `[build-dependencies]`.
fn parse_cargo_toml_content(content: &str, registry: &mut DependencyRegistry) {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
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

/// Parse `requirements.txt` content — one package per line.
///
/// Handles common formats:
/// - `package==1.0.0`
/// - `package>=1.0,<2.0`
/// - `package`
/// - Lines starting with `#` or `-r` are skipped.
fn parse_requirements_txt_content(content: &str, registry: &mut DependencyRegistry) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
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

/// Parse `pyproject.toml` content — supports PEP 621 `[project.dependencies]` and
/// Poetry `[tool.poetry.dependencies]`.
fn parse_pyproject_toml_content(content: &str, registry: &mut DependencyRegistry) {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
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
        ("group.dev.dependencies", false),
    ] {
        let table = val.get("tool").and_then(|t| t.get("poetry")).and_then(|p| {
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

/// Parse `spin.toml` content — Fermyon Spin WebAssembly application manifest.
///
/// Extracts WASI interface dependency identifiers from
/// `[component.<id>.dependencies]` tables.
fn parse_spin_toml_content(content: &str, registry: &mut DependencyRegistry) {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return;
    };

    if let Some(components) = val.get("component").and_then(|c| c.as_table()) {
        for (_id, component_val) in components {
            if let Some(deps) = component_val.get("dependencies").and_then(|d| d.as_table()) {
                for (iface, spec) in deps {
                    let name = iface.split('@').next().unwrap_or(iface).trim().to_owned();
                    if name.is_empty() {
                        continue;
                    }
                    let version = match spec {
                        toml::Value::String(s) => s.clone(),
                        toml::Value::Table(t) => t
                            .get("target")
                            .and_then(|v| v.as_str())
                            .unwrap_or("*")
                            .to_owned(),
                        _ => "*".to_owned(),
                    };
                    registry.insert(DependencyEntry {
                        name,
                        version,
                        ecosystem: DependencyEcosystem::Wasm,
                        dev: false,
                    });
                }
            }
        }
    }
}

/// Parse `wrangler.toml` content — Cloudflare Workers deployment manifest.
///
/// Extracts `binding` names from every binding-array section:
/// `[[kv_namespaces]]`, `[[d1_databases]]`, `[[r2_buckets]]`,
/// `[[services]]`, `[[analytics_engine_datasets]]`,
/// `[[dispatch_namespaces]]`, `[[durable_objects.bindings]]`, and `[vars]`.
fn parse_wrangler_toml_content(content: &str, registry: &mut DependencyRegistry) {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return;
    };

    for section in &[
        "kv_namespaces",
        "d1_databases",
        "r2_buckets",
        "services",
        "analytics_engine_datasets",
        "dispatch_namespaces",
    ] {
        extract_wrangler_bindings(&val, section, "binding", registry);
    }

    // Durable Objects use "name" instead of "binding".
    if let Some(dos) = val
        .get("durable_objects")
        .and_then(|d| d.get("bindings"))
        .and_then(|b| b.as_array())
    {
        for entry in dos {
            if let Some(b) = entry.get("name").and_then(|b| b.as_str()) {
                registry.insert(DependencyEntry {
                    name: b.to_owned(),
                    version: "*".to_owned(),
                    ecosystem: DependencyEcosystem::CloudflareBinding,
                    dev: false,
                });
            }
        }
    }

    // [vars] — plain environment variables exposed as `env.KEY`.
    if let Some(vars) = val.get("vars").and_then(|v| v.as_table()) {
        for (key, _) in vars {
            registry.insert(DependencyEntry {
                name: key.to_owned(),
                version: "*".to_owned(),
                ecosystem: DependencyEcosystem::CloudflareBinding,
                dev: false,
            });
        }
    }

    // [env.<name>] nested environment overrides.
    if let Some(envs) = val.get("env").and_then(|e| e.as_table()) {
        for (_, env_val) in envs {
            for section in &["kv_namespaces", "d1_databases", "r2_buckets"] {
                extract_wrangler_bindings(env_val, section, "binding", registry);
            }
        }
    }
}

/// Parse shell script content — extracts system tool names from install commands.
///
/// Recognises:
/// - `apt-get install [-y] TOOL1 TOOL2 …`
/// - `apt install [-y] TOOL1 TOOL2 …`
/// - `brew install TOOL1 TOOL2 …`
///
/// Flags (tokens starting with `-`) and the install command itself are skipped.
/// Each extracted name is registered as [`DependencyEcosystem::Apt`].
pub(crate) fn parse_shell_script_content(content: &str, registry: &mut DependencyRegistry) {
    const INSTALL_TRIGGERS: &[&str] = &[
        "apt-get install",
        "apt install",
        "brew install",
        "yum install",
        "dnf install",
    ];

    for line in content.lines() {
        let line = line.trim();
        // Skip comment lines.
        if line.starts_with('#') {
            continue;
        }
        // Find the earliest install-command marker on this line.
        let rest = INSTALL_TRIGGERS
            .iter()
            .filter_map(|trigger| line.find(trigger).map(|pos| &line[pos + trigger.len()..]))
            .min_by_key(|r| r.as_ptr() as usize);

        let Some(rest) = rest else {
            continue;
        };

        for token in rest.split_whitespace() {
            // Skip flags (-y, --no-install-recommends, etc.) and shell
            // variable references ($DEBIAN_FRONTEND=noninteractive).
            if token.starts_with('-') || token.starts_with('$') || token.starts_with('\\') {
                continue;
            }
            // Strip trailing backslash continuations and trailing semicolons.
            let name = token.trim_end_matches(['\\', ';', '&', '|']);
            if name.is_empty() || name == "&&" || name == "||" {
                continue;
            }
            registry.insert(DependencyEntry {
                name: name.to_owned(),
                version: "*".to_owned(),
                ecosystem: DependencyEcosystem::Apt,
                dev: false,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract `binding_key` values from an array-of-tables section in a Wrangler
/// TOML value, inserting each as a [`CloudflareBinding`] dep entry.
fn extract_wrangler_bindings(
    val: &toml::Value,
    section: &str,
    binding_key: &str,
    registry: &mut DependencyRegistry,
) {
    if let Some(arr) = val.get(section).and_then(|v| v.as_array()) {
        for entry in arr {
            if let Some(b) = entry.get(binding_key).and_then(|b| b.as_str()) {
                registry.insert(DependencyEntry {
                    name: b.to_owned(),
                    version: "*".to_owned(),
                    ecosystem: DependencyEcosystem::CloudflareBinding,
                    dev: false,
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
    fn test_parse_spin_toml() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
spin_manifest_version = 2

[application]
name = "hello"

[component.hello]
source = "target/wasm32-wasi/release/hello.wasm"

[component.hello.dependencies]
"wasi:http@0.2.0" = { target = "0.2.0" }
"fermyon:spin@2" = { target = "2.0.0" }
"#;
        std::fs::write(dir.path().join("spin.toml"), content).unwrap();
        let registry = scan_manifests(dir.path());
        let names: Vec<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"wasi:http"), "should strip @version suffix");
        assert!(names.contains(&"fermyon:spin"));
        assert!(registry
            .entries
            .iter()
            .all(|e| e.ecosystem == DependencyEcosystem::Wasm));
    }

    #[test]
    fn test_parse_wrangler_toml() {
        let dir = tempfile::tempdir().unwrap();
        let content = r#"
name = "my-worker"
main = "src/index.js"

[[kv_namespaces]]
binding = "MY_KV"
id = "abc123"

[[d1_databases]]
binding = "DB"
database_name = "my-db"
database_id = "def456"

[durable_objects]
[[durable_objects.bindings]]
name = "MY_DO"
class_name = "MyDurableObject"

[vars]
API_URL = "https://example.com"
"#;
        std::fs::write(dir.path().join("wrangler.toml"), content).unwrap();
        let registry = scan_manifests(dir.path());
        let names: Vec<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"MY_KV"), "kv binding");
        assert!(names.contains(&"DB"), "d1 binding");
        assert!(names.contains(&"MY_DO"), "durable object binding");
        assert!(names.contains(&"API_URL"), "var binding");
        assert!(registry
            .entries
            .iter()
            .all(|e| e.ecosystem == DependencyEcosystem::CloudflareBinding));
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

    #[test]
    fn test_find_zombie_deps_in_blobs_detects_zombie() {
        // Simulates a PR that adds lodash + axios to package.json but only uses lodash.
        let pkg_json = serde_json::json!({
            "dependencies": {"lodash": "^4.17.21", "axios": "^1.0.0"}
        })
        .to_string();

        let app_js = b"const _ = require('lodash');\nconsole.log('hello');\n".to_vec();

        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("package.json"), pkg_json.into_bytes());
        blobs.insert(PathBuf::from("src/app.js"), app_js);

        let zombies = find_zombie_deps_in_blobs(&blobs);
        assert!(
            zombies.contains(&"axios".to_owned()),
            "axios unused in PR blobs → zombie"
        );
        assert!(!zombies.contains(&"lodash".to_owned()), "lodash is used");
    }

    #[test]
    fn test_find_zombie_deps_in_blobs_no_manifest_returns_empty() {
        // PR without any manifest file — nothing to check.
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("src/utils.py"),
            b"def helper(): pass\n".to_vec(),
        );
        assert!(
            find_zombie_deps_in_blobs(&blobs).is_empty(),
            "no manifest in PR → no zombies"
        );
    }

    #[test]
    fn test_find_zombie_deps_in_blobs_all_used() {
        // PR adds both a dep and a file that uses it — no zombie.
        let cargo = r#"
[package]
name = "x"
[dependencies]
serde = "1.0"
"#;
        let lib_rs = b"use serde::Serialize;\n#[derive(Serialize)]\nstruct Foo;\n".to_vec();

        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.toml"), cargo.as_bytes().to_vec());
        blobs.insert(PathBuf::from("src/lib.rs"), lib_rs);

        let zombies = find_zombie_deps_in_blobs(&blobs);
        assert!(
            zombies.is_empty(),
            "serde is used in the PR blob → not a zombie"
        );
    }
}
