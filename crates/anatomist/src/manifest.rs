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
use common::wisdom::find_kev_dependency_hits;
use forge::slop_hunter::{Severity, SlopFinding};
use std::collections::{HashMap, HashSet};
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
const GO_MOD: &str = "go.mod";
const GEMFILE: &str = "Gemfile";

/// All manifest filenames — used to skip manifest blobs during source scanning.
const MANIFEST_NAMES: &[&str] = &[
    NPM_MANIFEST,
    CARGO_MANIFEST,
    PIP_REQUIREMENTS,
    PIP_PYPROJECT,
    SPIN_MANIFEST,
    WRANGLER_MANIFEST,
    GO_MOD,
    GEMFILE,
];

/// Cross-reference a resolved `Cargo.lock` payload against the KEV dependency
/// rules stored in `wisdom.rkyv`.
///
/// Returns one [`SlopFinding`] per matching dependency/CVE pair. Findings fire
/// at [`Severity::KevCritical`] (+150 pts) and use the canonical
/// `supply_chain:kev_dependency` category prefix in the description.
pub fn check_kev_deps(lockfile: &[u8], wisdom_db: &Path) -> Vec<SlopFinding> {
    let mut findings = Vec::new();
    for hit in find_kev_dependency_hits(lockfile, wisdom_db) {
        let mut description = format!(
            "supply_chain:kev_dependency — dependency `{}` resolved at v{} matches KEV {}",
            hit.package_name, hit.version, hit.cve_id
        );
        if !hit.summary.trim().is_empty() {
            description.push_str(&format!(" — {}", hit.summary.trim()));
        }

        findings.push(SlopFinding {
            start_byte: 0,
            end_byte: 0,
            description,
            domain: forge::metadata::DOMAIN_ALL,
            severity: Severity::KevCritical,
        });
    }

    findings.sort_by(|a, b| a.description.cmp(&b.description));
    findings
}

/// Evaluate Kubernetes routing CRDs for AKS/EKS internal-exposure drift.
pub fn check_crd_exposure(source: &[u8]) -> Vec<SlopFinding> {
    forge::slop_hunter::check_crd_exposure(source)
}

/// Resolve the verified KEV database from `janitor_dir` and apply
/// [`check_kev_deps`] against it.
///
/// This fail-closed entrypoint is intended for CI and MCP callers that must not
/// silently degrade to `kev_count = 0` when the KEV database is missing,
/// malformed, or reduced to the JSON manifest alone. `wisdom_manifest.json` is
/// treated strictly as a diffable receipt and never as a substitute authority.
pub fn check_kev_deps_required(
    lockfile: &[u8],
    janitor_dir: &Path,
) -> anyhow::Result<Vec<SlopFinding>> {
    let wisdom_db = common::wisdom::resolve_kev_database(janitor_dir)?;
    Ok(check_kev_deps(lockfile, &wisdom_db))
}

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
pub(crate) fn parse_pyproject_toml_content(content: &str, registry: &mut DependencyRegistry) {
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
/// Returns `true` if `name` is a syntactically valid apt/Debian package identifier.
///
/// Valid names start with an ASCII alphanumeric character and contain only
/// `[a-zA-Z0-9+._-]` — shell artifacts like `>&2`, `2>&1`, `/dev/null`, `>`,
/// `<`, and `=` are rejected before they can be registered as zombie dep names.
///
/// Reference: Debian Policy §5.6.1 (package names).
#[inline]
fn is_valid_apt_name(name: &str) -> bool {
    let mut chars = name.bytes();
    match chars.next() {
        Some(b) if b.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'+' | b'.' | b'_' | b'-'))
}

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
            // Reject shell artifacts: redirections (`>&2`, `2>&1`, `/dev/null`)
            // and any token that is not a valid Debian/apt package identifier.
            // Valid names: start with an alphanumeric and contain only
            // [a-zA-Z0-9+._-] — no `>`, `<`, `&`, `/`, `=`, `(`, `)`.
            if !is_valid_apt_name(name) {
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
// Version silo detection
// ---------------------------------------------------------------------------

/// PR-scoped version silo detection.
///
/// Parses every `Cargo.toml` and `package.json` blob present in the PR diff and
/// builds a `name → HashSet<version>` map.  Any crate/package whose name maps to
/// more than one **distinct, non-wildcard** version string is a **version silo** —
/// the PR is introducing or widening a dependency split that the resolver must
/// reconcile at compile time.
///
/// Returns a sorted list of siloed crate/package names.
pub fn find_version_silos_in_blobs(blobs: &HashMap<PathBuf, Vec<u8>>) -> Vec<String> {
    let mut version_map: HashMap<String, HashSet<String>> = HashMap::new();

    for (path, bytes) in blobs {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let Ok(content) = std::str::from_utf8(bytes) else {
            continue;
        };
        match name {
            CARGO_MANIFEST => collect_cargo_versions(content, &mut version_map),
            NPM_MANIFEST => collect_npm_versions(content, &mut version_map),
            _ => {}
        }
    }

    let mut silos: Vec<String> = version_map
        .into_iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, _)| name)
        .collect();
    silos.sort();
    silos
}

/// Collect `name → version` entries from a `Cargo.toml` content string into `map`.
///
/// Skips `workspace = true` stubs and wildcard (`"*"`) version specs so that
/// workspace-level pin omissions do not spuriously inflate the silo count.
fn collect_cargo_versions(content: &str, map: &mut HashMap<String, HashSet<String>>) {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return;
    };
    for section in &["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(table) = val.get(section).and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, spec) in table {
            if name == "workspace" {
                continue;
            }
            let version = match spec {
                toml::Value::String(s) => s.clone(),
                toml::Value::Table(t) => {
                    // workspace = true stubs have no version field — skip.
                    if t.get("workspace")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    t.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_owned()
                }
                _ => "*".to_owned(),
            };
            if version != "*" && !version.is_empty() {
                map.entry(name.clone()).or_default().insert(version);
            }
        }
    }
}

/// Collect `name → version` entries from a `package.json` content string into `map`.
fn collect_npm_versions(content: &str, map: &mut HashMap<String, HashSet<String>>) {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(obj) = json.as_object() else {
        return;
    };
    for section in &["dependencies", "devDependencies"] {
        if let Some(deps) = obj.get(*section).and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let v = version.as_str().unwrap_or("*").to_owned();
                if v != "*" && !v.is_empty() {
                    map.entry(name.clone()).or_default().insert(v);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lockfile-based resolved version silo detection
// ---------------------------------------------------------------------------

/// A crate that appears at multiple distinct resolved versions in `Cargo.lock`.
///
/// Returned by [`find_version_silos_from_lockfile`].  Each entry represents a crate
/// whose version was resolved differently across workspace members — a dependency graph
/// split that increases binary size and can introduce subtle API incompatibilities.
pub struct CrateVersionSilo {
    /// Crate name (e.g. `"serde"`).
    pub name: String,
    /// All distinct resolved versions, sorted ascending (e.g. `["1.0.100", "1.0.200"]`).
    pub versions: Vec<String>,
}

impl CrateVersionSilo {
    /// Format for antipattern display: `"serde (v1.0.100 vs v1.0.200)"`.
    pub fn display(&self) -> String {
        let vs = self
            .versions
            .iter()
            .map(|v| format!("v{v}"))
            .collect::<Vec<_>>()
            .join(" vs ");
        format!("{} ({})", self.name, vs)
    }
}

/// Scan the `Cargo.lock` blob present in the PR diff and return every crate
/// that appears at more than one distinct resolved version **and was not already
/// a version-split on the base branch**.
///
/// ## Why the lockfile — not `cargo metadata`
/// `cargo metadata` invokes a subprocess that reads the **physical disk**.  In the
/// hyper-drive path the entire merge is simulated in-memory via `simulate_merge`
/// and the resulting `Cargo.lock` content lives in the `MergeSnapshot.blobs`
/// HashMap — the disk has not been touched.  Reading from the in-memory blob is
/// both faster and architecturally correct: we analyse the graph as it would exist
/// **after** the PR merges, not as it exists on the working tree today.
///
/// ## Delta logic — base subtraction
/// `base_lock` should be the raw bytes of the **base** `Cargo.lock` (the lockfile
/// at the merge-base commit, before this PR).  When provided, any crate that was
/// already showing a version split on the base branch is **excluded** from the
/// result.  Only silos that are genuinely *introduced* by this PR are returned.
///
/// Pass `None` when no base lockfile is available (e.g. patch-mode bounce where
/// only unified-diff `+` lines are in `blobs`).  In that case all silos found in
/// the head lockfile are returned — callers must accept the possibility of false
/// positives from pre-existing splits.
///
/// ## When it fires
/// Only when the PR diff includes a `Cargo.lock` modification.  If the lock file
/// is unchanged the PR cannot introduce new version splits, so no detection is
/// needed and an empty `Vec` is returned.
pub fn find_version_silos_from_lockfile(
    blobs: &HashMap<PathBuf, Vec<u8>>,
    base_lock: Option<&[u8]>,
) -> Vec<CrateVersionSilo> {
    // Find the head Cargo.lock blob (only present when the PR modifies it).
    let head_content = blobs.iter().find_map(|(path, bytes)| {
        if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock") {
            std::str::from_utf8(bytes).ok()
        } else {
            None
        }
    });

    let Some(head_content) = head_content else {
        return Vec::new();
    };

    let head_silos = parse_lockfile_silos(head_content);
    if head_silos.is_empty() {
        return Vec::new();
    }

    // Delta: build the set of crate names that were ALREADY a version-split on
    // the base branch.  Any silo whose name appears here is pre-existing — it
    // was not introduced by this PR — and must be excluded from the result.
    let pre_existing: HashSet<String> = base_lock
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(parse_lockfile_silos)
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.name)
        .collect();

    head_silos
        .into_iter()
        .filter(|s| !pre_existing.contains(&s.name))
        .collect()
}

/// Parse a `Cargo.lock` TOML string and return every crate present at more
/// than one distinct version.
///
/// Cargo.lock uses a `[[package]]` array; each entry has `name` and `version`
/// string fields.  Two entries with the same `name` but different `version`
/// values represent a true multi-version dependency split.
fn parse_lockfile_silos(content: &str) -> Vec<CrateVersionSilo> {
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return Vec::new();
    };
    let Some(packages) = val.get("package").and_then(|p| p.as_array()) else {
        return Vec::new();
    };

    let mut version_map: HashMap<String, HashSet<String>> = HashMap::new();
    for pkg in packages {
        let Some(table) = pkg.as_table() else {
            continue;
        };
        let name = table
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_default();
        let version = table
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !name.is_empty() && !version.is_empty() {
            version_map
                .entry(name.to_owned())
                .or_default()
                .insert(version.to_owned());
        }
    }

    let mut silos: Vec<CrateVersionSilo> = version_map
        .into_iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, versions)| {
            let mut v: Vec<String> = versions.into_iter().collect();
            v.sort();
            CrateVersionSilo { name, versions: v }
        })
        .collect();
    silos.sort_by(|a, b| a.name.cmp(&b.name));
    silos
}

// ---------------------------------------------------------------------------
// Phantom call detection (Model Decay Detector)
// ---------------------------------------------------------------------------

/// PR-scoped phantom call detector — Model Decay signal.
///
/// Cross-references standalone function call sites in the PR's added lines
/// against the base-branch [`common::registry::SymbolRegistry`].  A call is a
/// **phantom hallucination** when:
///
/// 1. The callee name is absent from `registry` (not a known symbol in the base branch).
/// 2. The callee name is not introduced by a function definition anywhere in the current diff.
/// 3. The name meets the complexity threshold (≥ 8 characters, contains `_`) that
///    distinguishes project-specific identifiers from single-word stdlib calls.
///
/// This is the structural signature of AI context-collapse: the model generates a call to a
/// function it hallucinated — neither importing it from an external crate nor defining it in
/// the current PR.  The callee resolves to nothing at compile time yet passes superficial
/// review because the name is plausible.
///
/// **Performance**: O(B + R) where B = total bytes in `blobs` and R = registry entry count.
/// No filesystem access — operates entirely on the in-memory blob map from
/// [`forge::slop_filter::extract_patch_blobs`].
///
/// Returns a sorted `Vec` of callee names flagged as phantoms.  Empty when the registry
/// is absent, no suspicious calls are detected, or the diff contains no analysable source files.
pub fn find_phantom_calls(
    blobs: &HashMap<PathBuf, Vec<u8>>,
    registry: &common::registry::SymbolRegistry,
) -> Vec<String> {
    if registry.entries.is_empty() {
        return Vec::new();
    }

    // Build the base-branch symbol name set for O(1) membership testing.
    let known: HashSet<&str> = registry.entries.iter().map(|e| e.name.as_str()).collect();

    // Pass 1: collect every function name *defined* anywhere in this diff so that
    // a call to a function introduced by the same PR is not flagged.
    let mut defined_in_diff: HashSet<String> = HashSet::new();
    for (path, bytes) in blobs {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !is_source_ext(ext) || bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(src) = std::str::from_utf8(bytes) else {
            continue;
        };
        phantom_extract_defined(src, &mut defined_in_diff);
    }

    // Pass 2: collect every standalone call site in the diff.
    let mut calls: HashSet<String> = HashSet::new();
    for (path, bytes) in blobs {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !is_source_ext(ext) || bytes.len() > 4 * 1024 * 1024 {
            continue;
        }
        let Ok(src) = std::str::from_utf8(bytes) else {
            continue;
        };
        phantom_extract_calls(src, &mut calls);
    }

    // Phantom = called AND (not in base registry) AND (not defined in this diff).
    let mut phantoms: Vec<String> = calls
        .into_iter()
        .filter(|name| !known.contains(name.as_str()) && !defined_in_diff.contains(name))
        .collect();
    phantoms.sort();
    phantoms
}

/// Extract function/method definition names from blob content.
///
/// Recognises:
/// - Rust: `fn`, `pub fn`, `async fn`, `pub async fn`
/// - Python: `def`
/// - Go: `func`
/// - JavaScript/TypeScript: `function`, `async function`
fn phantom_extract_defined(src: &str, out: &mut HashSet<String>) {
    for line in src.lines() {
        let trimmed = line.trim();
        // Check longest prefixes first to avoid `fn` matching inside `async fn`.
        for prefix in &[
            "pub async fn ",
            "pub fn ",
            "async fn ",
            "fn ",
            "async function ",
            "function ",
            "def ",
            "func ",
        ] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                if let Some(name) = phantom_leading_ident(rest) {
                    out.insert(name.to_owned());
                }
                break;
            }
        }
    }
}

/// Extract standalone function call names from blob content.
///
/// Scans byte-by-byte for `identifier(` patterns.  Filters out:
/// - Names shorter than 8 characters (stdlib noise: `len`, `push`, `unwrap`, etc.)
/// - Names without an underscore (project functions are typically snake_case)
/// - Language keywords and common builtins
/// - Calls preceded by `::` (associated functions on external types)
/// - Calls preceded by `.` (method chains on external types)
fn phantom_extract_calls(src: &str, out: &mut HashSet<String>) {
    let bytes = src.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' && i > 0 {
            // Walk backwards past any whitespace between the name and `(`.
            let mut j = i - 1;
            while j > 0 && bytes[j] == b' ' {
                j -= 1;
            }
            let end = j + 1;
            // Collect the identifier characters preceding `(`.
            while j > 0 && is_phantom_ident_byte(bytes[j - 1]) {
                j -= 1;
            }
            if j < end {
                // Skip calls that are path-qualified (`Foo::bar(`) or method chains (`.bar(`).
                let preceded_by_colons = j >= 2 && bytes[j - 1] == b':' && bytes[j - 2] == b':';
                let preceded_by_dot = j >= 1 && bytes[j - 1] == b'.';
                if !preceded_by_colons && !preceded_by_dot {
                    if let Ok(name) = std::str::from_utf8(&bytes[j..end]) {
                        if phantom_is_candidate(name) {
                            out.insert(name.to_owned());
                        }
                    }
                }
            }
        }
        i += 1;
    }
}

/// Returns `true` for bytes that can appear inside an identifier.
#[inline]
fn is_phantom_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Extract the leading identifier from a string (skips leading non-ident chars).
fn phantom_leading_ident(s: &str) -> Option<&str> {
    let bytes = s.as_bytes();
    let start = bytes
        .iter()
        .position(|&b| b.is_ascii_alphabetic() || b == b'_')?;
    let end = bytes[start..]
        .iter()
        .position(|&b| !b.is_ascii_alphanumeric() && b != b'_')
        .map(|n| start + n)
        .unwrap_or(bytes.len());
    let name = &s[start..end];
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Returns `true` when a callee name is a plausible phantom hallucination candidate.
///
/// Thresholds are chosen to exclude stdlib and single-word builtins while
/// retaining multi-word project-specific identifiers that AI models are known to
/// hallucinate (e.g. `validate_user_token`, `parse_config_payload`).
fn phantom_is_candidate(name: &str) -> bool {
    // Minimum length: excludes `unwrap`, `clone`, `collect`, etc.
    if name.len() < 8 {
        return false;
    }
    // Must contain at least one underscore: project functions are snake_case.
    if !name.contains('_') {
        return false;
    }
    // All-uppercase: likely a constant or macro (e.g. `MAX_RETRIES`).
    if name.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
        return false;
    }
    // Language keywords and high-frequency builtins that take `(` arguments.
    !phantom_is_keyword(name)
}

/// Returns `true` for keywords and high-frequency builtins that appear before `(`.
fn phantom_is_keyword(name: &str) -> bool {
    matches!(
        name,
        "assert_eq"
            | "assert_ne"
            | "debug_assert"
            | "write_all"
            | "read_line"
            | "read_to_string"
            | "from_utf8"
            | "to_string"
            | "from_str"
            | "into_iter"
            | "to_owned"
            | "to_vec"
            | "vec_deque"
            | "hash_map"
            | "hash_set"
            | "btree_map"
            | "btree_set"
    )
}

// ---------------------------------------------------------------------------
// Git-ref dependency extractor (P1-4 — Repojacking Pre-Flight)
// ---------------------------------------------------------------------------

/// Pinning class of a git-sourced dependency reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    /// Pinned to a specific commit SHA (safe against force-push squatting).
    CommitSha(String),
    /// Pinned to a named branch (mutable — attacker can push after squatting).
    Branch(String),
    /// Pinned to a tag (stable by convention but deletable; not flagged here).
    Tag(String),
    /// No explicit ref; defaults to HEAD (most dangerous).
    Head,
}

impl RefKind {
    /// Returns `true` when the ref is mutable and attackers can update it
    /// after squatting the GitHub account.
    pub fn is_mutable(&self) -> bool {
        matches!(self, RefKind::Branch(_) | RefKind::Head)
    }

    /// Human-readable label for inclusion in finding descriptions.
    pub fn label(&self) -> String {
        match self {
            RefKind::CommitSha(s) => format!("commit:{}", &s[..s.len().min(12)]),
            RefKind::Branch(b) => format!("branch:{b}"),
            RefKind::Tag(t) => format!("tag:{t}"),
            RefKind::Head => "HEAD".to_string(),
        }
    }
}

/// A dependency resolved via a direct git URL or replace directive.
#[derive(Debug, Clone)]
pub struct GitRefDependency {
    /// Manifest file this was extracted from (relative or absolute path).
    pub manifest_file: String,
    /// Package / crate / gem name.
    pub package_name: String,
    /// Resolved git HTTPS or SSH URL.
    pub source_url: String,
    /// Ref pinning class.
    pub ref_kind: RefKind,
}

/// Seed corpus of known-squatted GitHub usernames (refreshed via update-wisdom).
const KNOWN_SQUATTED_USERNAMES: &[&str] = &[];

fn extract_github_username(url: &str) -> Option<&str> {
    let url = url.trim_end_matches(".git");
    for prefix in &[
        "https://github.com/",
        "http://github.com/",
        "git+https://github.com/",
        "git+ssh://github.com/",
        "git+ssh://git@github.com/",
        "ssh://git@github.com/",
        "git@github.com:",
    ] {
        if let Some(rest) = url.strip_prefix(prefix) {
            return rest.split('/').next().filter(|u| !u.is_empty());
        }
    }
    None
}

fn is_commit_sha_like(s: &str) -> bool {
    s.len() >= 12 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns `true` when `version` is a go.mod pseudo-version with a 12-char
/// hex commit hash suffix, e.g. `v0.0.0-20260101000000-deadbeefcafe`.
fn is_go_pseudo_version(version: &str) -> bool {
    let parts: Vec<&str> = version.rsplitn(2, '-').collect();
    parts
        .first()
        .is_some_and(|s| s.len() == 12 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Extract git-ref dependencies from all manifest blobs in a PR diff.
pub fn find_git_ref_deps_in_blobs(blobs: &HashMap<PathBuf, Vec<u8>>) -> Vec<GitRefDependency> {
    let mut deps = Vec::new();
    for (path, bytes) in blobs {
        let Ok(content) = std::str::from_utf8(bytes) else {
            continue;
        };
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        match filename {
            GO_MOD => parse_go_mod_git_refs(path, content, &mut deps),
            CARGO_MANIFEST => parse_cargo_toml_git_refs(path, content, &mut deps),
            NPM_MANIFEST => parse_package_json_git_refs(path, content, &mut deps),
            PIP_PYPROJECT => parse_pyproject_toml_git_refs(path, content, &mut deps),
            GEMFILE => parse_gemfile_git_refs(path, content, &mut deps),
            _ => {}
        }
    }
    deps
}

/// Convert a `GitRefDependency` slice into `SlopFinding`s.
///
/// Mutable refs (`branch` / `HEAD`) emit `security:unpinned_git_dependency` at
/// `Critical`.  Dependencies whose GitHub username matches the known-squatted
/// corpus emit `security:repojacking_window` at `KevCritical`.
pub fn emit_git_ref_dep_findings(deps: &[GitRefDependency]) -> Vec<SlopFinding> {
    let mut findings = Vec::new();
    for dep in deps {
        if dep.ref_kind.is_mutable() {
            findings.push(SlopFinding {
                start_byte: 0,
                end_byte: 0,
                description: format!(
                    "supply_chain:unpinned_git_dependency — `{}` in `{}` pins to \
                     mutable ref `{}` ({}); an attacker who squats the repository \
                     can push arbitrary code to this ref",
                    dep.package_name,
                    dep.manifest_file,
                    dep.source_url,
                    dep.ref_kind.label()
                ),
                domain: forge::metadata::DOMAIN_ALL,
                severity: Severity::Critical,
            });
        }
        if let Some(username) = extract_github_username(&dep.source_url) {
            if KNOWN_SQUATTED_USERNAMES.contains(&username) {
                findings.push(SlopFinding {
                    start_byte: 0,
                    end_byte: 0,
                    description: format!(
                        "supply_chain:repojacking_window — `{}` in `{}` references \
                         GitHub username `{username}` which is in the known-squatted \
                         username corpus; source: {}",
                        dep.package_name, dep.manifest_file, dep.source_url
                    ),
                    domain: forge::metadata::DOMAIN_ALL,
                    severity: Severity::KevCritical,
                });
            }
        }
    }
    findings
}

/// Wrap every Critical+ git-ref finding in a `GovernanceProof` capsule.
pub fn emit_git_ref_governance_proofs(
    deps: &[GitRefDependency],
) -> Vec<common::receipt::GovernanceProof> {
    deps.iter()
        .filter(|d| {
            d.ref_kind.is_mutable()
                || extract_github_username(&d.source_url)
                    .is_some_and(|u| KNOWN_SQUATTED_USERNAMES.contains(&u))
        })
        .map(|dep| {
            let is_squatted = extract_github_username(&dep.source_url)
                .is_some_and(|u| KNOWN_SQUATTED_USERNAMES.contains(&u));
            let (id, sev) = if is_squatted {
                ("supply_chain:repojacking_window", "KevCritical")
            } else {
                ("supply_chain:unpinned_git_dependency", "Critical")
            };
            let finding = common::slop::StructuredFinding {
                id: id.to_string(),
                file: Some(dep.manifest_file.clone()),
                severity: Some(sev.to_string()),
                remediation: Some(format!(
                    "Pin `{}` to a specific commit SHA instead of mutable ref `{}`",
                    dep.package_name,
                    dep.ref_kind.label()
                )),
                ..Default::default()
            };
            common::receipt::GovernanceProof {
                finding,
                taint_chain: Some(vec![
                    dep.source_url.clone(),
                    format!("ref:{}", dep.ref_kind.label()),
                    dep.package_name.clone(),
                    "build_graph \u{2192} CI_execution \u{2192} deployed_artifact".to_string(),
                ]),
                sealed_receipt: None,
            }
        })
        .collect()
}

// go.mod replace directives.
fn parse_go_mod_git_refs(path: &Path, content: &str, deps: &mut Vec<GitRefDependency>) {
    let manifest_file = path.to_string_lossy().to_string();
    let mut in_block = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "replace (" {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let effective = if in_block {
            line
        } else if let Some(rest) = line.strip_prefix("replace ") {
            rest.trim()
        } else {
            continue;
        };

        let Some(arrow) = effective.find(" => ") else {
            continue;
        };
        let rhs = effective[arrow + 4..].trim();
        // Skip local-path replacements
        if rhs.starts_with('.') || rhs.starts_with('/') {
            continue;
        }
        let parts: Vec<&str> = rhs.splitn(2, ' ').collect();
        let target_path = parts[0];
        let version = parts.get(1).map(|s| s.trim()).unwrap_or("");

        if !target_path.starts_with("github.com/") && !target_path.starts_with("gitlab.com/") {
            continue;
        }
        let source_url = format!("https://{target_path}");

        let ref_kind = if version.is_empty() {
            RefKind::Head
        } else if is_go_pseudo_version(version) {
            let sha = version.rsplit('-').next().unwrap_or("").to_string();
            RefKind::CommitSha(sha)
        } else if version.starts_with('v') && version.chars().filter(|&c| c == '.').count() >= 2 {
            // Looks like a proper semver tag — not mutable by our definition
            RefKind::Tag(version.to_string())
        } else {
            // Non-standard version string (e.g. branch-derived pseudo-version)
            RefKind::Branch(version.to_string())
        };

        let pkg_name = effective[..arrow]
            .trim()
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string();

        deps.push(GitRefDependency {
            manifest_file: manifest_file.clone(),
            package_name: pkg_name,
            source_url,
            ref_kind,
        });
    }
}

// Cargo.toml [patch."url"] git entries.
fn parse_cargo_toml_git_refs(path: &Path, content: &str, deps: &mut Vec<GitRefDependency>) {
    let manifest_file = path.to_string_lossy().to_string();
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return;
    };
    let Some(patch) = val.get("patch").and_then(|p| p.as_table()) else {
        return;
    };
    for (_patch_url, entries) in patch {
        let Some(table) = entries.as_table() else {
            continue;
        };
        for (pkg_name, spec) in table {
            let Some(spec_t) = spec.as_table() else {
                continue;
            };
            let Some(git_url) = spec_t.get("git").and_then(|v| v.as_str()) else {
                continue;
            };
            // `rev =` is always an immutable pin regardless of SHA format.
            // Only `branch =` or a missing pin is mutable.
            let ref_kind = if let Some(rev) = spec_t.get("rev").and_then(|v| v.as_str()) {
                RefKind::CommitSha(rev.to_string())
            } else if let Some(b) = spec_t.get("branch").and_then(|v| v.as_str()) {
                RefKind::Branch(b.to_string())
            } else if let Some(t) = spec_t.get("tag").and_then(|v| v.as_str()) {
                RefKind::Tag(t.to_string())
            } else {
                RefKind::Head
            };
            deps.push(GitRefDependency {
                manifest_file: manifest_file.clone(),
                package_name: pkg_name.clone(),
                source_url: git_url.to_string(),
                ref_kind,
            });
        }
    }
}

// package.json git+ and github: URL dependencies.
fn parse_package_json_git_refs(path: &Path, content: &str, deps: &mut Vec<GitRefDependency>) {
    let manifest_file = path.to_string_lossy().to_string();
    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return;
    };
    let Some(obj) = json.as_object() else {
        return;
    };
    for section in &["dependencies", "devDependencies"] {
        let Some(dep_obj) = obj.get(*section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (pkg_name, version_val) in dep_obj {
            let Some(v) = version_val.as_str() else {
                continue;
            };
            let (url, fragment) = if let Some(rest) = v
                .strip_prefix("git+https://")
                .or_else(|| v.strip_prefix("git+ssh://git@"))
                .or_else(|| v.strip_prefix("git+ssh://"))
                .or_else(|| v.strip_prefix("git://"))
            {
                let (u, f) = rest
                    .split_once('#')
                    .map(|(a, b)| (format!("https://{a}"), Some(b.to_string())))
                    .unwrap_or_else(|| (format!("https://{rest}"), None));
                (u, f)
            } else if let Some(gh) = v.strip_prefix("github:") {
                let (u, f) = gh
                    .split_once('#')
                    .map(|(a, b)| (format!("https://github.com/{a}"), Some(b.to_string())))
                    .unwrap_or_else(|| (format!("https://github.com/{gh}"), None));
                (u, f)
            } else {
                continue;
            };

            let ref_kind = match fragment.as_deref() {
                Some(f) if is_commit_sha_like(f) => RefKind::CommitSha(f.to_string()),
                Some(f) => RefKind::Branch(f.to_string()),
                None => RefKind::Head,
            };
            deps.push(GitRefDependency {
                manifest_file: manifest_file.clone(),
                package_name: pkg_name.clone(),
                source_url: url,
                ref_kind,
            });
        }
    }
}

// pyproject.toml Poetry git dependencies.
fn parse_pyproject_toml_git_refs(path: &Path, content: &str, deps: &mut Vec<GitRefDependency>) {
    let manifest_file = path.to_string_lossy().to_string();
    let Ok(val) = toml::from_str::<toml::Value>(content) else {
        return;
    };
    for section in &["dependencies", "dev-dependencies"] {
        let Some(table) = val
            .get("tool")
            .and_then(|t| t.get("poetry"))
            .and_then(|p| p.get(section))
            .and_then(|d| d.as_table())
        else {
            continue;
        };
        for (pkg_name, spec) in table {
            if pkg_name == "python" {
                continue;
            }
            let Some(spec_t) = spec.as_table() else {
                continue;
            };
            let Some(git_url) = spec_t.get("git").and_then(|v| v.as_str()) else {
                continue;
            };
            // `rev =` is always an immutable pin regardless of SHA format.
            let ref_kind = if let Some(rev) = spec_t.get("rev").and_then(|v| v.as_str()) {
                RefKind::CommitSha(rev.to_string())
            } else if let Some(b) = spec_t.get("branch").and_then(|v| v.as_str()) {
                RefKind::Branch(b.to_string())
            } else if let Some(t) = spec_t.get("tag").and_then(|v| v.as_str()) {
                RefKind::Tag(t.to_string())
            } else {
                RefKind::Head
            };
            deps.push(GitRefDependency {
                manifest_file: manifest_file.clone(),
                package_name: pkg_name.clone(),
                source_url: git_url.to_string(),
                ref_kind,
            });
        }
    }
}

// Gemfile git / github option parsing.
fn parse_gemfile_git_refs(path: &Path, content: &str, deps: &mut Vec<GitRefDependency>) {
    let manifest_file = path.to_string_lossy().to_string();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("gem ") else {
            continue;
        };
        let Some(pkg_name) = ruby_string_value(rest) else {
            continue;
        };
        let (source_url, ref_kind) = if let Some(git_url) = ruby_option_value(trimmed, "git:") {
            let rk = if let Some(r) = ruby_option_value(trimmed, "ref:") {
                if is_commit_sha_like(&r) {
                    RefKind::CommitSha(r)
                } else {
                    RefKind::Branch(r)
                }
            } else if let Some(b) = ruby_option_value(trimmed, "branch:") {
                RefKind::Branch(b)
            } else if let Some(t) = ruby_option_value(trimmed, "tag:") {
                RefKind::Tag(t)
            } else {
                RefKind::Head
            };
            (git_url, rk)
        } else if let Some(gh) = ruby_option_value(trimmed, "github:") {
            (format!("https://github.com/{gh}"), RefKind::Head)
        } else {
            continue;
        };
        deps.push(GitRefDependency {
            manifest_file: manifest_file.clone(),
            package_name: pkg_name,
            source_url,
            ref_kind,
        });
    }
}

fn ruby_string_value(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('\'') {
        inner.split_once('\'').map(|(v, _)| v.to_string())
    } else if let Some(inner) = s.strip_prefix('"') {
        inner.split_once('"').map(|(v, _)| v.to_string())
    } else {
        None
    }
}

fn ruby_option_value(line: &str, key: &str) -> Option<String> {
    let pos = line.find(key)?;
    let rest = line[pos + key.len()..].trim_start();
    ruby_string_value(rest).filter(|s| !s.is_empty())
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

    #[test]
    fn test_version_silo_detected_across_cargo_tomls() {
        // Two Cargo.toml blobs with serde at different versions → silo.
        let crate_a = r#"
[package]
name = "crate-a"
[dependencies]
serde = "1.0.100"
tokio = "1.20"
"#;
        let crate_b = r#"
[package]
name = "crate-b"
[dependencies]
serde = "1.0.200"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("crate-a/Cargo.toml"),
            crate_a.as_bytes().to_vec(),
        );
        blobs.insert(
            PathBuf::from("crate-b/Cargo.toml"),
            crate_b.as_bytes().to_vec(),
        );

        let silos = find_version_silos_in_blobs(&blobs);
        assert_eq!(silos, vec!["serde"], "serde appears at two versions → silo");
    }

    #[test]
    fn test_no_silo_when_single_version() {
        let cargo = r#"
[package]
name = "x"
[dependencies]
serde = "1.0.200"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.toml"), cargo.as_bytes().to_vec());

        let silos = find_version_silos_in_blobs(&blobs);
        assert!(silos.is_empty(), "single version → no silo");
    }

    #[test]
    fn test_version_silo_npm() {
        let pkg_a = serde_json::json!({
            "dependencies": { "lodash": "^4.17.20" }
        });
        let pkg_b = serde_json::json!({
            "dependencies": { "lodash": "^4.17.21" }
        });
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("pkg-a/package.json"),
            pkg_a.to_string().into_bytes(),
        );
        blobs.insert(
            PathBuf::from("pkg-b/package.json"),
            pkg_b.to_string().into_bytes(),
        );

        let silos = find_version_silos_in_blobs(&blobs);
        assert_eq!(silos, vec!["lodash"], "lodash at two versions → npm silo");
    }

    #[test]
    fn test_workspace_stub_excluded_from_silo() {
        // workspace = true stubs should not be counted as a pinned version.
        let workspace_member = r#"
[package]
name = "member"
[dependencies]
serde = { workspace = true }
"#;
        let root = r#"
[workspace]
[dependencies]
serde = "1.0.200"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("member/Cargo.toml"),
            workspace_member.as_bytes().to_vec(),
        );
        blobs.insert(PathBuf::from("Cargo.toml"), root.as_bytes().to_vec());

        let silos = find_version_silos_in_blobs(&blobs);
        assert!(
            silos.is_empty(),
            "workspace stub should not create a silo with the root pin"
        );
    }

    #[test]
    fn test_lockfile_silo_detected() {
        // Cargo.lock with serde at two resolved versions — hard split.
        let lockfile = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aabbcc"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ddeeff"

[[package]]
name = "tokio"
version = "1.20.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "112233"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.lock"), lockfile.as_bytes().to_vec());

        let silos = find_version_silos_from_lockfile(&blobs, None);
        assert_eq!(silos.len(), 1, "one crate at two versions");
        assert_eq!(silos[0].name, "serde");
        assert_eq!(silos[0].versions, vec!["1.0.100", "1.0.200"]);
        assert_eq!(silos[0].display(), "serde (v1.0.100 vs v1.0.200)");
    }

    #[test]
    fn test_lockfile_no_silo_when_all_unique() {
        let lockfile = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "tokio"
version = "1.20.0"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.lock"), lockfile.as_bytes().to_vec());

        let silos = find_version_silos_from_lockfile(&blobs, None);
        assert!(silos.is_empty(), "all crates at single version → no silo");
    }

    #[test]
    fn test_lockfile_absent_returns_empty() {
        // No Cargo.lock in the blobs at all.
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("Cargo.toml"),
            b"[package]\nname = \"x\"\n".to_vec(),
        );

        let silos = find_version_silos_from_lockfile(&blobs, None);
        assert!(silos.is_empty(), "no Cargo.lock blob → empty result");
    }

    #[test]
    fn test_lockfile_multiple_silos_sorted() {
        let lockfile = r#"
version = 4

[[package]]
name = "toml"
version = "1.1.0"

[[package]]
name = "toml"
version = "1.0.6"

[[package]]
name = "anyhow"
version = "1.0.80"

[[package]]
name = "anyhow"
version = "1.0.75"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.lock"), lockfile.as_bytes().to_vec());

        let silos = find_version_silos_from_lockfile(&blobs, None);
        assert_eq!(silos.len(), 2);
        // Sorted by name: anyhow < toml.
        assert_eq!(silos[0].name, "anyhow");
        assert_eq!(silos[1].name, "toml");
        assert_eq!(silos[1].display(), "toml (v1.0.6 vs v1.1.0)");
    }

    #[test]
    fn test_lockfile_delta_suppresses_preexisting_silo() {
        // Base already has serde at two versions — the PR must NOT be blamed.
        let base_lock = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "serde"
version = "1.0.200"
"#;
        // Head lockfile: serde silo unchanged, but a NEW toml silo appears.
        let head_lock = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "toml"
version = "1.0.6"

[[package]]
name = "toml"
version = "1.1.0"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.lock"), head_lock.as_bytes().to_vec());

        let silos = find_version_silos_from_lockfile(&blobs, Some(base_lock.as_bytes()));
        // serde was pre-existing → suppressed.  Only toml (new) is returned.
        assert_eq!(silos.len(), 1, "pre-existing serde silo must be suppressed");
        assert_eq!(silos[0].name, "toml");
        assert_eq!(silos[0].display(), "toml (v1.0.6 vs v1.1.0)");
    }

    #[test]
    fn test_lockfile_delta_no_base_returns_all_silos() {
        // When base_lock is None the function must return all head silos (no delta).
        let head_lock = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.100"

[[package]]
name = "serde"
version = "1.0.200"
"#;
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.lock"), head_lock.as_bytes().to_vec());

        let silos = find_version_silos_from_lockfile(&blobs, None);
        assert_eq!(silos.len(), 1, "with no base, all head silos returned");
        assert_eq!(silos[0].name, "serde");
    }

    fn write_wisdom_file(
        dir: &tempfile::TempDir,
        rules: Vec<common::wisdom::KevDependencyRule>,
    ) -> std::path::PathBuf {
        let path = dir.path().join("wisdom.rkyv");
        let mut wisdom = common::wisdom::WisdomSet {
            kev_dependency_rules: rules,
            ..Default::default()
        };
        wisdom.sort();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wisdom).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn test_check_kev_deps_detects_exact_version_match() {
        let dir = tempfile::tempdir().unwrap();
        let wisdom_path = write_wisdom_file(
            &dir,
            vec![common::wisdom::KevDependencyRule {
                package_name: "serde".into(),
                ecosystem: DependencyEcosystem::Cargo,
                cve_id: "CVE-2026-9999".into(),
                affected_versions: vec!["1.0.150".into()],
                summary: "synthetic regression fixture".into(),
            }],
        );
        let lockfile = br#"
version = 4

[[package]]
name = "serde"
version = "1.0.150"
"#;

        let findings = check_kev_deps(lockfile, &wisdom_path);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::KevCritical);
        assert!(
            findings[0]
                .description
                .contains("supply_chain:kev_dependency"),
            "category prefix must be preserved"
        );
        assert!(
            findings[0].description.contains("CVE-2026-9999"),
            "CVE identifier must be present in the finding"
        );
    }

    #[test]
    fn test_check_kev_deps_detects_semver_range_match() {
        let dir = tempfile::tempdir().unwrap();
        let wisdom_path = write_wisdom_file(
            &dir,
            vec![common::wisdom::KevDependencyRule {
                package_name: "tokio".into(),
                ecosystem: DependencyEcosystem::Cargo,
                cve_id: "CVE-2026-1111".into(),
                affected_versions: vec![">=1.20.0, <1.30.0".into()],
                summary: String::new(),
            }],
        );
        let lockfile = br#"
version = 4

[[package]]
name = "tokio"
version = "1.25.0"
"#;

        let findings = check_kev_deps(lockfile, &wisdom_path);
        assert_eq!(
            findings.len(),
            1,
            "semver range should match resolved version"
        );
    }

    #[test]
    fn test_check_kev_deps_legacy_wisdom_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let legacy = common::wisdom::LegacyWisdomSet::default();
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&legacy).unwrap();
        let wisdom_path = dir.path().join("wisdom.rkyv");
        std::fs::write(&wisdom_path, bytes).unwrap();

        let lockfile = br#"
version = 4

[[package]]
name = "serde"
version = "1.0.150"
"#;

        assert!(
            check_kev_deps(lockfile, &wisdom_path).is_empty(),
            "legacy wisdom archive without KEV rules must not emit findings"
        );
    }

    #[test]
    fn test_check_kev_deps_required_fails_when_only_manifest_exists() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).unwrap();
        std::fs::write(
            janitor_dir.join("wisdom_manifest.json"),
            br#"{"entry_count":1,"entries":[{"cve_id":"CVE-2026-9999"}]}"#,
        )
        .unwrap();

        let lockfile = br#"
version = 4

[[package]]
name = "serde"
version = "1.0.150"
"#;

        let err = check_kev_deps_required(lockfile, &janitor_dir).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot replace package-version bindings"),
            "manifest-only KEV state must fail closed"
        );
    }

    // ── find_phantom_calls tests ─────────────────────────────────────────────

    fn make_registry(names: &[&str]) -> common::registry::SymbolRegistry {
        use common::registry::{SymbolEntry, SymbolRegistry};
        let mut r = SymbolRegistry::new();
        for (i, &name) in names.iter().enumerate() {
            r.insert(SymbolEntry {
                id: i as u64,
                name: name.to_owned(),
                qualified_name: name.to_owned(),
                file_path: "src/lib.rs".to_owned(),
                entity_type: 0,
                start_line: 1,
                end_line: 10,
                start_byte: 0,
                end_byte: 100,
                structural_hash: 0,
                protected_by: None,
            });
        }
        r
    }

    #[test]
    fn test_phantom_call_detected_when_absent_from_registry() {
        // Registry knows `process_payload`; diff calls `send_telemetry_data`
        // which neither exists in registry nor is defined in the diff.
        let registry = make_registry(&["process_payload", "validate_input"]);

        let src = b"\
fn process_payload(data: &[u8]) -> bool {
    // calls a helper that was hallucinated
    send_telemetry_data(data);
    true
}
";
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("src/handler.rs"), src.to_vec());

        let phantoms = find_phantom_calls(&blobs, &registry);
        assert!(
            phantoms.iter().any(|p| p == "send_telemetry_data"),
            "send_telemetry_data must be flagged as phantom; got: {phantoms:?}"
        );
    }

    #[test]
    fn test_phantom_call_not_flagged_when_defined_in_diff() {
        // `send_telemetry_data` is both called and defined in the same diff blob.
        let registry = make_registry(&["process_payload"]);

        let src = b"\
fn send_telemetry_data(data: &[u8]) {
    // implementation present in diff
}

fn process_payload(data: &[u8]) -> bool {
    send_telemetry_data(data);
    true
}
";
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("src/handler.rs"), src.to_vec());

        let phantoms = find_phantom_calls(&blobs, &registry);
        assert!(
            !phantoms.iter().any(|p| p == "send_telemetry_data"),
            "send_telemetry_data is defined in diff — must not be flagged; got: {phantoms:?}"
        );
    }

    #[test]
    fn test_phantom_call_not_flagged_when_in_registry() {
        let registry = make_registry(&["process_payload", "send_telemetry_data"]);

        let src = b"\
fn main() {
    send_telemetry_data(&[]);
    process_payload(&[]);
}
";
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("src/main.rs"), src.to_vec());

        let phantoms = find_phantom_calls(&blobs, &registry);
        assert!(
            phantoms.is_empty(),
            "both functions are in registry — no phantoms expected; got: {phantoms:?}"
        );
    }

    #[test]
    fn test_phantom_empty_registry_returns_no_phantoms() {
        let registry = common::registry::SymbolRegistry::new();

        let src = b"fn main() { some_unknown_function(); }\n";
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(PathBuf::from("src/main.rs"), src.to_vec());

        let phantoms = find_phantom_calls(&blobs, &registry);
        assert!(
            phantoms.is_empty(),
            "empty registry must short-circuit to no phantoms"
        );
    }

    // ── parse_pyproject_toml_content ─────────────────────────────────────

    #[test]
    fn test_parse_pyproject_toml_pep621() {
        let content = r#"
[project]
name = "my-app"
dependencies = [
    "requests>=2.28",
    "click>=8.0",
    "pydantic[dotenv]>=1.10",
]
"#;
        let mut registry = DependencyRegistry::new();
        parse_pyproject_toml_content(content, &mut registry);
        let names: Vec<_> = registry.entries.iter().map(|e| e.name.clone()).collect();
        assert!(
            names.contains(&"requests".to_owned()),
            "requests not found: {names:?}"
        );
        assert!(
            names.contains(&"click".to_owned()),
            "click not found: {names:?}"
        );
        assert!(
            names.contains(&"pydantic".to_owned()),
            "pydantic not found: {names:?}"
        );
    }

    #[test]
    fn test_parse_pyproject_toml_poetry() {
        let content = r#"
[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.28"
click = "^8.0"

[tool.poetry.dev-dependencies]
pytest = "^7.0"
"#;
        let mut registry = DependencyRegistry::new();
        parse_pyproject_toml_content(content, &mut registry);
        let names: Vec<_> = registry.entries.iter().map(|e| e.name.clone()).collect();
        // python is excluded by the parser
        assert!(
            !names.contains(&"python".to_owned()),
            "python must be filtered: {names:?}"
        );
        assert!(
            names.contains(&"requests".to_owned()),
            "requests not found: {names:?}"
        );
        assert!(
            names.contains(&"click".to_owned()),
            "click not found: {names:?}"
        );
        assert!(
            names.contains(&"pytest".to_owned()),
            "pytest not found: {names:?}"
        );
        // pytest should be marked as dev dep
        let pytest = registry
            .entries
            .iter()
            .find(|e| e.name == "pytest")
            .unwrap();
        assert!(pytest.dev, "pytest must be marked as dev dependency");
    }

    #[test]
    fn test_parse_pyproject_toml_empty_returns_empty() {
        let content = "[build-system]\nrequires = [\"setuptools\"]\n";
        let mut registry = DependencyRegistry::new();
        parse_pyproject_toml_content(content, &mut registry);
        assert!(
            registry.is_empty(),
            "no [project.dependencies] or [tool.poetry] → empty registry"
        );
    }

    // ── parse_shell_script_content ───────────────────────────────────────

    #[test]
    fn test_parse_shell_script_apt_get_install() {
        let content = "apt-get install -y curl git libssl-dev\n";
        let mut registry = DependencyRegistry::new();
        parse_shell_script_content(content, &mut registry);
        let names: Vec<_> = registry.entries.iter().map(|e| e.name.clone()).collect();
        assert!(
            names.contains(&"curl".to_owned()),
            "curl not found: {names:?}"
        );
        assert!(
            names.contains(&"git".to_owned()),
            "git not found: {names:?}"
        );
        assert!(
            names.contains(&"libssl-dev".to_owned()),
            "libssl-dev not found: {names:?}"
        );
        // flags must not be included
        assert!(
            !names.iter().any(|n| n.starts_with('-')),
            "flags must be filtered: {names:?}"
        );
    }

    #[test]
    fn test_parse_shell_script_brew_install() {
        let content = "brew install jq bc pandoc\n";
        let mut registry = DependencyRegistry::new();
        parse_shell_script_content(content, &mut registry);
        let names: Vec<_> = registry.entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&"jq".to_owned()), "jq not found: {names:?}");
        assert!(names.contains(&"bc".to_owned()), "bc not found: {names:?}");
        assert!(
            names.contains(&"pandoc".to_owned()),
            "pandoc not found: {names:?}"
        );
    }

    #[test]
    fn test_parse_shell_script_skips_comments_and_flags() {
        let content = "\
# Install build tools
apt-get install -y --no-install-recommends build-essential
# End of install block
";
        let mut registry = DependencyRegistry::new();
        parse_shell_script_content(content, &mut registry);
        let names: Vec<_> = registry.entries.iter().map(|e| e.name.clone()).collect();
        assert!(
            names.contains(&"build-essential".to_owned()),
            "build-essential not found: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.starts_with('-')),
            "flags/options must be filtered: {names:?}"
        );
    }

    #[test]
    fn test_parse_shell_script_no_install_returns_empty() {
        let content = "echo 'Hello, world!'\ncargo build --release\n";
        let mut registry = DependencyRegistry::new();
        parse_shell_script_content(content, &mut registry);
        assert!(
            registry.is_empty(),
            "no install commands → empty registry: {:?}",
            registry.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
    }

    // ── Git-ref dependency extractor (P1-4) ─────────────────────────────────

    #[test]
    fn test_go_mod_replace_without_version_emits_unpinned_git_dependency() {
        // A go.mod replace directive with no RHS version is a HEAD reference —
        // the mutable form the directive mandates we detect.
        let content = "\
module example.com/mymod\n\
\n\
go 1.21\n\
\n\
replace github.com/foo/bar => github.com/squatter/bar\n\
";
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("go.mod"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1, "one git-ref dep found in replace directive");
        assert_eq!(deps[0].package_name, "github.com/foo/bar");
        assert_eq!(deps[0].ref_kind, RefKind::Head, "no version → HEAD");

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "HEAD replace must emit unpinned_git_dependency; got: {:?}",
            findings.iter().map(|f| &f.description).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_go_mod_replace_with_sha_is_not_flagged() {
        // A replace with a valid pseudo-version (12-char hex at the end) is pinned.
        let content = "\
module example.com/mymod\n\
\n\
replace github.com/foo/bar v1.2.3 => github.com/safe/bar v0.0.0-20260101000000-deadbeefcafe\n\
";
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("go.mod"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1);
        assert!(
            !deps[0].ref_kind.is_mutable(),
            "SHA-pinned replace must not be mutable"
        );

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            !findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "SHA-pinned replace must not emit unpinned_git_dependency"
        );
    }

    #[test]
    fn test_package_json_branch_ref_emits_unpinned_git_dependency() {
        let pkg = serde_json::json!({
            "dependencies": {
                "my-lib": "git+https://github.com/foo/my-lib#main"
            }
        });
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("package.json"), pkg.to_string().into_bytes());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ref_kind, RefKind::Branch("main".to_string()));

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "branch ref must emit unpinned_git_dependency"
        );
    }

    #[test]
    fn test_package_json_sha_ref_not_flagged() {
        let sha = "a".repeat(40);
        let pkg = serde_json::json!({
            "dependencies": {
                "my-lib": format!("git+https://github.com/foo/my-lib#{sha}")
            }
        });
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("package.json"), pkg.to_string().into_bytes());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1);
        assert!(
            matches!(deps[0].ref_kind, RefKind::CommitSha(_)),
            "40-char hex must be CommitSha"
        );
        assert!(
            emit_git_ref_dep_findings(&deps)
                .iter()
                .all(|f| !f.description.contains("unpinned_git_dependency")),
            "SHA-pinned package.json dep must not emit unpinned_git_dependency"
        );
    }

    #[test]
    fn test_pyproject_toml_branch_dep_flagged() {
        let content = r#"
[tool.poetry.dependencies]
python = "^3.11"
my-lib = { git = "https://github.com/foo/my-lib", branch = "develop" }
"#;
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("pyproject.toml"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1, "one git dep found; python is skipped");
        assert_eq!(deps[0].ref_kind, RefKind::Branch("develop".to_string()));

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "develop branch must be flagged"
        );
    }

    #[test]
    fn test_gemfile_branch_dep_flagged() {
        let content = "gem 'my-gem', git: 'https://github.com/foo/my-gem', branch: 'main'\n";
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("Gemfile"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].ref_kind, RefKind::Branch("main".to_string()));

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "Gemfile branch dep must emit unpinned_git_dependency"
        );
    }

    #[test]
    fn test_cargo_toml_patch_branch_flagged() {
        let content = r#"
[package]
name = "my-crate"

[patch."https://github.com/foo/crate"]
my-crate = { git = "https://github.com/attacker/crate", branch = "main" }
"#;
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("Cargo.toml"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        assert_eq!(deps.len(), 1, "one patch entry found");
        assert_eq!(deps[0].ref_kind, RefKind::Branch("main".to_string()));

        let findings = emit_git_ref_dep_findings(&deps);
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_git_dependency")),
            "Cargo.toml patch branch must be flagged"
        );
    }

    #[test]
    fn test_governance_proof_wraps_mutable_ref_dep() {
        let content = "replace github.com/foo/bar => github.com/squatter/bar\n";
        let mut blobs = HashMap::new();
        blobs.insert(PathBuf::from("go.mod"), content.as_bytes().to_vec());

        let deps = find_git_ref_deps_in_blobs(&blobs);
        let proofs = emit_git_ref_governance_proofs(&deps);
        assert!(
            !proofs.is_empty(),
            "mutable HEAD replace must produce a governance proof"
        );
        assert!(
            proofs[0].is_critical_or_above(),
            "governance proof must be Critical or above"
        );
        assert!(
            proofs[0]
                .taint_chain
                .as_ref()
                .map_or(false, |c| !c.is_empty()),
            "taint chain must be populated"
        );
    }
}
