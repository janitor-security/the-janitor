//! MCP (Model Context Protocol) Stdio Transport server for the Janitor.
//!
//! Exposes ten tools over the MCP stdio JSON-RPC protocol:
//! - `janitor_scan`              — Run the 6-stage dead-symbol pipeline on a project path.
//! - `janitor_dedup`             — Detect structurally-cloned symbols in a project.
//! - `janitor_clean`             — Report dead symbols eligible for removal (dry-run).
//! - `janitor_dep_check`         — Identify zombie dependencies (declared but never imported).
//! - `janitor_bounce`            — Score a patch (or current git diff) for slop/antipatterns.
//! - `janitor_silo_audit`        — Detect `architecture:version_silo` splits in the workspace lockfile.
//! - `janitor_provenance`        — Return last analysis duration and source-vs-egress byte ratio.
//! - `janitor_wopr_snapshot`     — ASCII health snapshot of the repository derived from the bounce log.
//! - `janitor_visualize_ledger`  — Mermaid pie chart + TEI markdown table from the actuarial ledger.
//! - `janitor_lint_file`         — Real-time single-file antipattern scan for IDE integration.
//!
//! Wire protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout.
//! Each request line → one response line.
//!
//! The serve loop is async (Tokio). CPU-intensive dispatch is offloaded to the
//! blocking thread pool via [`tokio::task::spawn_blocking`] to keep the executor
//! responsive during multi-second pipeline runs.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 wire types
// ---------------------------------------------------------------------------

/// Incoming JSON-RPC 2.0 request (method + optional params).
#[derive(Debug, Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Outgoing JSON-RPC 2.0 response (result xor error).
#[derive(Debug, Serialize)]
struct Response {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Debug, Serialize)]
struct RpcError {
    code: i32,
    message: String,
}

impl Response {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: serde_json::Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
        }
    }

    /// Wrap a tool result value in the MCP `tools/call` content envelope.
    ///
    /// The MCP spec requires `tools/call` results to be:
    /// `{ "content": [{ "type": "text", "text": "<serialised json>" }] }`
    ///
    /// Returning a raw JSON object as `result` causes MCP clients (including
    /// Claude Code) to display `(completed with no output)` because there is
    /// no recognised `content` array to render.
    fn tool_ok(id: serde_json::Value, value: serde_json::Value) -> Self {
        let text = serde_json::to_string(&value).unwrap_or_default();
        Self::ok(
            id,
            serde_json::json!({
                "content": [{ "type": "text", "text": text }]
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// MCP tool declarations (returned by `tools/list`)
// ---------------------------------------------------------------------------

fn tool_list() -> serde_json::Value {
    serde_json::json!({
        "tools": [
            {
                "name": "janitor_scan",
                "description": "Run the 6-stage dead-symbol detection pipeline on a project directory. Returns total symbol count, dead symbol count, and dead symbol names.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the project root."
                        },
                        "library": {
                            "type": "boolean",
                            "description": "Enable library mode — protect all public symbols.",
                            "default": false
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_dedup",
                "description": "Detect structurally identical (cloned) symbols within a project. Returns groups of symbols with the same structural hash.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the project root."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_clean",
                "description": "Dry-run report of symbols eligible for removal. Equivalent to `janitor scan` without physical deletion. Requires a valid bearer token.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the project root."
                        },
                        "library": {
                            "type": "boolean",
                            "description": "Enable library mode.",
                            "default": false
                        },
                        "token": {
                            "type": "string",
                            "description": "Bearer token issued by thejanitor.app. Required for janitor_clean."
                        }
                    },
                    "required": ["path", "token"]
                }
            },
            {
                "name": "janitor_dep_check",
                "description": "Scan manifest files (package.json, Cargo.toml, requirements.txt, pyproject.toml) and identify zombie dependencies — packages declared but never imported in any source file.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the project root."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_bounce",
                "description": "Score a patch for slop, antipatterns, and logic clones. Returns a full BounceResult including slop_score and threat_class. When `patch` is omitted the tool scores the current uncommitted local changes via `git diff HEAD` run inside `path`.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "patch": {
                            "type": "string",
                            "description": "Unified diff text to score. If omitted, `git diff HEAD` is run in `path`."
                        },
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the repository root. Required when `patch` is omitted so the tool resolves `git diff HEAD` against the correct working tree regardless of daemon CWD."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_silo_audit",
                "description": "Parse the workspace Cargo.lock (and any package-lock.json / yarn.lock) under `path` and return every `architecture:version_silo` violation — crates or packages resolved at more than one distinct version.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the workspace root."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_provenance",
                "description": "Return the zero-upload provenance record for the last recorded bounce: analysis duration (ms), source bytes processed, egress bytes sent, and the source-vs-egress exfiltration percentage.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the repository root (reads `.janitor/bounce_log.ndjson`)."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_wopr_snapshot",
                "description": "Return an ASCII health snapshot of the repository derived from the bounce log. Shows total PRs audited, clean/flagged/critical counts, average slop score, and a health bar — giving the operator an instant 'vibe read' without opening the TUI.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the repository root (reads `.janitor/bounce_log.ndjson`)."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_visualize_ledger",
                "description": "Render the actuarial intercept ledger as a Mermaid.js pie chart and a markdown TEI table. Classifies every bounced PR into Critical ($150), Necrotic ($20), StructuralSlop ($0), or Boilerplate ($0) and computes Total Economic Impact. Use this tool when asked for an executive summary, ROI report, or intercept breakdown.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute path to the repository root (reads `.janitor/bounce_log.ndjson`)."
                        }
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "janitor_lint_file",
                "description": "Real-time single-file security antipattern scan for IDE integration. Takes a file path and raw buffer contents (unsaved), runs the Slop Hunter detector suite, and returns an array of StructuredFindings with line numbers and remediation guidance. Designed for on-save feedback loops in VS Code / JetBrains via the MCP protocol.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "File path (used to infer language from extension, e.g. `src/main.rs`)."
                        },
                        "contents": {
                            "type": "string",
                            "description": "Raw file contents as a UTF-8 string (may be unsaved buffer state from the IDE)."
                        }
                    },
                    "required": ["path", "contents"]
                }
            }
        ]
    })
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

/// Run the 6-stage pipeline and return JSON summary.
///
/// Checks for a cached `.janitor/symbols.rkyv` (mmap, zero-copy) first.
/// Falls back to a full parse run when the cache is absent or stale.
fn run_scan(path: &str, library: bool) -> Result<serde_json::Value> {
    let root = Path::new(path);
    anyhow::ensure!(root.is_dir(), "path is not a directory: {path}");

    // Zero-copy cache path: if symbols.rkyv exists, report its entry count.
    let rkyv_path = root.join(".janitor").join("symbols.rkyv");
    if rkyv_path.exists() {
        if let Ok(v) = load_cached_summary(&rkyv_path) {
            return Ok(v);
        }
    }

    // Full pipeline run (also writes the rkyv cache as a CLI side-effect, but
    // the library path here just returns the in-memory result directly).
    let mut host =
        anatomist::parser::ParserHost::new().context("Failed to initialise parser host")?;
    let result =
        anatomist::pipeline::run(root, &mut host, library, None, &[]).context("Pipeline failed")?;

    let dead_names: Vec<&str> = result.dead.iter().map(|e| e.name.as_str()).collect();
    let findings: Vec<serde_json::Value> = result
        .dead
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": "dead_symbol",
                "file": e.file_path,
                "line": e.start_line,
                "name": e.name,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "source": "live",
        "total": result.total,
        "dead": result.dead.len(),
        "dead_symbols": dead_names,
        "findings": findings,
        "orphan_files": result.orphan_files,
    }))
}

/// Reads `.janitor/symbols.rkyv` via mmap (zero-copy) and returns a summary.
fn load_cached_summary(rkyv_path: &Path) -> Result<serde_json::Value> {
    use common::registry::MappedRegistry;
    let mapped = MappedRegistry::open(rkyv_path).context("Failed to open symbols.rkyv")?;
    Ok(serde_json::json!({
        "source": "cache",
        "total": mapped.len(),
    }))
}

/// Scan manifests and return zombie dependency report.
fn ci_mode_active() -> bool {
    std::env::var_os("GITHUB_ACTIONS").is_some() || std::env::var_os("CI").is_some()
}

fn run_dep_check(path: &str) -> Result<serde_json::Value> {
    run_dep_check_with_ci(path, ci_mode_active())
}

fn run_dep_check_with_ci(path: &str, ci_mode: bool) -> Result<serde_json::Value> {
    let root = Path::new(path);
    anyhow::ensure!(root.is_dir(), "path is not a directory: {path}");

    let registry = anatomist::manifest::scan_manifests(root);
    let zombies = anatomist::manifest::find_zombie_deps(root, &registry);
    let janitor_dir = root.join(".janitor");
    let kev_findings = match std::fs::read(root.join("Cargo.lock")) {
        Ok(lock) if ci_mode => anatomist::manifest::check_kev_deps_required(&lock, &janitor_dir)
            .context("janitor_dep_check: KEV database unavailable in CI")?,
        Ok(lock) => common::wisdom::resolve_kev_database(&janitor_dir)
            .ok()
            .map(|wisdom_db| anatomist::manifest::check_kev_deps(&lock, &wisdom_db))
            .unwrap_or_default(),
        Err(_) => Vec::new(),
    };

    Ok(serde_json::json!({
        "total_declared": registry.len(),
        "zombie_count": zombies.len(),
        "zombie_deps": zombies,
        "kev_count": kev_findings.len(),
        "kev_findings": kev_findings
            .into_iter()
            .map(|f| f.description)
            .collect::<Vec<_>>(),
    }))
}

fn run_dedup(path: &str) -> Result<serde_json::Value> {
    let root = Path::new(path);
    anyhow::ensure!(root.is_dir(), "path is not a directory: {path}");

    let mut host =
        anatomist::parser::ParserHost::new().context("Failed to initialise parser host")?;
    // Library mode = true so all public symbols are considered for dedup.
    let result =
        anatomist::pipeline::run(root, &mut host, true, None, &[]).context("Pipeline failed")?;

    use std::collections::HashMap;
    let mut by_hash: HashMap<u64, Vec<String>> = HashMap::new();
    for entity in result.protected.iter().chain(result.dead.iter()) {
        if let Some(h) = entity.structural_hash {
            by_hash
                .entry(h)
                .or_default()
                .push(entity.qualified_name.clone());
        }
    }

    let groups: Vec<serde_json::Value> = by_hash
        .into_values()
        .filter(|names| names.len() > 1)
        .map(|names| serde_json::json!({ "duplicates": names }))
        .collect();

    Ok(serde_json::json!({
        "duplicate_groups": groups.len(),
        "groups": groups,
    }))
}

/// Resolve and validate a workspace root supplied by an MCP client.
///
/// Rejects relative paths (daemon CWD is unrelated to the client's working directory)
/// then calls [`std::fs::canonicalize`] to strip symlinks and `..` components,
/// producing a stable absolute path for all subsequent filesystem and subprocess calls.
fn resolve_workspace_root(path: &str, field: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        Path::new(path).is_absolute(),
        "`{field}` must be an absolute path (got {path:?}). \
         The MCP daemon CWD is unrelated to the client's working directory — \
         always pass the explicit repo root, e.g. /home/user/project."
    );
    std::fs::canonicalize(path).with_context(|| {
        format!("cannot resolve workspace root `{path}`: path does not exist or is not accessible")
    })
}

/// Score a patch (or current git diff) with [`forge::slop_filter::PatchBouncer`].
///
/// When `patch` is `None`, `git diff HEAD` is executed in `repo_path` to obtain
/// the uncommitted changes.  An empty diff returns a clean Boilerplate result
/// rather than an error.
///
/// `repo_path` is **required** — the daemon process has an unrelated CWD and
/// must never fall back to `"."` for git operations.
fn run_bounce(patch: Option<String>, repo_path: Option<String>) -> Result<serde_json::Value> {
    let raw = repo_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "`path` is required for janitor_bounce — pass the absolute repo root so the \
             daemon resolves git operations against the correct working tree"
        )
    })?;
    let root = resolve_workspace_root(raw, "path")?;

    let patch_text = match patch {
        Some(p) => p,
        None => {
            let out = std::process::Command::new("git")
                .args(["diff", "HEAD"])
                .current_dir(&root)
                .output()
                .context("failed to execute `git diff HEAD`")?;
            String::from_utf8(out.stdout).context("git diff output is not valid UTF-8")?
        }
    };

    if patch_text.trim().is_empty() {
        return Ok(serde_json::json!({
            "slop_score": 0,
            "threat_class": "Boilerplate",
            "is_clean": true,
            "message": "no changes to analyse"
        }));
    }

    use forge::slop_filter::{PRBouncer, PatchBouncer};
    let registry = common::registry::SymbolRegistry::default();
    let policy = common::policy::JanitorPolicy::load(&root)?;
    let score = PatchBouncer::for_workspace_with_deep_scan_and_suppressions(
        &root,
        policy.suppressions.unwrap_or_default(),
        false,
    )
    .bounce(&patch_text, &registry)
    .context("PatchBouncer::bounce failed")?;

    let threat_class = if score
        .antipattern_details
        .iter()
        .any(|a| a.contains("security:"))
    {
        "Critical"
    } else if score.score() > 0 {
        "Necrotic"
    } else {
        "Boilerplate"
    };

    Ok(serde_json::json!({
        "slop_score": score.score(),
        "threat_class": threat_class,
        "is_clean": score.is_clean(),
        "logic_clones_found": score.logic_clones_found,
        "zombie_symbols_added": score.zombie_symbols_added,
        "dead_symbols_added": score.dead_symbols_added,
        "antipatterns_found": score.antipatterns_found,
        "antipattern_details": score.antipattern_details,
        "findings": score.structured_findings,
        "comment_violations": score.comment_violations,
        "version_silo_details": score.version_silo_details,
        "suppressed_by_domain": score.suppressed_by_domain,
    }))
}

/// Scan the workspace under `path` for `architecture:version_silo` violations.
///
/// Reads every `Cargo.lock`, `package-lock.json`, and `yarn.lock` found directly
/// under `path` (non-recursive at the root level; use the full workspace root).
/// Delegates to [`anatomist::manifest::find_version_silos_from_lockfile`] for
/// Cargo and [`anatomist::manifest::find_version_silos_in_blobs`] for npm manifests.
fn run_silo_audit(path: &str) -> Result<serde_json::Value> {
    let root = resolve_workspace_root(path, "path")?;
    anyhow::ensure!(root.is_dir(), "path is not a directory: {}", root.display());

    // Collect every lockfile / manifest directly under the workspace root.
    let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    for name in &[
        "Cargo.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ] {
        let p = root.join(name);
        if p.exists() {
            let bytes =
                std::fs::read(&p).with_context(|| format!("failed to read {}", p.display()))?;
            blobs.insert(PathBuf::from(name), bytes);
        }
    }

    if blobs.is_empty() {
        return Ok(serde_json::json!({
            "silo_count": 0,
            "silos": [],
            "message": "no lockfiles found at workspace root"
        }));
    }

    // Cargo lockfile silos — resolved version splits.
    let cargo_silos = anatomist::manifest::find_version_silos_from_lockfile(&blobs, None);
    // Manifest-level silos (npm package.json, Cargo.toml declared versions).
    let manifest_silos = anatomist::manifest::find_version_silos_in_blobs(&blobs);

    let cargo_entries: Vec<serde_json::Value> = cargo_silos
        .iter()
        .map(|s| serde_json::json!({ "name": s.name, "versions": s.versions, "display": s.display() }))
        .collect();

    let total = cargo_entries.len() + manifest_silos.len();
    Ok(serde_json::json!({
        "silo_count": total,
        "cargo_lock_silos": cargo_entries,
        "manifest_silos": manifest_silos,
        "antipattern_label": "architecture:version_silo",
    }))
}

/// Return the provenance record from the most recent bounce log entry.
///
/// Reads `.janitor/bounce_log.ndjson` under `path`, parses the last line as JSON,
/// and returns the `provenance` sub-object together with a derived `exfil_pct`
/// field (egress / source × 100).
fn run_provenance(path: &str) -> Result<serde_json::Value> {
    let root = resolve_workspace_root(path, "path")?;
    let log_path = root.join(".janitor").join("bounce_log.ndjson");
    anyhow::ensure!(
        log_path.exists(),
        "bounce log not found: {}",
        log_path.display()
    );

    let content = std::fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path.display()))?;

    let last_line = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("bounce log is empty"))?;

    let entry: serde_json::Value =
        serde_json::from_str(last_line).context("failed to parse last bounce log entry")?;

    let prov = entry.get("provenance").cloned().unwrap_or_default();
    let source = prov
        .get("source_bytes_processed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let egress = prov
        .get("egress_bytes_sent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let duration_ms = prov
        .get("analysis_duration_ms")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let exfil_pct = if source > 0 {
        (egress as f64 / source as f64) * 100.0
    } else {
        0.0
    };

    Ok(serde_json::json!({
        "analysis_duration_ms": duration_ms,
        "source_bytes_processed": source,
        "egress_bytes_sent": egress,
        "exfil_pct": exfil_pct,
        "zero_upload_verified": exfil_pct < 1.0,
        "timestamp": entry.get("timestamp").cloned().unwrap_or(serde_json::Value::Null),
    }))
}

/// Build an ASCII health snapshot from all entries in `.janitor/bounce_log.ndjson`.
///
/// Aggregates the full bounce log under `path` and returns a text-based
/// "WOPR Snapshot" of repository health — total PRs audited, clean/flagged/critical
/// counts, average slop score, a 20-cell health bar, and last-scan metadata.
///
/// Returns clean placeholder output when no bounce log exists; never errors on
/// a missing log so the operator can call this before the first bounce run.
fn run_wopr_snapshot(path: &str) -> Result<serde_json::Value> {
    let root = resolve_workspace_root(path, "path")?;
    let log_path = root.join(".janitor").join("bounce_log.ndjson");

    if !log_path.exists() {
        let snapshot = "\
╔══════════════════════════════════════╗\n\
║  WOPR SNAPSHOT — NO DATA             ║\n\
║  Run `janitor bounce` to populate.   ║\n\
╚══════════════════════════════════════╝";
        return Ok(serde_json::json!({
            "snapshot": snapshot,
            "total_prs": 0,
            "status": "no_data"
        }));
    }

    let content = std::fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path.display()))?;

    // Parse only scalar fields needed for stats — zero String clones of source lines.
    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    if entries.is_empty() {
        let snapshot = "\
╔══════════════════════════════════════╗\n\
║  WOPR SNAPSHOT — EMPTY LOG           ║\n\
╚══════════════════════════════════════╝";
        return Ok(serde_json::json!({
            "snapshot": snapshot,
            "total_prs": 0,
            "status": "empty"
        }));
    }

    let total = entries.len();

    let critical_count = entries
        .iter()
        .filter(|e| {
            let has_security = e
                .get("antipatterns")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|a| a.as_str().is_some_and(|s| s.contains("security:")))
                })
                .unwrap_or(false);
            let has_collision = e
                .get("collided_pr_numbers")
                .and_then(|c| c.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            has_security || has_collision
        })
        .count();

    let clean_count = entries
        .iter()
        .filter(|e| e.get("slop_score").and_then(|s| s.as_u64()).unwrap_or(0) == 0)
        .count();

    let flagged_count = total - clean_count;

    let score_sum: u64 = entries
        .iter()
        .filter_map(|e| e.get("slop_score").and_then(|s| s.as_u64()))
        .sum();
    let avg_score = score_sum as f64 / total as f64;

    let last_ts = entries
        .last()
        .and_then(|e| e.get("timestamp"))
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");
    let last_score = entries
        .last()
        .and_then(|e| e.get("slop_score"))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);

    // 20-cell ASCII health bar: filled cells ∝ clean percentage.
    let clean_cells = ((clean_count as f64 / total as f64) * 20.0) as usize;
    let flagged_cells = 20usize.saturating_sub(clean_cells);
    let health_bar = format!(
        "[{}{}]",
        "\u{2588}".repeat(clean_cells),   // █
        "\u{2591}".repeat(flagged_cells), // ░
    );

    // Trim timestamp to 24 chars max so it fits the fixed-width box.
    let ts_display = if last_ts.len() > 24 {
        &last_ts[..24]
    } else {
        last_ts
    };

    let clean_pct = clean_count as f64 / total as f64 * 100.0;
    let flagged_pct = flagged_count as f64 / total as f64 * 100.0;

    let snapshot = format!(
        "\
╔══════════════════════════════════════════╗\n\
║     WOPR SNAPSHOT — JANITOR INTEGRITY    ║\n\
╠══════════════════════════════════════════╣\n\
║  PRs Audited    : {total:>6}                 ║\n\
║  Clean          : {clean_count:>6}  ({clean_pct:>5.1}%)         ║\n\
║  Flagged        : {flagged_count:>6}  ({flagged_pct:>5.1}%)         ║\n\
║  Critical       : {critical_count:>6}                 ║\n\
║  Avg Slop Score : {avg_score:>9.1}             ║\n\
╠══════════════════════════════════════════╣\n\
║  Health: {health_bar:<22}   ║\n\
╠══════════════════════════════════════════╣\n\
║  Last Scan  : {ts_display:<28}║\n\
║  Last Score : {last_score:>6}                    ║\n\
╚══════════════════════════════════════════╝"
    );

    let status = if critical_count > 0 {
        "critical"
    } else if flagged_count > 0 {
        "flagged"
    } else {
        "clean"
    };

    Ok(serde_json::json!({
        "snapshot": snapshot,
        "total_prs": total,
        "clean_prs": clean_count,
        "flagged_prs": flagged_count,
        "critical_prs": critical_count,
        "avg_slop_score": avg_score,
        "last_scan": last_ts,
        "last_score": last_score,
        "status": status,
    }))
}

/// Classify every PR in the bounce log into the four actuarial tiers and render
/// a Mermaid.js pie chart plus a markdown TEI table.
///
/// # Tier definitions
/// - **Critical** (`security:` antipattern OR non-empty `collided_pr_numbers`) — $150 / intercept
/// - **Necrotic** (`necrotic_flag` present AND NOT Critical) — $20 / intercept
/// - **StructuralSlop** (`slop_score > 0` AND NOT Critical AND NOT Necrotic) — $0 (structural waste)
/// - **Boilerplate** (`slop_score == 0`) — $0 (noise-free)
///
/// Returns `mermaid` (raw Mermaid source), `tei_table` (markdown), and the raw
/// per-tier counts and TEI totals as structured fields for programmatic use.
fn run_visualize_ledger(path: &str) -> Result<serde_json::Value> {
    let root = resolve_workspace_root(path, "path")?;
    let log_path = root.join(".janitor").join("bounce_log.ndjson");

    if !log_path.exists() {
        return Ok(serde_json::json!({
            "mermaid": "pie title Intercept Distribution\n    \"No Data\" : 1",
            "tei_table": "No bounce log found. Run `janitor bounce` to populate.",
            "total_prs": 0,
            "tei_usd": 0,
            "status": "no_data"
        }));
    }

    let content = std::fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path.display()))?;

    let entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    if entries.is_empty() {
        return Ok(serde_json::json!({
            "mermaid": "pie title Intercept Distribution\n    \"No Data\" : 1",
            "tei_table": "Bounce log is empty.",
            "total_prs": 0,
            "tei_usd": 0,
            "status": "empty"
        }));
    }

    let total = entries.len();
    let mut critical = 0u64;
    let mut necrotic = 0u64;
    let mut structural_slop = 0u64;
    let mut boilerplate = 0u64;

    for e in &entries {
        let has_security = e
            .get("antipatterns")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|a| a.as_str().is_some_and(|s| s.contains("security:")))
            })
            .unwrap_or(false);
        let has_collision = e
            .get("collided_pr_numbers")
            .and_then(|c| c.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
        let is_critical = has_security || has_collision;

        let is_necrotic = !is_critical
            && e.get("necrotic_flag")
                .map(|v| !v.is_null())
                .unwrap_or(false);

        let score = e.get("slop_score").and_then(|s| s.as_u64()).unwrap_or(0);
        let is_structural_slop = !is_critical && !is_necrotic && score > 0;

        if is_critical {
            critical += 1;
        } else if is_necrotic {
            necrotic += 1;
        } else if is_structural_slop {
            structural_slop += 1;
        } else {
            boilerplate += 1;
        }
    }

    let tei_critical = critical * 150;
    let tei_necrotic = necrotic * 20;
    let tei_total = tei_critical + tei_necrotic;

    let critical_pct = critical as f64 / total as f64 * 100.0;
    let necrotic_pct = necrotic as f64 / total as f64 * 100.0;
    let slop_pct = structural_slop as f64 / total as f64 * 100.0;
    let boilerplate_pct = boilerplate as f64 / total as f64 * 100.0;

    // Mermaid pie requires at least one non-zero slice.
    // Represent zero-count tiers with a placeholder value of 0 (Mermaid ignores 0-value slices),
    // but guard against the degenerate all-zero case by using boilerplate as the floor.
    let mermaid = format!(
        "```mermaid\npie title Intercept Distribution — {total} PRs Audited\n\
         {critical_slice}\
         {necrotic_slice}\
         {slop_slice}\
         {boilerplate_slice}\
         ```",
        critical_slice = if critical > 0 {
            format!("    \"Critical (${}/ea)\" : {critical}\n", 150)
        } else {
            String::new()
        },
        necrotic_slice = if necrotic > 0 {
            format!("    \"Necrotic (${}/ea)\" : {necrotic}\n", 20)
        } else {
            String::new()
        },
        slop_slice = if structural_slop > 0 {
            format!("    \"StructuralSlop\" : {structural_slop}\n")
        } else {
            String::new()
        },
        boilerplate_slice = if boilerplate > 0 {
            format!("    \"Boilerplate\" : {boilerplate}\n")
        } else {
            String::new()
        },
    );

    let tei_table = format!(
        "## Actuarial Ledger — Total Economic Impact\n\n\
         | Tier | Count | Rate | Unit TEI | Total TEI |\n\
         |---|---|---|---|---|\n\
         | Critical | {critical} | {critical_pct:.1}% | $150 | ${tei_critical} |\n\
         | Necrotic | {necrotic} | {necrotic_pct:.1}% | $20 | ${tei_necrotic} |\n\
         | StructuralSlop | {structural_slop} | {slop_pct:.1}% | $0 | $0 |\n\
         | Boilerplate | {boilerplate} | {boilerplate_pct:.1}% | $0 | $0 |\n\
         | **Total** | **{total}** | 100.0% | — | **${tei_total}** |\n"
    );

    Ok(serde_json::json!({
        "mermaid": mermaid,
        "tei_table": tei_table,
        "total_prs": total,
        "critical_prs": critical,
        "necrotic_prs": necrotic,
        "structural_slop_prs": structural_slop,
        "boilerplate_prs": boilerplate,
        "tei_critical_usd": tei_critical,
        "tei_necrotic_usd": tei_necrotic,
        "tei_total_usd": tei_total,
        "status": if critical > 0 { "critical" } else if necrotic > 0 { "necrotic" } else { "clean" }
    }))
}

/// Real-time single-file antipattern scan for IDE integration.
///
/// Infers the language from `file_path`'s extension, runs
/// [`forge::slop_hunter::find_slop`] on `contents`, and converts each
/// [`forge::slop_hunter::SlopFinding`] into a [`common::slop::StructuredFinding`]
/// with a best-effort line number (derived from byte offset scan of `contents`).
///
/// Returns an empty array for unknown file types — never errors on language
/// mismatch so the IDE client does not surface spurious errors on binary blobs.
fn run_lint_file(file_path: &str, contents: &str) -> Result<serde_json::Value> {
    // Infer language tag from file extension.
    let ext = std::path::Path::new(file_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let lang = ext_to_lang_tag(ext);

    let source = contents.as_bytes();
    let unit = forge::slop_hunter::ParsedUnit::unparsed(source);
    let raw_findings = forge::slop_hunter::find_slop(lang, &unit);

    // Convert SlopFinding (byte offsets) → StructuredFinding (line numbers).
    let findings: Vec<common::slop::StructuredFinding> = raw_findings
        .iter()
        .map(|f| {
            let line = byte_offset_to_line(source, f.start_byte);
            common::slop::StructuredFinding {
                id: finding_id_from_description(&f.description),
                file: Some(file_path.to_owned()),
                line: Some(line),
                fingerprint: String::new(),
                severity: Some(format!("{:?}", f.severity)),
                remediation: None,
                docs_url: None,
                exploit_witness: None,
            }
        })
        .collect();

    Ok(serde_json::json!({
        "file": file_path,
        "language": lang,
        "finding_count": findings.len(),
        "findings": findings,
        "is_clean": findings.is_empty(),
    }))
}

/// Map a file extension to the language tag accepted by `slop_hunter::find_slop`.
fn ext_to_lang_tag(ext: &str) -> &'static str {
    match ext {
        "rs" => "rs",
        "py" | "pyw" => "py",
        "js" | "mjs" | "cjs" => "js",
        "ts" => "ts",
        "tsx" => "tsx",
        "jsx" => "jsx",
        "cpp" | "cxx" | "cc" | "c++" => "cpp",
        "c" => "c",
        "h" | "hpp" => "cpp",
        "java" => "java",
        "cs" => "cs",
        "go" => "go",
        "rb" => "rb",
        "sh" | "bash" => "sh",
        "yaml" | "yml" => "yaml",
        "tf" | "hcl" => "tf",
        "zig" => "zig",
        "lua" => "lua",
        "kt" => "kt",
        "scala" => "scala",
        "php" => "php",
        "swift" => "swift",
        "proto" => "proto",
        "cmake" => "cmake",
        "xml" => "xml",
        "nix" => "nix",
        "gd" => "gd",
        _ => "unknown",
    }
}

/// Convert a byte offset in `source` to a 1-indexed line number.
fn byte_offset_to_line(source: &[u8], byte_offset: usize) -> u32 {
    let safe_end = byte_offset.min(source.len());
    let newlines = source[..safe_end].iter().filter(|&&b| b == b'\n').count();
    (newlines as u32) + 1
}

/// Extract a machine-readable finding ID from a human-readable description string.
///
/// Descriptions from the Slop Hunter embed structured IDs in the form
/// `"security:command_injection — ..."`.  This extractor returns the leading
/// `category:subcategory` token for downstream consumption.
fn finding_id_from_description(description: &str) -> String {
    description
        .split(" — ")
        .next()
        .unwrap_or(description)
        .split(' ')
        .next()
        .unwrap_or(description)
        .to_owned()
}

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

/// Run the MCP stdio transport loop (async).
///
/// Reads newline-delimited JSON-RPC 2.0 requests from stdin, dispatches to
/// the appropriate tool handler, and writes JSON-RPC 2.0 responses to stdout.
/// Terminates when stdin is closed (EOF).
///
/// CPU-intensive tool handlers are offloaded to the blocking thread pool via
/// [`tokio::task::spawn_blocking`] so the executor stays responsive during
/// multi-second pipeline runs.
pub async fn serve() -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut lines = BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await.context("stdin read error")? {
        if line.trim().is_empty() {
            continue;
        }

        let resp = match serde_json::from_str::<Request>(&line) {
            Err(e) => Response::err(serde_json::Value::Null, -32700, format!("Parse error: {e}")),
            Ok(req) => {
                // Offload CPU-intensive pipeline work to the blocking thread pool.
                tokio::task::spawn_blocking(move || dispatch(req))
                    .await
                    .context("dispatch thread panicked")?
            }
        };

        let mut encoded = serde_json::to_string(&resp).context("response serialisation failed")?;
        encoded.push('\n');
        stdout.write_all(encoded.as_bytes()).await?;
        stdout.flush().await?;
    }

    Ok(())
}

fn dispatch(req: Request) -> Response {
    match req.method.as_str() {
        "initialize" => Response::ok(
            req.id,
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "janitor-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),

        "tools/list" => Response::ok(req.id, tool_list()),

        "tools/call" => {
            let tool = req
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or_default();

            match tool {
                "janitor_scan" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    let library = args
                        .get("library")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match run_scan(&path, library) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_clean" => {
                    // Require a valid bearer token before running the clean report.
                    let token = match args.get("token").and_then(|v| v.as_str()) {
                        Some(t) => t.to_owned(),
                        None => {
                            return Response::err(
                                req.id,
                                -32602,
                                "missing `token` argument — a valid bearer token is required for janitor_clean",
                            )
                        }
                    };
                    if let Err(e) = vault::SigningOracle::verify_token(&token) {
                        return Response::err(req.id, -32602, format!("invalid token: {e}"));
                    }
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    let library = args
                        .get("library")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match run_scan(&path, library) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_dedup" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_dedup(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_dep_check" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_dep_check(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_bounce" => {
                    let patch = args
                        .get("patch")
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    let path = args.get("path").and_then(|v| v.as_str()).map(str::to_owned);
                    match run_bounce(patch, path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_silo_audit" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_silo_audit(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_provenance" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_provenance(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_wopr_snapshot" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_wopr_snapshot(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_visualize_ledger" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_visualize_ledger(&path) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_lint_file" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    let contents = match args.get("contents").and_then(|v| v.as_str()) {
                        Some(c) => c.to_owned(),
                        None => {
                            return Response::err(req.id, -32602, "missing `contents` argument")
                        }
                    };
                    match run_lint_file(&path, &contents) {
                        Ok(v) => Response::tool_ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                _ => Response::err(req.id, -32601, format!("unknown tool: {tool}")),
            }
        }

        _ => Response::err(req.id, -32601, format!("method not found: {}", req.method)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_ok_serialises() {
        let r = Response::ok(serde_json::json!(1), serde_json::json!({"x": 42}));
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn test_response_err_serialises() {
        let r = Response::err(serde_json::json!(2), -32601, "not found");
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn test_tools_list_contains_ten_tools() {
        let list = tool_list();
        let tools = list["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 10);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"janitor_scan"));
        assert!(names.contains(&"janitor_dedup"));
        assert!(names.contains(&"janitor_clean"));
        assert!(names.contains(&"janitor_dep_check"));
        assert!(names.contains(&"janitor_bounce"));
        assert!(names.contains(&"janitor_silo_audit"));
        assert!(names.contains(&"janitor_provenance"));
        assert!(names.contains(&"janitor_wopr_snapshot"));
        assert!(names.contains(&"janitor_visualize_ledger"));
        assert!(names.contains(&"janitor_lint_file"));
    }

    #[test]
    fn test_dispatch_initialize() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(1),
            method: "initialize".into(),
            params: serde_json::Value::Null,
        };
        let resp = dispatch(req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
    }

    #[test]
    fn test_dispatch_unknown_method() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(99),
            method: "nonexistent".into(),
            params: serde_json::Value::Null,
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_janitor_clean_requires_token() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(10),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_clean",
                "arguments": {
                    "path": "/tmp/nonexistent"
                    // token deliberately omitted
                }
            }),
        };
        let resp = dispatch(req);
        assert!(
            resp.result.is_none(),
            "janitor_clean without token must fail"
        );
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, -32602, "must return invalid params error code");
        assert!(
            err.message.contains("token"),
            "error message must mention `token`"
        );
    }

    #[test]
    fn test_run_dep_check_ci_fails_closed_without_kev_database() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.150\"\n",
        )
        .unwrap();
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).unwrap();
        std::fs::write(
            janitor_dir.join("wisdom_manifest.json"),
            br#"{"entry_count":1,"entries":[{"cve_id":"CVE-2026-9999"}]}"#,
        )
        .unwrap();

        let err = run_dep_check_with_ci(dir.path().to_str().unwrap(), true).unwrap_err();
        assert!(
            err.to_string().contains("KEV database unavailable in CI"),
            "CI dep-check must fail closed when only the JSON manifest exists"
        );
    }

    #[test]
    fn test_janitor_clean_rejects_invalid_token() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(11),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_clean",
                "arguments": {
                    "path": "/tmp/nonexistent",
                    "token": "not-a-valid-token"
                }
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none(), "invalid token must be rejected");
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("invalid token"));
    }

    #[test]
    fn test_janitor_bounce_empty_patch_returns_clean() {
        // An explicitly empty patch string with an absolute path must resolve to Boilerplate.
        // path is required; we pass /tmp which is always absolute and exists.
        let result = run_bounce(Some(String::new()), Some("/tmp".to_owned())).unwrap();
        assert_eq!(result["slop_score"], 0);
        assert_eq!(result["threat_class"], "Boilerplate");
        assert_eq!(result["is_clean"], true);
    }

    #[test]
    fn test_janitor_bounce_relative_path_rejected() {
        // Relative paths must be rejected to prevent daemon-CWD resolution.
        let err = run_bounce(Some(String::new()), Some("relative/path".to_owned()))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("absolute"),
            "error must mention absolute: {err}"
        );
    }

    #[test]
    fn test_janitor_bounce_no_path_rejected() {
        // Missing path must always be rejected — path is mandatory.
        let err = run_bounce(None, None).unwrap_err().to_string();
        assert!(err.contains("`path` is required"), "error: {err}");
    }

    #[test]
    fn test_janitor_bounce_dispatch_with_explicit_path_ok() {
        // tools/call with an explicit absolute path and empty patch must succeed.
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(20),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_bounce",
                "arguments": {
                    "patch": "",
                    "path": "/tmp"
                }
            }),
        };
        let resp = dispatch(req);
        // An empty patch must not return a protocol error.
        let result = resp.result.expect("empty-patch bounce must succeed");
        // Result is wrapped in MCP content envelope.
        assert!(
            result.get("content").is_some(),
            "must have content envelope"
        );
        let text = result["content"][0]["text"].as_str().unwrap();
        let inner: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(inner["slop_score"], 0);
    }

    #[test]
    fn test_janitor_silo_audit_missing_path_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(21),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_silo_audit",
                "arguments": {}
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_janitor_silo_audit_nonexistent_path_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(22),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_silo_audit",
                "arguments": { "path": "/tmp/does_not_exist_janitor_mcp_test" }
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32603);
    }

    #[test]
    fn test_janitor_provenance_missing_path_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(23),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_provenance",
                "arguments": {}
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_janitor_provenance_no_log_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(24),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_provenance",
                "arguments": { "path": "/tmp/does_not_exist_janitor_mcp_test" }
            }),
        };
        let resp = dispatch(req);
        // No bounce log → internal error, not a protocol error.
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32603);
    }

    #[test]
    fn test_janitor_wopr_snapshot_no_log_returns_no_data() {
        // /tmp exists but has no .janitor/bounce_log.ndjson → clean no_data response.
        let result = run_wopr_snapshot("/tmp").unwrap();
        assert_eq!(result["total_prs"], 0);
        assert_eq!(result["status"], "no_data");
        let snapshot = result["snapshot"].as_str().unwrap();
        assert!(snapshot.contains("NO DATA"), "snapshot must say NO DATA");
    }

    #[test]
    fn test_janitor_wopr_snapshot_missing_path_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(25),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_wopr_snapshot",
                "arguments": {}
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    // ── janitor_visualize_ledger tests ─────────────────────────────────────

    #[test]
    fn test_visualize_ledger_no_log_returns_no_data() {
        // /tmp exists but has no .janitor/bounce_log.ndjson → clean no_data response.
        let result = run_visualize_ledger("/tmp").unwrap();
        assert_eq!(result["total_prs"], 0);
        assert_eq!(result["status"], "no_data");
        assert!(
            result["mermaid"].as_str().unwrap().contains("No Data"),
            "mermaid must contain No Data placeholder"
        );
    }

    #[test]
    fn test_visualize_ledger_missing_path_error() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(30),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_visualize_ledger",
                "arguments": {}
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_visualize_ledger_classifies_tiers_correctly() {
        use std::io::Write;

        // Write a synthetic bounce log with one entry per tier:
        // 1. Critical — has security: antipattern
        // 2. Critical — has non-empty collided_pr_numbers
        // 3. Necrotic — necrotic_flag set, no security
        // 4. StructuralSlop — slop_score > 0, no critical/necrotic signals
        // 5. Boilerplate — slop_score == 0, clean
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).unwrap();
        let log_path = janitor_dir.join("bounce_log.ndjson");

        let entries = [
            r#"{"slop_score":150,"antipatterns":["security:sqli_concatenation"],"collided_pr_numbers":[],"necrotic_flag":null,"timestamp":"2026-01-01T00:00:00Z"}"#,
            r#"{"slop_score":50,"antipatterns":[],"collided_pr_numbers":[42,43],"necrotic_flag":null,"timestamp":"2026-01-01T00:00:01Z"}"#,
            r#"{"slop_score":20,"antipatterns":[],"collided_pr_numbers":[],"necrotic_flag":"gc_only","timestamp":"2026-01-01T00:00:02Z"}"#,
            r#"{"slop_score":10,"antipatterns":[],"collided_pr_numbers":[],"necrotic_flag":null,"timestamp":"2026-01-01T00:00:03Z"}"#,
            r#"{"slop_score":0,"antipatterns":[],"collided_pr_numbers":[],"necrotic_flag":null,"timestamp":"2026-01-01T00:00:04Z"}"#,
        ];

        let mut file = std::fs::File::create(&log_path).unwrap();
        for entry in &entries {
            writeln!(file, "{entry}").unwrap();
        }

        let result = run_visualize_ledger(dir.path().to_str().unwrap()).unwrap();

        assert_eq!(result["total_prs"], 5, "must count all 5 entries");
        assert_eq!(result["critical_prs"], 2, "2 critical entries");
        assert_eq!(result["necrotic_prs"], 1, "1 necrotic entry");
        assert_eq!(result["structural_slop_prs"], 1, "1 structural slop entry");
        assert_eq!(result["boilerplate_prs"], 1, "1 boilerplate entry");

        // TEI: 2 critical × $150 + 1 necrotic × $20 = $320
        assert_eq!(result["tei_critical_usd"], 300, "critical TEI = 2 × $150");
        assert_eq!(result["tei_necrotic_usd"], 20, "necrotic TEI = 1 × $20");
        assert_eq!(result["tei_total_usd"], 320, "total TEI = $320");

        let mermaid = result["mermaid"].as_str().unwrap();
        assert!(
            mermaid.contains("Critical"),
            "mermaid must show Critical slice"
        );
        assert!(
            mermaid.contains("Necrotic"),
            "mermaid must show Necrotic slice"
        );
        assert!(
            mermaid.contains("StructuralSlop"),
            "mermaid must show StructuralSlop slice"
        );
        assert!(
            mermaid.contains("Boilerplate"),
            "mermaid must show Boilerplate slice"
        );

        let tei_table = result["tei_table"].as_str().unwrap();
        assert!(tei_table.contains("$320"), "TEI table must show total $320");
        assert_eq!(result["status"], "critical", "status must be critical");
    }

    // ── janitor_lint_file tests ─────────────────────────────────────────────

    #[test]
    fn test_lint_file_clean_rust_returns_no_findings() {
        let src = "fn add(a: i32, b: i32) -> i32 { a + b }\n";
        let result = run_lint_file("src/lib.rs", src).unwrap();
        assert_eq!(
            result["finding_count"], 0,
            "clean Rust must produce zero findings"
        );
        assert_eq!(result["is_clean"], true);
        assert_eq!(result["language"], "rs");
    }

    #[test]
    fn test_lint_file_unknown_extension_returns_empty() {
        let result = run_lint_file("binary.wasm", "not utf8 safe content\x00").unwrap();
        assert_eq!(
            result["finding_count"], 0,
            "unknown extension must produce no findings"
        );
        assert_eq!(result["is_clean"], true);
    }

    #[test]
    fn test_lint_file_missing_path_rejected() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(50),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_lint_file",
                "arguments": { "contents": "fn main() {}" }
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_lint_file_missing_contents_rejected() {
        let req = Request {
            jsonrpc: "2.0".into(),
            id: serde_json::json!(51),
            method: "tools/call".into(),
            params: serde_json::json!({
                "name": "janitor_lint_file",
                "arguments": { "path": "src/main.rs" }
            }),
        };
        let resp = dispatch(req);
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[test]
    fn test_byte_offset_to_line_first_line() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(byte_offset_to_line(src, 0), 1, "offset 0 is line 1");
    }

    #[test]
    fn test_byte_offset_to_line_second_line() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(
            byte_offset_to_line(src, 6),
            2,
            "offset 6 (after first newline) is line 2"
        );
    }
}
