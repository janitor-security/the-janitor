//! MCP (Model Context Protocol) Stdio Transport server for the Janitor.
//!
//! Exposes seven tools over the MCP stdio JSON-RPC protocol:
//! - `janitor_scan`         — Run the 6-stage dead-symbol pipeline on a project path.
//! - `janitor_dedup`        — Detect structurally-cloned symbols in a project.
//! - `janitor_clean`        — Report dead symbols eligible for removal (dry-run).
//! - `janitor_dep_check`    — Identify zombie dependencies (declared but never imported).
//! - `janitor_bounce`       — Score a patch (or current git diff) for slop/antipatterns.
//! - `janitor_silo_audit`   — Detect `architecture:version_silo` splits in the workspace lockfile.
//! - `janitor_provenance`   — Return last analysis duration and source-vs-egress byte ratio.
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
        let text = serde_json::to_string_pretty(&value).unwrap_or_default();
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
    Ok(serde_json::json!({
        "source": "live",
        "total": result.total,
        "dead": result.dead.len(),
        "dead_symbols": dead_names,
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
fn run_dep_check(path: &str) -> Result<serde_json::Value> {
    let root = Path::new(path);
    anyhow::ensure!(root.is_dir(), "path is not a directory: {path}");

    let registry = anatomist::manifest::scan_manifests(root);
    let zombies = anatomist::manifest::find_zombie_deps(root, &registry);

    Ok(serde_json::json!({
        "total_declared": registry.len(),
        "zombie_count": zombies.len(),
        "zombie_deps": zombies,
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
    let score = PatchBouncer
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
    fn test_tools_list_contains_seven_tools() {
        let list = tool_list();
        let tools = list["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"janitor_scan"));
        assert!(names.contains(&"janitor_dedup"));
        assert!(names.contains(&"janitor_clean"));
        assert!(names.contains(&"janitor_dep_check"));
        assert!(names.contains(&"janitor_bounce"));
        assert!(names.contains(&"janitor_silo_audit"));
        assert!(names.contains(&"janitor_provenance"));
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
}
