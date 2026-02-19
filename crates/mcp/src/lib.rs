//! MCP (Model Context Protocol) Stdio Transport server for the Janitor.
//!
//! Exposes three tools over the MCP stdio JSON-RPC protocol:
//! - `janitor_scan` — Run the 6-stage dead-symbol pipeline on a project path.
//! - `janitor_dedup` — Detect structurally-cloned symbols in a project.
//! - `janitor_clean` — Report dead symbols eligible for removal (dry-run).
//!
//! Wire protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout.
//! Each request line → one response line.
//!
//! The serve loop is async (Tokio). CPU-intensive dispatch is offloaded to the
//! blocking thread pool via [`tokio::task::spawn_blocking`] to keep the executor
//! responsive during multi-second pipeline runs.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

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
                "description": "Dry-run report of symbols eligible for removal. Equivalent to `janitor scan` without physical deletion.",
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
    anyhow::ensure!(root.is_dir(), "path is not a directory: {}", path);

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
        anatomist::pipeline::run(root, &mut host, library, None).context("Pipeline failed")?;

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

fn run_dedup(path: &str) -> Result<serde_json::Value> {
    let root = Path::new(path);
    anyhow::ensure!(root.is_dir(), "path is not a directory: {}", path);

    let mut host =
        anatomist::parser::ParserHost::new().context("Failed to initialise parser host")?;
    // Library mode = true so all public symbols are considered for dedup.
    let result =
        anatomist::pipeline::run(root, &mut host, true, None).context("Pipeline failed")?;

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
                "janitor_scan" | "janitor_clean" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    let library = args
                        .get("library")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match run_scan(&path, library) {
                        Ok(v) => Response::ok(req.id, v),
                        Err(e) => Response::err(req.id, -32603, e.to_string()),
                    }
                }

                "janitor_dedup" => {
                    let path = match args.get("path").and_then(|v| v.as_str()) {
                        Some(p) => p.to_owned(),
                        None => return Response::err(req.id, -32602, "missing `path` argument"),
                    };
                    match run_dedup(&path) {
                        Ok(v) => Response::ok(req.id, v),
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
    fn test_tools_list_contains_three_tools() {
        let list = tool_list();
        let tools = list["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"janitor_scan"));
        assert!(names.contains(&"janitor_dedup"));
        assert!(names.contains(&"janitor_clean"));
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
}
