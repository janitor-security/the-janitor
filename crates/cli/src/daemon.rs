//! Long-lived Janitor daemon — serves `Bounce` requests over a Unix Domain Socket.
//!
//! Eliminates process-spawn overhead for high-frequency CI integrations by keeping
//! the parsed symbol registry resident in memory across multiple bounce requests.
//!
//! ## Protocol
//! Newline-delimited JSON (ndjson). Each connection sends one or more request lines;
//! the server replies with one response line per request.
//!
//! ### Request (one JSON object per line)
//! ```json
//! {"type":"Bounce","patch":"--- a/foo.py\n+++ b/foo.py\n@@..."}
//! ```
//!
//! ### Response
//! ```json
//! {"type":"Report","slop_score":15.0,"zombies":1}
//! {"type":"Error","message":"..."}
//! ```
//!
//! ## Lifecycle
//! 1. Load `symbols.rkyv` once at startup into `Arc<RwLock<SymbolRegistry>>`.
//! 2. Accept connections on the UDS; spawn a task per connection.
//! 3. Each task holds a read guard for the registry duration of each `Bounce` call.
//! 4. Graceful shutdown on SIGINT / SIGTERM — in-flight requests complete normally.
//!
//! ## Platform
//! Unix Domain Sockets are a Unix-only feature. This entire module is gated on
//! `#[cfg(unix)]`.

#[cfg(unix)]
pub mod unix {
    use std::path::Path;
    use std::sync::Arc;

    use anyhow::Result;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::RwLock;

    use common::registry::{MappedRegistry, SymbolRegistry};
    use forge::slop_filter::{PRBouncer, PatchBouncer};

    // ---------------------------------------------------------------------------
    // Protocol types
    // ---------------------------------------------------------------------------

    /// Daemon request payload — one JSON object per line.
    #[derive(serde::Deserialize)]
    #[serde(tag = "type")]
    pub enum DaemonRequest {
        /// Analyse a unified-diff patch for slop.
        Bounce { patch: String },
    }

    /// Daemon response payload — one JSON object per line.
    #[derive(serde::Serialize)]
    #[serde(tag = "type")]
    pub enum DaemonResponse {
        /// Successful slop analysis report.
        Report {
            /// Weighted aggregate slop score (`f64` for API consistency with scan).
            slop_score: f64,
            /// Number of zombie symbol reintroductions detected.
            zombies: u32,
        },
        /// Error during request processing.
        Error { message: String },
    }

    // ---------------------------------------------------------------------------
    // Registry loading
    // ---------------------------------------------------------------------------

    /// Load a `SymbolRegistry` from a `symbols.rkyv` file at `path`.
    ///
    /// Uses the same `MappedRegistry` + rkyv zero-copy path as the CLI commands.
    fn load_registry(path: &Path) -> Result<SymbolRegistry> {
        let mapped = MappedRegistry::open(path)
            .map_err(|e| anyhow::anyhow!("Cannot open registry at {}: {e}", path.display()))?;
        rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
            .map_err(|e| anyhow::anyhow!("Registry deserialisation failed: {e}"))
    }

    // ---------------------------------------------------------------------------
    // Daemon entry-point
    // ---------------------------------------------------------------------------

    /// Start the Janitor daemon bound to `socket_path`.
    ///
    /// Loads the symbol registry from `registry_path` once at startup and shares
    /// it across all connections via `Arc<RwLock<SymbolRegistry>>`.
    ///
    /// Blocks until SIGINT or SIGTERM is received, then shuts down gracefully.
    ///
    /// # Errors
    /// Returns `Err` if the registry cannot be loaded or the socket cannot be bound.
    pub async fn serve(socket_path: &Path, registry_path: &Path) -> Result<()> {
        let registry = Arc::new(RwLock::new(load_registry(registry_path)?));

        // Remove a stale socket file from a previous run.
        if socket_path.exists() {
            std::fs::remove_file(socket_path).map_err(|e| {
                anyhow::anyhow!("Cannot remove stale socket {}: {e}", socket_path.display())
            })?;
        }

        let listener = UnixListener::bind(socket_path).map_err(|e| {
            anyhow::anyhow!("Cannot bind UDS socket {}: {e}", socket_path.display())
        })?;

        eprintln!("janitor daemon: listening on {}", socket_path.display());

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _)) => {
                            let reg = Arc::clone(&registry);
                            tokio::spawn(handle_connection(stream, reg));
                        }
                        Err(e) => {
                            eprintln!("janitor daemon: accept error: {e}");
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("janitor daemon: shutting down (SIGINT)");
                    break;
                }
            }
        }

        // Remove the socket file on clean exit.
        let _ = std::fs::remove_file(socket_path);
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Per-connection handler
    // ---------------------------------------------------------------------------

    /// Handle a single UDS client connection.
    ///
    /// Reads newline-delimited JSON requests until the client disconnects.
    /// Writes one JSON response per request.
    async fn handle_connection(stream: UnixStream, registry: Arc<RwLock<SymbolRegistry>>) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let response = process_request(&line, &registry).await;
            let mut json = match serde_json::to_string(&response) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("janitor daemon: serialisation error: {e}");
                    continue;
                }
            };
            json.push('\n');
            if let Err(e) = writer.write_all(json.as_bytes()).await {
                eprintln!("janitor daemon: write error: {e}");
                break;
            }
        }
    }

    /// Parse and execute one daemon request, returning the appropriate response.
    async fn process_request(line: &str, registry: &Arc<RwLock<SymbolRegistry>>) -> DaemonResponse {
        match serde_json::from_str::<DaemonRequest>(line) {
            Ok(DaemonRequest::Bounce { patch }) => {
                let reg = registry.read().await;
                match PatchBouncer.bounce(&patch, &reg) {
                    Ok(score) => DaemonResponse::Report {
                        slop_score: score.score() as f64,
                        zombies: score.zombie_symbols_added,
                    },
                    Err(e) => DaemonResponse::Error {
                        message: e.to_string(),
                    },
                }
            }
            Err(e) => DaemonResponse::Error {
                message: format!("Invalid request: {e}"),
            },
        }
    }
}
