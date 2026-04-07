//! Long-lived Janitor daemon — serves `Bounce` requests over a Unix Domain Socket.
//!
//! Eliminates process-spawn overhead for high-frequency CI integrations by keeping
//! the parsed symbol registry resident in memory across multiple bounce requests.
//!
//! ## Architecture
//! - **`HotRegistry`**: wraps `ArcSwap<Arc<SymbolRegistry>>` for lock-free reads
//!   and atomic hot-swap reloads without blocking in-flight requests.
//! - **`LshIndex`**: per-daemon MinHash index for cross-request PR collision detection.
//!   Each `Bounce` request contributes a `PrDeltaSignature`; subsequent requests are
//!   checked against prior ones to detect near-duplicate PRs.
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
//! {"type":"Report","slop_score":15.0,"zombies":1,"antipatterns":0}
//! {"type":"Error","message":"..."}
//! ```
//!
//! ## Lifecycle
//! 1. Load `symbols.rkyv` once at startup into `HotRegistry`.
//! 2. Accept connections on the UDS; spawn a task per connection.
//! 3. Each task holds a lock-free guard via `HotRegistry::load()` (no blocking).
//! 4. Graceful shutdown on SIGINT / SIGTERM — in-flight requests complete normally.
//!
//! ## Platform
//! Unix Domain Sockets are a Unix-only feature. This entire module is gated on
//! `#[cfg(unix)]`.

#[cfg(unix)]
pub mod unix {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::Result;
    use arc_swap::ArcSwap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Semaphore;

    use common::physarum::{Pulse, SystemHeart};
    use common::registry::{MappedRegistry, SymbolRegistry};
    use forge::pr_collider::LshIndex;
    use forge::slop_filter::{PRBouncer, PatchBouncer};

    /// Max concurrent bounce tasks in [`Pulse::Flow`] mode.
    const FLOW_CONCURRENCY: usize = 4;
    /// Max concurrent bounce tasks in [`Pulse::Constrict`] mode.
    const CONSTRICT_CONCURRENCY: usize = 2;

    // ---------------------------------------------------------------------------
    // Protocol types
    // ---------------------------------------------------------------------------

    /// Daemon request payload — one JSON object per line.
    #[derive(serde::Deserialize)]
    #[serde(tag = "type")]
    pub enum DaemonRequest {
        /// Analyse a unified-diff patch for slop.
        Bounce {
            patch: String,
            /// Optional: PR author handle for Vouch identity verification.
            #[serde(default)]
            author: Option<String>,
            /// Optional: absolute path to the cloned PR repository root.
            /// When provided alongside `author`, `is_vouched` is computed from
            /// the Vouch identity files present in that directory.
            #[serde(default)]
            repo_path: Option<String>,
        },
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
            /// Number of language-specific antipatterns detected (×50 each).
            /// Kept for backward-compatibility with old Governor versions that
            /// read only the count field.
            antipatterns: u32,
            /// Full human-readable description strings for each detected
            /// antipattern (one entry per finding).  Matches the
            /// `BounceLogEntry.antipatterns` field so the Governor can
            /// perform structural threat classification (`security:` prefix
            /// check) without requiring an additional round-trip.
            antipattern_details: Vec<String>,
            /// PR numbers of prior patches sharing ≥85% MinHash Jaccard
            /// similarity — structural clones detected by the Swarm engine.
            collided_pr_numbers: Vec<u32>,
            /// Whether the PR author is listed in a Vouch identity file
            /// (`.vouched`, `trust.td`, or `.github/vouched.td`) inside the
            /// repository.  Always `false` when `author` or `repo_path` were
            /// not supplied in the request.
            is_vouched: bool,
        },
        /// Error during request processing.
        Error { message: String },
    }

    // ---------------------------------------------------------------------------
    // HotRegistry — lock-free atomic symbol registry
    // ---------------------------------------------------------------------------

    /// Lock-free symbol registry with atomic hot-swap capability.
    ///
    /// Wraps [`ArcSwap<Arc<SymbolRegistry>>`] so that:
    /// - Reads are lock-free: `load()` returns a guard with no mutex acquisition.
    /// - Reloads are atomic: `reload()` swaps the current registry with a freshly
    ///   deserialised one; readers holding the old guard are unaffected.
    ///
    /// Uses `MappedRegistry::archived()` → `rkyv::access_unchecked` internally for
    /// zero-copy deserialization on load.
    pub struct HotRegistry {
        inner: ArcSwap<SymbolRegistry>,
        // Retained for `reload()` — hot-swap API wired up in a future release.
        #[allow(dead_code)]
        path: std::path::PathBuf,
    }

    impl HotRegistry {
        /// Open and deserialise the registry at `path`.
        ///
        /// Uses `rkyv::access_unchecked` via [`MappedRegistry`] for zero-copy reads;
        /// the resulting `SymbolRegistry` is heap-owned and held in the `ArcSwap`.
        ///
        /// # Errors
        /// Returns `Err` if the file cannot be opened, the BLAKE3 checksum fails,
        /// or rkyv deserialisation fails.
        pub fn open(path: &Path) -> Result<Self> {
            let registry = load_registry(path)?;
            Ok(Self {
                inner: ArcSwap::from_pointee(registry),
                path: path.to_path_buf(),
            })
        }

        /// Returns a lock-free guard holding a reference to the current registry.
        ///
        /// The guard keeps the `Arc<SymbolRegistry>` alive for its lifetime.
        /// Concurrent [`reload`][Self::reload] calls are safe — readers hold the old
        /// snapshot until the guard is dropped.
        pub fn load(&self) -> arc_swap::Guard<Arc<SymbolRegistry>> {
            self.inner.load()
        }

        /// Atomically reload the registry from disk.
        ///
        /// After this call, new `load()` calls return the updated registry.
        /// In-flight requests holding the previous guard are unaffected.
        ///
        /// # Errors
        /// Returns `Err` if the file cannot be re-opened or deserialization fails.
        #[allow(dead_code)]
        pub fn reload(&self) -> Result<()> {
            let registry = load_registry(&self.path)?;
            self.inner.store(Arc::new(registry));
            Ok(())
        }
    }

    // ---------------------------------------------------------------------------
    // Daemon state
    // ---------------------------------------------------------------------------

    /// Shared daemon state — held in `Arc` and passed to every connection handler.
    pub struct DaemonState {
        /// Lock-free symbol registry (hot-swappable).
        pub registry: HotRegistry,
        /// Cross-request LSH index for near-duplicate PR detection.
        ///
        /// Each `Bounce` request inserts its `PrDeltaSignature` and queries for
        /// prior near-duplicate patches.  Near-duplicate matches contribute to
        /// `logic_clones_found` in the response score.
        pub lsh_index: LshIndex,
        /// Absolute path to the `.janitor/` directory.
        ///
        /// Used by `process_request` to append each bounce result to
        /// `bounce_log.ndjson` so that `janitor report` can aggregate
        /// daemon-served bounce activity alongside CLI invocations.
        pub janitor_dir: std::path::PathBuf,
        /// Physarum Protocol — OS memory pressure monitor.
        ///
        /// Sampled before each new connection is handed off to a task.
        pub heart: SystemHeart,
        /// Concurrency gate for [`Pulse::Flow`] mode — [`FLOW_CONCURRENCY`] permits.
        pub flow_semaphore: Arc<Semaphore>,
        /// Concurrency gate for [`Pulse::Constrict`] mode — [`CONSTRICT_CONCURRENCY`] permits.
        pub constrict_semaphore: Arc<Semaphore>,
    }

    // ---------------------------------------------------------------------------
    // Registry loading
    // ---------------------------------------------------------------------------

    /// Load a `SymbolRegistry` from a `symbols.rkyv` file at `path`.
    ///
    /// Uses the `MappedRegistry` mmap + rkyv zero-copy path:
    /// - [`MappedRegistry::open`] verifies the BLAKE3 checksum and calls
    ///   `rkyv::access_unchecked` internally.
    /// - [`rkyv::deserialize`] produces a heap-owned `SymbolRegistry`.
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
    /// it across all connections via [`HotRegistry`] (lock-free `ArcSwap`).
    /// A per-daemon [`LshIndex`] accumulates `PrDeltaSignature` entries for
    /// cross-request near-duplicate detection.
    ///
    /// Blocks until SIGINT or SIGTERM is received, then shuts down gracefully.
    ///
    /// # Errors
    /// Returns `Err` if the registry cannot be loaded or the socket cannot be bound.
    pub async fn serve(socket_path: &Path, registry_path: &Path) -> Result<()> {
        let janitor_dir = registry_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let state = Arc::new(DaemonState {
            registry: HotRegistry::open(registry_path)?,
            lsh_index: LshIndex::new(),
            janitor_dir,
            heart: SystemHeart::new(),
            flow_semaphore: Arc::new(Semaphore::new(FLOW_CONCURRENCY)),
            constrict_semaphore: Arc::new(Semaphore::new(CONSTRICT_CONCURRENCY)),
        });

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
                            let s = Arc::clone(&state);
                            tokio::spawn(async move {
                                // ── Physarum Protocol: backpressure ──────────
                                // If memory pressure is critical, hold the
                                // connection open and retry every 500 ms until
                                // the system digests current load.  The client
                                // socket stays alive; the task simply parks.
                                while let Pulse::Stop = s.heart.beat() {
                                    eprintln!(
                                        "janitor daemon: memory pressure STOP — \
                                         holding request (500 ms)"
                                    );
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                }
                                // Acquire a concurrency permit proportional to
                                // current pressure before entering the handler.
                                // `acquire_owned` takes `Arc<Self>` by value —
                                // clone the Arc cheaply to pass ownership.
                                let _permit = match s.heart.beat() {
                                    Pulse::Constrict => Arc::clone(&s.constrict_semaphore)
                                        .acquire_owned()
                                        .await
                                        .ok(),
                                    _ => Arc::clone(&s.flow_semaphore)
                                        .acquire_owned()
                                        .await
                                        .ok(),
                                };
                                handle_connection(stream, s).await;
                            });
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
    async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let response = process_request(&line, &state).await;
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
    ///
    /// Uses a lock-free `HotRegistry::load()` guard for registry access.
    /// After scoring, inserts a `PrDeltaSignature` for the patch into the `LshIndex`
    /// and adds any cross-PR collision count to `logic_clones_found`.
    async fn process_request(line: &str, state: &Arc<DaemonState>) -> DaemonResponse {
        match serde_json::from_str::<DaemonRequest>(line) {
            Ok(DaemonRequest::Bounce {
                patch,
                author,
                repo_path,
            }) => {
                // Lock-free read guard — no blocking.
                let guard = state.registry.load();
                let registry: &SymbolRegistry = &guard;

                let bouncer = repo_path
                    .as_deref()
                    .map(std::path::Path::new)
                    .map(PatchBouncer::for_workspace)
                    .unwrap_or_default();

                match bouncer.bounce(&patch, registry) {
                    Ok(mut score) => {
                        // Cross-PR collision detection via LSH MinHash index.
                        let sig =
                            forge::pr_collider::PrDeltaSignature::from_bytes(patch.as_bytes());
                        let near_matches = state.lsh_index.query(&sig, 0.85);
                        score.logic_clones_found += near_matches.len() as u32;
                        score.collided_pr_numbers = near_matches.clone();
                        // Insert for future comparisons — daemon has no PR number context.
                        state.lsh_index.insert(sig.clone(), 0);

                        // Persist to bounce_log.ndjson for `janitor report` aggregation.
                        // Daemon connections have no PR-number / author context — those
                        // Cache computed values before consuming Vec fields via move.
                        let slop_score = score.score();
                        let antipatterns_count = score.antipatterns_found;
                        let zombie_symbols_added = score.zombie_symbols_added;
                        // Clone detail strings before move into BounceLogEntry so
                        // the same Vec can be forwarded in DaemonResponse::Report.
                        let antipattern_details = score.antipattern_details.clone();
                        let collided_pr_numbers_response = near_matches.clone();

                        // fields are None.  Best-effort: I/O errors are silently dropped.
                        let log_entry = crate::report::BounceLogEntry {
                            pr_number: None,
                            author: author.clone(),
                            timestamp: crate::utc_now_iso8601(),
                            slop_score,
                            dead_symbols_added: score.dead_symbols_added,
                            logic_clones_found: score.logic_clones_found,
                            zombie_symbols_added,
                            unlinked_pr: score.unlinked_pr,
                            antipatterns: score.antipattern_details,
                            comment_violations: score.comment_violation_details,
                            min_hashes: sig.min_hashes.to_vec(),
                            zombie_deps: Vec::new(),
                            state: crate::report::PrState::Open,
                            is_bot: false,
                            repo_slug: String::new(),
                            suppressed_by_domain: score.suppressed_by_domain,
                            collided_pr_numbers: near_matches,
                            necrotic_flag: score.necrotic_flag,
                            commit_sha: String::new(),
                            policy_hash: String::new(),
                            version_silos: Vec::new(),
                            agentic_pct: 0.0,
                            ci_energy_saved_kwh: if slop_score > 0 { 0.1 } else { 0.0 },
                            provenance: crate::report::Provenance::default(),
                            governor_status: None,
                            pqc_sig: None,
                            pqc_slh_sig: None,
                            pqc_key_source: None,
                            transparency_log: None,
                            wisdom_hash: None,
                            wisdom_signature: None,
                            wasm_policy_receipts: Vec::new(),
                            capsule_hash: None,
                            decision_receipt: None,
                            cognition_surrender_index: 0.0,
                        };
                        crate::report::append_bounce_log(&state.janitor_dir, &log_entry);

                        // Vouch identity check: requires both the author handle and the
                        // repository root path supplied in the request.  Falls back to
                        // `false` when either is absent (e.g. MCP or direct CLI callers).
                        let is_vouched = match (&author, &repo_path) {
                            (Some(a), Some(r)) => {
                                forge::metadata::is_author_vouched(std::path::Path::new(r), a)
                            }
                            _ => false,
                        };

                        DaemonResponse::Report {
                            slop_score: slop_score as f64,
                            zombies: zombie_symbols_added,
                            antipatterns: antipatterns_count,
                            antipattern_details,
                            collided_pr_numbers: collided_pr_numbers_response,
                            is_vouched,
                        }
                    }
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
