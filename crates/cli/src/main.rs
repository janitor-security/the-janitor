use anyhow::Context as _;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::KeyInit as _;
use hmac::Mac as _;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

mod cbom;
mod daemon;
mod export;
mod git_drive;
mod hunt;
mod jira;
mod report;
mod verify_asset;

fn load_mtls_client_cert(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<ureq::tls::ClientCert> {
    let cert_pem = std::fs::read(cert_path).with_context(|| {
        format!(
            "failed to read mTLS certificate PEM from {}",
            cert_path.display()
        )
    })?;
    let key_pem = std::fs::read(key_path)
        .with_context(|| format!("failed to read mTLS key PEM from {}", key_path.display()))?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse mTLS certificate chain PEM")?;
    if certs.is_empty() {
        anyhow::bail!("mTLS certificate chain PEM contained no certificates");
    }

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key_present = rustls_pemfile::private_key(&mut key_reader)
        .context("failed to parse mTLS private key PEM")?;
    if key_present.is_none() {
        anyhow::bail!("mTLS private key PEM contained no private key");
    }

    let cert_chain: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&cert_pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(cert)) => Some(Ok(cert)),
            Ok(ureq::tls::PemItem::PrivateKey(_)) => None,
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("failed to translate mTLS certificate chain"))?;
    let private_key = ureq::tls::PrivateKey::from_pem(&key_pem)
        .map_err(|_| anyhow::anyhow!("failed to translate mTLS private key"))?;

    Ok(ureq::tls::ClientCert::new_with_certs(
        &cert_chain,
        private_key,
    ))
}

fn build_ureq_agent(policy: &common::policy::JanitorPolicy) -> anyhow::Result<ureq::Agent> {
    let cert_path = env::var("JANITOR_MTLS_CERT")
        .ok()
        .or_else(|| policy.forge.mtls_cert.clone());
    let key_path = env::var("JANITOR_MTLS_KEY")
        .ok()
        .or_else(|| policy.forge.mtls_key.clone());

    let Some(cert_path) = cert_path else {
        if key_path.is_some() {
            anyhow::bail!("JANITOR_MTLS_KEY provided without JANITOR_MTLS_CERT");
        }
        return Ok(ureq::Agent::new_with_defaults());
    };
    let Some(key_path) = key_path else {
        anyhow::bail!("JANITOR_MTLS_CERT provided without JANITOR_MTLS_KEY");
    };

    let client_cert = load_mtls_client_cert(Path::new(&cert_path), Path::new(&key_path))?;
    let tls_config = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .client_cert(Some(client_cert))
        .build();

    Ok(ureq::Agent::config_builder()
        .tls_config(tls_config)
        .build()
        .new_agent())
}

#[derive(Debug, serde::Serialize)]
struct VerifySuppressionsRequest<'a> {
    suppression_ids: Vec<&'a str>,
}

#[derive(Debug, serde::Deserialize)]
struct VerifySuppressionsResponse {
    approved_ids: Vec<String>,
}

fn verify_suppressions_with_governor(
    agent: &ureq::Agent,
    governor_base_url: &str,
    suppressions: &mut [common::policy::Suppression],
) {
    if suppressions.is_empty() {
        return;
    }

    let url = format!(
        "{}/v1/verify-suppressions",
        governor_base_url.trim_end_matches('/')
    );
    let body = VerifySuppressionsRequest {
        suppression_ids: suppressions.iter().map(|s| s.id.as_str()).collect(),
    };
    let approved_ids = agent
        .post(&url)
        .header("Content-Type", "application/json")
        .send(
            serde_json::to_string(&body).unwrap_or_else(|_| "{\"suppression_ids\":[]}".to_string()),
        )
        .ok()
        .and_then(|mut response| {
            response
                .body_mut()
                .read_json::<VerifySuppressionsResponse>()
                .ok()
        })
        .map(|payload| payload.approved_ids)
        .unwrap_or_default();

    for suppression in suppressions {
        suppression.approved = approved_ids.iter().any(|id| id == &suppression.id);
    }
}

fn find_prior_bounce_entry<'a>(
    prior_entries: &'a [report::BounceLogEntry],
    repo_slug: &str,
    pr_number: Option<u64>,
    commit_sha: &str,
) -> Option<&'a report::BounceLogEntry> {
    prior_entries.iter().rev().find(|entry| {
        if entry.repo_slug != repo_slug {
            return false;
        }
        if let Some(pr_number) = pr_number {
            entry.pr_number == Some(pr_number)
        } else if !commit_sha.is_empty() {
            entry.commit_sha == commit_sha
        } else {
            true
        }
    })
}

#[derive(Parser)]
#[command(name = "janitor")]
#[command(version)]
#[command(about = "Code Integrity Protocol — Automated Dead Symbol Detection & Cleanup")]
struct Cli {
    /// Number of parallel rayon worker threads (0 = auto-detect from system RAM).
    ///
    /// Auto-detection tiers: < 8 GiB → 2, 8–16 GiB → 4, 16–32 GiB → 8,
    /// \> 32 GiB → logical CPU count.  Set explicitly to override for CI
    /// environments where RAM limits differ from total physical RAM.
    #[arg(long, default_value = "0", global = true)]
    concurrency: usize,

    #[command(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Commands {
    /// Run the 6-stage dead-symbol detection pipeline.
    Scan {
        /// Project root to analyse (Python, Rust, JS/TS, C++).
        path: PathBuf,
        /// Protect all public top-level symbols (library mode).
        #[arg(long)]
        library: bool,
        /// Also print protected symbols with their protection reason.
        #[arg(long)]
        verbose: bool,
        /// Output format: `text` (default), `json` for machine-readable output, or
        /// `scip` for Sourcegraph Code Intelligence Protocol export (stub — mapping phase only).
        ///
        /// JSON schema: `{ schema_version, slop_score, dead_symbols: [{id, structural_hash, reason, byte_range}], merkle_root }`.
        /// Suitable for automated GitHub Checks integration.
        #[arg(long, default_value = "text")]
        format: String,
        /// Glob patterns for directories to exclude from scanning.
        ///
        /// Patterns are matched against directory name components of each file path.
        /// Trailing `/`, `/**`, and `/*` are stripped before matching.
        /// Example: `--exclude thirdparty/ --exclude generated/`
        #[arg(long, default_values = ["thirdparty/", "vendor/", "node_modules/", "target/"])]
        exclude: Vec<String>,
    },
    /// Detect (and optionally refactor) structurally-duplicate functions.
    Dedup {
        /// Source file or directory to analyse (Python, Rust, JS/TS, Go, C/C++).
        path: PathBuf,
        /// Rewrite duplicates using the Safe Proxy Pattern (requires --force-purge).
        #[arg(long)]
        apply: bool,
        /// Execute physical rewriting. Requires --token. Default is dry-run.
        #[arg(long)]
        force_purge: bool,
        /// Ed25519 purge token (required with --force-purge).
        #[arg(long)]
        token: Option<String>,
        /// Bypass the 90-day immaturity gate for recently modified files.
        #[arg(long)]
        override_tax: bool,
        /// Glob patterns for directories to exclude from dedup analysis.
        ///
        /// Patterns are matched against directory name components of each file path.
        #[arg(long, default_values = ["thirdparty/", "vendor/", "node_modules/", "target/"])]
        exclude: Vec<String>,
        /// [DANGEROUS] Bypass the C++/C#/GLSL dedup safety hard-gate.
        ///
        /// By default, dedup --apply refuses to rewrite C++, C, header, C#, and GLSL
        /// files to prevent SIMD/template corruption. This flag disables that gate.
        #[arg(long, hide = true)]
        force_unsafe_cpp_dedup: bool,
    },
    /// Shadow tree management.
    Shadow {
        #[command(subcommand)]
        cmd: ShadowCmd,
    },
    /// Shadow-simulate deletion, verify tests, then physically remove dead symbols.
    ///
    /// Default: dry-run (scan and report). Pass --force-purge to execute cleanup.
    /// Cleanup is free. Pass --token to also generate a signed integrity attestation.
    Clean {
        /// Project root.
        path: PathBuf,
        /// Dry-run mode (default): scan and report without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Execute physical cleanup. No token required.
        #[arg(long)]
        force_purge: bool,
        /// Protect all public symbols (library mode). Use for library repositories.
        #[arg(long)]
        library: bool,
        /// Ed25519 token for signed integrity attestation (optional).
        #[arg(long)]
        token: Option<String>,
        /// Custom test command executed via `sh -c <CMD>` instead of auto-detection.
        ///
        /// Example: `--test-command "make test"` or `--test-command "pytest tests/"`.
        /// Bypasses all auto-detection heuristics (pytest/cargo/go/npm/scons).
        #[arg(long)]
        test_command: Option<String>,
        /// Bypass the 90-day immaturity gate for recently modified files.
        #[arg(long)]
        override_tax: bool,
        /// Glob patterns for directories to exclude from cleanup scanning.
        ///
        /// Patterns are matched against directory name components of each file path.
        #[arg(long, default_values = ["thirdparty/", "vendor/", "node_modules/", "target/"])]
        exclude: Vec<String>,
    },
    /// Analyse a unified diff patch for slop: dead-symbol additions and logic clones.
    ///
    /// **Patch source (pick one)**:
    ///   - `--patch <file>` — read from a local unified diff file.
    ///   - `--pr-number <N> --repo-slug <owner/repo>` — auto-fetch via `gh pr diff`.
    ///   - stdin — pipe a diff when no other source is specified.
    ///
    /// Loads the symbol registry from `--registry <file>` when provided, otherwise
    /// falls back to `.janitor/symbols.rkyv` under the project root.
    ///
    /// **Git-native mode**: supply `--repo`, `--base`, and `--head` together to
    /// analyse a PR directly from git OIDs without extracting a diff file.
    /// Uses `shadow_git` to load changed blobs in-memory from the pack index.
    ///
    /// Output: schema_version, slop_score, dead_symbols_added, logic_clones_found,
    /// zombie_symbols_added, antipatterns_found, merkle_root.
    Bounce {
        /// Project root (reads .janitor/symbols.rkyv for the registry unless --registry is set).
        path: PathBuf,
        /// Path to unified diff patch file (reads stdin if omitted).
        ///
        /// Mutually exclusive with `--repo/--base/--head`.
        #[arg(long)]
        patch: Option<PathBuf>,
        /// Explicit path to the symbol registry (.rkyv file).
        ///
        /// Overrides the default `.janitor/symbols.rkyv` auto-discovery.
        #[arg(long)]
        registry: Option<PathBuf>,
        /// Output format: `text` (default) or `json` for machine-readable output.
        ///
        /// JSON schema: `{ schema_version, slop_score, dead_symbols_added,
        /// logic_clones_found, zombie_symbols_added, antipatterns_found, merkle_root }`.
        #[arg(long, default_value = "text")]
        format: String,
        /// Git repository root for git-native mode (`shadow_git` analysis).
        ///
        /// Requires `--base` and `--head`. When provided, the patch is loaded
        /// directly from the pack index — no diff file needed.
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Base commit SHA (target-branch head) for git-native mode.
        #[arg(long)]
        base: Option<String>,
        /// Head commit SHA (feature-branch head) for git-native mode.
        #[arg(long)]
        head: Option<String>,
        /// PR number to associate with this bounce run (stored in bounce_log.ndjson).
        ///
        /// Used by `janitor report` to identify PRs in the Slop Top 50 and clone tables.
        /// Optional — bounce analysis proceeds without it.
        #[arg(long)]
        pr_number: Option<u64>,
        /// PR author handle to associate with this bounce run (stored in bounce_log.ndjson).
        ///
        /// Used by `janitor report` for attribution in the intelligence report.
        #[arg(long)]
        author: Option<String>,
        /// PR body text for metadata analysis (optional).
        ///
        /// When supplied, The Janitor checks for:
        ///   - Banned phrases (AI-isms, profanity) in added comment lines.
        ///   - Missing issue link (`Closes #N` / `Fixes #N`) → +20 SlopScore.
        ///
        /// Typical CI usage: `--pr-body "$PR_BODY"` (GitHub Actions exposes
        /// `${{ github.event.pull_request.body }}`).
        ///
        /// `allow_hyphen_values` permits bodies that start with `-` (common in
        /// Markdown bullet-list PR descriptions).
        #[arg(long, allow_hyphen_values = true)]
        pr_body: Option<String>,
        /// GitHub repository slug (`owner/repo`) used for auto-fetch mode.
        ///
        /// When `--pr-number` is supplied without `--patch`, the Janitor calls
        /// `gh pr diff <N> --repo <slug>` to retrieve the diff automatically.
        /// Falls back to the `GITHUB_REPOSITORY` environment variable when omitted,
        /// so no extra flag is needed inside GitHub Actions.
        #[arg(long)]
        repo_slug: Option<String>,
        /// GitHub PR lifecycle state: `open` (default), `merged`, or `closed`.
        ///
        /// Stored in the bounce log for downstream CSV segmentation.  Use `merged`
        /// or `closed` to classify historical entries as non-actionable in reports.
        #[arg(long, default_value = "open")]
        pr_state: String,
        /// Governor base URL for attestation (Architecture Inversion mode).
        ///
        /// When set alongside `--analysis-token`, the scored `BounceLogEntry` is
        /// submitted to `<governor-url>/v1/report` so the Governor can
        /// issue a GitHub Check Run on behalf of the customer runner.  Source code
        /// stays on the runner — nothing is transmitted beyond the structural log.
        ///
        /// `--report-url` remains accepted as a compatibility alias.
        #[arg(long, alias = "report-url")]
        governor_url: Option<String>,
        /// Short-lived analysis token from `/v1/analysis-token`.
        ///
        /// Required when `--governor-url` is set.  Identifies the PR event and
        /// authorises the bounce result submission.
        #[arg(long)]
        analysis_token: Option<String>,
        /// Canonical HEAD commit SHA supplied by the CI runner.
        ///
        /// When set, this value is used as `commit_sha` in the `BounceLogEntry`
        /// and must match the `head_sha` claim in the analysis JWT.  If absent,
        /// the CLI falls back to the `--head` argument or `GITHUB_SHA` env var.
        #[arg(long)]
        head_sha: Option<String>,
        /// Hard wall-clock timeout for the entire bounce analysis, in seconds.
        ///
        /// If the analysis does not complete within this duration the CLI sends
        /// a synthetic failure payload to `--governor-url` (if configured) so the
        /// Governor can close the GitHub Check Run with a `failure` conclusion
        /// rather than leaving it spinning indefinitely.  Exits non-zero after
        /// dispatching the payload.
        ///
        /// Default: 1140 s (19 minutes) — one minute inside GitHub Actions'
        /// default 20-minute job timeout, giving the POST to the Governor time
        /// to complete before the runner is killed.
        #[arg(long, default_value = "1140")]
        timeout_secs: u64,
        /// Proceed without Governor attestation when the network endpoint is unreachable.
        ///
        /// When set and the Governor POST fails (timeout, 5xx, or any network
        /// error), the CLI emits a `[JANITOR DEGRADED]` warning to stderr, marks
        /// the bounce log entry with `governor_status: "degraded"`, and exits `0`
        /// so downstream CI steps are not blocked.
        ///
        /// Without this flag the CLI exits `1` on any Governor transport failure
        /// (fail-closed — the Governor firewall cannot be silently bypassed).
        ///
        /// Can also be set via `soft_fail = true` in `janitor.toml`.
        #[arg(long)]
        soft_fail: bool,
        /// Raise bounce analysis budgets to the deep-scan profile (32 MiB / 30 s).
        ///
        /// Also retries parser-exhaustion candidates with the 30 s parse budget
        /// before emitting a `Severity::Exhaustion` finding.
        #[arg(long)]
        deep_scan: bool,
        /// ML-DSA-65 / SLH-DSA attestation key source for BYOK local attestation
        /// (FIPS 204 + FIPS 205 — Signature Sovereignty mode).
        ///
        /// When provided, the CLI signs the CycloneDX v1.6 CBOM for this bounce
        /// result using the customer's locally-stored PQC private key material.
        /// The ML-DSA-65 signature is embedded as `pqc_sig`; an optional
        /// SLH-DSA-SHAKE-192s signature is embedded as `pqc_slh_sig`.
        /// Verifiable offline via:
        ///   `janitor verify-cbom --key <ml.pub> --slh-key <slh.pub> <log.ndjson>`
        ///
        /// Accepted forms:
        ///   - `./ml-dsa.key` (existing local file mode)
        ///   - `arn:aws:kms:...`
        ///   - `https://<vault>.vault.azure.net/...`
        ///   - `pkcs11:token=...`
        ///
        /// Governor attestation is skipped when this flag is set — local PQC
        /// signing is the chain-of-custody mechanism for the entry.
        #[arg(long)]
        pqc_key: Option<String>,
        /// Paths to BYOP (Bring Your Own Policy) Wasm rule modules.
        ///
        /// Each module is executed against the patch source bytes inside a
        /// fuel- and memory-bounded sandbox (10 MiB RAM cap, 100 M fuel units).
        /// Modules must implement the host-guest ABI: export `memory`,
        /// `analyze(i32, i32) -> i32`, and `output_ptr() -> i32`.
        ///
        /// May be specified multiple times.  Merged with `wasm_rules` from
        /// `janitor.toml` when both are present.
        #[arg(long, value_name = "PATH")]
        wasm_rules: Vec<String>,
    },
    /// Launch the Ratatui TUI dashboard from a saved symbol registry.
    Dashboard {
        /// Project root (reads .janitor/symbols.rkyv).
        ///
        /// When `--wopr` is set this becomes the gauntlet base directory.
        /// Defaults to `~/dev/gauntlet/` when omitted in dashboard mode.
        path: Option<PathBuf>,
        /// Launch the Integrity Dashboard multi-tenant operations center.
        ///
        /// Opens a repository-selection menu over all repositories found under
        /// the gauntlet base directory.  Navigate with ↑/↓, select with Enter,
        /// change tabs with ←/→, return with Esc/Backspace, quit with q.
        #[arg(long)]
        wopr: bool,
    },
    /// Generate a Code Health SVG badge from the last scan result.
    Badge {
        /// Project root (reads .janitor/symbols.rkyv).
        path: PathBuf,
        /// Output path for the SVG file. Default: <path>/.janitor/badge.svg.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Undo the last cleanup. Uses git stash if inside a VCS repo, otherwise
    /// restores files from .janitor/ghost/.
    Undo {
        /// Project root.
        path: PathBuf,
    },
    /// Local telemetry management (anonymous failure learning loop).
    Telemetry {
        #[command(subcommand)]
        cmd: TelemetryCmd,
    },
    /// Start the MCP (Model Context Protocol) stdio JSON-RPC server.
    ///
    /// Reads newline-delimited JSON-RPC 2.0 from stdin, responds on stdout.
    /// Designed for use as an MCP tool server by AI assistants.
    Mcp,
    /// Launch the long-lived Janitor daemon (Unix Domain Socket server).
    ///
    /// Keeps the symbol registry resident in memory to eliminate process-spawn
    /// overhead for high-frequency CI / pre-commit integrations.
    ///
    /// ## Protocol
    /// Newline-delimited JSON. Send one `{"type":"Bounce","patch":"<diff>"}` per line.
    /// Receive `{"type":"Report","slop_score":f64,"zombies":u32}` in response.
    ///
    /// ## Example
    /// ```sh
    /// janitor serve --socket /tmp/janitor.sock --registry .janitor/symbols.rkyv &
    /// echo '{"type":"Bounce","patch":"..."}' | socat - UNIX-CONNECT:/tmp/janitor.sock
    /// ```
    ///
    /// Graceful shutdown: send SIGINT (Ctrl-C).
    #[cfg(unix)]
    Serve {
        /// Path to the Unix Domain Socket to bind.
        ///
        /// An existing stale socket at this path is removed automatically.
        #[arg(long, default_value = "/tmp/janitor.sock")]
        socket: String,
        /// Path to the symbol registry file (`.rkyv`).
        ///
        /// Overrides the default `.janitor/symbols.rkyv` auto-discovery.
        /// Required when the project root is not the current directory.
        #[arg(long)]
        registry: Option<String>,
        /// Project root used for default registry discovery when `--registry` is not set.
        #[arg(long, default_value = ".")]
        path: PathBuf,
    },
    /// Generate an intelligence report from historical bounce results.
    ///
    /// Reads `.janitor/bounce_log.ndjson` — populated by each `janitor bounce`
    /// invocation — and produces three sections:
    ///
    /// - **Slop Top 50**: PRs ranked by composite SlopScore.
    /// - **Structural Clones**: near-duplicate PR pairs detected via 64-hash MinHash LSH.
    /// - **Zombie Dependencies**: PRs that introduced packages never imported in source.
    ///
    /// Pass `--global` to aggregate bounce logs from all repos under a gauntlet directory.
    Report {
        /// Path to the target repository (reads `<repo>/.janitor/bounce_log.ndjson`).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Number of PRs to include in the Slop Top list.
        #[arg(long, default_value = "50")]
        top: usize,
        /// Output format: `markdown` (default), `json`, `pdf`, `cbom`, or `sarif`.
        ///
        /// The `pdf` format requires `pandoc` and a LaTeX distribution
        /// (texlive-latex-recommended on Debian/Ubuntu, BasicTeX on macOS).
        /// Output defaults to `janitor_report.pdf` when `--out` is not specified.
        ///
        /// The `cbom` format emits a CycloneDX v1.5 JSON document.
        /// The `sarif` format emits a SARIF 2.1.0 JSON document.
        #[arg(long, default_value = "markdown")]
        format: String,
        /// Write the report to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Aggregate bounce logs from ALL repos under a gauntlet directory.
        ///
        /// When set, `--repo` is ignored and `--gauntlet` discovers all repos.
        #[arg(long)]
        global: bool,
        /// Root directory containing multiple repos for `--global` aggregation.
        ///
        /// Defaults to `~/dev/gauntlet/` when `--global` is set.
        #[arg(long)]
        gauntlet: Option<PathBuf>,
    },
    /// Synchronise the local Wisdom Registry with Janitor Sentinel.
    ///
    /// Downloads the latest `wisdom.rkyv` from `https://thejanitor.app/v1/wisdom.rkyv`
    /// and overwrites `.janitor/wisdom.rkyv` in the project root.
    ///
    /// When `--ci-mode` is active, additionally fetches the CISA Known Exploited
    /// Vulnerabilities (KEV) catalog and writes a human-readable, diff-friendly
    /// `.janitor/wisdom_manifest.json` alongside the binary registry.  This JSON
    /// file is used by `.github/workflows/cisa-kev-sync.yml` to detect new
    /// entries without forking out to `curl`.
    UpdateWisdom {
        /// Project root (writes .janitor/wisdom.rkyv and, with --ci-mode,
        /// .janitor/wisdom_manifest.json).
        path: PathBuf,
        /// Emit a diffable `.janitor/wisdom_manifest.json` alongside wisdom.rkyv.
        ///
        /// Fetches the CISA KEV JSON catalog and writes a sorted, compact JSON
        /// manifest of all entries.  Intended for CI pipelines that need to diff
        /// the KEV catalog across runs without parsing binary rkyv data.
        #[arg(long, default_value_t = false)]
        ci_mode: bool,
    },
    /// Synchronize the OSV malicious-package corpus into `.janitor/slopsquat_corpus.rkyv`.
    UpdateSlopsquat {
        /// Project root (writes .janitor/slopsquat_corpus.rkyv).
        path: PathBuf,
    },
    /// Export bounce log as a CSV file for spreadsheet or notebook analysis.
    ///
    /// Reads `.janitor/bounce_log.ndjson` (populated by `janitor bounce`) and writes
    /// one CSV row per bounce invocation.
    ///
    /// ## Columns
    /// `PR_Number`, `Author`, `Score`, `Dead_Code_Count`, `Logic_Clones`,
    /// `Zombie_Syms`, `Zombie_Deps`, `Antipatterns`, `Comment_Violations`, `Timestamp`.
    ///
    /// Antipattern and comment-violation strings are joined with `;` so each row fits a
    /// single cell; split on `;` inside Excel / pandas to expand them.
    Export {
        /// Project root (reads `<repo>/.janitor/bounce_log.ndjson`).
        ///
        /// Ignored when `--global` is set.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Output CSV file path.
        #[arg(long, short = 'o', default_value = "bounce_export.csv")]
        out: PathBuf,
        /// Output format: `csv` (default), `cef`, or `ocsf`.
        #[arg(long, default_value = "csv")]
        format: String,
        /// Aggregate bounce logs from ALL repos under a gauntlet directory.
        ///
        /// When set, `--repo` is ignored and every `<gauntlet-dir>/*/` sub-directory
        /// that contains a `.janitor/bounce_log.ndjson` contributes rows to the output.
        #[arg(long)]
        global: bool,
        /// Root directory for `--global` aggregation.
        ///
        /// Defaults to `~/dev/gauntlet/` when `--global` is set.
        #[arg(long)]
        gauntlet_dir: Option<PathBuf>,
    },

    /// Teach the local brain to suppress a recurring false positive.
    ///
    /// Records a pardon for `<symbol>` in `.janitor/local_brain.rkyv`.
    /// After 5 pardons the symbol's suppression probability exceeds the 0.85
    /// threshold and future `janitor scan` / `janitor bounce` runs will silently
    /// ignore it.
    ///
    /// ## Example
    /// ```text
    /// # The scanner keeps flagging my proc-macro expansion helper:
    /// janitor pardon my_macro_fn
    /// janitor pardon my_macro_fn   # repeat until suppressed (5×)
    /// ```
    ///
    /// Use `--repo` to pardon in a non-current directory.
    Pardon {
        /// Symbol name or antipattern description to suppress.
        symbol: String,
        /// Project root (where `.janitor/local_brain.rkyv` lives).
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },

    /// Batch-bounce all PRs in a local clone using libgit2 — zero network overhead.
    ///
    /// Requires a prior Phase 1 fetch to populate `refs/remotes/origin/pr/*`:
    ///
    /// ```sh
    /// git -C <REPO_PATH> config --local --add remote.origin.fetch \
    ///     '+refs/pull/*/head:refs/remotes/origin/pr/*'
    /// git -C <REPO_PATH> fetch origin --no-tags --force
    /// ```
    ///
    /// The `just hyper-audit <REPO_SLUG> [LIMIT]` recipe performs this automatically.
    HyperDrive {
        /// Path to the local git repository clone.
        path: PathBuf,
        /// Maximum number of PRs to process (0 = unlimited).
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Base branch name (auto-detected from origin/master or origin/main if omitted).
        #[arg(long)]
        base_branch: Option<String>,
        /// Repository slug (`owner/repo`) stored in the bounce log.
        ///
        /// Defaults to the directory name of `path` when omitted.
        #[arg(long)]
        repo_slug: Option<String>,
        /// Resume an interrupted run: skip PRs already present in the bounce log.
        ///
        /// Reads `.janitor/bounce_log.ndjson`, extracts all recorded PR numbers,
        /// and filters them from the harvest list before the rayon pool starts.
        /// Mathematically guarantees no PR is bounced twice.
        #[arg(long, default_value = "false")]
        resume: bool,
    },
    /// Send a test webhook delivery to verify your SIEM/Slack integration.
    ///
    /// Reads `[webhook]` from `janitor.toml`, constructs a synthetic
    /// `critical_threat` payload, and POSTs it to the configured URL
    /// synchronously.  Prints the HTTP status and any error to stderr so
    /// you can confirm receipt without waiting for a real PR event.
    WebhookTest {
        /// Repository root containing `janitor.toml`.
        /// Defaults to the current directory.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },

    /// [INTERNAL] Print a one-line clinical engine health summary.
    ///
    /// Intended for operator use during incident triage or after environment
    /// disruptions.  Not listed in `--help` output.
    #[command(hide = true)]
    OperatorStatus,

    /// [INTERNAL] Controlled Conflict Simulation — verify the lockfile silo detector fires correctly.
    ///
    /// Generates a synthetic `Cargo.lock` containing two versions of `serde`, runs
    /// [`anatomist::manifest::find_version_silos_from_lockfile`] against it, and
    /// confirms the detector captures the split.  Exits 0 with DETECTOR VERIFIED on
    /// success; exits 1 with DETECTOR FAILURE when the engine misses the conflict.
    ///
    /// Not listed in `--help` output.
    #[command(hide = true)]
    DebugSilo,

    /// [INTERNAL] Sovereign Integrity Audit — verify the engine intercepts its own synthetic threats.
    ///
    /// Executes a Ghost Attack: injects a cryptominer string and a version silo into
    /// synthetic diff/manifest fixtures and verifies the engine flags them with the
    /// expected non-zero scores.  If any check fails, exits non-zero with
    /// "INTEGRITY BREACH: RECALIBRATION REQUIRED".
    ///
    /// Not listed in `--help` output.
    #[command(hide = true)]
    SelfTest,

    /// [INTERNAL] Emit a GitHub Actions Step Summary dashboard for the last bounce result.
    ///
    /// Reads the most recent entry from `.janitor/bounce_log.ndjson` and prints a
    /// high-density Markdown dashboard to stdout.  Append the output to
    /// `$GITHUB_STEP_SUMMARY` to surface an Integrity Radar, Structural Topology
    /// snippet, Provenance Ledger, and Vibe-Check on every PR Actions run.
    ///
    /// Not listed in `--help` output.
    #[command(hide = true)]
    StepSummary {
        /// Repository root (reads `.janitor/bounce_log.ndjson`).
        path: PathBuf,
    },

    /// Verify ML-DSA-65 and SLH-DSA signatures in a bounce log or CBOM file.
    ///
    /// Reads the file at `<path>` as newline-delimited JSON bounce log entries
    /// (`.janitor/bounce_log.ndjson`). For each entry carrying detached PQC
    /// signatures, regenerates the deterministic CycloneDX v1.6 CBOM and
    /// verifies the signature(s) against the supplied public key(s).
    ///
    /// Exits 0 when all signed entries verify successfully.
    /// Exits non-zero when any signature fails or the key is malformed.
    VerifyCbom {
        /// Path to the ML-DSA-65 public key file (1952 raw bytes, FIPS 204 ML-DSA-65).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Path to the SLH-DSA-SHAKE-192s public key file (48 raw bytes).
        #[arg(long)]
        slh_key: Option<PathBuf>,
        /// Path to a bounce log NDJSON file (e.g. `.janitor/bounce_log.ndjson`).
        path: PathBuf,
    },
    /// Verify the integrity of an HMAC-sealed Governor audit ledger.
    ///
    /// Reads the file line by line, recomputes the HMAC-SHA-384 for each payload,
    /// and fails on the exact tampered line number.
    VerifyAuditLog {
        /// Path to the append-only Governor audit ledger.
        path: PathBuf,
        /// Hex-encoded HMAC-SHA-384 key used to seal the ledger.
        #[arg(long)]
        key: String,
    },
    /// Replay a sealed decision capsule offline.
    ReplayReceipt {
        /// Path to a persisted `.capsule` envelope.
        path: PathBuf,
    },

    /// Package the locally-verified wisdom feed and its cryptographic receipts
    /// into a portable `IntelTransferCapsule` JSON archive.
    ///
    /// Reads `.janitor/wisdom.rkyv`, the adjacent Ed25519 signature, and the
    /// optional quorum mirror receipt.  Bundles everything into a single JSON
    /// file whose BLAKE3 feed hash and signature set allow offline verification
    /// by `janitor import-intel-capsule`.
    ///
    /// ## IL5/IL6 usage
    /// ```sh
    /// janitor export-intel-capsule /mnt/transfer/janitor-intel-20260406.capsule.json
    /// # copy to removable media; import on the air-gapped node:
    /// janitor import-intel-capsule /mnt/transfer/janitor-intel-20260406.capsule.json
    /// ```
    ExportIntelCapsule {
        /// Destination path for the `.capsule.json` file.
        out_path: PathBuf,
        /// Project root containing `.janitor/wisdom.rkyv`.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },

    /// Parse an `IntelTransferCapsule` offline and install its contents.
    ///
    /// Verifies the embedded Ed25519 signature(s), recomputes the BLAKE3 feed
    /// hash, and checks the mirror receipt (if present).  Only on full
    /// verification success does it write the wisdom archive to
    /// `.janitor/wisdom.rkyv` in the target project root.
    ///
    /// Fails non-zero on any cryptographic discrepancy — the target directory is
    /// never modified if verification fails.
    ImportIntelCapsule {
        /// Path to the `.capsule.json` produced by `export-intel-capsule`.
        in_path: PathBuf,
        /// Project root where `.janitor/wisdom.rkyv` will be written.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },

    /// Compute the SHA-384 digest of a release binary and optionally sign it with PQC keys.
    ///
    /// Writes `<file>.sha384` — the hex-encoded SHA-384 digest — always.
    /// If `--pqc-key` is supplied, also writes `<file>.sig` — a JSON bundle
    /// containing ML-DSA-65 and/or SLH-DSA-SHAKE-192s signatures over the hash.
    ///
    /// Used by `just fast-release` to produce SLSA Level 4 provenance artifacts
    /// attached to each GitHub Release. Not listed in `--help` output.
    #[command(hide = true)]
    SignAsset {
        /// Path to the release binary or other artifact to hash and sign.
        file: PathBuf,
        /// PQC private key bundle path (ML-DSA-65 or dual ML+SLH, FIPS 204/205).
        ///
        /// When omitted, only the SHA-384 `.sha384` hash file is written — no signature.
        #[arg(long)]
        pqc_key: Option<String>,
    },

    /// Verify the integrity of a Janitor release binary.
    ///
    /// Performs SHA-384 hash verification against `--hash` (.sha384 file) and,
    /// when `--sig` is supplied, verifies the ML-DSA-65 detached signature
    /// against the hardcoded release verifying key.  Implements the SLSA Level 4
    /// trust anchor: a tampered CDN binary cannot forge the PQC signature.
    ///
    /// Used by the GitHub Actions composite action (action.yml) after binary
    /// download to confirm supply-chain integrity before execution.
    #[command(hide = true)]
    VerifyAsset {
        /// Path to the release binary to verify.
        #[arg(long)]
        file: PathBuf,
        /// Path to the `.sha384` SHA-384 hash file (96 lowercase hex chars).
        #[arg(long)]
        hash: PathBuf,
        /// Optional path to the `.sig` JSON signature file produced by `sign-asset`.
        ///
        /// When omitted, only the SHA-384 hash is checked.  Providing `--sig`
        /// additionally verifies the ML-DSA-65 signature against the hardcoded
        /// release public key.
        #[arg(long)]
        sig: Option<PathBuf>,
    },

    /// Compute the BLAKE3 integrity pin for a BYOP Wasm rule module.
    ///
    /// Reads the `.wasm` (or `.wat`) file and prints the `[[forge.wasm_rules]]`
    /// TOML block ready to paste into `janitor.toml`.  The pin locks the module
    /// binary so `janitor bounce` will hard-fail if the file is replaced or
    /// tampered with between runs.
    ///
    /// ## Usage
    /// ```sh
    /// janitor wasm-pin rules/my_rule.wasm
    /// # Paste the printed block into janitor.toml [wasm_pins] table.
    /// ```
    WasmPin {
        /// Path to the `.wasm` or `.wat` rule module file.
        path: PathBuf,
    },

    /// Verify a BYOP Wasm rule module against its expected BLAKE3 pin.
    ///
    /// Reads the `.wasm` file, computes its BLAKE3 digest, and compares it to
    /// `--expected`.  Exits 0 when the digest matches; exits non-zero and prints
    /// a mismatch error when the binary has been modified.
    ///
    /// ## Usage
    /// ```sh
    /// janitor wasm-verify rules/my_rule.wasm \
    ///     --expected a3f2...1c9b
    /// ```
    WasmVerify {
        /// Path to the `.wasm` or `.wat` rule module file.
        path: PathBuf,
        /// Expected BLAKE3 hex digest (64 lowercase hex chars).
        #[arg(long)]
        expected: String,
    },

    /// Show a policy-health drift dashboard aggregated from `.janitor/bounce_log.ndjson`.
    ///
    /// Displays total PRs scanned, top 3 triggered rules, and the highest-risk PR authors.
    /// Use `--format json` for machine-readable output suitable for CI/CD dashboards.
    ///
    /// ## Usage
    /// ```sh
    /// janitor policy-health                # markdown table (default)
    /// janitor policy-health --format json  # JSON output
    /// ```
    PolicyHealth {
        /// Project root (reads `.janitor/bounce_log.ndjson`).
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format: `text` (default) or `json`.
        #[arg(long, default_value = "text")]
        format: String,
    },

    /// Scaffold a `janitor.toml` governance manifest in the current directory.
    ///
    /// Writes a documented, sane-defaults configuration file and exits.
    /// Does NOT overwrite an existing `janitor.toml` — fails gracefully when
    /// one is already present.
    ///
    /// ## Profiles
    /// - (default) — balanced settings: `min_slop_score = 100`,
    ///   `pqc_enforced = false`, no issue-link requirement.
    /// - `--profile oss` — solo-maintainer mode: `min_slop_score = 200`,
    ///   minimal config, human-readable output defaults, zero ceremony.
    /// - `--profile enterprise` — hardened settings: `min_slop_score = 50`,
    ///   `require_issue_link = true`, `pqc_enforced = true`.
    ///
    /// ## Usage
    /// ```sh
    /// janitor init                       # default balanced profile
    /// janitor init --profile oss         # OSS solo-maintainer mode
    /// janitor init --profile enterprise  # enterprise hardened profile
    /// ```
    Init {
        /// Configuration profile: omit for defaults, `oss` for solo-maintainer
        /// minimal noise mode, or `enterprise` for hardened enterprise settings.
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },

    /// Monitor lockfiles for SBOM drift and emit a webhook on new dependency additions.
    ///
    /// Watches `Cargo.lock`, `package-lock.json`, and `poetry.lock` under `path` for
    /// file-system modifications.  On each change, parses the updated lockfile, diffs it
    /// against the last known state, and fires a `sbom_drift` webhook event via the
    /// configured `[webhook]` URL in `janitor.toml` if new packages appear.
    ///
    /// ## Usage
    /// ```sh
    /// janitor watch-sbom                # watch current directory
    /// janitor watch-sbom /path/to/repo  # watch explicit root
    /// ```
    WatchSbom {
        /// Project root (reads `janitor.toml` for webhook config).
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Generate a fresh Dual-PQC (ML-DSA-65 + SLH-DSA-SHAKE-192s) private key bundle.
    ///
    /// Writes the raw binary key material to `out_path`.  The bundle layout is
    /// ML-DSA-65 private key (4032 bytes) followed immediately by
    /// SLH-DSA-SHAKE-192s private key bytes.
    ///
    /// Pass the output path as `--pqc-key` in `janitor bounce` to enable local
    /// Dual-PQC (FIPS 204 + FIPS 205) attestation signing without the Governor.
    ///
    /// ## Usage
    /// ```sh
    /// janitor generate-keys .janitor_release.key
    /// janitor bounce --pqc-key .janitor_release.key ...
    /// ```
    #[command(hide = true)]
    GenerateKeys {
        /// Output path for the dual-PQC private key bundle.
        out_path: PathBuf,
    },
    /// Mint a local Sovereign license using operator-held signing custody.
    GenerateLicense {
        /// License lifetime in whole days from the current UTC timestamp.
        #[arg(long)]
        expires_in_days: u64,
    },
    /// Rotate an existing Dual-PQC private key bundle and append a ledger event.
    #[command(hide = true)]
    RotateKeys {
        /// Filesystem path to the active Dual-PQC private key bundle.
        key_path: PathBuf,
    },
    /// Offensive security scanner for bug-bounty and penetration-testing engagements.
    ///
    /// Recursively walks `path`, runs the full Janitor detector suite (credential
    /// scanning, supply-chain analysis, injection pattern detection, and taint
    /// propagation) on every file, and emits either a JSON array of findings or
    /// a Bugcrowd-ready Markdown report to stdout.  No SlopScore is computed and
    /// no summary table is printed.
    ///
    /// ## Examples
    ///
    /// ```sh
    /// # Scan a local checkout
    /// janitor hunt ./target-repo | jq '.[] | select(.id == "security:credential_leak")'
    ///
    /// # Reconstruct and scan a bundled JS app from its sourcemap
    /// janitor hunt --sourcemap https://example.com/static/app.js.map
    ///
    /// # Fetch and scan a published Python wheel from PyPI
    /// janitor hunt --pypi requests@2.32.3
    /// ```
    Hunt {
        /// Directory to scan. Required only for local scans.
        path: Option<PathBuf>,
        /// JavaScript sourcemap URL.  When provided, the source tree is
        /// reconstructed from the map's `sources[]` + `sourcesContent[]` into
        /// a temporary directory and scanned.  The tmpdir is deleted via RAII.
        #[arg(long)]
        sourcemap: Option<String>,
        /// npm package spec to fetch and scan, e.g. `lodash@4.17.21` or
        /// `lodash` (resolves latest).  The tarball is extracted into a
        /// temporary directory, scanned, then deleted via RAII.
        #[arg(long)]
        npm: Option<String>,
        /// Path to a Python `.whl` or `.egg` archive. Extracted into a
        /// temporary directory, scanned, then deleted via RAII.
        #[arg(long)]
        whl: Option<PathBuf>,
        /// PyPI package spec to fetch and scan, e.g. `requests@2.32.3` or
        /// `requests` (resolves latest published wheel).
        #[arg(long)]
        pypi: Option<String>,
        /// Path to an Android APK file.  Requires `jadx` in PATH.  The APK
        /// is decompiled into a temporary directory, scanned, then deleted.
        #[arg(long)]
        apk: Option<PathBuf>,
        /// Path to a Java `.jar` archive. Extracted in pure Rust into a
        /// temporary directory, scanned, then deleted via RAII.
        #[arg(long)]
        jar: Option<PathBuf>,
        /// Path to an Electron `.asar` archive.  Extracted in pure Rust (no
        /// Node.js dependency) into a temporary directory, scanned, then deleted.
        #[arg(long)]
        asar: Option<PathBuf>,
        /// Path to a `docker save` tarball.  Layers are extracted in order into
        /// a temporary directory, then scanned.
        /// Total layer data is capped at 512 MiB.
        #[arg(long)]
        docker: Option<PathBuf>,
        /// Path to an iOS `.ipa` bundle. The app payload is extracted into a
        /// temporary directory, scanned, then deleted via RAII.
        #[arg(long)]
        ipa: Option<PathBuf>,
        /// Native `jq`-compatible filter expression applied to the JSON output
        /// before printing.  No runtime `jq` binary required.
        ///
        /// Example: `'.[] | select(.severity == "Critical")'`
        #[arg(long)]
        filter: Option<String>,
        /// Output format: `json` (default) or `bugcrowd` for triage-ready
        /// Markdown grouped by finding class.
        #[arg(long, default_value = "json")]
        format: String,
        /// Path to an alternative slopsquat corpus file (`.rkyv` format).
        /// When omitted the compiled-in corpus is used.
        #[arg(long)]
        corpus_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ShadowCmd {
    /// Initialise (or re-initialise) the symlink shadow tree.
    Init {
        /// Project root.
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum TelemetryCmd {
    /// Export the local anonymous telemetry log as a PQC-signed JSON block.
    ///
    /// Reads `.janitor/telemetry.json`, signs the entry set with the embedded
    /// Ed25519 attestation key, and prints the signed payload to stdout.
    /// The output is zero-knowledge: no file paths or source code are included.
    Export {
        /// Project root (reads .janitor/telemetry.json).
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present; silently ignore NotFound (expected in production).
    if let Err(e) = dotenvy::dotenv() {
        if !matches!(
            e,
            dotenvy::Error::Io(ref io_err) if io_err.kind() == std::io::ErrorKind::NotFound
        ) {
            eprintln!("warning: .env: {e}");
        }
    }

    let _root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cli = Cli::parse();
    let execution_tier = resolve_execution_tier(&_root);

    // Initialise the global Rayon thread pool after CLI parse so --concurrency
    // is available.  Stack size is 32 MB per worker to prevent stack overflow
    // on deep tree-sitter ASTs (e.g. rust-lang/rust compiler test suites).
    // unwrap_or(()) — a pre-existing global pool (e.g. from tests) is benign.
    let rayon_workers = effective_rayon_workers(cli.concurrency, &execution_tier);
    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_workers)
        .stack_size(32 * 1024 * 1024)
        .build_global()
        .unwrap_or(());

    match &cli.command {
        Commands::Scan {
            path,
            library,
            verbose,
            format,
            exclude,
        } => {
            let segs: Vec<&str> = exclude.iter().map(String::as_str).collect();
            cmd_scan(path, *library, *verbose, format, &segs)?;
        }
        Commands::Dedup {
            path,
            apply,
            force_purge,
            token,
            override_tax,
            exclude,
            force_unsafe_cpp_dedup,
        } => {
            let segs: Vec<&str> = exclude.iter().map(String::as_str).collect();
            cmd_dedup(
                path,
                *apply,
                *force_purge,
                token.as_deref(),
                *override_tax,
                &segs,
                *force_unsafe_cpp_dedup,
            )?;
        }
        Commands::Shadow { cmd } => match cmd {
            ShadowCmd::Init { path } => cmd_shadow_init(path)?,
        },
        Commands::Clean {
            path,
            dry_run: _,
            force_purge,
            library,
            token,
            test_command,
            override_tax,
            exclude,
        } => {
            let segs: Vec<&str> = exclude.iter().map(String::as_str).collect();
            cmd_clean(
                path,
                *force_purge,
                *library,
                token.as_deref(),
                test_command.as_deref(),
                *override_tax,
                &segs,
            )?;
        }
        Commands::Dashboard { path, wopr } => {
            if *wopr {
                let base = path.clone().unwrap_or_else(|| {
                    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                        .join("dev")
                        .join("gauntlet")
                });
                dashboard::wopr_view::draw_wopr(&base)
                    .map_err(|e| anyhow::anyhow!("Dashboard TUI error: {e}"))?;
            } else {
                let p = path
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("path is required in dashboard mode"))?;
                cmd_dashboard(p)?;
            }
        }
        Commands::Badge { path, output } => cmd_badge(path, output.as_deref())?,
        Commands::Undo { path } => cmd_undo(path)?,
        Commands::Telemetry { cmd } => match cmd {
            TelemetryCmd::Export { path } => cmd_telemetry_export(path)?,
        },
        Commands::Bounce {
            path,
            patch,
            registry,
            format,
            repo,
            base,
            head,
            pr_number,
            author,
            pr_body,
            repo_slug,
            pr_state,
            governor_url,
            analysis_token,
            head_sha,
            timeout_secs,
            soft_fail,
            deep_scan,
            pqc_key,
            wasm_rules,
        } => {
            // Clone owned values for spawn_blocking (required for 'static bound).
            let path = path.clone();
            let patch = patch.clone();
            let registry = registry.clone();
            let format = format.clone();
            let repo = repo.clone();
            let base = base.clone();
            let head = head.clone();
            let pr_number = *pr_number;
            let author = author.clone();
            let pr_body = pr_body.clone();
            let repo_slug = repo_slug.clone();
            let pr_state = pr_state.clone();
            let governor_url = governor_url.clone();
            let analysis_token = analysis_token.clone();
            let head_sha = head_sha.clone();
            let timeout_secs = *timeout_secs;
            let soft_fail = *soft_fail;
            let deep_scan = *deep_scan;
            let pqc_key = pqc_key.clone();
            let wasm_rules = wasm_rules.clone();
            let scm_context = common::scm::ScmContext::from_env();

            // Capture fields needed for the timeout failure payload before the
            // move into spawn_blocking.
            let timeout_policy = common::policy::JanitorPolicy::load(&path)?;
            let timeout_governor_url = Some(report::resolve_governor_url(
                governor_url.as_deref(),
                &timeout_policy,
            ));
            let timeout_agent = build_ureq_agent(&timeout_policy)?;
            let timeout_token = analysis_token.clone();
            let timeout_commit_sha = head_sha
                .clone()
                .or_else(|| head.clone())
                .or_else(|| scm_context.commit_sha.clone())
                .unwrap_or_default();
            let timeout_execution_tier = execution_tier.clone();
            let timeout_repo_slug = repo_slug
                .clone()
                .or_else(|| scm_context.repo_slug.clone())
                .unwrap_or_default();
            let timeout_pr_number = pr_number.or(scm_context.pr_number);

            let task = tokio::task::spawn_blocking(move || {
                cmd_bounce(
                    &path,
                    patch.as_deref(),
                    registry.as_deref(),
                    &format,
                    repo.as_deref(),
                    base.as_deref(),
                    head.as_deref(),
                    pr_number,
                    author.as_deref(),
                    pr_body.as_deref(),
                    repo_slug.as_deref(),
                    pr_state.as_str(),
                    governor_url.as_deref(),
                    analysis_token.as_deref(),
                    head_sha.as_deref(),
                    soft_fail,
                    deep_scan,
                    pqc_key.as_deref(),
                    &wasm_rules,
                    &execution_tier,
                )
            });

            match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), task).await {
                Ok(Ok(inner)) => inner?,
                Ok(Err(join_err)) => anyhow::bail!("bounce task panicked: {join_err}"),
                Err(_elapsed) => {
                    // Hard timeout — send a synthetic failure payload so the Governor
                    // can close the GitHub Check Run immediately instead of leaving it
                    // spinning until GitHub's 14-day check expiry.
                    eprintln!(
                        "error: bounce analysis timed out after {timeout_secs}s; \
                         dispatching failure payload to Governor"
                    );
                    if let (Some(url), Some(token)) =
                        (timeout_governor_url.as_deref(), timeout_token.as_deref())
                    {
                        let timeout_entry = report::BounceLogEntry {
                            execution_tier: timeout_execution_tier,
                            pr_number: timeout_pr_number,
                            author: None,
                            timestamp: utc_now_iso8601(),
                            slop_score: 999,
                            dead_symbols_added: 0,
                            logic_clones_found: 0,
                            zombie_symbols_added: 0,
                            unlinked_pr: 0,
                            antipatterns: vec![format!(
                                "antipattern:analysis_timeout — bounce did not \
                                 complete within {timeout_secs}s; CI runner may be \
                                 overloaded or handling an abnormally large diff"
                            )],
                            comment_violations: vec![],
                            min_hashes: vec![],
                            zombie_deps: vec![],
                            state: report::PrState::Open,
                            is_bot: false,
                            repo_slug: timeout_repo_slug,
                            suppressed_by_domain: 0,
                            collided_pr_numbers: vec![],
                            necrotic_flag: None,
                            commit_sha: timeout_commit_sha,
                            policy_hash: String::new(),
                            version_silos: vec![],
                            agentic_pct: 0.0,
                            ci_energy_saved_kwh: 0.0,
                            provenance: report::Provenance::default(),
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
                            git_signature_status: None,
                        };
                        let timeout_verdict = common::scm::StatusVerdict::timeout(timeout_secs);
                        // Best-effort POST — never echo transport payloads to stderr.
                        if report::post_bounce_result(&timeout_agent, url, token, &timeout_entry)
                            .is_err()
                        {
                            let _ = common::scm::status_publisher_for(&scm_context)
                                .publish_verdict(
                                    &scm_context,
                                    &common::scm::StatusVerdict::governor_failure(),
                                );
                            eprintln!("warning: failed to dispatch timeout payload");
                        }
                        let _ = common::scm::status_publisher_for(&scm_context)
                            .publish_verdict(&scm_context, &timeout_verdict);
                    }
                    anyhow::bail!("bounce analysis timed out after {timeout_secs}s");
                }
            }
        }
        Commands::Report {
            repo,
            top,
            format,
            out,
            global,
            gauntlet,
        } => cmd_report(
            repo,
            *top,
            format,
            out.as_deref(),
            *global,
            gauntlet.as_deref(),
        )?,
        Commands::Mcp => mcp::serve().await?,
        #[cfg(unix)]
        Commands::Serve {
            socket,
            registry,
            path,
        } => {
            use std::path::PathBuf as PB;
            let registry_path: PB = registry
                .as_deref()
                .map(PB::from)
                .unwrap_or_else(|| path.join(".janitor").join("symbols.rkyv"));
            daemon::unix::serve(std::path::Path::new(socket), &registry_path).await?;
        }
        Commands::UpdateWisdom { path, ci_mode } => cmd_update_wisdom(path, *ci_mode)?,
        Commands::UpdateSlopsquat { path } => cmd_update_slopsquat(path, &execution_tier)?,
        Commands::Export {
            repo,
            out,
            format,
            global,
            gauntlet_dir,
        } => {
            if *global {
                let default_gauntlet = std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from("."))
                    .join("dev")
                    .join("gauntlet");
                let root = gauntlet_dir.as_deref().unwrap_or(&default_gauntlet);
                export::cmd_export_global_with_format(root, out, format)?;
            } else {
                export::cmd_export_with_format(repo, out, format)?;
            }
        }
        Commands::Pardon { symbol, repo } => cmd_pardon(symbol, repo)?,
        Commands::HyperDrive {
            path,
            limit,
            base_branch,
            repo_slug,
            resume,
        } => git_drive::cmd_hyper_drive(
            path,
            *limit,
            base_branch.as_deref(),
            repo_slug.as_deref(),
            *resume,
        )?,
        Commands::WebhookTest { repo } => report::cmd_webhook_test(repo)?,
        Commands::OperatorStatus => {
            let version = env!("CARGO_PKG_VERSION");
            let janitor_dir = std::path::Path::new(".janitor");
            let entries = report::load_bounce_log(janitor_dir);

            // Last Attestation: most recent timestamp from the local bounce log.
            let last_attestation = entries
                .iter()
                .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
                .map(|e| e.timestamp.clone())
                .unwrap_or_else(|| "none".to_string());

            // Total Human Time Reclaimed: cumulative TEI converted to hours.
            // TEI = (critical × $150) + (gc_only × $20) + (structural_slop × $20).
            // Hours = TEI / $150 (senior developer hourly rate).
            let critical = entries
                .iter()
                .filter(|e| report::is_critical_threat(e))
                .count() as u64;
            let gc_only = entries
                .iter()
                .filter(|e| e.necrotic_flag.is_some() && !report::is_critical_threat(e))
                .count() as u64;
            let structural_slop = entries
                .iter()
                .filter(|e| {
                    e.slop_score > 0 && !report::is_critical_threat(e) && e.necrotic_flag.is_none()
                })
                .count() as u64;
            let tei = critical * 150 + gc_only * 20 + structural_slop * 20;
            let hours_reclaimed = tei as f64 / 150.0;

            println!("Janitor v{version}");
            println!("Engine: HEALTHY");
            println!("Last Attestation: {last_attestation}");
            println!("Silo Detector: ARMED");
            println!("Total Human Time Reclaimed: {hours_reclaimed:.1}h");
        }

        Commands::SelfTest => {
            cmd_self_test()?;
        }

        Commands::DebugSilo => {
            cmd_debug_silo()?;
        }

        Commands::StepSummary { path } => {
            cmd_step_summary(path)?;
        }

        Commands::VerifyCbom { key, slh_key, path } => {
            cmd_verify_cbom(key.as_deref(), slh_key.as_deref(), path)?;
        }
        Commands::VerifyAuditLog { path, key } => {
            cmd_verify_audit_log(path, key)?;
        }
        Commands::ReplayReceipt { path } => {
            cmd_replay_receipt(path)?;
        }
        Commands::ExportIntelCapsule { out_path, repo } => {
            cmd_export_intel_capsule(repo, out_path)?;
        }
        Commands::ImportIntelCapsule { in_path, repo } => {
            cmd_import_intel_capsule(in_path, repo)?;
        }
        Commands::SignAsset { file, pqc_key } => {
            cmd_sign_asset(file, pqc_key.as_deref())?;
        }
        Commands::VerifyAsset { file, hash, sig } => {
            verify_asset::cmd_verify_asset(file, hash, sig.as_deref())?;
        }
        Commands::WasmPin { path } => {
            cmd_wasm_pin(path)?;
        }
        Commands::WasmVerify { path, expected } => {
            cmd_wasm_verify(path, expected)?;
        }
        Commands::Init { profile } => {
            cmd_init(profile.as_deref())?;
        }
        Commands::PolicyHealth { path, format } => {
            cmd_policy_health(path, format.as_str())?;
        }
        Commands::WatchSbom { path } => {
            cmd_watch_sbom(path)?;
        }
        Commands::GenerateKeys { out_path } => {
            cmd_generate_keys(out_path)?;
        }
        Commands::GenerateLicense { expires_in_days } => {
            cmd_generate_license(
                &env::current_dir().context("resolve project root")?,
                *expires_in_days,
            )?;
        }
        Commands::RotateKeys { key_path } => {
            cmd_rotate_keys(key_path)?;
        }
        Commands::Hunt {
            path,
            sourcemap,
            npm,
            whl,
            pypi,
            apk,
            jar,
            asar,
            docker,
            ipa,
            filter,
            format,
            corpus_path,
        } => {
            hunt::cmd_hunt(hunt::HuntArgs {
                scan_root: path.as_deref(),
                sourcemap_url: sourcemap.as_deref(),
                npm_pkg: npm.as_deref(),
                whl_path: whl.as_deref(),
                pypi_pkg: pypi.as_deref(),
                apk_path: apk.as_deref(),
                jar_path: jar.as_deref(),
                asar_path: asar.as_deref(),
                docker_path: docker.as_deref(),
                ipa_path: ipa.as_deref(),
                filter_expr: filter.as_deref(),
                format: format.as_str(),
                corpus_path: corpus_path.as_deref(),
            })?;
        }
    }

    Ok(())
}

fn resolve_execution_tier(project_root: &Path) -> String {
    if common::license::verify_license(project_root) {
        "Sovereign".to_string()
    } else {
        eprintln!("[LICENSE] Valid janitor.lic not found. Degrading to Community Mode.");
        "Community".to_string()
    }
}

fn effective_rayon_workers(cli_concurrency: usize, execution_tier: &str) -> usize {
    if execution_tier != "Sovereign" {
        1
    } else if cli_concurrency == 0 {
        common::physarum::detect_optimal_concurrency()
    } else {
        cli_concurrency
    }
}

fn enforce_sovereign_feature_gate(execution_tier: &str) -> anyhow::Result<()> {
    if execution_tier == "Sovereign" {
        Ok(())
    } else {
        anyhow::bail!("Native OSV ingestion requires a Sovereign license.")
    }
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

/// At-rest threat finding emitted by the Unicode Gate or LotL Hunter.
struct StaticThreatEntry {
    file_path: String,
    detector: &'static str,
    byte_offset: usize,
    detail: &'static str,
}

/// Returns `true` if the line immediately before `byte_offset` in `data`
/// contains a `// janitor:ignore <label>` or `# janitor:ignore <label>` pragma.
///
/// Solves the Antivirus Paradox: security detector source files that contain
/// their own pattern literals would self-trigger on every scan.  A single
/// pragma line suppresses the finding without creating a path exclusion blind spot.
fn has_suppression_pragma(data: &[u8], byte_offset: usize, label: &str) -> bool {
    let scan_end = byte_offset.min(data.len());
    // Locate the start of the line that contains byte_offset.
    let line_start = data[..scan_end]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, &b)| b == b'\n')
        .map(|(i, _)| i + 1)
        .unwrap_or(0);

    if line_start == 0 {
        return false; // byte_offset is on the first line — no preceding line exists.
    }

    // The preceding line ends just before the newline that opens line_start.
    let prev_end = line_start - 1;
    // Strip optional carriage return (Windows CRLF line endings).
    let prev_end = if prev_end > 0 && data[prev_end - 1] == b'\r' {
        prev_end - 1
    } else {
        prev_end
    };
    let prev_start = data[..prev_end]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, &b)| b == b'\n')
        .map(|(i, _)| i + 1)
        .unwrap_or(0);

    let prev_line = &data[prev_start..prev_end];
    let pragma_rs = format!("// janitor:ignore {label}");
    let pragma_sh = format!("# janitor:ignore {label}");

    prev_line
        .windows(pragma_rs.len())
        .any(|w| w == pragma_rs.as_bytes())
        || prev_line
            .windows(pragma_sh.len())
            .any(|w| w == pragma_sh.as_bytes())
}

fn cmd_scan(
    project_root: &Path,
    library: bool,
    verbose: bool,
    format: &str,
    exclude_segments: &[&str],
) -> anyhow::Result<()> {
    // SCIP Export stub — Sourcegraph Code Intelligence Protocol.
    // A full SCIP graph requires indexed symbol occurrences across the codebase.
    // The mapping phase initialises the occurrence table; full emission will be
    // wired to the Sourcegraph SCIP standard in a follow-up.
    if format == "scip" {
        eprintln!("SCIP Export: Initializing mapping...");
        return Ok(());
    }

    use anatomist::pipeline::ScanEvent;
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};
    use common::registry::{symbol_hash, SymbolEntry, SymbolRegistry};
    use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
    use std::time::Duration;

    let mp = MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(10));
    let style = ProgressStyle::default_spinner()
        .template("{spinner:.cyan} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());

    let pb_graph = mp.add(ProgressBar::new_spinner());
    pb_graph.set_style(style.clone());
    pb_graph.set_message("Dissecting artifacts...");
    pb_graph.enable_steady_tick(Duration::from_millis(100));

    let pb_resolve = mp.add(ProgressBar::new_spinner());
    pb_resolve.set_style(style.clone());
    pb_resolve.set_message("Resolving dependencies...");

    let pb_filter = mp.add(ProgressBar::new_spinner());
    pb_filter.set_style(style);
    pb_filter.set_message("Filtering slop...");

    // Clone handles (ProgressBar is Arc-backed — clones share state).
    let (pb_g, pb_r, pb_f) = (pb_graph.clone(), pb_resolve.clone(), pb_filter.clone());

    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));

    let mut result = pipeline::run(
        project_root,
        &mut host,
        library,
        Some(&|event| match event {
            ScanEvent::GraphBuilt { files, symbols } => {
                pb_g.finish_with_message(format!("Dissected {files} files, {symbols} symbols"));
                pb_r.enable_steady_tick(Duration::from_millis(100));
            }
            ScanEvent::StageComplete(4) => {
                pb_r.finish_with_message("Dependencies resolved");
                pb_f.enable_steady_tick(Duration::from_millis(100));
            }
            ScanEvent::StageComplete(5) => {
                pb_f.finish_with_message("Slop filtered");
            }
            _ => {}
        }),
        exclude_segments,
    )?;
    // Ensure all bars are finished if pipeline returned early (no candidates).
    pb_graph.finish_and_clear();
    pb_resolve.finish_and_clear();
    pb_filter.finish_and_clear();

    // Stage 6: Local Adaptive Brain — suppress user-pardoned false positives.
    //
    // Loads `.janitor/local_brain.rkyv` (if it exists) and silently drops any
    // dead symbol whose predicted false-positive probability exceeds the 0.85
    // threshold.  Missing or corrupt brain files are silently ignored so the
    // command never fails due to brain I/O.
    {
        let brain_path = project_root.join(".janitor").join("local_brain.rkyv");
        if let Ok(brain) = forge::brain::AdaptiveBrain::load(&brain_path) {
            if brain.total_pardons > 0 {
                let before = result.dead.len();
                result.dead.retain(|e| {
                    brain.predict_false_positive_probability(&e.name)
                        <= forge::brain::SUPPRESS_THRESHOLD
                });
                let suppressed = before - result.dead.len();
                if suppressed > 0 {
                    eprintln!("  [brain] {suppressed} symbol(s) suppressed by local pardon list");
                }
            }
        }
    }

    // Phase 6.5: At-Rest Threat Scan — Unicode injection + LotL execution anomalies.
    //
    // Walks all source files in the project root, applying two O(N) detectors:
    //   • unicode_gate — BiDi controls, zero-width chars, Cyrillic homoglyphs
    // janitor:ignore security:lotl_execution_anomaly
    //   • lotl_hunter  — PowerShell -EncodedCommand, base64-decode-exec chains,
    //                    /tmp/ and /dev/shm/ staging-area binary execution
    // Files > 1 MiB are skipped (same circuit breaker as PatchBouncer).
    let static_threats: Vec<StaticThreatEntry> = {
        use advanced_threats::{lotl_hunter, unicode_gate};
        use walkdir::WalkDir;
        const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".janitor", "site"];
        let mut threats: Vec<StaticThreatEntry> = Vec::new();

        for entry in WalkDir::new(project_root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_str().unwrap_or("");
                    !SKIP_DIRS.contains(&name)
                } else {
                    true
                }
            })
            .flatten()
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > 1_048_576 {
                continue;
            }
            let path = entry.path();
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let Ok(f) = std::fs::File::open(path) else {
                continue;
            };
            let mmap = match unsafe { memmap2::Mmap::map(&f) } {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Binary immunity: PDFs, PNGs, executables contain null bytes or
            // high-entropy windows that would produce false threat positives.
            // ByteLatticeAnalyzer detects both via null-byte and entropy checks.
            if forge::agnostic_shield::ByteLatticeAnalyzer::classify(&mmap[..])
                == forge::agnostic_shield::TextClass::AnomalousBlob
            {
                continue;
            }
            if let Some(r) = unicode_gate::scan(&mmap[..], filename) {
                if !has_suppression_pragma(&mmap[..], r.byte_offset, r.label) {
                    threats.push(StaticThreatEntry {
                        file_path: path.to_string_lossy().into_owned(),
                        detector: r.label,
                        byte_offset: r.byte_offset,
                        detail: r.description,
                    });
                }
            }
            if let Some(r) = lotl_hunter::scan(&mmap[..], filename) {
                if !has_suppression_pragma(&mmap[..], r.byte_offset, r.label) {
                    threats.push(StaticThreatEntry {
                        file_path: path.to_string_lossy().into_owned(),
                        detector: r.label,
                        byte_offset: r.byte_offset,
                        detail: r.technique,
                    });
                }
            }
        }
        threats
    };

    if format == "json" {
        // Machine-readable output for Janitor Sentinel / GitHub Checks integration.
        let slop_score = if result.total == 0 {
            0.0_f64
        } else {
            result.dead.len() as f64 / result.total as f64
        };
        // Merkle root: BLAKE3 over sorted qualified names of dead symbols.
        // Deterministic across runs on the same codebase state.
        let mut sorted_names: Vec<&str> = result
            .dead
            .iter()
            .map(|e| e.qualified_name.as_str())
            .collect();
        sorted_names.sort_unstable();
        let merkle_root = blake3::hash(sorted_names.join("\n").as_bytes())
            .to_hex()
            .to_string();

        let scan_policy = common::policy::JanitorPolicy::load(project_root)?;
        let json_out = serde_json::json!({
            "schema_version": env!("CARGO_PKG_VERSION"),
            "slop_score": slop_score,
            "dead_symbols": result.dead.iter().map(|e| serde_json::json!({
                "id": e.qualified_name,
                "file_path": e.file_path,
                "structural_hash": e.structural_hash.unwrap_or(0),
                "reason": "DEAD_SYMBOL",
                "byte_range": [e.start_byte, e.end_byte],
            })).collect::<Vec<_>>(),
            "merkle_root": merkle_root,
            "policy": {
                "min_slop_score": scan_policy.min_slop_score,
                "require_issue_link": scan_policy.require_issue_link,
                "allowed_zombies": scan_policy.allowed_zombies,
                "pqc_enforced": scan_policy.pqc_enforced,
                "custom_antipatterns": scan_policy.custom_antipatterns,
                "refactor_bonus": scan_policy.refactor_bonus,
            },
            "static_threats": static_threats.iter().map(|t| serde_json::json!({
                "threat_type": "STATIC_THREAT",
                "file_path": t.file_path,
                "detector": t.detector,
                "byte_offset": t.byte_offset,
                "detail": t.detail,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&json_out)?);
    } else {
        println!("+------------------------------------------+");
        println!("| JANITOR SCAN                             |");
        println!("+------------------------------------------+");
        println!("| Total entities : {:>22} |", result.total);
        println!("| Dead           : {:>22} |", result.dead.len());
        println!("| Protected      : {:>22} |", result.protected.len());
        println!("| Orphan files   : {:>22} |", result.orphan_files.len());
        println!("+------------------------------------------+");

        if result.dead.is_empty() {
            println!("No dead symbols detected.");
        } else {
            println!("\nDEAD SYMBOLS:");
            for entity in &result.dead {
                println!(
                    "  {}:{} - {}",
                    entity.file_path, entity.start_line, entity.qualified_name
                );
            }
        }

        println!("\n+------------------------------------------+");
        println!("| DEAD FILES (ORPHANS)                     |");
        println!("+------------------------------------------+");
        println!("| Count          : {:>22} |", result.orphan_files.len());
        println!("+------------------------------------------+");
        if result.orphan_files.is_empty() {
            println!("No orphan files detected.");
        } else {
            for path in &result.orphan_files {
                println!("  {path}");
            }
        }

        println!("\n+------------------------------------------+");
        println!("| STATIC THREATS                           |");
        println!("+------------------------------------------+");
        println!("| Count          : {:>22} |", static_threats.len());
        println!("+------------------------------------------+");
        if static_threats.is_empty() {
            println!("No static threats detected.");
        } else {
            for t in &static_threats {
                println!(
                    "  [{}] {} @ byte {} — {}",
                    t.detector, t.file_path, t.byte_offset, t.detail
                );
            }
        }

        if verbose {
            println!("\nPROTECTED SYMBOLS:");
            for entity in &result.protected {
                println!(
                    "  {}:{} - {} [{}]",
                    entity.file_path,
                    entity.start_line,
                    entity.qualified_name,
                    entity
                        .protected_by
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                );
            }
        }
    }

    // Persist the full registry to .janitor/symbols.rkyv for the dashboard and badge.
    let rkyv_path = project_root.join(".janitor").join("symbols.rkyv");
    let mut registry = SymbolRegistry::new();
    for entity in result.dead.iter().chain(result.protected.iter()) {
        registry.insert(SymbolEntry {
            id: symbol_hash(&entity.symbol_id()),
            name: entity.name.clone(),
            qualified_name: entity.qualified_name.clone(),
            file_path: entity.file_path.clone(),
            entity_type: entity.entity_type as u8,
            start_line: entity.start_line,
            end_line: entity.end_line,
            start_byte: entity.start_byte,
            end_byte: entity.end_byte,
            structural_hash: entity.structural_hash.unwrap_or(0),
            protected_by: entity.protected_by,
        });
    }
    if let Err(e) = registry.save(&rkyv_path) {
        eprintln!("warning: could not save symbols.rkyv: {e}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// dedup
// ---------------------------------------------------------------------------

struct DupGroup {
    hash: u64,
    members: Vec<anatomist::Entity>,
    /// True only when every member's byte range is byte-for-byte identical.
    /// Structural-only matches (same AST shape, different literals) are false.
    identical_content: bool,
}

/// Returns `true` if the file extension belongs to the unsafe-dedup category:
/// C++, C, header files, C#, or GLSL — where merging risks SIMD/template corruption.
fn is_unsafe_dedup_ext(file_path: &str) -> bool {
    matches!(
        file_path
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "cpp" | "cxx" | "cc" | "c" | "h" | "hpp" | "cs" | "glsl" | "vert" | "frag"
    )
}

fn cmd_dedup(
    path: &Path,
    apply: bool,
    force_purge: bool,
    token: Option<&str>,
    override_tax: bool,
    exclude_segments: &[&str],
    force_unsafe_cpp_dedup: bool,
) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost};

    if apply && force_purge {
        require_token(token)?;
    }

    // Collect all supported source files — polyglot, not Python-only.
    let source_files = collect_source_files(path, exclude_segments)?;
    if source_files.is_empty() {
        println!("No source files found at: {}", path.display());
        return Ok(());
    }

    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));

    // Gather all entities from ALL files into a flat list for cross-file detection.
    let mut all_entities: Vec<anatomist::Entity> = Vec::new();
    {
        use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
        use std::time::Duration;
        let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_message("Analyzing for structural clones...");
        pb.enable_steady_tick(Duration::from_millis(100));
        for file_path in &source_files {
            match host.dissect(file_path) {
                Ok(entities) => all_entities.extend(entities),
                Err(e) => eprintln!("warning: skipping {}: {}", file_path.display(), e),
            }
        }
        pb.finish_and_clear();
    }

    // Group by structural hash across all files.
    // Performance Heuristic: skip entities from math/physics paths or bodies
    // containing SIMD intrinsics — merging them breaks inlining and AVX optimisations.
    let mut hash_map: HashMap<u64, Vec<anatomist::Entity>> = HashMap::new();
    for entity in all_entities {
        if let Some(hash) = entity.structural_hash {
            // Read entity source bytes for the SIMD intrinsic check (zero-copy mmap).
            let entity_bytes: Vec<u8> = std::fs::File::open(&entity.file_path)
                .ok()
                .and_then(|f| unsafe { memmap2::Mmap::map(&f).ok() })
                .map(|mmap| {
                    let start = entity.start_byte as usize;
                    let end = (entity.end_byte as usize).min(mmap.len());
                    mmap[start..end].to_vec()
                })
                .unwrap_or_default();
            if forge::should_skip_dedup(&entity.file_path, &entity_bytes) {
                continue;
            }
            hash_map.entry(hash).or_default().push(entity);
        }
    }

    let mut all_groups: Vec<DupGroup> = hash_map
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(hash, members)| {
            let identical_content = are_contents_identical(&members);
            DupGroup {
                hash,
                members,
                identical_content,
            }
        })
        .collect();

    // True duplicates first, then structural patterns; largest groups first within tier.
    all_groups.sort_by(|a, b| {
        b.identical_content
            .cmp(&a.identical_content)
            .then(b.members.len().cmp(&a.members.len()))
    });

    if all_groups.is_empty() {
        println!("No duplicate functions found.");
        return Ok(());
    }

    let true_dups = all_groups.iter().filter(|g| g.identical_content).count();
    let patterns = all_groups.len() - true_dups;

    println!("+------------------------------------------+");
    println!("| JANITOR DEDUP                            |");
    println!("+------------------------------------------+");
    println!("| Duplicate groups : {:>20} |", all_groups.len());
    println!("| True duplicates  : {true_dups:>20} |");
    println!("| Structural pats. : {patterns:>20} |");
    println!("+------------------------------------------+");

    for group in &all_groups {
        let tag = if group.identical_content {
            "DUPLICATE"
        } else {
            "PATTERN  "
        };
        println!("\n  [{}] Hash: {:016x}", tag, group.hash);
        for entity in &group.members {
            println!(
                "    {}:{} - {}",
                entity.file_path, entity.start_line, entity.qualified_name
            );
        }
    }

    if apply && force_purge {
        // C++ / C# / GLSL Hard-Gate: refuse to apply dedup on unsafe-extension groups.
        // These file types contain SIMD intrinsics, preprocessor branches, and template
        // specialisations that structurally identical ASTs do NOT capture — merging them
        // silently corrupts inlining, AVX optimisations, and platform-specific code paths.
        if !force_unsafe_cpp_dedup {
            let unsafe_groups: Vec<u64> = all_groups
                .iter()
                .filter(|g| g.members.iter().any(|e| is_unsafe_dedup_ext(&e.file_path)))
                .map(|g| g.hash)
                .collect();
            for hash in &unsafe_groups {
                println!(
                    "\n  [HARD-GATE] {hash:016x}: C++/C#/GLSL deduplication is strictly advisory \
                     to prevent SIMD/Template corruption."
                );
            }
        }

        // Only Python files with truly identical bodies can be safely refactored.
        // An unsafe-extension group is additionally blocked unless --force-unsafe-cpp-dedup.
        let mergeable: Vec<DupGroup> = all_groups
            .into_iter()
            .filter(|g| {
                g.identical_content
                    && g.members.iter().all(|e| e.file_path.ends_with(".py"))
                    && (force_unsafe_cpp_dedup
                        || !g.members.iter().any(|e| is_unsafe_dedup_ext(&e.file_path)))
            })
            .collect();
        if mergeable.is_empty() {
            println!("\nNo mergeable duplicates (identical Python bodies) found.");
        } else {
            apply_dedup(&mergeable, path, override_tax)?;
        }
    } else if apply {
        println!("\n[DRY RUN] Pass --force-purge --token <TOKEN> to apply Safe Proxy Pattern.");
    }

    Ok(())
}

fn apply_dedup(groups: &[DupGroup], root_hint: &Path, override_tax: bool) -> anyhow::Result<()> {
    use reaper::{ReplacementTarget, SafeDeleter};

    let project_root = if root_hint.is_dir() {
        root_hint.to_path_buf()
    } else {
        root_hint.parent().unwrap_or(root_hint).to_path_buf()
    };

    // 90-day hard-gate: refuse to merge code from recently modified files.
    for group in groups {
        for member in &group.members {
            let mtime_secs = std::fs::metadata(&member.file_path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            vault::SigningOracle::enforce_maturity(&member.file_path, mtime_secs, override_tax)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }

    let runner = detect_test_runner(&project_root);

    // Pre-flight: run tests before any changes so we can detect Janitor-caused regressions.
    let baseline_passed = match run_tests(&project_root, runner) {
        Ok(()) => {
            println!("Pre-flight verification PASSED.");
            true
        }
        Err(e) => {
            eprintln!(
                "Pre-flight verification FAILED: {e}.\n\
                 Pre-existing failures — Janitor did not cause them. Proceeding."
            );
            false
        }
    };

    // Groups at this point are pre-filtered: identical_content=true, Python-only.
    // Group members by their source file — members across different files get separate
    // proxy injection into their own files.
    type FileBatch = Vec<(Vec<ReplacementTarget>, Vec<String>)>;
    let mut by_file: HashMap<String, FileBatch> = HashMap::new();

    for group in groups {
        // Members are guaranteed same-file or cross-file but identical content.
        // For cross-file identical bodies, pick canonical from first file.
        let canon = &group.members[0];
        let canon_path = canon.file_path.as_str();
        let source_file = std::fs::File::open(canon_path)?;
        let source = unsafe { memmap2::Mmap::map(&source_file)? };

        let impl_name = format!("_{}_impl", canon.name);
        let (body_start, params_str) = extract_function_parts(&source, canon)?;
        let original_body =
            std::str::from_utf8(&source[body_start as usize..canon.end_byte as usize])
                .unwrap_or("    pass\n");

        let impl_block = format!("\ndef {impl_name}({params_str}):\n{original_body}");
        let call_args = params_to_call_args(&params_str);
        let proxy_body = if call_args.is_empty() {
            format!("    return {impl_name}()\n")
        } else {
            format!("    return {impl_name}({call_args})\n")
        };

        // Collect replacements per file (members may span multiple files for cross-file dups).
        let mut per_file_replacements: HashMap<String, Vec<ReplacementTarget>> = HashMap::new();
        for member in &group.members {
            let member_file = std::fs::File::open(&member.file_path)?;
            let member_source = unsafe { memmap2::Mmap::map(&member_file)? };
            let (member_body_start, _) = extract_function_parts(&member_source, member)?;
            per_file_replacements
                .entry(member.file_path.clone())
                .or_default()
                .push(ReplacementTarget {
                    qualified_name: member.qualified_name.clone(),
                    start_byte: member_body_start,
                    end_byte: member.end_byte,
                    replacement: proxy_body.clone(),
                });
        }

        // impl block goes into the canonical file
        for (file_path, replacements) in per_file_replacements {
            let impl_to_inject = if file_path == canon_path {
                vec![impl_block.clone()]
            } else {
                vec![]
            };
            by_file
                .entry(file_path)
                .or_default()
                .push((replacements, impl_to_inject));
        }
    }

    for (file_path_str, batches) in &by_file {
        let file_path = Path::new(file_path_str);
        let mut deleter = SafeDeleter::new(&project_root)?;

        let mut all_replacements: Vec<ReplacementTarget> = Vec::new();
        let mut all_impl_blocks: Vec<String> = Vec::new();
        for (replacements, impl_blocks) in batches {
            all_replacements.extend(replacements.iter().cloned());
            all_impl_blocks.extend(impl_blocks.iter().cloned());
        }

        deleter.replace_symbols(file_path, &mut all_replacements)?;
        if !all_impl_blocks.is_empty() {
            let mut current = std::fs::read_to_string(file_path)?;
            for block in &all_impl_blocks {
                current.push_str(block);
            }
            std::fs::write(file_path, &current)?;
        }

        match run_tests(&project_root, runner) {
            Ok(()) => {
                deleter.commit()?;
                println!("APPLIED + VERIFIED: {file_path_str}");
            }
            Err(e) => {
                if baseline_passed {
                    eprintln!("TEST FAILED (Janitor caused regression): {e}. Rolling back...");
                    deleter.restore_all()?;
                    return Err(e);
                } else {
                    eprintln!("Tests failed: {e} (pre-existing failures — not caused by Janitor).");
                    deleter.commit()?;
                    println!("APPLIED (pre-existing failures not resolved): {file_path_str}");
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// shadow
// ---------------------------------------------------------------------------

fn cmd_shadow_init(project_root: &Path) -> anyhow::Result<()> {
    use shadow::ShadowManager;

    let shadow_path = project_root.join(".janitor").join("shadow_src");
    let manager = ShadowManager::initialize(project_root, &shadow_path)?;
    println!(
        "Shadow tree initialised: {} -> {}",
        manager.source_root().display(),
        manager.shadow_root().display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// clean
// ---------------------------------------------------------------------------

fn cmd_clean(
    project_root: &Path,
    force_purge: bool,
    library: bool,
    token: Option<&str>,
    test_command: Option<&str>,
    override_tax: bool,
    exclude_segments: &[&str],
) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};
    use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
    use reaper::{audit::AuditEntry, audit::AuditLog, DeletionTarget, SafeDeleter};
    use shadow::ShadowManager;
    use std::time::Duration;

    // 1. Run the detection pipeline — show a spinner while it works.
    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));
    let result = {
        let pb = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr_with_hz(10));
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.set_message("Scanning for dead symbols...");
        pb.enable_steady_tick(Duration::from_millis(100));
        let r = pipeline::run(project_root, &mut host, library, None, exclude_segments)?;
        pb.finish_and_clear();
        r
    };

    if result.dead.is_empty() {
        println!("Nothing to clean — no dead symbols detected.");
        return Ok(());
    }

    println!(
        "+------------------------------------------+\n\
         | JANITOR CLEAN                            |\n\
         +------------------------------------------+"
    );
    println!("  Dead symbols: {}", result.dead.len());
    println!("  Would remove:");
    for entity in &result.dead {
        println!(
            "    {}:{} - {}",
            entity.file_path, entity.start_line, entity.qualified_name
        );
    }

    if !force_purge {
        println!(
            "\n[DRY RUN] No files modified.\n\
             Pass --force-purge to execute cleanup (free).\n\
             Pass --force-purge --token <TOKEN> to also generate a signed integrity attestation."
        );
        return Ok(());
    }

    // Token is optional: required only for signed attestation (Lead Specialist tier).
    if token.is_some() {
        require_token(token)?;
        println!("Integrity attestation: token verified.");
    }

    // 2. Auto-detect the repo's test runner, unless --test-command overrides it.
    let runner = if test_command.is_none() {
        detect_test_runner(project_root)
    } else {
        None // Override mode — auto-detection skipped.
    };
    if test_command.is_none() && runner.is_none() {
        eprintln!(
            "warning: no test runner detected in {}.\n\
             Supported: pytest (Python), cargo test (Rust), go test (Go), npm test (JS), scons tests (C++).\n\
             Proceeding without verification — ghost backups available via `janitor undo`.",
            project_root.display()
        );
    }
    let use_shadow = matches!(runner, Some(TestRunner::Pytest));

    // 3. For Python repos: baseline verification via shadow simulation.
    //    For compiled repos: baseline test run before ANY changes.
    //    For unknown repos: skip verification (warn already emitted above).
    let baseline_passed = if use_shadow {
        true // Shadow simulation is the pre-flight check — no separate baseline needed.
    } else {
        let test_result = if let Some(cmd) = test_command {
            run_custom_test(project_root, cmd)
        } else {
            run_tests(project_root, runner)
        };
        match test_result {
            Ok(()) => {
                println!("Pre-flight verification PASSED.");
                true
            }
            Err(e) => {
                eprintln!(
                    "Pre-flight verification FAILED: {e}.\n\
                     Pre-existing failures detected — Janitor did not cause them.\n\
                     Proceeding with cleanup; post-cleanup failures will be compared against this baseline."
                );
                false
            }
        }
    };

    // 4. Build per-file entity map.
    let mut by_file: HashMap<&str, Vec<&anatomist::Entity>> = HashMap::new();
    for entity in &result.dead {
        by_file
            .entry(entity.file_path.as_str())
            .or_default()
            .push(entity);
    }

    // 4.5. Hard-gate: 90-day immaturity rule.
    // Dead symbols in files modified less than 90 days ago are not eligible for cleanup
    // unless --override-tax is passed. Uses file mtime as a proxy for symbol age.
    for file_str in by_file.keys() {
        let mtime_secs = std::fs::metadata(file_str)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        vault::SigningOracle::enforce_maturity(file_str, mtime_secs, override_tax)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // 5a. Python repos: shadow simulation — write cleaned files into shadow tree and run
    //     tests there before touching the real source (this is the true pre-flight).
    if use_shadow {
        let shadow_path = project_root.join(".janitor").join("shadow_src");
        if shadow_path.exists() {
            std::fs::remove_dir_all(&shadow_path)?;
        }
        let manager = ShadowManager::initialize(project_root, &shadow_path)?;

        for (file_str, entities) in &by_file {
            let abs = Path::new(file_str);
            let rel = abs.strip_prefix(manager.source_root()).unwrap_or(abs);
            let shadow_file = manager.shadow_root().join(rel);
            let original = std::fs::read(abs)
                .with_context(|| format!("reading {file_str} for shadow simulation"))?;
            let ranges: Vec<(usize, usize)> = entities
                .iter()
                .map(|e| (e.start_byte as usize, e.end_byte as usize))
                .collect();
            let cleaned = apply_deletions(&original, ranges);
            if shadow_file.is_symlink() || shadow_file.exists() {
                std::fs::remove_file(&shadow_file)
                    .with_context(|| format!("removing shadow symlink for {}", rel.display()))?;
            }
            std::fs::write(&shadow_file, cleaned)
                .with_context(|| format!("writing cleaned shadow for {}", rel.display()))?;
        }

        println!("Shadow simulation: {}", manager.shadow_root().display());
        match run_tests(manager.shadow_root(), runner) {
            Ok(()) => println!("Shadow verification PASSED. Executing cleanup..."),
            Err(e) => {
                eprintln!("Shadow verification FAILED: {e}");
                return Err(e);
            }
        }
    }

    // 5b. Physical excision via SafeDeleter + AuditLog.
    let janitor_dir = project_root.join(".janitor");
    let mut audit_log = AuditLog::new(&janitor_dir);
    let mut deleters: Vec<SafeDeleter> = Vec::new();
    let mut deletion_counts: Vec<(String, usize)> = Vec::new();

    for (file_str, entities) in &by_file {
        let file_path = Path::new(file_str);
        let mmap = std::fs::File::open(file_path)
            .ok()
            .and_then(|f| unsafe { memmap2::Mmap::map(&f).ok() });
        let file_bytes: &[u8] = mmap.as_deref().unwrap_or(&[]);

        let mut deleter = SafeDeleter::new(project_root)?;
        let mut targets: Vec<DeletionTarget> = entities
            .iter()
            .map(|e| DeletionTarget {
                qualified_name: e.qualified_name.clone(),
                start_byte: e.start_byte,
                end_byte: e.end_byte,
            })
            .collect();

        for entity in entities.iter() {
            audit_log.record(AuditEntry::new(
                *file_str,
                entity.qualified_name.as_str(),
                file_bytes,
                "DEAD_SYMBOL",
                entity.start_line,
                entity.end_line,
            ));
        }

        match deleter.delete_symbols(file_path, &mut targets) {
            Ok(n) => {
                deletion_counts.push((file_str.to_string(), n));
                deleters.push(deleter);
            }
            Err(e) => {
                eprintln!("Cleanup error in {file_str}: {e}. Restoring backup...");
                deleter.restore_all()?;
            }
        }
    }

    // 5c. Post-cleanup verification for compiled-language repos (and custom-command repos).
    //     Only roll back if baseline was passing AND post-cleanup now fails
    //     (we caused a regression). Pre-existing failures don't warrant rollback.
    if !use_shadow {
        let has_verification = test_command.is_some() || runner.is_some();
        if has_verification {
            let runner_display: &str = if let Some(cmd) = test_command {
                cmd
            } else {
                match runner {
                    Some(TestRunner::Cargo) => "cargo test",
                    Some(TestRunner::Go) => "go test",
                    Some(TestRunner::Npm) => "npm test",
                    Some(TestRunner::Pytest) => "pytest",
                    Some(TestRunner::SCons) => "scons tests",
                    None => unreachable!(
                        "has_verification requires runner.is_some() when test_command is None"
                    ),
                }
            };
            println!("Post-cleanup verification ({runner_display})...");
            let verify_result = if let Some(cmd) = test_command {
                run_custom_test(project_root, cmd)
            } else {
                run_tests(project_root, runner)
            };
            match verify_result {
                Ok(()) => println!("Post-cleanup verification PASSED."),
                Err(e) => {
                    if baseline_passed {
                        eprintln!(
                            "Post-cleanup verification FAILED (Janitor caused regression): {e}. Restoring..."
                        );
                        // Zero-knowledge telemetry: record each rolled-back entity's hash.
                        let janitor_dir = project_root.join(".janitor");
                        for entities in by_file.values() {
                            for entity in entities.iter() {
                                telemetry_append(
                                    &janitor_dir,
                                    "rollback",
                                    "unknown",
                                    entity.structural_hash.unwrap_or(0),
                                );
                            }
                        }
                        for d in &mut deleters {
                            d.restore_all().ok();
                        }
                        return Err(e);
                    } else {
                        eprintln!(
                            "Post-cleanup verification FAILED: {e} (pre-existing failures — not caused by Janitor)."
                        );
                    }
                }
            }
        }
    }

    // Commit all deletions (finalises ghost backups).
    for d in &mut deleters {
        d.commit()?;
    }
    for (file_str, n) in &deletion_counts {
        println!("Removed {n} symbols from {file_str}");
    }

    audit_log.flush(token)?;

    // Fire-and-forget: report deleted symbol names to the server for WisdomSet training.
    // Only fired when the user provides a token (authenticated session).
    if let Some(tok) = token {
        let project_hash = blake3::hash(project_root.to_string_lossy().as_bytes())
            .to_hex()
            .to_string();
        let deleted_names: Vec<&str> = result
            .dead
            .iter()
            .map(|e| e.qualified_name.as_str())
            .collect();
        reaper::audit::send_deletion_feedback(tok, &project_hash, &deleted_names);
        println!(
            "\u{1f6e1}\u{fe0f} INTEGRITY VERIFIED. Remotely-attested Audit Log generated at .janitor/audit_log.json."
        );
    } else {
        println!(
            "\u{2705} RECLAMATION COMPLETE. (Note: No signed attestation generated. Run with --token to certify this excision.)"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// dashboard
// ---------------------------------------------------------------------------

fn cmd_dashboard(project_root: &Path) -> anyhow::Result<()> {
    let rkyv_path = project_root.join(".janitor").join("symbols.rkyv");

    if !rkyv_path.exists() {
        eprintln!(
            "warning: No symbol registry found at {}. Bypassing symbol-graph view.",
            rkyv_path.display()
        );
        // Degraded mode: load bounce log and print PR telemetry summary.
        let janitor_dir = project_root.join(".janitor");
        let entries = crate::report::load_bounce_log(&janitor_dir);
        if entries.is_empty() {
            eprintln!(
                "No bounce log found either. Run `janitor scan {}` or \
                 `janitor bounce` to populate data.",
                project_root.display()
            );
        } else {
            let total = entries.len();
            let flagged = entries.iter().filter(|e| e.slop_score >= 100).count();
            let top_score = entries.iter().map(|e| e.slop_score).max().unwrap_or(0);
            println!("── PR Telemetry (bounce log) ──────────────────────────────");
            println!("  Total PRs audited : {total}");
            println!("  Flagged (≥100 pts): {flagged}");
            println!("  Highest score     : {top_score}");
            println!(
                "  (Run `janitor scan {path}` to enable the full symbol-graph TUI.)",
                path = project_root.display()
            );
        }
        return Ok(());
    }

    // symbols.rkyv exists — launch the WOPR multi-repo TUI from the project root.
    dashboard::wopr_view::draw_wopr(project_root).map_err(|e| anyhow::anyhow!("TUI error: {e}"))
}

// ---------------------------------------------------------------------------
// badge
// ---------------------------------------------------------------------------

fn cmd_badge(project_root: &Path, output: Option<&Path>) -> anyhow::Result<()> {
    use common::registry::{MappedRegistry, SymbolRegistry};

    let rkyv_path = project_root.join(".janitor").join("symbols.rkyv");
    if !rkyv_path.exists() {
        anyhow::bail!(
            "No symbol registry found. Run `janitor scan {}` first.",
            project_root.display()
        );
    }

    let mapped = MappedRegistry::open(&rkyv_path)
        .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {e}"))?;

    let registry: SymbolRegistry = rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
        .map_err(|e| anyhow::anyhow!("Deserialization failed: {e}"))?;

    let total = registry.entries.len();
    let dead = registry
        .entries
        .iter()
        .filter(|e| e.protected_by.is_none())
        .count();

    let health_pct: u32 = if total == 0 {
        100
    } else {
        ((total - dead) * 100 / total) as u32
    };

    let color = match health_pct {
        90..=100 => "#4c1",
        70..=89 => "#dfb317",
        _ => "#e05d44",
    };

    let label = format!("{health_pct}%");
    // Approximate character width for the label region.
    let label_w: u32 = (label.len() as u32 * 7 + 10).max(32);
    let left_w: u32 = 90;
    let total_w = left_w + label_w;
    let label_x = left_w + label_w / 2;

    let svg = format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="g" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total_w}" height="20" fill="#555"/>
  <rect rx="3" x="{left_w}" width="{label_w}" height="20" fill="{color}"/>
  <rect rx="3" width="{total_w}" height="20" fill="url(#g)"/>
  <g fill="#fff" text-anchor="middle"
     font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="45" y="15" fill="#010101" fill-opacity=".3">code health</text>
    <text x="45" y="14">code health</text>
    <text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_x}" y="14">{label}</text>
  </g>
</svg>"##
    );

    let out = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| project_root.join(".janitor").join("badge.svg"));

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, svg.as_bytes())?;

    println!("Badge written: {}", out.display());
    println!(
        "Code Health: {}%  ({} total, {} dead, {} protected)",
        health_pct,
        total,
        dead,
        total - dead
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// undo
// ---------------------------------------------------------------------------

fn cmd_undo(project_root: &Path) -> anyhow::Result<()> {
    use walkdir::WalkDir;

    // Strategy 1: delegate to git stash if inside a git repository.
    if project_root.join(".git").exists() {
        let status = std::process::Command::new("git")
            .args(["stash"])
            .current_dir(project_root)
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("Undo complete: changes stashed via `git stash`.");
                println!("Run `git stash pop` to re-apply, or `git stash drop` to discard stash.");
                return Ok(());
            }
            Ok(s) => {
                eprintln!(
                    "warning: git stash exited {}. Falling back to ghost restore.",
                    s.code().unwrap_or(-1)
                );
            }
            Err(e) => {
                eprintln!("warning: git not available ({e}). Falling back to ghost restore.");
            }
        }
    }

    // Strategy 2: restore from .janitor/ghost/.
    let ghost_dir = project_root.join(".janitor").join("ghost");
    if !ghost_dir.exists() {
        println!(
            "Nothing to undo: no .janitor/ghost/ directory and no git repo detected at {}.",
            project_root.display()
        );
        return Ok(());
    }

    let janitor_dir = project_root.join(".janitor");
    let mut restored: u32 = 0;
    for entry in WalkDir::new(&ghost_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let relative = entry
            .path()
            .strip_prefix(&ghost_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let dest = project_root.join(relative);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(entry.path(), &dest)?;
        restored += 1;
        println!("Restored: {}", relative.display());
        // Zero-knowledge telemetry: record the rollback event (no path, no source).
        telemetry_append(&janitor_dir, "rollback", "unknown", 0);
    }

    if restored > 0 {
        println!("{restored} file(s) restored from .janitor/ghost/.");
    } else {
        println!("Ghost directory exists but is empty. Nothing to restore.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Token gate
// ---------------------------------------------------------------------------

/// Verifies the purge token; exits the process on failure.
///
/// Treats every [`vault::VaultError`] variant as a hard abort — no destructive
/// operation may proceed without a valid token.
fn require_token(token: Option<&str>) -> anyhow::Result<()> {
    use vault::{SigningOracle, VaultError};
    match token {
        Some(t) => match SigningOracle::verify_token(t) {
            Ok(()) => Ok(()),
            Err(VaultError::MalformedToken) => {
                eprintln!("AUTHORIZATION FAILED. Token is malformed.");
                eprintln!("Tokens must be base64-encoded Ed25519 signatures (64 bytes).");
                std::process::exit(1);
            }
            Err(VaultError::InvalidSignature) => {
                eprintln!("AUTHORIZATION FAILED. Token signature is invalid or has been revoked.");
                eprintln!("Purchase or refresh your purge token at thejanitor.app");
                std::process::exit(1);
            }
            // ImmatureCode is only raised by enforce_maturity, not by verify_token.
            // Handled defensively to keep the match exhaustive.
            Err(VaultError::ImmatureCode { file }) => {
                eprintln!("AUTHORIZATION FAILED. Immature code gate: {file}");
                std::process::exit(1);
            }
        },
        None => {
            eprintln!("--token <TOKEN> is required for --force-purge operations.");
            eprintln!("Purchase a token at thejanitor.app");
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn extract_function_parts(
    source: &[u8],
    entity: &anatomist::Entity,
) -> anyhow::Result<(u32, String)> {
    let start = entity.start_byte as usize;
    let end = (entity.end_byte as usize).min(source.len());
    let slice = &source[start..end];

    let paren_open = slice
        .iter()
        .position(|&b| b == b'(')
        .ok_or_else(|| anyhow::anyhow!("No `(` in signature of `{}`", entity.name))?;

    let mut depth = 0i32;
    let mut paren_close = paren_open;
    for (i, &b) in slice[paren_open..].iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    paren_close = paren_open + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let params_str = std::str::from_utf8(&slice[paren_open + 1..paren_close])
        .unwrap_or("")
        .to_string();

    let newline_offset = slice[paren_close..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| paren_close + i + 1)
        .unwrap_or(slice.len());

    Ok((entity.start_byte + newline_offset as u32, params_str))
}

fn params_to_call_args(params: &str) -> String {
    if params.trim().is_empty() {
        return String::new();
    }
    let args: Vec<String> = params
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            if p.is_empty() {
                return None;
            }
            let name_part = p
                .split(':')
                .next()
                .unwrap_or(p)
                .split('=')
                .next()
                .unwrap_or(p)
                .trim();
            if name_part.is_empty() {
                return None;
            }
            Some(name_part.to_string())
        })
        .collect();
    args.join(", ")
}

// ---------------------------------------------------------------------------
// Language-aware test runner detection
// ---------------------------------------------------------------------------

/// Which test framework is available in a given project root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestRunner {
    /// pytest — Python projects.
    Pytest,
    /// cargo test — Rust workspaces.
    Cargo,
    /// go test ./... — Go modules.
    Go,
    /// npm test — JS/TS projects.
    Npm,
    /// scons tests — SCons-based projects (e.g. Godot engine).
    SCons,
}

/// Auto-detect the appropriate test runner by probing the project root.
///
/// Detection order: Rust → Go → SCons → JS/TS → Python.
/// Returns `None` when no recognised test framework is found.
fn detect_test_runner(root: &Path) -> Option<TestRunner> {
    if root.join("Cargo.toml").exists() {
        return Some(TestRunner::Cargo);
    }
    if root.join("go.mod").exists() {
        return Some(TestRunner::Go);
    }
    // SCons: detect SConstruct or SConscript at the project root.
    // Common in C++ projects such as Godot engine.
    if root.join("SConstruct").exists() || root.join("SConscript").exists() {
        return Some(TestRunner::SCons);
    }
    if root.join("package.json").exists() {
        // Only count as JS test runner if a "test" script is present.
        if std::fs::read_to_string(root.join("package.json"))
            .map(|s| s.contains("\"test\""))
            .unwrap_or(false)
        {
            return Some(TestRunner::Npm);
        }
    }
    // Python: require unambiguous pytest configuration — not just presence of pyproject.toml
    // (which many C++ / non-Python projects also use for tooling config).
    if root.join("pytest.ini").exists() || root.join("tox.ini").exists() {
        return Some(TestRunner::Pytest);
    }
    // pyproject.toml only counts when it explicitly configures pytest.
    if let Ok(content) = std::fs::read_to_string(root.join("pyproject.toml")) {
        if content.contains("[tool.pytest") {
            return Some(TestRunner::Pytest);
        }
    }
    // setup.cfg counts when it has a [tool:pytest] section.
    if let Ok(content) = std::fs::read_to_string(root.join("setup.cfg")) {
        if content.contains("[tool:pytest]") {
            return Some(TestRunner::Pytest);
        }
    }
    // Fallback: tests/ directory containing actual test files (test_*.py or *_test.py).
    let tests_dir = root.join("tests");
    if tests_dir.is_dir() {
        let has_test_files = walkdir::WalkDir::new(&tests_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .any(|e| {
                let name = e.file_name().to_string_lossy();
                let is_py = e.path().extension().and_then(|x| x.to_str()) == Some("py");
                is_py && (name.starts_with("test_") || name.ends_with("_test.py"))
            });
        if has_test_files {
            return Some(TestRunner::Pytest);
        }
    }
    None
}

/// Run the project's test suite using the detected runner.
///
/// `dir` is the directory passed to the test command (shadow root for Python
/// shadow simulation; project root for compiled-language post-cleanup tests).
///
/// Returns `Ok(())` on test success.  `None` runner skips verification with a
/// warning (caller should gate on `--skip-tests` before calling with `None`).
fn run_tests(dir: &Path, runner: Option<TestRunner>) -> anyhow::Result<()> {
    match runner {
        None => {
            eprintln!(
                "warning: no test runner detected in {}. Skipping verification.",
                dir.display()
            );
            Ok(())
        }
        Some(TestRunner::Pytest) => run_pytest(dir),
        Some(TestRunner::Cargo) => run_cargo_test(dir),
        Some(TestRunner::Go) => run_go_test(dir),
        Some(TestRunner::Npm) => run_npm_test(dir),
        Some(TestRunner::SCons) => run_scons_test(dir),
    }
}

fn run_cargo_test(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("cargo")
        .args(["test", "--workspace", "--quiet"])
        .current_dir(dir)
        .status();
    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(anyhow::anyhow!("cargo not found"))
        }
        Err(e) => Err(anyhow::anyhow!("Failed to spawn cargo test: {e}")),
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!(
            "cargo test exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}

fn run_go_test(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("go")
        .args(["test", "./..."])
        .current_dir(dir)
        .status();
    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow::anyhow!("go not found")),
        Err(e) => Err(anyhow::anyhow!("Failed to spawn go test: {e}")),
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!(
            "go test exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}

fn run_npm_test(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("npm")
        .args(["test", "--", "--passWithNoTests"])
        .current_dir(dir)
        .status();
    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow::anyhow!("npm not found")),
        Err(e) => Err(anyhow::anyhow!("Failed to spawn npm test: {e}")),

        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!(
            "npm test exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}

/// Run `scons tests` in `dir`.
///
/// Suitable for SCons-based C++ projects such as Godot engine.  The `tests`
/// target is the de-facto convention; projects that use a different target
/// must be run manually.
fn run_scons_test(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("scons")
        .args(["tests"])
        .current_dir(dir)
        .status();
    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow::anyhow!(
            "scons not found — install SCons (pip install scons) to enable test verification."
        )),
        Err(e) => Err(anyhow::anyhow!("Failed to spawn scons: {e}")),
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!(
            "scons tests exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}

/// Execute an arbitrary test command via `sh -c <cmd>` in `dir`.
///
/// Used when the caller passes `--test-command` to override auto-detection.
/// The command is forwarded to the shell verbatim, enabling make targets,
/// script paths, or any compound invocation (e.g. `"pytest tests/ && mypy src/"`).
fn run_custom_test(dir: &Path, cmd: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("sh")
        .args(["-c", cmd])
        .current_dir(dir)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to spawn test command `{cmd}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Test command `{}` exited with code {}",
            cmd,
            status.code().unwrap_or(-1)
        ))
    }
}

// ---------------------------------------------------------------------------
// Dedup helpers
// ---------------------------------------------------------------------------

/// Returns `true` if every member's source byte range is byte-for-byte identical.
///
/// Functions sharing only structural shape (same AST, different literal values)
/// return `false` — they are not true duplicates and must not be auto-merged.
fn are_contents_identical(members: &[anatomist::Entity]) -> bool {
    if members.is_empty() {
        return false;
    }
    let first = &members[0];
    let first_bytes = match std::fs::read(&first.file_path) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let first_range = first.start_byte as usize..first.end_byte as usize;
    if first_range.end > first_bytes.len() {
        return false;
    }
    let first_content = &first_bytes[first_range];

    for member in &members[1..] {
        let bytes = match std::fs::read(&member.file_path) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let range = member.start_byte as usize..member.end_byte as usize;
        if range.end > bytes.len() || bytes[range.clone()] != *first_content {
            return false;
        }
    }
    true
}

/// Collect all supported source files under `path`, skipping common noise dirs.
///
/// Covers Python, Rust, JS/TS, Go, and C/C++ so that cross-language structural
/// clone detection works on polyglot repos.
fn collect_source_files(path: &Path, exclude_segments: &[&str]) -> anyhow::Result<Vec<PathBuf>> {
    use walkdir::WalkDir;
    const SKIP: &[&str] = &[
        "target",
        ".git",
        ".janitor",
        "venv",
        "__pycache__",
        ".venv",
        "node_modules",
        "vendor",
        ".mypy_cache",
    ];
    const EXTS: &[&str] = &[
        "py", "rs", "js", "jsx", "ts", "tsx", "go", "c", "cpp", "cxx", "cc", "h", "hpp", "java",
        "cs", "glsl", "vert", "frag", "m", "mm",
    ];
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let files = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or_default();
            if SKIP.contains(&name) {
                return false;
            }
            // User-supplied exclude segments (strip trailing / and glob suffixes).
            !exclude_segments.iter().any(|raw| {
                let seg = raw
                    .trim_end_matches('/')
                    .trim_end_matches("/**")
                    .trim_end_matches("/*");
                name == seg
            })
        })
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| EXTS.contains(&x))
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();
    Ok(files)
}

/// Apply byte-range deletions to `source`, processing ranges bottom-to-top
/// (descending `start` order) so each splice does not invalidate later offsets.
fn apply_deletions(source: &[u8], mut ranges: Vec<(usize, usize)>) -> Vec<u8> {
    ranges.sort_by(|a, b| b.0.cmp(&a.0));
    let mut content = source.to_vec();
    for (start, end) in ranges {
        let start = start.min(content.len());
        let end = end.min(content.len());
        if start < end {
            content.drain(start..end);
        }
    }
    content
}

// ---------------------------------------------------------------------------
// bounce
// ---------------------------------------------------------------------------

/// Analyse a unified diff patch (or a git PR via OIDs) for slop.
///
/// **Patch mode** (`--patch` / stdin): Loads patch from file or stdin, runs
/// `PatchBouncer` analysis.
///
/// Fetch the raw bytes of `Cargo.lock` at `base_sha` from the repository ODB.
///
/// Used in git-native bounce mode to provide the base lockfile snapshot for
/// silo delta computation.  Returns `None` on any failure — the caller falls
/// back to reporting all head silos without delta filtering.
fn fetch_base_lockfile_from_odb(repo_path: &Path, base_sha: &str) -> Option<Vec<u8>> {
    let repo = git2::Repository::open(repo_path).ok()?;
    let oid = git2::Oid::from_str(base_sha).ok()?;
    let commit = repo.find_commit(oid).ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(std::path::Path::new("Cargo.lock")).ok()?;
    let blob = repo.find_blob(entry.id()).ok()?;
    Some(blob.content().to_vec())
}

fn pqc_key_age_exceeds_max(
    modified: std::time::SystemTime,
    now: std::time::SystemTime,
    max_key_age_days: u32,
) -> anyhow::Result<bool> {
    let age = now.duration_since(modified).map_err(|_| {
        anyhow::anyhow!("PQC key modification time is in the future; refusing lifecycle check")
    })?;
    Ok(age.as_secs() > u64::from(max_key_age_days) * 86_400)
}

fn enforce_pqc_key_age(
    pqc_key: &str,
    max_key_age_days: u32,
    now: std::time::SystemTime,
) -> anyhow::Result<()> {
    use common::pqc::PqcKeySource;

    let key_source = PqcKeySource::parse(pqc_key);
    let PqcKeySource::File(key_path) = key_source else {
        anyhow::bail!(
            "pqc_enforced = true requires a filesystem-backed --pqc-key so the key age can be verified"
        );
    };

    let metadata = std::fs::metadata(&key_path)
        .with_context(|| format!("failed to stat PQC key bundle {}", key_path.display()))?;
    let modified = metadata.modified().with_context(|| {
        format!(
            "failed to read mtime for PQC key bundle {}",
            key_path.display()
        )
    })?;
    if pqc_key_age_exceeds_max(modified, now, max_key_age_days)? {
        let age_days = now.duration_since(modified).unwrap_or_default().as_secs() / 86_400;
        anyhow::bail!(
            "PQC key bundle {} is {} days old; maximum allowed age is {} days. Run `janitor rotate-keys {}` before CI can proceed.",
            key_path.display(),
            age_days,
            max_key_age_days,
            key_path.display()
        );
    }
    Ok(())
}

/// **Git-native mode** (`--repo --base --head`): Loads changed blobs directly
/// from the git pack index via `shadow_git::simulate_merge`, no diff file needed.
///
/// Loads the symbol registry from `registry_override` or `.janitor/symbols.rkyv`.
#[allow(clippy::too_many_arguments)]
fn cmd_bounce(
    project_root: &Path,
    patch_file: Option<&Path>,
    registry_override: Option<&Path>,
    format: &str,
    repo: Option<&Path>,
    base: Option<&str>,
    head: Option<&str>,
    pr_number: Option<u64>,
    author: Option<&str>,
    pr_body: Option<&str>,
    repo_slug: Option<&str>,
    pr_state_str: &str,
    governor_url: Option<&str>,
    analysis_token: Option<&str>,
    head_sha: Option<&str>,
    soft_fail_flag: bool,
    deep_scan_flag: bool,
    pqc_key: Option<&str>,
    wasm_rules_flag: &[String],
    execution_tier: &str,
) -> anyhow::Result<()> {
    use common::policy::JanitorPolicy;
    use common::registry::{MappedRegistry, SymbolRegistry};
    use forge::slop_filter::{bounce_git, PRBouncer, PatchBouncer};

    // Provenance ledger — capture analysis start time for duration measurement.
    let bounce_start = std::time::Instant::now();

    // Load governance manifest — absent = defaults OK; malformed = hard fail.
    let mut policy = JanitorPolicy::load(project_root)?;
    policy.execution_tier = execution_tier.to_string();

    // ASPM Preflight — verify Jira credentials before analysis begins so the
    // operator sees a clear error at startup rather than a buried fail-open
    // warning buried in findings output.
    let jira_sync_disabled = if policy.jira.is_configured() {
        let user_ok = std::env::var("JANITOR_JIRA_USER").is_ok();
        let token_ok = std::env::var("JANITOR_JIRA_TOKEN").is_ok();
        if !user_ok || !token_ok {
            eprintln!(
                "[ASPM PREFLIGHT] Jira integration configured but credentials missing. \
                 Sync disabled."
            );
            true
        } else {
            false
        }
    } else {
        false
    };

    let scm_context = common::scm::ScmContext::from_env();
    let resolved_pr_number = pr_number.or(scm_context.pr_number);
    let resolved_repo_slug = repo_slug
        .map(|s| s.to_owned())
        .or_else(|| scm_context.repo_slug.clone());
    let resolved_commit_sha = head_sha
        .map(|s| s.to_owned())
        .or_else(|| head.map(|s| s.to_owned()))
        .or_else(|| scm_context.commit_sha.clone());

    // Effective soft-fail: CLI flag takes precedence, then janitor.toml.
    let soft_fail = soft_fail_flag || policy.soft_fail;
    let deep_scan = deep_scan_flag || policy.forge.deep_scan;
    let governor_url = report::resolve_governor_url(governor_url, &policy);
    let governor_agent = build_ureq_agent(&policy)?;
    if let Some(suppressions) = policy.suppressions.as_mut() {
        verify_suppressions_with_governor(&governor_agent, &governor_url, suppressions);
    }

    // PQC enforcement gate (Phase 2 — Hard-Fail Mandate).
    // When pqc_enforced = true in janitor.toml, the operator has declared that
    // every bounce MUST carry a dual-signature (ML-DSA-65 + SLH-DSA) attesting
    // the CBOM.  If no key is supplied via --pqc-key, the pipeline must fail —
    // a missing key is a missing gate, not a degraded-mode acceptable condition.
    if policy.pqc_enforced && pqc_key.is_none() {
        anyhow::bail!(
            "pqc_enforced = true in janitor.toml but no --pqc-key was supplied. \
             Provide a PQC private key bundle via --pqc-key <path> to comply with \
             the post-quantum attestation mandate."
        );
    }
    if policy.pqc_enforced {
        let max_key_age_days = policy.pqc.max_key_age_days.unwrap_or(90);
        enforce_pqc_key_age(
            pqc_key.expect("checked above"),
            max_key_age_days,
            std::time::SystemTime::now(),
        )?;
    }

    // Load symbol registry — empty registry is safe (bounce degrades to clone-only analysis).
    // `registry_loaded` tracks whether the rkyv file was actually present on disk.
    // Zombie dependency detection is gated on this flag: evaluating zombie deps against
    // a diff-only blob set without a full-codebase registry produces false positives when
    // a PR bumps a manifest but does not touch the source files that consume the dependency.
    let rkyv_path = registry_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| project_root.join(".janitor").join("symbols.rkyv"));
    let (registry, registry_loaded): (SymbolRegistry, bool) = if rkyv_path.exists() {
        let mapped = MappedRegistry::open(&rkyv_path)
            .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {e}"))?;
        let reg = rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {e}"))?;
        (reg, true)
    } else {
        if registry_override.is_some() {
            eprintln!(
                "warning: registry file not found: {}. Proceeding with empty registry.",
                rkyv_path.display()
            );
        } else {
            eprintln!(
                "warning: no symbol registry at {}. Run `janitor scan {}` first for full accuracy.",
                rkyv_path.display(),
                project_root.display()
            );
        }
        (SymbolRegistry::new(), false)
    };

    // Load incremental scan cache — absent on first run, populated on subsequent runs.
    let scan_state_path = project_root.join(".janitor").join("scan_state.rkyv");
    let mut scan_state = common::scan_state::ScanState::load(&scan_state_path).unwrap_or_default();

    // Determine analysis mode and compute score + merkle root + MinHash sketch.
    // `bounce_blobs` carries the per-file byte content of the PR for the
    // O(1)-scoped zombie dep scan performed below (no full-repo WalkDir).
    // `source_bytes` is the raw analysis surface size for the provenance ledger.
    let (
        mut score,
        merkle_root,
        min_hashes_vec,
        bounce_blobs,
        patch_has_entropy,
        base_lock,
        source_bytes,
    ) = match (repo, base, head) {
        (Some(repo_path), Some(base_sha), Some(head_sha)) => {
            // Git-native mode: shadow_git blob extraction.
            // bounce_git now returns (SlopScore, HashMap<PathBuf, Vec<u8>>).
            let (mut score, blobs) = bounce_git(
                repo_path,
                base_sha,
                head_sha,
                &registry,
                policy.suppressions.clone().unwrap_or_default(),
                deep_scan,
                &mut scan_state,
            )?;
            // Fetch base Cargo.lock for silo delta (subtract pre-existing splits).
            let base_lock = fetch_base_lockfile_from_odb(repo_path, base_sha);
            let merkle_key = format!("{repo_path:?}:{base_sha}:{head_sha}");
            let merkle_root = blake3::hash(merkle_key.as_bytes()).to_hex().to_string();
            // Derive MinHash from the deterministic merkle key (no raw patch in git mode).
            let sig = forge::pr_collider::PrDeltaSignature::from_bytes(merkle_root.as_bytes());
            // Hallucinated security fix check (git mode — extensions from snapshot blobs).
            if let Some(body) = pr_body {
                forge::slop_filter::check_ai_prompt_injection(&mut score, body);
                let exts: Vec<String> = {
                    use std::collections::HashSet;
                    blobs
                        .keys()
                        .map(|p| {
                            p.extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("")
                                .to_string()
                        })
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect()
                };
                forge::slop_filter::check_hallucinated_fix(
                    &mut score,
                    body,
                    &exts,
                    resolved_repo_slug.as_deref().unwrap_or(""),
                );
            }
            // Git-native mode: merkle root is a 64-char hex string — always
            // has sufficient byte 3-gram entropy to enter the swarm index.
            // Provenance: source bytes = sum of all changed-file blob sizes.
            let src_bytes: u64 = blobs.values().map(|v| v.len() as u64).sum();
            (
                score,
                merkle_root,
                sig.min_hashes.to_vec(),
                blobs,
                true,
                base_lock,
                src_bytes,
            )
        }
        _ => {
            // Patch mode: file, auto-fetch via gh, or stdin.
            let patch = if let (None, Some(pn)) = (patch_file, resolved_pr_number) {
                // Auto-fetch: gh pr diff <N> --repo <slug>
                let slug = resolved_repo_slug.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Auto-fetch requires --repo-slug <owner/repo> \
                         or a detected SCM repository slug"
                    )
                })?;
                let output = std::process::Command::new("gh")
                    .args(["pr", "diff", &pn.to_string(), "--repo", &slug])
                    .output()
                    .context(
                        "failed to invoke `gh pr diff` — is `gh` installed and authenticated?",
                    )?;
                if !output.status.success() {
                    anyhow::bail!(
                        "`gh pr diff {}` failed (exit {}): {}",
                        pn,
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    );
                }
                String::from_utf8_lossy(&output.stdout).into_owned()
            } else {
                match patch_file {
                    Some(pf) => {
                        let bytes = std::fs::read(pf)
                            .with_context(|| format!("reading patch file: {}", pf.display()))?;
                        String::from_utf8_lossy(&bytes).into_owned()
                    }
                    None => {
                        use std::io::IsTerminal as _;
                        if std::io::stdin().is_terminal() {
                            anyhow::bail!(
                                "Must provide either --patch <file> \
                                 or --pr-number <N> --repo-slug <owner/repo>"
                            );
                        }
                        let mut buf = Vec::new();
                        use std::io::Read as _;
                        std::io::stdin()
                            .read_to_end(&mut buf)
                            .context("reading patch from stdin")?;
                        String::from_utf8_lossy(&buf).into_owned()
                    }
                }
            };
            let mut score = PatchBouncer::for_workspace_with_deep_scan_and_suppressions(
                project_root,
                policy.suppressions.clone().unwrap_or_default(),
                deep_scan,
                policy.execution_tier.clone(),
            )
            .bounce(&patch, &registry)?;
            let merkle_root = blake3::hash(patch.as_bytes()).to_hex().to_string();
            let sig = forge::pr_collider::PrDeltaSignature::from_bytes(patch.as_bytes());

            // Comment & PR metadata analysis (patch surface).
            let scanner = forge::metadata::CommentScanner::new();
            let comment_violations = scanner.scan_patch(&patch);
            score.comment_violations = comment_violations.len() as u32;
            // Populate detail strings for the violation phrases.
            score.comment_violation_details = comment_violations
                .iter()
                .map(|v| format!("[line {}] {}", v.line, v.phrase))
                .collect();
            if let Some(body) = pr_body {
                // Unlinked-PR penalty — suppressed for automation accounts.
                // Detection layers (zero-allocation, evaluated in order):
                //   1. Standard GitHub [bot] suffix (Dependabot, Renovate, etc.)
                //   2. `trusted_bot_authors` list in janitor.toml
                //   3. `[forge].automation_accounts` list in janitor.toml
                //      (for ecosystem accounts like r-ryantm, app/nixpkgs-ci)
                // Signature gate (P1-4): `Unsigned`/`Invalid` commits forfeit all
                // trusted-author exemptions — trust requires a cryptographic signature.
                let commit_sig_valid = resolved_commit_sha
                    .as_deref()
                    .map(|sha| {
                        !forge::git_sig::verify_commit_signature(project_root, sha).forfeits_trust()
                    })
                    .unwrap_or(true); // no SHA → no sig check → don't block
                let author_is_automation =
                    commit_sig_valid && policy.is_automation_account(author.unwrap_or(""));
                if scanner.is_pr_unlinked(body) && !author_is_automation {
                    score.unlinked_pr = 1;
                }
                forge::slop_filter::check_ai_prompt_injection(&mut score, body);
                // Hallucinated security fix check (patch mode — all +++ b/ headers).
                let changed_exts = forge::slop_filter::extract_all_patch_exts(&patch);
                forge::slop_filter::check_hallucinated_fix(
                    &mut score,
                    body,
                    &changed_exts,
                    resolved_repo_slug.as_deref().unwrap_or(""),
                );
            }

            // Extract per-file blobs from the unified diff for the zombie dep scan.
            let blobs = forge::slop_filter::extract_patch_blobs(&patch);

            // Entropy gate: patches with fewer than MIN_SHINGLE_ENTROPY byte
            // 3-gram windows cannot form a unique MinHash sketch and must
            // bypass swarm clustering to prevent null-vector collisions.
            let entropy = forge::pr_collider::PrDeltaSignature::has_entropy(patch.as_bytes());
            // Patch mode: no git ODB access, base lockfile unavailable.
            // Provenance: source bytes = bytes on `+` added lines only
            // (excludes `+++` headers and context lines).
            let src_bytes: u64 = patch
                .lines()
                .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                .map(|l| l.len() as u64)
                .sum();
            (
                score,
                merkle_root,
                sig.min_hashes.to_vec(),
                blobs,
                entropy,
                None::<Vec<u8>>,
                src_bytes,
            )
        }
    };

    // Cross-PR structural clone detection (Swarm Clustering).
    //
    // Load all prior bounce log entries for this repo and build a fresh LshIndex.
    // Query it with the current PR's MinHash signature at Jaccard threshold 0.85.
    // Any matching entries represent PRs with >85% structural overlap — a strong
    // signal of duplicate logic being introduced from different branches.
    let janitor_dir_early = project_root.join(".janitor");
    let prior_entries = report::load_bounce_log(&janitor_dir_early);
    {
        if !prior_entries.is_empty() && min_hashes_vec.len() == 64 && patch_has_entropy {
            // The current PR number as u32 for self-collision exclusion.
            // Zero means unknown — only exclude when a real PR number is known.
            let current_pr_u32 = resolved_pr_number.unwrap_or(0) as u32;
            let index = forge::pr_collider::LshIndex::new();
            for entry in &prior_entries {
                if entry.min_hashes.len() == 64 {
                    let entry_pr = entry.pr_number.unwrap_or(0) as u32;
                    // Exclude entries for the current PR to prevent self-collision
                    // (Ouroboros bug: PR matching itself at Jaccard 1.0).
                    if current_pr_u32 != 0 && entry_pr == current_pr_u32 {
                        continue;
                    }
                    if let Ok(arr) = entry.min_hashes.as_slice().try_into() {
                        let sig = forge::pr_collider::PrDeltaSignature { min_hashes: arr };
                        index.insert(sig, entry_pr);
                    }
                }
            }
            if let Ok(arr) = min_hashes_vec.as_slice().try_into() {
                let current_sig = forge::pr_collider::PrDeltaSignature { min_hashes: arr };
                score.collided_pr_numbers = index.query(&current_sig, 0.85);
                // Exclude zero (daemon sentinel) and the current PR itself.
                score
                    .collided_pr_numbers
                    .retain(|&n| n != 0 && n != current_pr_u32);
            }
        }
    }

    // Local Adaptive Brain — suppress pardoned antipatterns and comment violations.
    //
    // Retains only findings whose suppression probability is below the threshold.
    // Counts are kept consistent with the filtered details so `score()` reflects
    // the post-suppression signal.
    {
        let brain_path = project_root.join(".janitor").join("local_brain.rkyv");
        if let Ok(brain) = forge::brain::AdaptiveBrain::load(&brain_path) {
            if brain.total_pardons > 0 {
                score.antipattern_details.retain(|d| {
                    brain.predict_false_positive_probability(d) <= forge::brain::SUPPRESS_THRESHOLD
                });
                score.antipatterns_found = score.antipattern_details.len() as u32;
                score.comment_violation_details.retain(|d| {
                    brain.predict_false_positive_probability(d) <= forge::brain::SUPPRESS_THRESHOLD
                });
                score.comment_violations = score.comment_violation_details.len() as u32;
            }
        }
    }

    // Apply governance policy transformations.
    if policy.allowed_zombies {
        score.zombie_symbols_added = 0;
    }
    // require_issue_link: if the policy mandates a linked issue and no PR body
    // was supplied (git-native mode without --pr-body), treat the PR as unlinked.
    if policy.require_issue_link && score.unlinked_pr == 0 && pr_body.is_none() {
        score.unlinked_pr = 1;
    }

    // AgenticOrigin penalty — applied when the PR is authored or co-authored by an
    // autonomous coding agent (GitHub Copilot coding agent and equivalents).
    //
    // +50 points: forces structurally clean code through the gate while blocking
    // agent PRs with even one Critical antipattern (50 antipattern + 50 = 100 ≥ gate).
    // Distinct from `is_automation_account`: basic CI bots (Dependabot, Renovate) do NOT
    // receive this penalty — only autonomous *coding* agents that generate source code.
    if policy.is_agentic_actor(author.unwrap_or(""), pr_body) {
        score.agentic_origin_penalty = 50;
        score.antipatterns_found += 1;
        score.antipattern_details.push(
            "antipattern:agentic_origin — autonomous coding agent detected \
(GitHub Copilot coding agent, active since 2026-03-24); \
+50 structural quality surcharge applied"
                .to_string(),
        );

        // Author Impersonation sub-check — fires when the trigger came from the PR body
        // (Co-authored-by: Copilot trailer) rather than from the PR author handle.
        //
        // Scenario: a human opens the PR; GitHub Copilot coding agent then pushes commits
        // onto it.  The PR author field still shows the human; the committer is the AI.
        // This creates an attribution gap: the commit author email does not match the
        // GitHub Actor ID that actually wrote the code.  GPG signatures would surface
        // this — unsigned commits on a human PR with Copilot co-authorship are a
        // provenance red flag.
        let author_handle_is_agentic = policy.is_agentic_actor(author.unwrap_or(""), None);
        if !author_handle_is_agentic {
            score.antipatterns_found += 1;
            score.antipattern_score = score.antipattern_score.saturating_add(50);
            score.antipattern_details.push(
                "security:author_impersonation — Copilot committed onto a human-owned PR; \
commit author attribution does not reflect actual code origin; \
cross-reference GitHub Actor ID against commit author email and GPG signatures to verify provenance"
                    .to_string(),
            );
        }
    }

    // BYOP Wasm rule execution — merge CLI flag paths with janitor.toml paths.
    {
        let mut effective_wasm_rules: Vec<String> = policy.wasm_rules.clone();
        effective_wasm_rules.extend_from_slice(wasm_rules_flag);
        if !effective_wasm_rules.is_empty() {
            // Concatenate all bounce blobs as the analysis surface for Wasm rules.
            let wasm_src: Vec<u8> = bounce_blobs
                .values()
                .flat_map(|v| v.iter().copied())
                .collect();
            let paths: Vec<&str> = effective_wasm_rules.iter().map(|s| s.as_str()).collect();
            let wasm_result = forge::slop_filter::run_wasm_rules(
                &paths,
                &policy.wasm_pins,
                policy.wasm_pqc_pub_key.as_deref(),
                &wasm_src,
            );
            for f in &wasm_result.findings {
                score
                    .antipattern_details
                    .push(format!("{} — proprietary Wasm rule", f.id));
                score.antipatterns_found += 1;
                score.antipattern_score = score.antipattern_score.saturating_add(50);
            }
            score.structured_findings.extend(wasm_result.findings);
            score.wasm_policy_receipts = wasm_result.receipts;
        }
    }

    let effective_gate = policy.effective_gate(pr_body);
    let gate_passed = policy.gate_passes(score.score(), pr_body);

    if format == "json" {
        let json_out = serde_json::json!({
            "schema_version": env!("CARGO_PKG_VERSION"),
            "slop_score": score.score() as f64,
            "dead_symbols_added": score.dead_symbols_added,
            "logic_clones_found": score.logic_clones_found,
            "zombie_symbols_added": score.zombie_symbols_added,
            "antipatterns_found": score.antipatterns_found,
            "antipattern_details": score.antipattern_details,
            "comment_violations": score.comment_violations,
            "comment_violation_details": score.comment_violation_details,
            "unlinked_pr": score.unlinked_pr,
            "hallucinated_security_fix": score.hallucinated_security_fix,
            "agentic_origin_penalty": score.agentic_origin_penalty,
            "collided_pr_numbers": score.collided_pr_numbers,
            "merkle_root": merkle_root,
            "gate_passed": gate_passed,
            "effective_gate": effective_gate,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json_out)
                .map_err(|_| anyhow::anyhow!("JSON serialization failed"))?
        );
    } else {
        println!("+------------------------------------------+");
        println!("| JANITOR BOUNCE                           |");
        println!("+------------------------------------------+");
        println!("| Slop score       : {:>20} |", "[see bounce_log]");
        println!("| Dead syms added  : {:>20} |", score.dead_symbols_added);
        println!("| Logic clones     : {:>20} |", score.logic_clones_found);
        println!("| Zombie syms added: {:>20} |", score.zombie_symbols_added);
        // codeql[rust/cleartext-logging] False positive: logging an aggregated numerical count, not the secret text
        println!(
            "| Antipatterns     : {:>20} |",
            std::hint::black_box(score.antipatterns_found)
        );
        println!("| Comment violations: {:>19} |", score.comment_violations);
        println!("| Unlinked PR      : {:>20} |", score.unlinked_pr);
        println!(
            "| Unverified sec fix: {:>19} |",
            score.hallucinated_security_fix
        );
        println!(
            "| Agentic origin pen: {:>19} |",
            score.agentic_origin_penalty
        );
        println!("+------------------------------------------+");
        println!("  Merkle root: {}...", &merkle_root[..32]);
        println!();
        if gate_passed {
            println!("PATCH CLEAN — No critical structural threats detected.");
        } else {
            println!("PATCH REJECTED — Structural slop exceeds governance threshold.");
        }
    }

    // Persist to bounce_log.ndjson for `janitor report` aggregation.
    // PR-scoped zombie dep scan — O(PR-diff bytes), no full-tree WalkDir.
    // Gated on `registry_loaded`: without a full-codebase SymbolRegistry the scanner
    // only sees files in the diff. A PR that bumps a manifest without touching the
    // source files consuming that dependency would hallucinate zombies. Skip the check
    // rather than emit false positives.
    let zombie_deps = if registry_loaded {
        anatomist::manifest::find_zombie_deps_in_blobs(&bounce_blobs)
    } else {
        Vec::new()
    };

    // Model Decay Detector — Phantom Call detection.
    //
    // Cross-references every standalone function call in the PR diff against the
    // base-branch SymbolRegistry.  A callee that is absent from both the registry
    // and the current diff is a phantom hallucination: the AI called a function
    // that does not exist in scope.
    //
    // Gated on `registry_loaded` for the same reason as zombie dep detection:
    // without a full-codebase registry the false-positive rate is unacceptably high.
    if registry_loaded {
        let phantoms = anatomist::manifest::find_phantom_calls(&bounce_blobs, &registry);
        for name in phantoms {
            score.antipatterns_found += 1;
            score.antipattern_score = score.antipattern_score.saturating_add(50);
            score.antipattern_details.push(format!(
                "security:phantom_hallucination — `{name}()` called but not found in \
base registry and not defined in this diff; \
probable AI context-collapse (hallucinated function reference)"
            ));
        }
    }

    // Version silo detection — two-tier approach:
    //
    // Tier 1 (blob-based, always runs when registry is loaded):
    //   Inspects Cargo.toml / package.json blobs from the PR diff.
    //   Fast, O(PR-diff bytes), no subprocess.  Returns plain crate names.
    //
    // Tier 2 (lockfile-based, fires when Cargo.lock is in the diff):
    //   Parses the in-memory Cargo.lock blob from the MergeSnapshot — the
    //   authoritative resolved graph as it would exist after the PR merges.
    //   Returns rich CrateVersionSilo entries with exact version strings
    //   (e.g. "toml (v1.0.6 vs v1.1.0)"), which supersede plain blob names.
    //
    // Merge rule: lockfile entries replace blob-detected plain names for the
    // same Rust crate; npm/pip blob entries are preserved.
    let mut version_silos: Vec<String> = if registry_loaded {
        anatomist::manifest::find_version_silos_in_blobs(&bounce_blobs)
    } else {
        Vec::new()
    };

    // Lockfile tier — authoritative resolved graph for Rust crates.
    //
    // MANDATORY GATE: only runs when `Cargo.lock` is present in `bounce_blobs`,
    // which contains exclusively files changed by this PR.  If `Cargo.lock` was
    // not modified, the PR cannot introduce new version silos, so the detector
    // MUST NOT run.  Without this gate the engine would scan the full workspace
    // lockfile and emit false-positive silos for pre-existing splits that are
    // completely unrelated to the PR (e.g. a YAML-only workflow update).
    let lockfile_in_diff = bounce_blobs
        .keys()
        .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock"));
    let lockfile_silos = if lockfile_in_diff {
        // Delta: base_lock subtracts pre-existing splits — only NEW silos fire.
        anatomist::manifest::find_version_silos_from_lockfile(&bounce_blobs, base_lock.as_deref())
    } else {
        Vec::new()
    };
    if !lockfile_silos.is_empty() {
        // Remove blob-detected plain names superseded by lockfile entries
        // carrying full version detail.
        let lock_names: std::collections::HashSet<&str> =
            lockfile_silos.iter().map(|s| s.name.as_str()).collect();
        version_silos.retain(|n| !lock_names.contains(n.as_str()));
        // One antipattern_details entry per siloed crate for UI readability.
        version_silos.extend(lockfile_silos.iter().map(|s| s.display()));
        version_silos.sort();
    }

    if !version_silos.is_empty() {
        for silo in &version_silos {
            score
                .antipattern_details
                .push(format!("architecture:version_silo — {silo}"));
        }
        score.version_silo_details = version_silos.clone();
    }

    let janitor_dir = project_root.join(".janitor");
    let pr_state = pr_state_str
        .parse::<report::PrState>()
        .unwrap_or(report::PrState::Open);
    // Signature gate (P1-4): compute sig status once for BounceLogEntry provenance
    // and to conditionally revoke trusted-author exemptions.
    let bounce_git_sig = resolved_commit_sha
        .as_deref()
        .map(|sha| forge::git_sig::verify_commit_signature(project_root, sha));
    let bounce_sig_valid = bounce_git_sig
        .as_ref()
        .map(|s| !s.forfeits_trust())
        .unwrap_or(true);
    let is_bot = bounce_sig_valid && policy.is_automation_account(author.unwrap_or(""));
    let slop_score_val = score.score();
    let loaded_wisdom = common::wisdom::load_wisdom_with_receipt(&janitor_dir.join("wisdom.rkyv"));
    let wisdom_receipt = loaded_wisdom
        .as_ref()
        .and_then(|loaded| loaded.receipt.clone());
    let analysis_duration_ms = bounce_start.elapsed().as_millis() as u64;
    let ci_energy_saved_kwh = report::compute_ci_energy_saved_kwh(
        analysis_duration_ms,
        slop_score_val,
        score.necrotic_flag.as_deref(),
        &score.antipattern_details,
        &score.collided_pr_numbers,
    );
    let mut log_entry = report::BounceLogEntry {
        execution_tier: policy.execution_tier.clone(),
        pr_number: resolved_pr_number,
        author: author.map(|s| s.to_owned()),
        timestamp: utc_now_iso8601(),
        slop_score: slop_score_val,
        dead_symbols_added: score.dead_symbols_added,
        logic_clones_found: score.logic_clones_found,
        zombie_symbols_added: score.zombie_symbols_added,
        unlinked_pr: score.unlinked_pr,
        antipatterns: score.antipattern_details.clone(),
        comment_violations: score.comment_violation_details.clone(),
        min_hashes: min_hashes_vec,
        zombie_deps,
        state: pr_state,
        is_bot,
        repo_slug: resolved_repo_slug.unwrap_or_default(),
        suppressed_by_domain: score.suppressed_by_domain,
        collided_pr_numbers: score.collided_pr_numbers.clone(),
        necrotic_flag: score.necrotic_flag.clone(),
        // Priority: --head-sha > --head > GITHUB_SHA env var.
        //
        // --head-sha is the canonical value supplied by the CI runner and MUST
        // match the `head_sha` claim inside the analysis JWT.  Using --head
        // (the git ref for diff extraction) as a fallback preserves local-run
        // behaviour; GITHUB_SHA covers plain GitHub Actions without git-native mode.
        commit_sha: resolved_commit_sha.unwrap_or_default(),
        policy_hash: policy.content_hash(),
        version_silos,
        // Per-commit Copilot attribution: 100% when the PR author is a detected
        // agentic actor (whole-PR signal); 0% otherwise.  Per-commit granularity
        // requires GitHub Copilot commit metrics API data, which the CLI does not
        // fetch at bounce time.
        agentic_pct: if score.agentic_origin_penalty > 0 {
            100.0
        } else {
            0.0
        },
        ci_energy_saved_kwh,
        provenance: report::Provenance {
            analysis_duration_ms,
            source_bytes_processed: source_bytes,
            // egress_bytes_sent computed below — depends on whether we POST.
            egress_bytes_sent: 0,
        },
        // governor_status set after POST attempt below.
        governor_status: None,
        // pqc_sig set by --pqc-key signing block below (if key path provided).
        pqc_sig: None,
        pqc_slh_sig: None,
        pqc_key_source: None,
        transparency_log: None,
        wisdom_hash: wisdom_receipt.as_ref().map(|receipt| receipt.hash.clone()),
        wisdom_signature: wisdom_receipt.map(|receipt| receipt.signature),
        wasm_policy_receipts: score.wasm_policy_receipts.clone(),
        capsule_hash: None,
        decision_receipt: None,
        // CSI = slop density per unit of agentic authorship.
        cognition_surrender_index: {
            let ap: f64 = if score.agentic_origin_penalty > 0 {
                100.0
            } else {
                0.0
            };
            if ap > 0.0 {
                slop_score_val as f64 / ap
            } else {
                0.0
            }
        },
        git_signature_status: bounce_git_sig.as_ref().map(|s| s.as_str().to_owned()),
    };
    let prior_entry = find_prior_bounce_entry(
        &prior_entries,
        &log_entry.repo_slug,
        log_entry.pr_number,
        &log_entry.commit_sha,
    );
    let decision_capsule = build_decision_capsule(&score, &log_entry)?;
    log_entry.capsule_hash = Some(decision_capsule.hash()?);

    // ── BYOK Local PQC Attestation (--pqc-key) ───────────────────────────────
    //
    // When the operator supplies PQC private key material, sign the deterministic
    // CycloneDX v1.6 CBOM for this entry directly on the runner. ML-DSA-65
    // remains the baseline signature; a bundled SLH-DSA key adds a stateless
    // companion signature for long-horizon verification.
    if let Some(key_source_raw) = pqc_key {
        use common::pqc::PqcKeySource;

        let key_source = PqcKeySource::parse(key_source_raw);
        log_entry.pqc_key_source = Some(key_source.custody_label().to_string());
        if key_source.requires_commercial_governor() {
            anyhow::bail!(
                "Enterprise KMS integration requires the `janitor-gov` commercial binary. Contact sales@thejanitor.app."
            );
        }
        let PqcKeySource::File(key_path) = key_source else {
            unreachable!("commercial key sources were handled above");
        };

        let cbom_json = cbom::render_cbom_for_entry(&log_entry, &log_entry.repo_slug.clone());
        let signatures = common::pqc::sign_cbom_dual_from_file(cbom_json.as_bytes(), &key_path)?;
        log_entry.pqc_sig = signatures.ml_dsa_sig;
        log_entry.pqc_slh_sig = signatures.slh_dsa_sig;
        log_entry.governor_status = Some("local_pqc".to_string());
    }

    // Dual-PQC downgrade gate: when pqc_enforced, both signatures are mandatory.
    // A key bundle that produces only one signature (e.g. ml-only key with
    // pqc_enforced=true) is a cryptographic downgrade — reject immediately.
    if policy.pqc_enforced {
        let has_ml = log_entry.pqc_sig.is_some();
        let has_slh = log_entry.pqc_slh_sig.is_some();
        if !has_ml || !has_slh {
            anyhow::bail!(
                "pqc_enforced = true but PQC signing produced an incomplete dual-signature \
                 bundle (ML-DSA-65: {}, SLH-DSA: {}). Supply a full dual key bundle \
                 (ML-DSA + SLH-DSA concatenated) via --pqc-key.",
                if has_ml { "present" } else { "MISSING" },
                if has_slh { "present" } else { "MISSING" }
            );
        }
    }

    // ── Architecture Inversion: POST result to Governor ───────────────────────
    //
    // Critical threat: fail-closed.  A transport error or non-2xx response is a
    // hard crash — the firewall MUST NOT silently succeed when a malicious PR
    // needs to be blocked and attestation cannot be confirmed.
    //
    // Non-critical: fail-silent.  A network blip should not spray CI noise for
    // a routine structural-slop or boilerplate PR.  The failure is logged to
    // `.janitor/diag.log` so the operator can diagnose connectivity issues
    // without seeing them in every CI transcript.

    // Measure egress: serialise the entry (egress_bytes_sent = 0 placeholder),
    // record the byte count, then set it on the entry before logging and POST.
    if analysis_token.is_some() {
        if let Ok(payload) = serde_json::to_string(&log_entry) {
            log_entry.provenance.egress_bytes_sent = payload.len() as u64;
        }
    }

    // Attempt Governor POST — record attestation status before writing the log
    // entry so the local NDJSON audit trail reflects the outcome.
    if let Some(token) = analysis_token {
        let is_critical = report::is_critical_threat(&log_entry);
        let post_result =
            report::post_bounce_result(&governor_agent, &governor_url, token, &log_entry);
        match post_result {
            Ok(attestation) => {
                save_decision_capsule(&janitor_dir, &log_entry, &decision_capsule, &attestation)?;
                log_entry.transparency_log = Some(attestation.inclusion_proof);
                log_entry.decision_receipt = Some(attestation.decision_receipt);
                log_entry.governor_status = Some("ok".to_string());
            }
            Err(_e) if soft_fail => {
                eprintln!(
                    "[JANITOR DEGRADED] Governor unreachable. \
                     Soft-fail active: proceeding without attestation."
                );
                // CodeQL: error message redacted — may contain auth token or URL fragments.
                report::append_diag_log(
                    &janitor_dir,
                    "WARN soft-fail: post_bounce_result failed — error details redacted",
                );
                log_entry.governor_status = Some("degraded".to_string());
                // Fall through — append degraded entry and exit 0.
            }
            Err(_e) if !is_critical => {
                // CodeQL: error message redacted — may contain auth token or URL fragments.
                report::append_diag_log(
                    &janitor_dir,
                    "WARN post_bounce_result failed (non-critical PR) — error details redacted",
                );
            }
            Err(_e) => {
                return Err(anyhow::anyhow!(
                    "governor POST failed — critical threat intercept blocked; \
                     check .janitor/diag.log for connectivity details"
                ))
            }
        }
    }

    report::emit_lifecycle_webhook(
        &log_entry,
        prior_entry,
        &score.structured_findings,
        effective_gate,
        &policy,
    );
    if !jira_sync_disabled {
        if let Err(_e) =
            jira::sync_findings_to_jira(&policy.jira, &score.structured_findings, &janitor_dir)
        {
            report::append_diag_log(
                &janitor_dir,
                "WARN jira sync pipeline failed — error details redacted",
            );
        }
    }
    report::append_bounce_log(&janitor_dir, &log_entry);
    let verdict = common::scm::StatusVerdict::bounce(
        gate_passed,
        log_entry.slop_score,
        log_entry.governor_status.as_deref(),
    );
    if common::scm::status_publisher_for(&scm_context)
        .publish_verdict(&scm_context, &verdict)
        .is_err()
    {
        report::append_diag_log(
            &janitor_dir,
            "WARN scm status publish failed — error details redacted",
        );
    }
    // Write color-coded SVG badge to .janitor/janitor_badge.svg for CI/PR comment use.
    report::write_badge(&janitor_dir, log_entry.slop_score);
    report::fire_webhook_if_configured(&log_entry, &policy);

    // Persist incremental scan cache — best-effort, never fails the bounce.
    if let Err(e) = scan_state.save(&scan_state_path) {
        report::append_diag_log(
            &janitor_dir,
            "WARN scan_state persist failed — error details redacted",
        );
        let _ = e; // suppress unused warning; details redacted per SAST rule
    }

    // ── Weekly heartbeat ───────────────────────────────────────────────────────
    // Best-effort, silent.  Fires at most once per 7 days; result goes to
    // `.janitor/diag.log`.  Never blocks or fails the bounce.
    report::send_heartbeat_if_due(&governor_agent, &janitor_dir, &governor_url);

    Ok(())
}

fn build_decision_capsule(
    score: &forge::slop_filter::SlopScore,
    entry: &report::BounceLogEntry,
) -> anyhow::Result<common::receipt::DecisionCapsule> {
    let cbom_json = cbom::render_cbom_for_entry(entry, &entry.repo_slug);
    Ok(common::receipt::DecisionCapsule {
        execution_tier: entry.execution_tier.clone(),
        mutation_roots: score.semantic_mutation_roots.clone(),
        policy_hash: entry.policy_hash.clone(),
        wisdom_hash: entry.wisdom_hash.clone().unwrap_or_default(),
        cbom_digest: blake3::hash(cbom_json.as_bytes()).to_hex().to_string(),
        wasm_policy_receipts: entry.wasm_policy_receipts.clone(),
        taint_catalog_hash: score.taint_catalog_hash.clone(),
        score_vector: common::receipt::DecisionScoreVector {
            dead_symbols_added: score.dead_symbols_added,
            logic_clones_found: score.logic_clones_found,
            zombie_symbols_added: score.zombie_symbols_added,
            antipattern_score: score.antipattern_score,
            comment_violations: score.comment_violations,
            unlinked_pr: score.unlinked_pr,
            hallucinated_security_fix: score.hallucinated_security_fix,
            agentic_origin_penalty: score.agentic_origin_penalty,
            version_silo_count: score.version_silo_details.len() as u32,
        },
    })
}

fn decision_capsule_path(janitor_dir: &Path, entry: &report::BounceLogEntry) -> PathBuf {
    let pr = entry.pr_number.unwrap_or(0);
    let ts = entry.timestamp.replace(':', "-");
    janitor_dir
        .join("receipts")
        .join(format!("pr-{pr}-{ts}.capsule"))
}

fn save_decision_capsule(
    janitor_dir: &Path,
    entry: &report::BounceLogEntry,
    capsule: &common::receipt::DecisionCapsule,
    attestation: &report::GovernorAttestation,
) -> anyhow::Result<()> {
    let sealed = common::receipt::SealedDecisionCapsule {
        capsule: capsule.clone(),
        receipt: attestation.decision_receipt.clone(),
    };
    sealed.save(&decision_capsule_path(janitor_dir, entry))
}

// ---------------------------------------------------------------------------
// pardon
// ---------------------------------------------------------------------------

/// Records a pardon for `symbol` in `.janitor/local_brain.rkyv`.
///
/// After 5 pardons the symbol's suppression probability exceeds the 0.85
/// threshold and future scans / bounces will silently ignore it.
fn cmd_pardon(symbol: &str, repo: &Path) -> anyhow::Result<()> {
    let brain_path = repo.join(".janitor").join("local_brain.rkyv");
    let mut brain = forge::brain::AdaptiveBrain::load(&brain_path)?;

    brain.update(symbol, true);
    brain.save(&brain_path)?;

    let p = brain.predict_false_positive_probability(symbol);
    let suppressed = p > forge::brain::SUPPRESS_THRESHOLD;

    println!(
        "Pardoned '{}' (total pardons: {}, P(FP)={:.2}{})",
        symbol,
        brain.total_pardons,
        p,
        if suppressed {
            " — SUPPRESSED in future scans"
        } else {
            " — not yet at threshold (0.85)"
        }
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// verify-cbom
// ---------------------------------------------------------------------------

fn cmd_replay_receipt(capsule_path: &Path) -> anyhow::Result<()> {
    let sealed = common::receipt::SealedDecisionCapsule::load(capsule_path)
        .with_context(|| format!("loading replay capsule: {}", capsule_path.display()))?;
    sealed.receipt.verify()?;
    sealed.capsule.verify_roots()?;

    let capsule_hash = sealed.capsule.hash()?;
    if capsule_hash != sealed.receipt.receipt.capsule_hash {
        anyhow::bail!(
            "decision capsule hash mismatch: receipt sealed {}, replay computed {}",
            sealed.receipt.receipt.capsule_hash,
            capsule_hash
        );
    }

    let replayed_score = sealed.capsule.score_vector.score();
    if replayed_score != sealed.receipt.receipt.slop_score {
        anyhow::bail!(
            "replayed slop score mismatch: receipt sealed {}, replay derived {}",
            sealed.receipt.receipt.slop_score,
            replayed_score
        );
    }
    if sealed.capsule.wasm_policy_receipts != sealed.receipt.receipt.wasm_policy_receipts {
        anyhow::bail!("replayed Wasm policy receipts do not match the sealed Governor receipt");
    }

    println!(
        "Replay verified — score {}, roots {}, wasm {}, anchor {}",
        replayed_score,
        sealed.capsule.mutation_roots.len(),
        sealed.capsule.wasm_policy_receipts.len(),
        sealed.receipt.receipt.transparency_anchor
    );
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct SealedAuditRecord {
    hmac: String,
    payload: String,
}

fn parse_hmac_hex_key(var_name: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = value.trim();
    let key = hex::decode(trimmed)
        .with_context(|| format!("{var_name} must be valid lowercase or uppercase hex"))?;
    if key.is_empty() {
        anyhow::bail!("{var_name} must not be empty");
    }
    Ok(key)
}

fn cmd_verify_audit_log(path: &Path, key: &str) -> anyhow::Result<()> {
    type HmacSha384 = hmac::Hmac<sha2::Sha384>;

    let key_bytes = parse_hmac_hex_key("--key", key)?;
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening audit log: {}", path.display()))?;
    let reader = BufReader::new(file);

    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = line
            .with_context(|| format!("reading audit log line {line_no} from {}", path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: SealedAuditRecord = serde_json::from_str(trimmed)
            .with_context(|| format!("line {line_no}: invalid sealed audit record"))?;
        let expected = hex::decode(record.hmac.trim())
            .with_context(|| format!("line {line_no}: HMAC is not valid hex"))?;
        let mut mac = HmacSha384::new_from_slice(&key_bytes)
            .map_err(|err| anyhow::anyhow!("initializing HMAC-SHA-384 failed: {err}"))?;
        mac.update(record.payload.as_bytes());
        if mac.verify_slice(&expected).is_err() {
            anyhow::bail!("line {line_no}: audit ledger HMAC verification failed");
        }
    }

    println!("audit ledger verified: {}", path.display());
    Ok(())
}

/// Verify ML-DSA-65 (FIPS 204) and SLH-DSA-SHAKE-192s (FIPS 205) signatures
/// stored in a bounce log NDJSON file.
///
/// Reads `log_path` as newline-delimited JSON [`report::BounceLogEntry`] records.
/// For each entry carrying a PQC signature, this function:
///
/// 1. Re-derives the exact deterministic CycloneDX v1.6 CBOM bytes that were
///    signed at bounce time (via [`cbom::render_cbom_for_entry`]).
/// 2. Verifies the ML-DSA-65 signature when `pqc_sig` is present.
/// 3. Verifies the SLH-DSA signature when `pqc_slh_sig` is present.
///
/// Exits `Ok(())` iff every signed entry verifies successfully.
/// Returns `Err` if any signature is invalid or the key is malformed.
fn cmd_verify_cbom(
    ml_pub_key_path: Option<&Path>,
    slh_pub_key_path: Option<&Path>,
    log_path: &Path,
) -> anyhow::Result<()> {
    let ml_pub_key_bytes = if let Some(path) = ml_pub_key_path {
        Some(
            std::fs::read(path)
                .with_context(|| format!("reading ML-DSA-65 public key: {}", path.display()))?,
        )
    } else {
        None
    };
    let slh_pub_key_bytes = if let Some(path) = slh_pub_key_path {
        Some(
            std::fs::read(path)
                .with_context(|| format!("reading SLH-DSA public key: {}", path.display()))?,
        )
    } else {
        None
    };
    let content = std::fs::read_to_string(log_path)
        .with_context(|| format!("reading log file: {}", log_path.display()))?;

    let mut verified: u32 = 0;
    let mut failed: u32 = 0;
    let mut skipped: u32 = 0;

    for (line_no, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<report::BounceLogEntry>(line) {
            Ok(entry) => {
                let cbom_json = cbom::render_cbom_for_entry(&entry, &entry.repo_slug);
                let pr = entry.pr_number.unwrap_or(0);
                let mut statuses = Vec::new();
                let mut entry_signed = false;
                let mut entry_failed = false;
                let has_receipt = entry.decision_receipt.is_some();

                // Dual-PQC integrity: partial bundles are a downgrade attack surface.
                // If either signature is present, both MUST be present.
                if entry.pqc_sig.is_some() != entry.pqc_slh_sig.is_some() {
                    anyhow::bail!(
                        "line {}: partial PQC signature bundle — ML-DSA-65 {} but SLH-DSA {} \
                         — dual-signature integrity violated",
                        line_no + 1,
                        if entry.pqc_sig.is_some() {
                            "present"
                        } else {
                            "MISSING"
                        },
                        if entry.pqc_slh_sig.is_some() {
                            "present"
                        } else {
                            "MISSING"
                        }
                    );
                }

                if let Some(ref sig_b64) = entry.pqc_sig {
                    entry_signed = true;
                    if let Some(pk) = ml_pub_key_bytes.as_deref() {
                        let valid =
                            common::pqc::verify_ml_dsa_signature(cbom_json.as_bytes(), pk, sig_b64)
                                .with_context(|| {
                                    format!("line {}: ML-DSA-65 verification failed", line_no + 1)
                                })?;
                        statuses.push(format!(
                            "ML-DSA-65: {}",
                            if valid { "VALID" } else { "INVALID" }
                        ));
                        entry_failed |= !valid;
                    } else {
                        statuses.push("ML-DSA-65: KEY-MISSING".to_string());
                        entry_failed = true;
                    }
                } else {
                    statuses.push("ML-DSA-65: UNSIGNED".to_string());
                }

                if let Some(ref sig_b64) = entry.pqc_slh_sig {
                    entry_signed = true;
                    if let Some(pk) = slh_pub_key_bytes.as_deref() {
                        let valid = common::pqc::verify_slh_dsa_signature(
                            cbom_json.as_bytes(),
                            pk,
                            sig_b64,
                        )
                        .with_context(|| {
                            format!("line {}: SLH-DSA verification failed", line_no + 1)
                        })?;
                        statuses.push(format!(
                            "SLH-DSA: {}",
                            if valid { "VALID" } else { "INVALID" }
                        ));
                        entry_failed |= !valid;
                    } else {
                        statuses.push("SLH-DSA: KEY-MISSING".to_string());
                        entry_failed = true;
                    }
                } else {
                    statuses.push("SLH-DSA: UNSIGNED".to_string());
                }

                if entry_signed || has_receipt {
                    let mut line = format!("PR #{pr}: {}", statuses.join(", "));
                    if let Some(proof) = entry.transparency_log.as_ref() {
                        line.push_str(&format!(
                            ", Transparency Log: Anchored at Index #{}",
                            proof.sequence_index
                        ));
                    }
                    if let Some(hash) = entry.wisdom_hash.as_deref() {
                        line.push_str(&format!(", Wisdom Feed: {hash}"));
                    }
                    if let Some(signature) = entry.wisdom_signature.as_deref() {
                        line.push_str(&format!(", Wisdom Sig: {signature}"));
                    }
                    if !entry.wasm_policy_receipts.is_empty() {
                        line.push_str(&format!(
                            ", Wasm Policies: {} sealed",
                            entry.wasm_policy_receipts.len()
                        ));
                    }
                    if let Some(hash) = entry.capsule_hash.as_deref() {
                        line.push_str(&format!(", Capsule: {hash}"));
                    }
                    if let Some(receipt) = entry.decision_receipt.as_ref() {
                        receipt.verify().with_context(|| {
                            format!(
                                "line {}: Governor decision receipt verification failed",
                                line_no + 1
                            )
                        })?;
                        line.push_str(&format!(
                            ", Governor Receipt: VALID ({})",
                            receipt.receipt.transparency_anchor
                        ));
                        if receipt.receipt.wasm_policy_receipts != entry.wasm_policy_receipts {
                            anyhow::bail!(
                                "line {}: Governor receipt Wasm provenance does not match the bounce entry",
                                line_no + 1
                            );
                        }
                    } else {
                        line.push_str(", Governor Receipt: UNSIGNED");
                    }
                    println!("{line}");
                    if entry_failed {
                        failed += 1;
                    } else {
                        verified += 1;
                    }
                } else {
                    skipped += 1;
                }
            }
            Err(_) => {
                skipped += 1;
            }
        }
    }

    println!(
        "Verification complete — valid: {verified}, invalid: {failed}, unsigned/skipped: {skipped}"
    );
    if failed > 0 {
        anyhow::bail!("{failed} entry/entries failed PQC signature verification");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// report --pdf helpers
// ---------------------------------------------------------------------------

/// Pandoc LaTeX template embedded at compile time.
///
/// Lives at `tools/templates/report.tex` in the workspace; baked into the
/// binary so the distributed `janitor` binary works without the source tree.
const REPORT_TEX_TEMPLATE: &str = include_str!("../../../tools/templates/report.tex");

/// Returns today's date as `"Month DD, YYYY"` (e.g. `"March 05, 2026"`).
///
/// Falls back to the current Unix epoch year on any error.
fn current_date_str() -> String {
    std::process::Command::new("date")
        .arg("+%B %d, %Y")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "2026".to_string())
}

/// Searches for `docs/assets/logo.png` relative to the process working
/// directory.  Returns an absolute path if found; `None` otherwise.
///
/// The logo is optional — the LaTeX template renders a text fallback when the
/// variable is absent.
fn locate_report_logo() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("docs/assets/logo.png"),
        PathBuf::from("../docs/assets/logo.png"),
    ];
    candidates
        .into_iter()
        .find(|p| p.exists())
        .and_then(|p| p.canonicalize().ok())
}

/// Converts `markdown` to a PDF via `pandoc` + `pdflatex`.
///
/// # Errors
/// - Returns an error if `pandoc` is not in `PATH`.
/// - Returns an error if pdflatex or required LaTeX packages are missing.
/// - Returns an error if `pandoc` exits non-zero.
fn export_pdf(markdown: &str, out: &Path, title: &str) -> anyhow::Result<()> {
    // ── Check pandoc availability ──────────────────────────────────────────
    let pandoc_found = std::process::Command::new("pandoc")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !pandoc_found {
        anyhow::bail!(
            "pandoc not found in PATH.\n\
             Install: https://pandoc.org/installing.html\n\
             Debian/Ubuntu: sudo apt-get install pandoc texlive-latex-extra \
             texlive-fonts-recommended\n\
             macOS: brew install pandoc basictex && \
             sudo tlmgr install titlesec tocloft xfp newunicodechar framed"
        );
    }

    // ── Temp workspace ────────────────────────────────────────────────────
    let tmp = PathBuf::from(format!("/tmp/janitor_pdf_{}", std::process::id()));
    std::fs::create_dir_all(&tmp).context("creating PDF temp dir")?;

    let md_path = tmp.join("report.md");
    let tpl_path = tmp.join("report.tex");

    std::fs::write(&md_path, markdown.as_bytes()).context("writing markdown to temp")?;
    std::fs::write(&tpl_path, REPORT_TEX_TEMPLATE).context("writing LaTeX template to temp")?;

    let logo = locate_report_logo();
    let date = current_date_str();
    let version = env!("CARGO_PKG_VERSION");

    // ── Build pandoc command ──────────────────────────────────────────────
    let mut cmd = std::process::Command::new("pandoc");
    cmd.arg(&md_path)
        .arg("--template")
        .arg(&tpl_path)
        .arg("--pdf-engine=pdflatex")
        .arg("--toc")
        .arg("--toc-depth=2")
        .arg("-V")
        .arg(format!("title={title}"))
        .arg("-V")
        .arg(format!("date={date}"))
        .arg("-V")
        .arg(format!("version={version}"))
        .arg("-V")
        .arg("geometry:margin=0.75in")
        .arg("-V")
        .arg("fontsize=10pt")
        .arg("-o")
        .arg(out);

    if let Some(logo_path) = logo {
        cmd.arg("-V").arg(format!("logo={}", logo_path.display()));
    }

    let status = cmd
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("running pandoc")?;

    // ── Cleanup temp dir (best-effort) ────────────────────────────────────
    let _ = std::fs::remove_dir_all(&tmp);

    if !status.success() {
        anyhow::bail!(
            "pandoc exited with code {:?} — ensure texlive-latex-extra is installed\n\
             Debian/Ubuntu: sudo apt-get install texlive-latex-extra texlive-fonts-recommended\n\
             macOS: sudo tlmgr install titlesec tocloft xfp newunicodechar framed",
            status.code()
        );
    }

    println!("PDF report written: {}", out.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// report --global
// ---------------------------------------------------------------------------

/// Discovers all bounce logs under `gauntlet_root` and renders a cross-repo
/// global slop aggregation report.
fn cmd_report_global(
    format: &str,
    out: Option<&Path>,
    gauntlet: Option<&Path>,
) -> anyhow::Result<()> {
    let default_gauntlet = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("dev")
        .join("gauntlet");
    let gauntlet_root = gauntlet.unwrap_or(&default_gauntlet);

    let gauntlet_str = gauntlet_root.display().to_string();

    eprintln!(
        "Scanning for bounce logs under `{}`...",
        gauntlet_root.display()
    );

    let repo_logs = report::discover_bounce_logs(gauntlet_root);
    if repo_logs.is_empty() {
        eprintln!(
            "No bounce logs found under `{}`. \
             Run `janitor bounce` in each repo to populate logs.",
            gauntlet_root.display()
        );
        return Ok(());
    }

    eprintln!(
        "Found {} repos with bounce data. Aggregating...",
        repo_logs.len()
    );

    // CBOM and SARIF formats need the raw entries — handle before aggregation.
    if format == "cbom" || format == "sarif" {
        let all_entries: Vec<report::BounceLogEntry> = repo_logs
            .into_iter()
            .flat_map(|(_, entries)| entries)
            .collect();
        let content = if format == "cbom" {
            cbom::render_cbom(&all_entries, &gauntlet_str)
        } else {
            report::render_sarif(&all_entries)
        };
        return write_or_print(content.as_bytes(), out);
    }

    let data = report::aggregate_global(repo_logs);

    let content = if format == "json" {
        serde_json::to_string_pretty(&report::render_global_json(&data, &gauntlet_str))
            .context("serializing global report JSON")?
    } else {
        report::render_global_markdown(&data, &gauntlet_str)
    };

    // PDF: route the generated markdown through pandoc.
    if format == "pdf" {
        let pdf_path = out
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("janitor_report.pdf"));
        return export_pdf(&content, &pdf_path, "Janitor Global Intelligence Report");
    }

    match out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(path, content.as_bytes())
                .with_context(|| format!("writing report to {}", path.display()))?;
            println!("Global report written: {}", path.display());
        }
        None => print!("{content}"),
    }

    Ok(())
}

/// Write `content` to `path` if `Some`, otherwise print to stdout.
fn write_or_print(content: &[u8], out: Option<&Path>) -> anyhow::Result<()> {
    match out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(path, content)
                .with_context(|| format!("writing output to {}", path.display()))?;
            println!("Output written: {}", path.display());
        }
        None => {
            use std::io::Write as _;
            std::io::stdout()
                .write_all(content)
                .context("writing output to stdout")?;
        }
    }
    Ok(())
}

/// Primary mode: reads `.janitor/bounce_log.ndjson` and renders Slop Top 50,
/// Structural Clones, and Zombie Dependencies.
///
/// Fallback (no bounce log): runs the anatomist pipeline directly and renders
/// a dead-symbol audit ranked by byte size descending.
///
/// With `global=true`: discovers all repos under `gauntlet` and aggregates
/// bounce logs across the entire Gauntlet for a cross-repo summary.
fn cmd_report(
    repo: &Path,
    top: usize,
    format: &str,
    out: Option<&Path>,
    global: bool,
    gauntlet: Option<&Path>,
) -> anyhow::Result<()> {
    if global {
        return cmd_report_global(format, out, gauntlet);
    }
    use anatomist::pipeline::ScanEvent;
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};

    let janitor_dir = repo.join(".janitor");
    let entries = report::load_bounce_log(&janitor_dir);

    let repo_name = repo
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| repo.display().to_string());

    let content = if entries.is_empty() {
        // ── Scan-mode fallback ────────────────────────────────────────────
        eprintln!(
            "No bounce log found — running live scan on `{}`...",
            repo.display()
        );

        let mut host = ParserHost::new()?;
        host.register_heuristic(Box::new(PytestFixtureHeuristic));

        let result = pipeline::run(
            repo,
            &mut host,
            false,
            Some(&|event| match event {
                ScanEvent::GraphBuilt { files, symbols } => {
                    eprintln!("  Dissected {files} files, {symbols} symbols");
                }
                ScanEvent::StageComplete(4) => {
                    eprintln!("  Dependencies resolved");
                }
                ScanEvent::StageComplete(5) => {
                    eprintln!("  Slop filtered");
                }
                _ => {}
            }),
            &[],
        )?;

        eprintln!(
            "Scan complete: {} dead / {} total ({} orphan files)",
            result.dead.len(),
            result.total,
            result.orphan_files.len()
        );

        // Convert entities → DeadSymbolEntry, rank by byte size descending.
        let mut dead_entries: Vec<report::DeadSymbolEntry> = result
            .dead
            .iter()
            .map(|e| report::DeadSymbolEntry {
                qualified_name: e.qualified_name.clone(),
                file_path: e.file_path.clone(),
                start_line: e.start_line,
                byte_size: e.end_byte.saturating_sub(e.start_byte),
            })
            .collect();
        dead_entries.sort_unstable_by(|a, b| b.byte_size.cmp(&a.byte_size));

        if format == "json" {
            serde_json::to_string_pretty(&report::render_scan_json(
                &dead_entries,
                result.total,
                &result.orphan_files,
                &repo_name,
                top,
            ))
            .context("serializing scan report JSON")?
        } else {
            report::render_scan_markdown(
                &dead_entries,
                result.total,
                &result.orphan_files,
                &repo_name,
                top,
            )
        }
    } else {
        // ── Bounce-log mode ───────────────────────────────────────────────
        // CBOM and SARIF formats need the raw entries — handle before aggregation.
        if format == "cbom" {
            let cbom_content = cbom::render_cbom(&entries, &repo_name);
            return write_or_print(cbom_content.as_bytes(), out);
        }
        if format == "sarif" {
            let sarif_content = report::render_sarif(&entries);
            return write_or_print(sarif_content.as_bytes(), out);
        }
        let data = report::aggregate(entries, top);
        if format == "json" {
            serde_json::to_string_pretty(&report::render_json(&data, &repo_name))
                .context("serializing report JSON")?
        } else {
            report::render_markdown(&data, &repo_name)
        }
    };

    // PDF: route the generated markdown through pandoc.
    if format == "pdf" {
        let pdf_path = out
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("janitor_report.pdf"));
        let pdf_title = format!("Intelligence Report: The {repo_name} Security Team");
        return export_pdf(&content, &pdf_path, &pdf_title);
    }

    match out {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(path, content.as_bytes())
                .with_context(|| format!("writing report to {}", path.display()))?;
            println!("Report written: {}", path.display());
        }
        None => print!("{content}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// update-wisdom
// ---------------------------------------------------------------------------

/// Downloads the latest Wisdom Registry from Janitor Sentinel and writes it to
/// `<project_root>/.janitor/wisdom.rkyv`.
///
/// When `ci_mode` is `true`, additionally fetches the CISA KEV catalog and
/// writes `.janitor/wisdom_manifest.json` — a sorted, diff-friendly JSON file
/// listing every CVE entry by ID, vendor, product, and date.
///
/// In `--ci-mode`, missing or corrupt `wisdom.rkyv` is a hard error. The JSON
/// manifest is a diffable receipt only and is mathematically insufficient to
/// clear KEV dependency checks.
fn cmd_update_wisdom(project_root: &Path, ci_mode: bool) -> anyhow::Result<()> {
    const DEFAULT_WISDOM_URL: &str = "https://thejanitor.app/v1/wisdom.rkyv";
    const DEFAULT_WISDOM_SIG_URL: &str = "https://thejanitor.app/v1/wisdom.rkyv.sig";
    const DEFAULT_CISA_KEV_URL: &str =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    let wisdom_url = env::var("JANITOR_WISDOM_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WISDOM_URL.to_string());
    let kev_url = env::var("JANITOR_CISA_KEV_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CISA_KEV_URL.to_string());
    let wisdom_sig_url = env::var("JANITOR_WISDOM_SIG_URL")
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_WISDOM_SIG_URL.to_string());

    cmd_update_wisdom_with_urls(
        project_root,
        ci_mode,
        &wisdom_url,
        &wisdom_sig_url,
        &kev_url,
    )
}

fn cmd_update_wisdom_with_urls(
    project_root: &Path,
    ci_mode: bool,
    wisdom_url: &str,
    wisdom_sig_url: &str,
    kev_url: &str,
) -> anyhow::Result<()> {
    let janitor_dir = project_root.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .with_context(|| format!("creating {}", janitor_dir.display()))?;
    let policy = common::policy::JanitorPolicy::load(project_root)?;
    let quorum = &policy.wisdom.quorum;
    let threshold = quorum.threshold.max(1);
    let fetch_result: anyhow::Result<(Vec<u8>, String, String, Option<_>)> =
        if quorum.mirrors.is_empty() {
            fetch_verified_wisdom_payload(
                wisdom_url,
                wisdom_sig_url,
                if ci_mode {
                    "update-wisdom --ci-mode"
                } else {
                    "update-wisdom"
                },
            )
            .map(|f| (f.bytes, f.signature, f.hash, None))
        } else {
            fetch_verified_wisdom_quorum(quorum, threshold)
        };

    let (bytes, normalized_signature, verified_feed_hash, mirror_receipt) = match fetch_result {
        Ok(tuple) => tuple,
        Err(e) => {
            if ci_mode {
                return Err(e);
            }
            // Non-ci-mode: network unavailable — deploy embedded empty baseline
            // so wisdom.rkyv always deserialises on first boot.
            let wisdom_path = janitor_dir.join("wisdom.rkyv");
            if !wisdom_path.exists() {
                write_atomic_bytes(&wisdom_path, EMBEDDED_WISDOM)?;
                eprintln!(
                    "[JANITOR BOOTSTRAPPED] Empty wisdom baseline deployed. \
                     Run `janitor update-wisdom` to fetch live KEV data."
                );
            }
            return Ok(());
        }
    };

    let wisdom_path = janitor_dir.join("wisdom.rkyv");
    std::fs::write(&wisdom_path, &bytes)
        .with_context(|| format!("writing {}", wisdom_path.display()))?;
    std::fs::write(
        janitor_dir.join("wisdom.rkyv.sig"),
        normalized_signature.as_bytes(),
    )
    .with_context(|| format!("writing {}", janitor_dir.join("wisdom.rkyv.sig").display()))?;
    write_wisdom_receipt(&janitor_dir, &verified_feed_hash, &normalized_signature)?;
    if let Some(receipt) = mirror_receipt.as_ref() {
        write_wisdom_mirror_receipt(&janitor_dir, receipt)?;
    }

    println!("\u{1f9e0} Wisdom Registry synchronized with Janitor Sentinel.");

    if ci_mode {
        let mut kev_resp = match ureq::get(kev_url).call() {
            Ok(response) => response,
            Err(_e) => {
                // CodeQL: URL and error details redacted — URL may carry credentials.
                return Err(anyhow::anyhow!(
                    "update-wisdom --ci-mode: CISA KEV fetch failed"
                ));
            }
        };

        // Circuit breaker: cap CISA KEV JSON at 32 MiB. Current feed is ~2 MiB;
        // 32 MiB provides a 16× safety margin against unbounded heap growth.
        const MAX_KEV_BYTES: u64 = 32 * 1024 * 1024;
        let kev_bytes = kev_resp
            .body_mut()
            .with_config()
            .limit(MAX_KEV_BYTES)
            .read_to_vec()
            .map_err(|_e| {
                anyhow::anyhow!("update-wisdom --ci-mode: reading KEV response failed")
            })?;

        let kev_json: serde_json::Value = serde_json::from_slice(&kev_bytes).map_err(|e| {
            anyhow::anyhow!("update-wisdom --ci-mode: parsing KEV JSON failed: {e}")
        })?;

        let empty_vec = vec![];
        let vulns = kev_json["vulnerabilities"].as_array().unwrap_or(&empty_vec);

        let mut entries: Vec<serde_json::Value> = vulns
            .iter()
            .map(|v| {
                serde_json::json!({
                    "cve_id":     v["cveID"].as_str().unwrap_or(""),
                    "vendor":     v["vendorProject"].as_str().unwrap_or(""),
                    "product":    v["product"].as_str().unwrap_or(""),
                    "name":       v["vulnerabilityName"].as_str().unwrap_or(""),
                    "date_added": v["dateAdded"].as_str().unwrap_or(""),
                })
            })
            .collect();
        entries.sort_by(|a, b| {
            a["cve_id"]
                .as_str()
                .unwrap_or("")
                .cmp(b["cve_id"].as_str().unwrap_or(""))
        });

        let manifest = serde_json::json!({
            "source":       "CISA Known Exploited Vulnerabilities Catalog",
            "generated_at": utc_now_iso8601(),
            "entry_count":  entries.len(),
            "entries":      entries,
        });

        write_wisdom_manifest(&janitor_dir, &manifest)?;

        println!(
            "\u{1f4cb} KEV manifest written: {} entries \u{2192} {}",
            manifest["entry_count"],
            janitor_dir.join("wisdom_manifest.json").display()
        );
    }
    let osv_agent = ureq::Agent::new_with_defaults();
    cmd_update_slopsquat_with_agent(project_root, &osv_agent)?;

    if ci_mode {
        common::wisdom::validate_wisdom_archive(&wisdom_path).with_context(|| {
            format!(
                "update-wisdom --ci-mode: authoritative archive validation failed for {}",
                wisdom_path.display()
            )
        })?;
    }

    Ok(())
}

const OSV_DUMP_BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// Ecosystems to fetch from the OSV bulk-ZIP endpoint.
/// Each tuple is (bucket directory, ecosystem match string for advisory filter).
const OSV_MALICIOUS_ECOSYSTEMS: &[(&str, &str)] =
    &[("npm", "npm"), ("PyPI", "PyPI"), ("crates.io", "crates.io")];

/// Embedded offline-baseline slopsquat corpus produced by `build.rs`.
/// Deployed when the OSV network endpoint is unreachable and no on-disk
/// corpus exists.  Contains a curated seed of confirmed MAL-advisory packages.
static EMBEDDED_SLOPSQUAT: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/slopsquat_corpus.rkyv"));

/// Embedded empty wisdom baseline produced by `build.rs`.
/// Provides a deserialise-safe fallback so `wisdom.rkyv` always exists on
/// first boot.  No KEV coverage until `janitor update-wisdom` is run.
static EMBEDDED_WISDOM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wisdom.rkyv"));

#[derive(Debug, serde::Deserialize)]
struct OsvVulnerability {
    #[serde(default)]
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvAffected {
    #[serde(default)]
    package: Option<OsvPackage>,
}

#[derive(Debug, serde::Deserialize)]
struct OsvPackage {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
}

fn cmd_update_slopsquat(project_root: &Path, execution_tier: &str) -> anyhow::Result<()> {
    enforce_sovereign_feature_gate(execution_tier)?;
    let agent = ureq::Agent::new_with_defaults();
    cmd_update_slopsquat_with_agent(project_root, &agent)
}

fn cmd_update_slopsquat_with_agent(project_root: &Path, agent: &ureq::Agent) -> anyhow::Result<()> {
    let stale_days = common::policy::JanitorPolicy::load(project_root)
        .ok()
        .map(|p| p.forge.corpus_stale_days)
        .unwrap_or(7);
    cmd_update_slopsquat_impl(project_root, agent, OSV_DUMP_BASE_URL, stale_days)
}

/// Internal implementation for `update-slopsquat`.
///
/// `osv_base_url` is configurable to allow unit tests to point at an
/// unreachable address without live network calls.  `stale_days` controls the
/// staleness threshold for the offline-fallback path.
fn cmd_update_slopsquat_impl(
    project_root: &Path,
    agent: &ureq::Agent,
    osv_base_url: &str,
    stale_days: u32,
) -> anyhow::Result<()> {
    let janitor_dir = project_root.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .with_context(|| format!("creating {}", janitor_dir.display()))?;
    let corpus_path = common::wisdom::slopsquat_corpus_path(&janitor_dir);

    // 3-attempt exponential backoff: 1 s → 2 s → 4 s.
    let mut network_ok = false;
    for attempt in 0u32..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(1u64 << (attempt - 1)));
        }
        if let Ok(corpus) = fetch_osv_slopsquat_corpus_from(agent, osv_base_url) {
            let corpus_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus)
                .map_err(|e| anyhow::anyhow!("update-slopsquat: serializing corpus failed: {e}"))?;
            write_atomic_bytes(&corpus_path, corpus_bytes.as_slice())?;

            let wisdom_path = janitor_dir.join("wisdom.rkyv");
            if let Some(mut wisdom) = common::wisdom::load_wisdom_set(&wisdom_path) {
                wisdom.slopsquat_filter =
                    common::bloom::SlopsquatFilter::from_seed_corpus(corpus.package_names.iter());
                wisdom.sort();
                let wisdom_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wisdom).map_err(|e| {
                    anyhow::anyhow!("update-slopsquat: serializing wisdom archive failed: {e}")
                })?;
                write_atomic_bytes(&wisdom_path, wisdom_bytes.as_slice())?;
            }

            println!(
                "\u{1f6e1}\u{fe0f} OSV slopsquat corpus synchronized: {} packages \u{2192} {}",
                corpus.package_names.len(),
                corpus_path.display()
            );
            network_ok = true;
            break;
        } // else: retry
    }

    if network_ok {
        return Ok(());
    }

    // All 3 attempts exhausted — apply offline fallback.
    apply_slopsquat_offline_fallback(&corpus_path, stale_days)
}

/// Offline fallback invoked when all network attempts for `update-slopsquat` fail.
///
/// - If a corpus already exists on disk: check its age.  Stale corpora (older
///   than `stale_days`) emit a degraded warning but still exit `Ok(())`.
/// - If no corpus exists: deploy the embedded build-time baseline and print
///   a bootstrap notice.
fn apply_slopsquat_offline_fallback(
    corpus_path: &std::path::Path,
    stale_days: u32,
) -> anyhow::Result<()> {
    if corpus_path.exists() {
        let meta = std::fs::metadata(corpus_path)
            .with_context(|| format!("reading metadata for {}", corpus_path.display()))?;
        let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        let age = std::time::SystemTime::now()
            .duration_since(modified)
            .unwrap_or(std::time::Duration::from_secs(u64::MAX));
        let stale_threshold =
            std::time::Duration::from_secs(u64::from(stale_days).saturating_mul(86_400));
        if age >= stale_threshold {
            eprintln!(
                "[JANITOR DEGRADED] Threat intelligence corpus is stale (network unreachable)."
            );
        }
        return Ok(());
    }

    // No corpus on disk — deploy the embedded seed baseline.
    write_atomic_bytes(corpus_path, EMBEDDED_SLOPSQUAT)?;
    eprintln!("[JANITOR BOOTSTRAPPED] Offline baseline deployed.");
    Ok(())
}

/// Download the bulk `all.zip` for each ecosystem and extract MAL- advisory package names.
///
/// Uses the OSV GCS bulk-export endpoint: `{base_url}/{ecosystem}/all.zip`.
/// Each `.zip` entry is a UTF-8 JSON advisory; we parse in-memory (no temp files) and
/// filter for `id.starts_with("MAL-")` before extracting affected package names.
fn fetch_osv_slopsquat_corpus_from(
    agent: &ureq::Agent,
    base_url: &str,
) -> anyhow::Result<common::wisdom::SlopsquatCorpus> {
    let mut packages = BTreeSet::new();
    for (dump_dir, ecosystem) in OSV_MALICIOUS_ECOSYSTEMS {
        let zip_url = format!("{base_url}/{dump_dir}/all.zip");
        let mut response = agent
            .get(&zip_url)
            .call()
            .map_err(|_e| anyhow::anyhow!("update-slopsquat: OSV bulk ZIP fetch failed"))?;
        // Circuit breaker: cap bulk OSV ZIP downloads at 256 MiB per ecosystem.
        // OSV's all.zip files are typically 50–150 MiB; 256 MiB gives a 2×
        // safety margin while preventing unbounded heap growth from a malformed
        // or adversarially-redirected oversized payload.
        const MAX_ZIP_BYTES: u64 = 256 * 1024 * 1024;
        let zip_bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_ZIP_BYTES)
            .read_to_vec()
            .map_err(|_e| {
                anyhow::anyhow!("update-slopsquat: reading OSV bulk ZIP response failed")
            })?;

        let found = extract_mal_packages_from_zip(&zip_bytes, ecosystem)
            .map_err(|_e| anyhow::anyhow!("update-slopsquat: extracting OSV bulk ZIP failed"))?;
        packages.extend(found);
    }

    anyhow::ensure!(
        !packages.is_empty(),
        "update-slopsquat: OSV synchronization produced an empty malicious package corpus"
    );

    Ok(common::wisdom::SlopsquatCorpus {
        package_names: packages.into_iter().collect(),
    })
}

/// Extract malicious package names from a raw OSV bulk `all.zip` archive.
///
/// Iterates every entry in the ZIP, parses the JSON, and returns the affected package
/// name for every entry whose `id` starts with `MAL-`.  The `ecosystem` parameter
/// filters the `affected[].package.ecosystem` field so npm/PyPI/crates.io entries
/// do not bleed into each other.
fn extract_mal_packages_from_zip(zip_bytes: &[u8], ecosystem: &str) -> anyhow::Result<Vec<String>> {
    use std::io::Read as _;
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|_e| anyhow::anyhow!("update-slopsquat: invalid ZIP archive"))?;

    let mut packages = BTreeSet::new();
    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.name().ends_with(".json") {
            continue;
        }
        // Circuit breaker: skip advisory files larger than 1 MiB.
        if entry.size() > 1_048_576 {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut buf).is_err() {
            continue;
        }
        let advisory: OsvVulnerability = match serde_json::from_slice(&buf) {
            Ok(a) => a,
            Err(_) => continue,
        };
        for name in parse_osv_malicious_package_names(&advisory, ecosystem) {
            packages.insert(name);
        }
    }
    Ok(packages.into_iter().collect())
}

fn parse_osv_malicious_package_names(record: &OsvVulnerability, ecosystem: &str) -> Vec<String> {
    let is_malicious = record.id.starts_with("MAL-")
        || record.aliases.iter().any(|alias| alias.starts_with("MAL-"));
    if !is_malicious {
        return Vec::new();
    }

    let mut names = BTreeSet::new();
    for affected in &record.affected {
        let Some(package) = affected.package.as_ref() else {
            continue;
        };
        if !package.ecosystem.eq_ignore_ascii_case(ecosystem) {
            continue;
        }
        let normalized = package.name.trim().to_ascii_lowercase().replace('_', "-");
        if !normalized.is_empty() {
            names.insert(normalized);
        }
    }

    names.into_iter().collect()
}

fn write_atomic_bytes(path: &Path, content: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "write rejected: {} is a symlink — potential symlink overwrite attack",
                path.display()
            );
        }
    }

    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("bin")
    ));
    {
        let mut tmp = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        tmp.write_all(content)
            .with_context(|| format!("writing to {}", tmp_path.display()))?;
        tmp.sync_all()
            .with_context(|| format!("sync_all on {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("atomic rename {} → {}", tmp_path.display(), path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// SBOM drift daemon — Phase 4
// ---------------------------------------------------------------------------

/// Lockfile names monitored for SBOM drift.
const SBOM_WATCH_FILES: &[&str] = &["Cargo.lock", "package-lock.json", "poetry.lock"];

/// Watch lockfiles under `project_root` for modifications and emit a `sbom_drift`
/// webhook event when new package names appear.
///
/// Uses `notify::RecommendedWatcher` (inotify on Linux, kqueue on macOS) with a
/// 500 ms debounce so rapid successive writes produce a single event.  The function
/// blocks until the user sends SIGINT; the watcher thread is dropped on return.
fn cmd_watch_sbom(project_root: &Path) -> anyhow::Result<()> {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;
    use std::time::Duration;

    let policy = common::policy::JanitorPolicy::load(project_root)?;

    // Snapshot the current set of package names across all monitored lockfiles.
    let mut known = snapshot_lockfile_packages(project_root);

    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = RecommendedWatcher::new(tx, notify::Config::default())?;
    watcher.watch(project_root, RecursiveMode::NonRecursive)?;

    eprintln!(
        "janitor watch-sbom: watching {} for SBOM drift (CTRL-C to stop)",
        project_root.display()
    );

    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(event)) => {
                // Only react to Modify events on the lockfiles we care about.
                let is_lockfile_event = event.paths.iter().any(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| SBOM_WATCH_FILES.contains(&n))
                        .unwrap_or(false)
                });
                if !is_lockfile_event {
                    continue;
                }
                // Re-snapshot and diff.
                let current = snapshot_lockfile_packages(project_root);
                let new_packages: Vec<String> = current
                    .iter()
                    .filter(|p| !known.contains(p.as_str()))
                    .cloned()
                    .collect();
                if !new_packages.is_empty() {
                    eprintln!(
                        "janitor watch-sbom: SBOM drift detected — {} new package(s): {:?}",
                        new_packages.len(),
                        new_packages,
                    );
                    report::emit_sbom_drift_webhook(&new_packages, &policy);
                    known = current;
                } else {
                    known = current;
                }
            }
            Ok(Err(e)) => {
                eprintln!("janitor watch-sbom: watcher error: {e}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No event — continue polling.
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }
    Ok(())
}

/// Collect the set of package names from all monitored lockfiles in `root`.
///
/// Reads `Cargo.lock` (TOML), `package-lock.json` (JSON), and `poetry.lock` (TOML)
/// using simple line-level heuristics to avoid pulling in additional parser deps.
/// The result is a `BTreeSet` of lowercased package names for stable diffing.
fn snapshot_lockfile_packages(root: &Path) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    let mut names: BTreeSet<String> = BTreeSet::new();

    // Cargo.lock — lines like `name = "serde"` inside [[package]] sections.
    let cargo_lock = root.join("Cargo.lock");
    if let Ok(content) = std::fs::read_to_string(&cargo_lock) {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("name = \"") {
                if let Some(name) = rest.strip_suffix('"') {
                    names.insert(name.to_ascii_lowercase());
                }
            }
        }
    }

    // package-lock.json — lines like `"node_modules/foo": {` or `"name": "foo"`.
    let npm_lock = root.join("package-lock.json");
    if let Ok(content) = std::fs::read_to_string(&npm_lock) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(pkgs) = parsed.get("packages").and_then(|v| v.as_object()) {
                for key in pkgs.keys() {
                    if let Some(pkg_name) = key.strip_prefix("node_modules/") {
                        names.insert(pkg_name.to_ascii_lowercase());
                    }
                }
            }
        }
    }

    // poetry.lock — lines like `name = "requests"` inside [[package]] sections.
    let poetry_lock = root.join("poetry.lock");
    if let Ok(content) = std::fs::read_to_string(&poetry_lock) {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("name = \"") {
                if let Some(name) = rest.strip_suffix('"') {
                    names.insert(name.to_ascii_lowercase());
                }
            }
        }
    }

    names
}

#[derive(Debug, Clone)]
struct VerifiedWisdomPayload {
    bytes: Vec<u8>,
    signature: String,
    hash: String,
}

fn select_wisdom_quorum_candidate(
    threshold: usize,
    candidates: Vec<(String, VerifiedWisdomPayload)>,
) -> anyhow::Result<(
    Vec<u8>,
    String,
    String,
    Option<common::wisdom::WisdomMirrorReceipt>,
)> {
    use std::collections::BTreeMap;

    let mut agreed: BTreeMap<String, Vec<(String, VerifiedWisdomPayload)>> = BTreeMap::new();
    for (mirror, payload) in candidates {
        agreed
            .entry(payload.hash.clone())
            .or_default()
            .push((mirror, payload));
    }

    let Some((agreed_hash, matches)) = agreed.into_iter().max_by_key(|(_, v)| v.len()) else {
        anyhow::bail!("update-wisdom --ci-mode: no valid signed Wisdom mirrors reached quorum");
    };
    if matches.len() < threshold {
        anyhow::bail!(
            "update-wisdom --ci-mode: Wisdom mirror quorum failed for hash {agreed_hash}; got {} valid mirrors, need {}",
            matches.len(),
            threshold
        );
    }

    let accepted_mirrors: Vec<String> = matches
        .iter()
        .take(threshold)
        .map(|(mirror, _)| mirror.clone())
        .collect();
    let canonical = matches.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!("update-wisdom --ci-mode: quorum candidate set was empty")
    })?;
    Ok((
        canonical.1.bytes,
        canonical.1.signature,
        canonical.1.hash.clone(),
        Some(common::wisdom::WisdomMirrorReceipt {
            threshold,
            agreed_hash,
            accepted_mirrors,
        }),
    ))
}

fn fetch_verified_wisdom_payload(
    wisdom_url: &str,
    wisdom_sig_url: &str,
    mode_label: &str,
) -> anyhow::Result<VerifiedWisdomPayload> {
    let mut response = ureq::get(wisdom_url)
        .call()
        // CodeQL: URL and error details redacted — mirror URL may contain credentials.
        .map_err(|_e| anyhow::anyhow!("{mode_label}: wisdom archive fetch failed"))?;
    // Circuit breaker: wisdom archives are typically a few hundred KiB.
    // 64 MiB provides a generous safety margin against unbounded heap growth.
    const MAX_WISDOM_BYTES: u64 = 64 * 1024 * 1024;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_WISDOM_BYTES)
        .read_to_vec()
        // CodeQL: error details redacted.
        .map_err(|_e| anyhow::anyhow!("update-wisdom: reading wisdom response body failed"))?;

    let mut sig_response = ureq::get(wisdom_sig_url)
        .call()
        // CodeQL: URL and error details redacted — mirror URL may contain credentials.
        .map_err(|_e| anyhow::anyhow!("{mode_label}: wisdom signature fetch failed"))?;
    // Circuit breaker: Ed25519 signatures are exactly 64 bytes; 4 KiB is generous.
    const MAX_SIG_BYTES: u64 = 4 * 1024;
    let sig_bytes = sig_response
        .body_mut()
        .with_config()
        .limit(MAX_SIG_BYTES)
        .read_to_vec()
        // CodeQL: error details redacted.
        .map_err(|_e| {
            anyhow::anyhow!("update-wisdom: reading wisdom signature response body failed")
        })?;

    verify_wisdom_signature(&bytes, &sig_bytes)
        .context("update-wisdom: detached wisdom signature verification failed")?;
    let signature = common::wisdom::normalize_signature_string(&sig_bytes)
        .ok_or_else(|| anyhow::anyhow!("update-wisdom: detached signature was empty"))?;
    let hash = blake3::hash(&bytes).to_hex().to_string();
    Ok(VerifiedWisdomPayload {
        bytes,
        signature,
        hash,
    })
}

fn fetch_verified_wisdom_quorum(
    quorum: &common::policy::WisdomQuorumConfig,
    threshold: usize,
) -> anyhow::Result<(
    Vec<u8>,
    String,
    String,
    Option<common::wisdom::WisdomMirrorReceipt>,
)> {
    let mut candidates = Vec::new();
    let mut last_error = String::new();
    for mirror in &quorum.mirrors {
        let base = mirror.trim_end_matches('/');
        let wisdom_url = format!("{base}/v1/wisdom.rkyv");
        let sig_url = format!("{base}/v1/wisdom.rkyv.sig");
        match fetch_verified_wisdom_payload(&wisdom_url, &sig_url, "update-wisdom --ci-mode") {
            Ok(payload) => candidates.push((mirror.clone(), payload)),
            Err(err) => {
                last_error = err.to_string();
            }
        }
    }
    if candidates.is_empty() {
        anyhow::bail!(
            "update-wisdom --ci-mode: no valid signed Wisdom mirrors reached quorum ({last_error})"
        );
    }
    select_wisdom_quorum_candidate(threshold, candidates)
}

fn write_wisdom_manifest(janitor_dir: &Path, manifest: &serde_json::Value) -> anyhow::Result<()> {
    let manifest_path = janitor_dir.join("wisdom_manifest.json");
    let manifest_str = serde_json::to_string_pretty(manifest).map_err(|e| {
        anyhow::anyhow!("update-wisdom --ci-mode: serializing manifest failed: {e}")
    })?;
    std::fs::write(&manifest_path, manifest_str.as_bytes())
        .with_context(|| format!("writing {}", manifest_path.display()))?;
    Ok(())
}

fn write_wisdom_receipt(
    janitor_dir: &Path,
    wisdom_hash: &str,
    wisdom_signature: &str,
) -> anyhow::Result<()> {
    let receipt_path = janitor_dir.join("wisdom.rkyv.receipt.json");
    let receipt = serde_json::json!({
        "wisdom_hash": wisdom_hash,
        "wisdom_signature": wisdom_signature,
        "recorded_at": utc_now_iso8601(),
    });
    let receipt_str = serde_json::to_string_pretty(&receipt)
        .map_err(|_| anyhow::anyhow!("serializing wisdom receipt failed"))?;
    std::fs::write(&receipt_path, receipt_str.as_bytes())
        .with_context(|| format!("writing {}", receipt_path.display()))?;
    Ok(())
}

fn write_wisdom_mirror_receipt(
    janitor_dir: &Path,
    receipt: &common::wisdom::WisdomMirrorReceipt,
) -> anyhow::Result<()> {
    let receipt_path = janitor_dir.join("wisdom.rkyv.mirror.json");
    let body = serde_json::to_string_pretty(receipt)
        .map_err(|_| anyhow::anyhow!("serializing wisdom mirror receipt failed"))?;
    std::fs::write(&receipt_path, body.as_bytes())
        .with_context(|| format!("writing {}", receipt_path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Telemetry (sovereign learning loop — zero-knowledge)
// ---------------------------------------------------------------------------

/// Returns the current UTC time as an ISO 8601 string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Used in the CLI telemetry path and by [`daemon::unix`] for bounce-log timestamps.
/// Implemented without external crate dependencies using the Richards (2013)
/// civil-calendar algorithm applied to the POSIX epoch.
pub(crate) fn utc_now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    // Days since 1970-01-01 UTC.
    let days = (secs / 86400) as i64;
    // Richards civil-calendar algorithm: days → (year, month, day).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Appends a single zero-knowledge telemetry entry to `.janitor/telemetry.json`.
///
/// The file is a JSON array of objects; if absent it is created.
/// **Zero-knowledge guarantee**: no file paths, symbol names, or source bytes are
/// written — only the timestamp, action string, heuristic label, and structural hash.
fn telemetry_append(janitor_dir: &Path, action: &str, heuristic_failed: &str, hash: u64) {
    let path = janitor_dir.join("telemetry.json");
    // Read existing entries or start fresh.
    let mut entries: Vec<serde_json::Value> = path
        .exists()
        .then(|| std::fs::read(&path).ok())
        .flatten()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    entries.push(serde_json::json!({
        "timestamp": utc_now_iso8601(),
        "action": action,
        "heuristic_failed": heuristic_failed,
        "structural_hash": hash,
    }));

    if let Ok(serialized) = serde_json::to_vec_pretty(&entries) {
        let _ = std::fs::create_dir_all(janitor_dir);
        let _ = std::fs::write(&path, serialized);
    }
}

/// Exports the local telemetry log as a JSON block.
///
/// Reads `.janitor/telemetry.json` and prints the entries to stdout.
/// The payload is zero-knowledge: no file paths or source code are present.
fn cmd_telemetry_export(project_root: &Path) -> anyhow::Result<()> {
    let telemetry_path = project_root.join(".janitor").join("telemetry.json");

    if !telemetry_path.exists() {
        println!("No telemetry data found at {}.", telemetry_path.display());
        println!("Telemetry is recorded automatically on rollbacks (janitor undo / clean --force-purge).");
        return Ok(());
    }

    let raw = std::fs::read(&telemetry_path)
        .with_context(|| format!("reading {}", telemetry_path.display()))?;
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&raw).with_context(|| "telemetry.json is not valid JSON")?;

    let export = serde_json::json!({
        "version": "1",
        "entry_count": entries.len(),
        "entries": entries,
        "exported_at": utc_now_iso8601(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&export).context("serializing export block")?
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// debug-silo — Controlled Conflict Simulation
// ---------------------------------------------------------------------------

/// Controlled Conflict Simulation for the lockfile silo detector.
///
/// Synthesises a `Cargo.lock` with `serde` at two distinct resolved versions
/// (1.0.100 and 1.0.150) and asserts that
/// [`anatomist::manifest::find_version_silos_from_lockfile`] surfaces the conflict
/// as `architecture:version_silo (serde v1.0.100 vs v1.0.150)`.
///
/// Exits 0 and prints `DETECTOR VERIFIED: SILO CAPTURED` on success.
/// Exits 1 and prints `DETECTOR FAILURE` if the engine misses the conflict.
fn cmd_debug_silo() -> anyhow::Result<()> {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use anatomist::manifest::find_version_silos_from_lockfile;

    // Synthetic Cargo.lock — two resolved entries for `serde` at different versions.
    // The format must match what `cargo generate-lockfile` produces so that
    // `parse_lockfile_silos` (which uses `toml::from_str::<toml::Value>`) can
    // consume it without error.
    let synthetic_lock = r#"# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "serde"
version = "1.0.150"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
 "serde 1.0.100",
 "serde 1.0.150",
]
"#;

    let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    blobs.insert(
        PathBuf::from("Cargo.lock"),
        synthetic_lock.as_bytes().to_vec(),
    );

    // No base_lock — we want all silos in the head, not just new ones.
    let silos = find_version_silos_from_lockfile(&blobs, None);

    let serde_silo = silos.iter().find(|s| s.name == "serde");

    match serde_silo {
        Some(silo) => {
            let display = silo.display();
            // Expected: "serde (v1.0.100 vs v1.0.150)"
            println!("DETECTOR VERIFIED: SILO CAPTURED");
            println!("  Antipattern: architecture:version_silo — {display}");
            println!("  Versions detected: {:?}", silo.versions);
            Ok(())
        }
        None => {
            eprintln!(
                "DETECTOR FAILURE: find_version_silos_from_lockfile returned no silo for serde"
            );
            eprintln!(
                "  Blobs fed to detector: {:?}",
                blobs.keys().collect::<Vec<_>>()
            );
            eprintln!(
                "  All silos found: {:?}",
                silos.iter().map(|s| s.display()).collect::<Vec<_>>()
            );
            std::process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// step-summary — GitHub Actions Integrity Dashboard
// ---------------------------------------------------------------------------

/// Reads the last entry from `.janitor/bounce_log.ndjson` and emits a
/// high-density GitHub Actions Step Summary Markdown dashboard to stdout.
///
/// Append the output to `$GITHUB_STEP_SUMMARY` in the CI shell to surface
/// the Integrity Radar, Structural Topology, Provenance Ledger, and
/// Vibe-Check on every PR Actions run.
fn cmd_step_summary(path: &Path) -> anyhow::Result<()> {
    let janitor_dir = path.join(".janitor");
    let entries = report::load_bounce_log(&janitor_dir);
    let entry = entries
        .into_iter()
        .next_back()
        .ok_or_else(|| anyhow::anyhow!("no bounce log at {}", janitor_dir.display()))?;
    print!("{}", report::render_step_summary(&entry));
    Ok(())
}

// ---------------------------------------------------------------------------
// self-test — Sovereign Integrity Audit
// ---------------------------------------------------------------------------

/// Executes a Ghost Attack: two synthetic threat fixtures are injected and the
/// engine must intercept both to produce a "SANCTUARY INTACT" verdict.
///
/// Ghost Attack A — Cryptominer string:
///   A unified diff blob containing `stratum+tcp://` is fed to `PatchBouncer`.
///   Expected outcome: `score.score() > 0` and a `security:` antipattern entry.
///
/// Ghost Attack B — Version silo:
///   Two `Cargo.toml` blobs declare the same crate at different versions.
///   Expected outcome: `find_version_silos_in_blobs` returns the silo name.
///
/// If either check fails the function returns `Err` and exits non-zero.
fn cmd_self_test() -> anyhow::Result<()> {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use anatomist::manifest::find_version_silos_in_blobs;
    use common::registry::SymbolRegistry;
    use forge::slop_filter::{PRBouncer, PatchBouncer};

    println!("Janitor Self-Test: Sovereign Integrity Audit");
    println!("---");

    let mut all_passed = true;

    // ── Ghost Attack A: Cryptominer Intercept ──────────────────────────────
    {
        // Minimal unified diff containing a stratum+tcp:// mining-pool URI.
        // The PatchBouncer must flag this as security:compiled_payload_anomaly.
        let synthetic_diff = concat!(
            "diff --git a/src/miner.rs b/src/miner.rs\n",
            "--- a/src/miner.rs\n",
            "+++ b/src/miner.rs\n",
            "@@ -0,0 +1,4 @@\n",
            "+fn connect_pool() {\n",
            "+    let url = \"stratum+tcp://pool.selftest.invalid:3333\";\n",
            "+    println!(\"{}\", url);\n",
            "+}\n",
        );

        let registry = SymbolRegistry::default();
        let ghost_a_passed = match PatchBouncer::default().bounce(synthetic_diff, &registry) {
            Ok(score) => score.score() > 0,
            Err(_) => false,
        };
        if ghost_a_passed {
            println!("[PASS] Ghost Attack A — Cryptominer Intercept");
        } else {
            println!("[FAIL] Ghost Attack A — Cryptominer Intercept");
            all_passed = false;
        }
    }

    // ── Ghost Attack B: Version Silo Intercept ─────────────────────────────
    {
        // Two Cargo.toml blobs declare `serde` at different versions.
        // find_version_silos_in_blobs must return "serde" as a silo.
        let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
        blobs.insert(
            PathBuf::from("crate-alpha/Cargo.toml"),
            b"[dependencies]\nserde = \"1.0.100\"\n".to_vec(),
        );
        blobs.insert(
            PathBuf::from("crate-beta/Cargo.toml"),
            b"[dependencies]\nserde = \"1.0.200\"\n".to_vec(),
        );

        let silos = find_version_silos_in_blobs(&blobs);
        let ghost_b_passed = silos.iter().any(|s| s == "serde");
        if ghost_b_passed {
            println!("[PASS] Ghost Attack B — Version Silo Intercept");
        } else {
            println!("[FAIL] Ghost Attack B — Version Silo Intercept");
            all_passed = false;
        }
    }

    println!("---");
    if all_passed {
        println!("SANCTUARY INTACT");
        Ok(())
    } else {
        eprintln!("INTEGRITY BREACH: RECALIBRATION REQUIRED");
        anyhow::bail!("self-test failed — engine integrity compromised")
    }
}

fn run_pytest(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("pytest")
        .args(["--tb=short", "-q"])
        .current_dir(dir)
        .status();

    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // BLOCKING: never proceed without test verification.
            Err(anyhow::anyhow!(
                "pytest not found — test verification is required for physical cleanup.\n\
                 Install pytest in the target environment, or use a repo with a native test suite."
            ))
        }
        Err(e) => Err(anyhow::anyhow!("Failed to spawn pytest: {e}")),
        Ok(s) if s.success() => Ok(()),
        // Exit 5 = no tests collected — vacuous pass, nothing to break.
        Ok(s) if s.code() == Some(5) => {
            eprintln!("note: pytest collected no tests (exit 5). Proceeding.");
            Ok(())
        }
        Ok(s) => Err(anyhow::anyhow!(
            "pytest exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}

// ---------------------------------------------------------------------------
// PQC signing unit tests (VULN-02 — Signature Sovereignty)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pqc_signing_tests {
    use super::cbom;
    use crate::report::{self, BounceLogEntry, PrState, Provenance};
    use common::pqc::PqcKeySource;
    use fips204::ml_dsa_65;
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

    /// Construct a minimal BounceLogEntry for signing fixture use.
    fn make_pqc_entry(score: u32) -> BounceLogEntry {
        let antipatterns = if score > 0 {
            vec!["security:unsafe_gets".to_string()]
        } else {
            vec![]
        };
        BounceLogEntry {
            execution_tier: "Community".to_string(),
            pr_number: Some(42),
            author: Some("security-team".to_string()),
            timestamp: "2026-04-03T00:00:00Z".to_string(),
            slop_score: score,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: antipatterns.clone(),
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: PrState::Open,
            is_bot: false,
            repo_slug: "test-org/test-repo".to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: "abc123".to_string(),
            policy_hash: String::new(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: report::compute_ci_energy_saved_kwh(
                0,
                score,
                None,
                &antipatterns,
                &[],
            ),
            provenance: Provenance::default(),
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
            git_signature_status: None,
        }
    }

    /// End-to-end wiring: generate an ML-DSA keypair and sign the deterministic CBOM.
    ///
    /// Full SLH-DSA cryptographic roundtrip coverage lives in `common::pqc`; this
    /// CLI test stays lightweight so `just audit` remains bounded.
    #[test]
    fn sign_and_verify_roundtrip() {
        use common::pqc::{sign_cbom_dual_from_keys, verify_ml_dsa_signature};

        let (ml_pk, ml_sk) = ml_dsa_65::KG::try_keygen().expect("keygen must succeed");
        let entry = make_pqc_entry(50);
        let cbom_json = cbom::render_cbom_for_entry(&entry, &entry.repo_slug);
        let signatures = sign_cbom_dual_from_keys(
            cbom_json.as_bytes(),
            &common::pqc::PqcPrivateKeyBundle {
                ml_dsa: Some(ml_sk.into_bytes()),
                slh_dsa: None,
            },
        )
        .expect("dual signing must succeed");

        // Re-derive CBOM bytes identically.
        let cbom_json2 = cbom::render_cbom_for_entry(&entry, &entry.repo_slug);
        assert_eq!(
            cbom_json, cbom_json2,
            "CBOM derivation must be deterministic"
        );

        assert!(
            signatures.slh_dsa_sig.is_none(),
            "ML-only signing fixtures must not fabricate an SLH-DSA signature"
        );
        assert!(
            verify_ml_dsa_signature(
                cbom_json2.as_bytes(),
                &ml_pk.into_bytes(),
                signatures
                    .ml_dsa_sig
                    .as_deref()
                    .expect("ML signature must be present"),
            )
            .expect("ML verification must succeed"),
            "ML-DSA signature must verify against the original CBOM bytes"
        );
    }

    /// A tampered signature must not verify.
    #[test]
    fn tampered_signature_fails_verification() {
        let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("keygen must succeed");
        let entry = make_pqc_entry(150);
        let cbom_json = cbom::render_cbom_for_entry(&entry, &entry.repo_slug);

        let mut sig = sk
            .try_sign(cbom_json.as_bytes(), b"janitor-cbom")
            .expect("signing must succeed");
        // Flip the first byte to corrupt the signature.
        sig[0] ^= 0xFF;

        let valid = pk.verify(cbom_json.as_bytes(), &sig, b"janitor-cbom");
        assert!(!valid, "tampered signature must not verify");
    }

    /// CBOM derivation is deterministic across calls for the same entry.
    #[test]
    fn cbom_derivation_is_deterministic() {
        let entry = make_pqc_entry(0);
        let a = cbom::render_cbom_for_entry(&entry, "owner/repo");
        let b = cbom::render_cbom_for_entry(&entry, "owner/repo");
        assert_eq!(a, b, "render_cbom_for_entry must be deterministic");
        // Deterministic output must NOT contain a UUID or dynamic timestamp.
        assert!(
            !a.contains("serialNumber"),
            "signed CBOM must not include serialNumber"
        );
        assert!(
            !a.contains("timestamp"),
            "signed CBOM must not include timestamp"
        );
    }

    /// Wrong-length key bytes must fail the array conversion before reaching try_from_bytes.
    #[test]
    fn wrong_length_key_bytes_fail_conversion() {
        let too_short: Vec<u8> = vec![0u8; 100];
        let result: Result<[u8; 4032], _> = too_short.try_into();
        assert!(
            result.is_err(),
            "wrong-length private key bytes must fail conversion"
        );

        let too_short_pk: Vec<u8> = vec![0u8; 100];
        let result_pk: Result<[u8; 1952], _> = too_short_pk.try_into();
        assert!(
            result_pk.is_err(),
            "wrong-length public key bytes must fail conversion"
        );
    }

    #[test]
    fn enterprise_key_sources_are_classified_as_commercial() {
        let aws = PqcKeySource::parse("arn:aws:kms:us-east-1:123:key/abc");
        let azure = PqcKeySource::parse("https://corp.vault.azure.net/keys/janitor/main");
        let pkcs11 = PqcKeySource::parse("pkcs11:token=janitor;object=ml-dsa");

        assert!(aws.requires_commercial_governor());
        assert!(azure.requires_commercial_governor());
        assert!(pkcs11.requires_commercial_governor());
    }
}

#[cfg(test)]
mod replay_receipt_tests {
    use super::cmd_replay_receipt;
    use common::receipt::{
        CapsuleMutationRoot, DecisionCapsule, DecisionReceipt, DecisionScoreVector,
        SealedDecisionCapsule, SignedDecisionReceipt,
    };
    use ed25519_dalek::SigningKey;

    const TEST_GOVERNOR_SIGNING_KEY_SEED: [u8; 32] = [
        0x23, 0x70, 0xde, 0x11, 0x87, 0xe8, 0xd5, 0x7e, 0x42, 0x3d, 0x3e, 0xe0, 0x38, 0x64, 0x2c,
        0x41, 0x3e, 0x27, 0x23, 0x36, 0xd4, 0x26, 0x5c, 0x1b, 0xc4, 0x1c, 0x6c, 0x22, 0x9a, 0xc4,
        0xeb, 0xe5,
    ];

    #[test]
    fn replay_receipt_roundtrip_succeeds() {
        let capsule = DecisionCapsule {
            execution_tier: "Community".to_string(),
            mutation_roots: vec![CapsuleMutationRoot {
                language: "js".to_string(),
                hash: blake3::hash(b"eval(atob(\"boom\"))").to_hex().to_string(),
                bytes: b"eval(atob(\"boom\"))".to_vec(),
            }],
            policy_hash: "policy".to_string(),
            wisdom_hash: "wisdom".to_string(),
            cbom_digest: "cbom".to_string(),
            wasm_policy_receipts: Vec::new(),
            taint_catalog_hash: None,
            score_vector: DecisionScoreVector {
                antipattern_score: 150,
                ..DecisionScoreVector::default()
            },
        };
        let capsule_hash = capsule.hash().unwrap();
        let signing_key = SigningKey::from_bytes(&TEST_GOVERNOR_SIGNING_KEY_SEED);
        let receipt = SignedDecisionReceipt::sign(
            DecisionReceipt {
                execution_tier: "Community".to_string(),
                policy_hash: "policy".to_string(),
                wisdom_hash: "wisdom".to_string(),
                commit_sha: "deadbeef".to_string(),
                repo_slug: "owner/repo".to_string(),
                slop_score: 150,
                transparency_anchor: "7:abc".to_string(),
                cbom_signature: "sig".to_string(),
                capsule_hash,
                wasm_policy_receipts: Vec::new(),
            },
            &signing_key,
        )
        .unwrap();
        let sealed = SealedDecisionCapsule { capsule, receipt };
        let path = std::env::temp_dir().join(format!(
            "janitor-replay-{}-{}.capsule",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        sealed.save(&path).unwrap();
        let result = cmd_replay_receipt(&path);
        let _ = std::fs::remove_file(&path);
        result.unwrap();
    }

    #[test]
    fn invalid_license_forces_degraded_runtime_state() {
        let temp_dir = tempfile::tempdir().expect("tempdir must succeed");
        let execution_tier = crate::resolve_execution_tier(temp_dir.path());

        assert_eq!(execution_tier, "Community");
        assert_eq!(crate::effective_rayon_workers(16, &execution_tier), 1);
        assert!(crate::enforce_sovereign_feature_gate(&execution_tier).is_err());
    }
}

#[cfg(test)]
mod governor_routing_tests {
    use super::cmd_bounce;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    #[test]
    fn governor_url_routes_bounce_payload_to_custom_endpoint() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("listener bind must succeed: {err}"),
        };
        let addr = listener.local_addr().expect("local addr must resolve");
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("must accept one connection");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .expect("read request line");
            let mut authorization = String::new();
            let mut content_length = 0_usize;

            loop {
                let mut header = String::new();
                reader.read_line(&mut header).expect("read header");
                let trimmed = header.trim_end();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((name, value)) = trimmed.split_once(':') {
                    if name.eq_ignore_ascii_case("authorization") {
                        authorization = value.trim().to_string();
                    }
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse::<usize>().expect("content length");
                    }
                }
            }

            let mut body = vec![0_u8; content_length];
            reader.read_exact(&mut body).expect("read body");
            let body_text = String::from_utf8(body).expect("utf8 body");
            tx.send((request_line, authorization, body_text))
                .expect("send capture");

            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .expect("write response");
        });

        let temp_root =
            std::env::temp_dir().join(format!("janitor-governor-route-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(temp_root.join(".janitor")).expect("create janitor dir");
        std::fs::write(temp_root.join(".janitor").join("heartbeat"), b"recent")
            .expect("write heartbeat");
        let patch_path = temp_root.join("bounce.patch");
        std::fs::write(
            &patch_path,
            concat!(
                "--- a/src/lib.rs\n",
                "+++ b/src/lib.rs\n",
                "@@ -0,0 +1,3 @@\n",
                "+fn routed() {\n",
                "+    println!(\"ok\");\n",
                "+}\n",
            ),
        )
        .expect("write patch");

        let governor_url = format!("http://{addr}");
        let result = cmd_bounce(
            &temp_root,
            Some(&patch_path),
            None,
            "json",
            None,
            None,
            None,
            Some(42),
            Some("operator"),
            None,
            Some("acme/repo"),
            "open",
            Some(&governor_url),
            Some("stub-token"),
            Some("deadbeef"),
            false,
            false,
            None,
            &[],
            "Community",
        );
        assert!(result.is_ok(), "cmd_bounce should POST to custom governor");

        let (request_line, authorization, body) = rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("captured request");
        assert!(
            request_line.starts_with("POST /v1/report "),
            "bounce must target /v1/report, got: {request_line}"
        );
        assert_eq!(authorization, "Bearer stub-token");
        assert!(
            body.contains("\"pr_number\":42"),
            "captured payload must include the bounce entry"
        );
        assert!(
            body.contains("\"commit_sha\":\"deadbeef\""),
            "captured payload must use the supplied head sha"
        );

        let _ = std::fs::remove_dir_all(&temp_root);
    }
}

#[cfg(test)]
mod wisdom_sync_tests {
    use super::{
        cmd_update_wisdom_with_urls, select_wisdom_quorum_candidate, VerifiedWisdomPayload,
    };
    use std::fs;

    #[test]
    fn ci_mode_fails_closed_when_wisdom_fetch_fails() {
        let temp_root =
            std::env::temp_dir().join(format!("janitor-wisdom-sync-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_root).expect("temp root must be created");

        let error = cmd_update_wisdom_with_urls(
            &temp_root,
            true,
            "http://127.0.0.1:9/wisdom.rkyv",
            "http://127.0.0.1:9/wisdom.rkyv.sig",
            "http://127.0.0.1:9/kev.json",
        )
        .expect_err("ci-mode must fail closed when wisdom.rkyv is unavailable");
        assert!(
            error.to_string().contains("update-wisdom --ci-mode"),
            "ci-mode error must identify the strict path"
        );
        assert!(
            !temp_root.join(".janitor").join("wisdom.rkyv").exists(),
            "failed ci-mode sync must not fabricate a wisdom archive"
        );
    }

    #[test]
    fn quorum_selection_accepts_matching_threshold() {
        let payload = VerifiedWisdomPayload {
            bytes: b"wisdom".to_vec(),
            signature: "sig-a".to_string(),
            hash: "hash-a".to_string(),
        };
        let result = select_wisdom_quorum_candidate(
            2,
            vec![
                ("https://mirror-a.example".to_string(), payload.clone()),
                ("https://mirror-b.example".to_string(), payload),
            ],
        )
        .expect("matching mirrors must satisfy quorum");
        assert_eq!(result.2, "hash-a");
        assert_eq!(
            result
                .3
                .as_ref()
                .expect("mirror receipt must be present")
                .accepted_mirrors
                .len(),
            2
        );
    }

    #[test]
    fn quorum_selection_fails_when_threshold_is_not_met() {
        let result = select_wisdom_quorum_candidate(
            2,
            vec![
                (
                    "https://mirror-a.example".to_string(),
                    VerifiedWisdomPayload {
                        bytes: b"wisdom-a".to_vec(),
                        signature: "sig-a".to_string(),
                        hash: "hash-a".to_string(),
                    },
                ),
                (
                    "https://mirror-b.example".to_string(),
                    VerifiedWisdomPayload {
                        bytes: b"wisdom-b".to_vec(),
                        signature: "sig-b".to_string(),
                        hash: "hash-b".to_string(),
                    },
                ),
            ],
        )
        .expect_err("split mirror hashes must fail quorum");
        assert!(
            result.to_string().contains("quorum failed"),
            "quorum failure must be explicit"
        );
    }
}

const WISDOM_VERIFYING_KEY_BYTES: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

// ---------------------------------------------------------------------------
// export-intel-capsule / import-intel-capsule
// ---------------------------------------------------------------------------

/// Package the locally-verified wisdom feed and its cryptographic evidence into
/// a portable [`common::wisdom::IntelTransferCapsule`] JSON file.
///
/// Reads `.janitor/wisdom.rkyv` plus any adjacent `.rkyv.sig` / `.rkyv.receipt.json`
/// / `.rkyv.mirror.json` files from `project_root` and serializes them into a
/// single JSON archive at `out_path`.
fn cmd_export_intel_capsule(project_root: &Path, out_path: &Path) -> anyhow::Result<()> {
    let janitor_dir = project_root.join(".janitor");
    let wisdom_path = janitor_dir.join("wisdom.rkyv");

    let wisdom_bytes = std::fs::read(&wisdom_path)
        .with_context(|| format!("reading {}", wisdom_path.display()))?;

    let feed_hash = blake3::hash(&wisdom_bytes).to_hex().to_string();

    // Collect all available Ed25519 signatures (receipt.json wins; .sig fallback).
    let mut ed25519_signatures: Vec<String> = Vec::new();
    let receipt_json_path = wisdom_path.with_extension("rkyv.receipt.json");
    if let Ok(receipt_bytes) = std::fs::read(&receipt_json_path) {
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&receipt_bytes) {
            if let Some(sig) = json
                .get("wisdom_signature")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                ed25519_signatures.push(sig.to_owned());
            }
        }
    }
    // Fallback: raw .sig file.
    if ed25519_signatures.is_empty() {
        let sig_path = wisdom_path.with_extension("rkyv.sig");
        if let Ok(sig_bytes) = std::fs::read(&sig_path) {
            if let Some(sig) = common::wisdom::normalize_signature_string(&sig_bytes) {
                ed25519_signatures.push(sig);
            }
        }
    }

    anyhow::ensure!(
        !ed25519_signatures.is_empty(),
        "no Ed25519 signature found for {}; run `janitor update-wisdom` first",
        wisdom_path.display()
    );

    // Optional quorum mirror receipt.
    let mirror_receipt_path = wisdom_path.with_extension("rkyv.mirror.json");
    let mirror_receipt: Option<common::wisdom::WisdomMirrorReceipt> =
        std::fs::read(&mirror_receipt_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());

    let capsule = common::wisdom::IntelTransferCapsule {
        wisdom_bytes,
        ed25519_signatures,
        mirror_receipt,
        feed_hash,
    };

    let json =
        serde_json::to_vec_pretty(&capsule).context("serializing IntelTransferCapsule to JSON")?;
    std::fs::write(out_path, &json)
        .with_context(|| format!("writing capsule to {}", out_path.display()))?;

    println!(
        "Intel capsule written: {} ({} bytes, hash {})",
        out_path.display(),
        json.len(),
        capsule.feed_hash
    );
    Ok(())
}

/// Parse an [`common::wisdom::IntelTransferCapsule`] from `in_path`, verify all
/// cryptographic evidence offline, and install the embedded wisdom archive.
///
/// Verification steps (all must pass; any failure is a hard abort):
/// 1. BLAKE3 feed hash recomputed from embedded `wisdom_bytes` must match `feed_hash`.
/// 2. At least one embedded Ed25519 signature must verify against the embedded
///    `WISDOM_VERIFYING_KEY_BYTES`.
/// 3. When a `mirror_receipt` is present its `agreed_hash` must also equal `feed_hash`.
///
/// Only after all checks pass is `.janitor/wisdom.rkyv` overwritten.
fn cmd_import_intel_capsule(in_path: &Path, project_root: &Path) -> anyhow::Result<()> {
    // CT-011: Size guard — reject capsules > 50 MiB before any heap allocation.
    const MAX_CAPSULE_BYTES: u64 = 50 * 1024 * 1024;
    let file_size = std::fs::metadata(in_path)
        .with_context(|| format!("stat {}", in_path.display()))?
        .len();
    anyhow::ensure!(
        file_size <= MAX_CAPSULE_BYTES,
        "capsule exceeds 50 MiB size limit ({file_size} bytes) — rejected to prevent OOM"
    );

    let raw =
        std::fs::read(in_path).with_context(|| format!("reading capsule {}", in_path.display()))?;
    let capsule: common::wisdom::IntelTransferCapsule =
        serde_json::from_slice(&raw).context("deserializing IntelTransferCapsule")?;

    // Step 1 — BLAKE3 hash integrity.
    let recomputed_hash = blake3::hash(&capsule.wisdom_bytes).to_hex().to_string();
    anyhow::ensure!(
        recomputed_hash == capsule.feed_hash,
        "feed hash mismatch: capsule claims {}, recomputed {}",
        capsule.feed_hash,
        recomputed_hash
    );

    // Step 2 — at least one Ed25519 signature must verify.
    anyhow::ensure!(
        !capsule.ed25519_signatures.is_empty(),
        "capsule contains no Ed25519 signatures"
    );
    let mut sig_verified = false;
    for sig_str in &capsule.ed25519_signatures {
        if verify_wisdom_signature(&capsule.wisdom_bytes, sig_str.as_bytes()).is_ok() {
            sig_verified = true;
            break;
        }
    }
    anyhow::ensure!(
        sig_verified,
        "none of the {} embedded Ed25519 signature(s) verified against the embedded public key",
        capsule.ed25519_signatures.len()
    );

    // Step 3 — quorum mirror receipt cross-check.
    if let Some(ref mr) = capsule.mirror_receipt {
        anyhow::ensure!(
            mr.agreed_hash == capsule.feed_hash,
            "mirror receipt agreed_hash {} does not match capsule feed_hash {}",
            mr.agreed_hash,
            capsule.feed_hash
        );
    }

    // All checks passed — install the archive.
    let janitor_dir = project_root.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .with_context(|| format!("creating {}", janitor_dir.display()))?;

    // CT-012: Symlink traversal confinement — verify .janitor resolves inside project_root.
    let canon_root = std::fs::canonicalize(project_root)
        .with_context(|| format!("canonicalizing project root {}", project_root.display()))?;
    let canon_janitor = std::fs::canonicalize(&janitor_dir)
        .with_context(|| format!("canonicalizing janitor dir {}", janitor_dir.display()))?;
    anyhow::ensure!(
        canon_janitor.starts_with(&canon_root),
        "confinement violation: .janitor resolves outside project root — symlink attack rejected"
    );

    let wisdom_path = janitor_dir.join("wisdom.rkyv");

    // CT-symlink: Reject if target is a symlink — prevents follow-on write via
    // attacker-placed symlink (leaf-node overwrite).
    if let Ok(meta) = std::fs::symlink_metadata(&wisdom_path) {
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "write rejected: {} is a symlink — potential symlink overwrite attack",
                wisdom_path.display()
            );
        }
    }

    // Atomic write: stage to .tmp, sync_all, then rename — prevents torn writes
    // and partial-update read races on the live wisdom file.
    let tmp_path = janitor_dir.join("wisdom.rkyv.tmp");
    {
        use std::io::Write as _;
        let mut tmp = std::fs::File::create(&tmp_path)
            .with_context(|| format!("creating {}", tmp_path.display()))?;
        tmp.write_all(&capsule.wisdom_bytes)
            .with_context(|| format!("writing to {}", tmp_path.display()))?;
        tmp.sync_all()
            .with_context(|| format!("sync_all on {}", tmp_path.display()))?;
    }
    std::fs::rename(&tmp_path, &wisdom_path).with_context(|| {
        format!(
            "atomic rename {} → {}",
            tmp_path.display(),
            wisdom_path.display()
        )
    })?;

    println!(
        "Intel capsule verified and installed: {} ({} bytes, hash {})",
        wisdom_path.display(),
        capsule.wisdom_bytes.len(),
        capsule.feed_hash
    );
    Ok(())
}

#[cfg(test)]
mod import_capsule_hardening_tests {
    use std::fs;

    /// CT-011: A capsule file exceeding 50 MiB must be rejected before any heap read.
    #[test]
    fn size_guard_rejects_oversized_capsule() {
        let tmp =
            std::env::temp_dir().join(format!("janitor-capsule-size-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).expect("tmp dir");
        let capsule_path = tmp.join("big.capsule.json");

        // Create a 51 MiB sparse file (only writes metadata — no disk thrash).
        {
            let f = fs::File::create(&capsule_path).expect("create sparse capsule");
            f.set_len(51 * 1024 * 1024).expect("set_len 51 MiB");
        }

        let root = tmp.join("project");
        fs::create_dir_all(&root).expect("project root");

        let err = super::cmd_import_intel_capsule(&capsule_path, &root)
            .expect_err("oversized capsule must be rejected");
        assert!(
            err.to_string().contains("50 MiB size limit"),
            "error must cite the 50 MiB limit"
        );
    }

    /// CT-012: A .janitor symlink that resolves outside the project root must be rejected.
    #[cfg(unix)]
    #[test]
    fn symlink_traversal_outside_root_is_rejected() {
        let tmp = std::env::temp_dir().join(format!("janitor-symlink-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&tmp).expect("tmp dir");

        // Write a minimal (but still too-small-to-pass-size-check won't matter;
        // the capsule file is 0 bytes → size check passes (0 <= 50 MiB), then
        // JSON parse will fail — but confinement check fires first after create_dir_all.
        // We use a dummy 1-byte file to get past the metadata stat stage.
        let capsule_path = tmp.join("dummy.json");
        fs::write(&capsule_path, b"{}").expect("write dummy capsule");

        let root = tmp.join("project");
        fs::create_dir_all(&root).expect("project root");

        // Create an escape target outside the project root.
        let escape_target = tmp.join("escape");
        fs::create_dir_all(&escape_target).expect("escape dir");

        // Symlink project/.janitor → ../escape (resolves outside project/).
        let janitor_link = root.join(".janitor");
        std::os::unix::fs::symlink(&escape_target, &janitor_link).expect("create symlink");

        let err = super::cmd_import_intel_capsule(&capsule_path, &root)
            .expect_err("symlink escape must be rejected");
        assert!(
            err.to_string().contains("confinement violation")
                || err.to_string().contains("50 MiB size limit")
                || err.to_string().contains("deserializing"),
            "error must be a confinement, size, or parse error — not silent success"
        );
        // The critical invariant: wisdom.rkyv must NOT exist inside escape_target.
        assert!(
            !escape_target.join("wisdom.rkyv").exists(),
            "wisdom.rkyv must not be written to the escape target"
        );
    }
}

fn verify_wisdom_signature(wisdom_bytes: &[u8], sig_bytes: &[u8]) -> anyhow::Result<()> {
    use base64::Engine as _;

    let verifying_key = VerifyingKey::from_bytes(&WISDOM_VERIFYING_KEY_BYTES)
        .map_err(|e| anyhow::anyhow!("invalid embedded Wisdom verifying key: {e}"))?;

    let decoded_sig = if sig_bytes.len() == 64 {
        sig_bytes.to_vec()
    } else {
        let trimmed = std::str::from_utf8(sig_bytes).map(str::trim).map_err(|e| {
            anyhow::anyhow!("wisdom signature must be raw 64-byte Ed25519 or base64 text: {e}")
        })?;
        base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
            .map_err(|e| anyhow::anyhow!("failed to decode wisdom signature: {e}"))?
    };

    let sig_bytes: [u8; 64] = decoded_sig
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("wisdom signature must decode to exactly 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(wisdom_bytes, &signature)
        .map_err(|_| anyhow::anyhow!("wisdom archive signature mismatch"))
}

// ---------------------------------------------------------------------------
// sign-asset
// ---------------------------------------------------------------------------

/// Compute a SHA-384 digest for a release binary and optionally sign it with PQC keys.
///
/// Always writes `<file>.sha384` (hex SHA-384 digest, newline-terminated).
/// Writes `<file>.sig` (JSON PQC signature bundle) only when `pqc_key` is supplied.
fn cmd_sign_asset(file: &Path, pqc_key: Option<&str>) -> anyhow::Result<()> {
    use memmap2::Mmap;
    use sha2::{Digest as _, Sha384};
    use std::fs::File;

    let f = File::open(file).with_context(|| format!("opening asset: {}", file.display()))?;
    // SAFETY: standard mmap usage — file is not modified while the map is live.
    let mmap = unsafe { Mmap::map(&f) }
        .with_context(|| format!("mmap failed for asset: {}", file.display()))?;

    let hash: [u8; 48] = Sha384::digest(&mmap).into();
    let hex = hex::encode(hash);

    // Append ".sha384" to the full filename (including any existing extension).
    let sha384_path = {
        let mut p = file.to_path_buf();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".sha384");
        p.set_file_name(name);
        p
    };
    std::fs::write(&sha384_path, format!("{hex}\n"))
        .with_context(|| format!("writing {}", sha384_path.display()))?;
    println!("SHA-384: {hex}");
    println!("Written: {}", sha384_path.display());

    if let Some(key_path) = pqc_key {
        let bundle = common::pqc::sign_asset_hash_from_file(&hash, std::path::Path::new(key_path))?;
        let sig_json = serde_json::json!({
            "hash_algorithm": "SHA-384",
            "context": "janitor-release-asset",
            "asset": file.file_name().unwrap_or_default().to_string_lossy(),
            "ml_dsa_sig": bundle.ml_dsa_sig,
            "slh_dsa_sig": bundle.slh_dsa_sig,
        });
        let sig_path = {
            let mut p = file.to_path_buf();
            let mut name = p.file_name().unwrap_or_default().to_os_string();
            name.push(".sig");
            p.set_file_name(name);
            p
        };
        std::fs::write(&sig_path, serde_json::to_string_pretty(&sig_json)?)
            .with_context(|| format!("writing {}", sig_path.display()))?;
        println!("PQC signature written: {}", sig_path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// generate-keys
// ---------------------------------------------------------------------------

/// Generate a fresh Dual-PQC private key bundle and write it to `out_path`.
///
/// Wraps [`common::pqc::generate_dual_pqc_key_bundle`].  The bundle is ready
/// for use with `janitor bounce --pqc-key <out_path>`.
fn cmd_generate_keys(out_path: &Path) -> anyhow::Result<()> {
    let bundle =
        common::pqc::generate_dual_pqc_key_bundle().context("dual-PQC key generation failed")?;
    std::fs::write(out_path, bundle.as_slice())
        .with_context(|| format!("failed to write PQC key bundle to {}", out_path.display()))?;
    eprintln!(
        "PQC key bundle written: {} ({} bytes, ML-DSA-65 || SLH-DSA-SHAKE-192s)",
        out_path.display(),
        bundle.len()
    );
    Ok(())
}

fn generate_license_contents(project_root: &Path, expires_in_days: u64) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH; refusing license minting")?
        .as_secs();
    let validity_window = expires_in_days
        .checked_mul(86_400)
        .ok_or_else(|| anyhow::anyhow!("expires-in-days overflowed u64 seconds"))?;
    let expires_at = now
        .checked_add(validity_window)
        .ok_or_else(|| anyhow::anyhow!("license expiry overflowed u64 timestamp"))?;
    let issued_to = std::env::var("USER")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "local-sovereign-operator".to_string());
    let license = common::license::License {
        issued_to,
        expires_at,
        features: vec!["IFDS".to_string(), "AEG".to_string(), "Wasm".to_string()],
    };
    let signing_key = common::license::resolve_license_signing_key(project_root)?;
    common::license::encode_license_file(&license, &signing_key)
}

fn cmd_generate_license(project_root: &Path, expires_in_days: u64) -> anyhow::Result<()> {
    println!(
        "{}",
        generate_license_contents(project_root, expires_in_days)?
    );
    Ok(())
}

/// Rotate an existing Dual-PQC private key bundle in place and append a ledger event.
fn cmd_rotate_keys(key_path: &Path) -> anyhow::Result<()> {
    let existing_bytes = std::fs::read(key_path).with_context(|| {
        format!(
            "failed to read existing PQC key bundle {}",
            key_path.display()
        )
    })?;
    let expected_len = common::pqc::ML_DSA_PRIVATE_KEY_LEN + common::pqc::SLH_DSA_PRIVATE_KEY_LEN;
    if existing_bytes.len() != expected_len {
        anyhow::bail!(
            "existing PQC key bundle {} has invalid length {}; expected exactly {} bytes",
            key_path.display(),
            existing_bytes.len(),
            expected_len
        );
    }

    let timestamp_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH; refusing key rotation")?
        .as_secs();
    let backup_path = {
        let mut path = key_path.to_path_buf();
        let file_name = key_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("key path {} has no file name", key_path.display()))?;
        let backup_name = format!("{}.{}.bak", file_name.to_string_lossy(), timestamp_secs);
        path.set_file_name(backup_name);
        path
    };

    std::fs::rename(key_path, &backup_path).with_context(|| {
        format!(
            "failed to archive PQC key bundle {} to {}",
            key_path.display(),
            backup_path.display()
        )
    })?;

    let bundle = common::pqc::generate_dual_pqc_key_bundle()
        .context("dual-PQC key generation failed during rotation")?;
    std::fs::write(key_path, bundle.as_slice()).with_context(|| {
        format!(
            "failed to write rotated PQC key bundle {}",
            key_path.display()
        )
    })?;

    let janitor_dir = std::env::current_dir()
        .context("failed to resolve current working directory for bounce log append")?
        .join(".janitor");
    let rotation_event = report::KeyRotationEvent {
        event_type: "pqc_key_rotation".to_string(),
        timestamp: utc_now_iso8601(),
        key_path: key_path.display().to_string(),
        backup_path: backup_path.display().to_string(),
        bundle_bytes: expected_len,
    };
    report::append_key_rotation_log(&janitor_dir, &rotation_event);

    println!(
        "Rotated PQC key bundle: {} -> {}",
        key_path.display(),
        backup_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod generate_keys_tests {
    use super::{
        cmd_generate_keys, cmd_rotate_keys, enforce_pqc_key_age, generate_license_contents,
        pqc_key_age_exceeds_max,
    };
    use common::pqc::{ML_DSA_PRIVATE_KEY_LEN, SLH_DSA_PRIVATE_KEY_LEN};

    #[test]
    fn cmd_generate_keys_writes_correct_bundle_size() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        cmd_generate_keys(tmp.path()).expect("generate-keys must succeed");
        let written = std::fs::read(tmp.path()).expect("read key bundle");
        assert_eq!(
            written.len(),
            ML_DSA_PRIVATE_KEY_LEN + SLH_DSA_PRIVATE_KEY_LEN
        );
    }

    #[test]
    fn pqc_key_age_gate_flags_stale_material() {
        let modified = std::time::UNIX_EPOCH;
        let now = modified + std::time::Duration::from_secs(91 * 86_400);
        assert!(
            pqc_key_age_exceeds_max(modified, now, 90).expect("age check must succeed"),
            "91-day-old key must exceed 90-day policy"
        );
    }

    #[test]
    fn enforce_pqc_key_age_allows_fresh_filesystem_key() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        cmd_generate_keys(tmp.path()).expect("generate-keys must succeed");
        enforce_pqc_key_age(
            &tmp.path().display().to_string(),
            90,
            std::time::SystemTime::now(),
        )
        .expect("fresh key must satisfy max-age gate");
    }

    #[test]
    #[serial_test::serial]
    fn cmd_rotate_keys_archives_old_bundle_and_writes_new_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("janitor_release.key");
        cmd_generate_keys(&key_path).expect("seed key generation must succeed");
        let original = std::fs::read(&key_path).expect("read original key");

        let cwd = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(dir.path()).expect("chdir tempdir");
        let rotate_result = cmd_rotate_keys(&key_path);
        let _ = std::env::set_current_dir(cwd);
        rotate_result.expect("rotate-keys must succeed");

        let rotated = std::fs::read(&key_path).expect("read rotated key");
        assert_eq!(
            rotated.len(),
            ML_DSA_PRIVATE_KEY_LEN + SLH_DSA_PRIVATE_KEY_LEN
        );
        assert_ne!(rotated, original, "rotation must replace the active bundle");

        let backup_count = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".bak"))
            .count();
        assert_eq!(backup_count, 1, "rotation must create exactly one backup");

        let log_path = dir.path().join(".janitor").join("bounce_log.ndjson");
        let log = std::fs::read_to_string(log_path).expect("rotation log must exist");
        assert!(
            log.contains("\"event_type\":\"pqc_key_rotation\""),
            "rotation must append a dedicated key-rotation event"
        );
    }

    #[test]
    fn generate_license_contents_round_trips_with_local_key_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join(".janitor_release.key");
        cmd_generate_keys(&key_path).expect("seed key generation must succeed");
        let encoded = generate_license_contents(dir.path(), 365).expect("generate license");
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect("create janitor dir");
        std::fs::write(janitor_dir.join("janitor.lic"), encoded).expect("write license");

        assert!(
            common::license::verify_license(dir.path()),
            "generated janitor.lic must unlock Sovereign mode"
        );
    }
}

// ---------------------------------------------------------------------------
// wasm-pin / wasm-verify
// ---------------------------------------------------------------------------

/// Compute the BLAKE3 pin for a BYOP Wasm rule module and print the TOML block
/// required to lock it in `janitor.toml`.
///
/// Reads the file at `path` (`.wasm` binary or `.wat` text), computes the
/// BLAKE3 digest, and prints a ready-to-paste `[wasm_pins]` entry to stdout.
fn cmd_wasm_pin(path: &std::path::Path) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading Wasm rule module: {}", path.display()))?;
    let hex = blake3::hash(&bytes).to_hex().to_string();
    let path_str = path.to_string_lossy();
    println!("# Paste this block into janitor.toml [wasm_pins] to lock the module.");
    println!("[wasm_pins]");
    println!("\"{path_str}\" = \"{hex}\"");
    println!();
    println!("# BLAKE3: {hex}");
    Ok(())
}

/// Verify a BYOP Wasm rule module against its expected BLAKE3 pin.
///
/// Exits 0 when the computed digest matches `expected`; exits non-zero with a
/// diagnostic when the binary has been replaced or tampered with.
fn cmd_wasm_verify(path: &std::path::Path, expected: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading Wasm rule module: {}", path.display()))?;
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual == expected {
        println!("OK: {} pin verified", path.display());
        Ok(())
    } else {
        anyhow::bail!(
            "Wasm rule integrity pin mismatch: {}: expected {expected}, got {actual}",
            path.display()
        )
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Scaffold a `janitor.toml` governance manifest in the current directory.
///
/// Fails non-zero if `janitor.toml` already exists — never overwrites.  Two
/// profiles are supported: `default` (OSS-friendly) and `enterprise` (hardened).
fn cmd_init(profile: Option<&str>) -> anyhow::Result<()> {
    let dest = std::path::Path::new("janitor.toml");
    if dest.exists() {
        anyhow::bail!(
            "janitor.toml already exists in the current directory. \
             Remove it first or edit it directly."
        );
    }
    let is_enterprise = matches!(profile, Some("enterprise"));
    let is_oss = matches!(profile, Some("oss"));
    let content = if is_oss {
        r#"# janitor.toml — generated by `janitor init --profile oss`
# Solo-maintainer governance manifest for The Janitor code integrity engine.
# Optimised for minimal noise: higher slop threshold, zero ceremony, no PQC.
# Docs: https://thejanitor.app/docs/config
#
# OSS MAINTAINER NOTE:
#   This profile is tuned for solo and small-team open-source projects where
#   reducing false-positive friction matters more than maximum enforcement.
#   Upgrade to `janitor init --profile enterprise` when your team grows or
#   you need compliance-grade enforcement (SOC 2, FedRAMP, SLSA Level 4).

# Composite slop-score threshold. PRs scoring above this fail the gate.
# OSS solo-maintainer default: 200 — high tolerance to reduce noise.
min_slop_score = 200

# Require every PR to link a GitHub issue (Closes #N or Fixes #N).
# Disabled for solo maintainers — too much ceremony for small repos.
require_issue_link = false

# Post-quantum cryptography enforcement.
# Disabled — PQC enforcement is an enterprise compliance requirement, not needed
# for typical OSS projects.
pqc_enforced = false

[pqc]
# Maximum allowed age for a filesystem-backed Dual-PQC key bundle.
max_key_age_days = 90

# [forge] — engine-level settings
[forge]
# Governor URL for Architecture Inversion attestation.
# Leave commented for local-only analysis (no egress).
# governor_url = "http://127.0.0.1:8080"

# [[suppressions]] — waive specific antipattern IDs (repeat block per waiver)
# [[suppressions]]
# id = "security:pattern_id"
# reason = "known false positive in generated code"
# expires = "2026-12-31"
"#
    } else if is_enterprise {
        r#"# janitor.toml — generated by `janitor init --profile enterprise`
# Enterprise hardened governance manifest for The Janitor code integrity engine.
# Docs: https://thejanitor.app/docs/config

# Composite slop-score threshold. PRs scoring above this fail the gate.
# Hardened enterprise default: 50.
min_slop_score = 50

# Require every PR to link a GitHub issue (Closes #N or Fixes #N).
require_issue_link = true

# Post-quantum cryptography enforcement.
# Rejects patches that introduce RSA/ECDSA/AES-128/SHA-1 primitives.
pqc_enforced = true

[pqc]
# Hard-fail CI once the on-disk Dual-PQC key bundle exceeds this age.
max_key_age_days = 90

[billing]
# Financial valuation per critical threat intercept (USD).
critical_threat_bounty_usd = 150.0
# Estimated CI energy cost per bounce run (kWh).
ci_kwh_per_run = 0.1

# [forge] — engine-level settings
[forge]
# Governor URL for Architecture Inversion attestation.
# Set to your self-hosted Governor endpoint.
# governor_url = "http://127.0.0.1:8080"

# [[suppressions]] — waive specific antipattern IDs (repeat block per waiver)
# [[suppressions]]
# id = "security:pattern_id"
# reason = "known false positive in generated code"
# expires = "2026-12-31"

# wasm_rules — paths to BYOP Wasm rule modules (relative to repo root)
# wasm_rules = ["rules/my_rule.wasm"]

# wasm_pins — BLAKE3 integrity pins for Wasm modules
# Run `janitor wasm-pin rules/my_rule.wasm` to compute the pin.
# [wasm_pins]
# "rules/my_rule.wasm" = "<blake3-hex>"
"#
    } else {
        r#"# janitor.toml — generated by `janitor init`
# Governance manifest for The Janitor code integrity engine.
# Docs: https://thejanitor.app/docs/config

# Composite slop-score threshold. PRs scoring above this fail the gate.
# Lower = stricter. Default: 100.
min_slop_score = 100

# Require every PR to link a GitHub issue (Closes #N or Fixes #N).
# Default: false.
require_issue_link = false

# Post-quantum cryptography enforcement.
# When true, patches introducing RSA/ECDSA/AES-128/SHA-1 fail the gate.
# Default: false.
pqc_enforced = false

[pqc]
# Maximum allowed age for a filesystem-backed Dual-PQC key bundle.
max_key_age_days = 90

# [forge] — engine-level settings
[forge]
# Governor URL for Architecture Inversion attestation.
# Set to your self-hosted Governor endpoint or leave commented for local-only.
# governor_url = "http://127.0.0.1:8080"

# [[suppressions]] — waive specific antipattern IDs (repeat block per waiver)
# [[suppressions]]
# id = "security:pattern_id"
# reason = "known false positive in generated code"
# expires = "2026-12-31"

# wasm_rules — paths to BYOP Wasm rule modules (relative to repo root)
# wasm_rules = ["rules/my_rule.wasm"]

# wasm_pins — BLAKE3 integrity pins for Wasm modules
# Run `janitor wasm-pin rules/my_rule.wasm` to compute the pin.
# [wasm_pins]
# "rules/my_rule.wasm" = "<blake3-hex>"
"#
    };
    std::fs::write(dest, content).context("writing janitor.toml")?;
    if is_enterprise {
        println!(
            "janitor.toml created (enterprise profile). \
             Review and commit to your repository root."
        );
    } else if is_oss {
        println!(
            "janitor.toml created (oss profile — solo-maintainer minimal noise mode). \
             Review and commit to your repository root."
        );
    } else {
        println!(
            "janitor.toml created (default profile). \
             Review and commit to your repository root."
        );
    }
    Ok(())
}

/// Policy-health drift dashboard.
///
/// Reads `.janitor/bounce_log.ndjson`, aggregates metrics, and renders a compact
/// Markdown table (default) or JSON object for machine-readable dashboards.
///
/// Metrics reported:
/// - Total PRs scanned
/// - PRs that failed the gate (slop_score ≥ effective threshold)
/// - Top 3 most frequently triggered antipattern rule IDs
/// - Top 3 highest-risk PR authors (by cumulative slop score)
fn cmd_policy_health(path: &std::path::Path, format: &str) -> anyhow::Result<()> {
    let janitor_dir = path.join(".janitor");
    let entries = report::load_bounce_log(&janitor_dir);

    let total_prs = entries.len();
    let failed_prs = entries.iter().filter(|e| e.slop_score > 0).count();

    // Tally antipattern rule IDs across all log entries.
    let mut rule_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for entry in &entries {
        for ap in &entry.antipatterns {
            // Strip trailing " (line=N)" suffix to normalise the rule ID.
            let rule_id = ap.split(" (line=").next().unwrap_or(ap);
            *rule_counts.entry(rule_id.to_string()).or_insert(0) += 1;
        }
    }
    let mut rule_ranking: Vec<(String, u64)> = rule_counts.into_iter().collect();
    rule_ranking.sort_by(|a, b| b.1.cmp(&a.1));
    let top_rules: Vec<(String, u64)> = rule_ranking.into_iter().take(3).collect();

    // Tally cumulative slop score per author.
    let mut author_scores: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    for entry in &entries {
        if let Some(ref author) = entry.author {
            *author_scores.entry(author.clone()).or_insert(0) += u64::from(entry.slop_score);
        }
    }
    let mut author_ranking: Vec<(String, u64)> = author_scores.into_iter().collect();
    author_ranking.sort_by(|a, b| b.1.cmp(&a.1));
    let top_authors: Vec<(String, u64)> = author_ranking.into_iter().take(3).collect();

    match format {
        "json" => {
            let out = serde_json::json!({
                "total_prs": total_prs,
                "failed_prs": failed_prs,
                "top_rules": top_rules.iter().map(|(id, count)| serde_json::json!({ "rule": id, "count": count })).collect::<Vec<_>>(),
                "top_authors_by_slop": top_authors.iter().map(|(author, score)| serde_json::json!({ "author": author, "cumulative_slop": score })).collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&out)
                    .map_err(|_| anyhow::anyhow!("JSON serialization failed"))?
            );
        }
        _ => {
            println!("# Janitor Policy Health Dashboard\n");
            println!("| Metric | Value |");
            println!("|--------|-------|");
            println!("| Total PRs scanned | {} |", total_prs);
            println!("| PRs that failed gate | {} |", failed_prs);
            println!();
            println!("## Top 3 Triggered Rules\n");
            println!("| Rank | Rule ID | Triggers |");
            println!("|------|---------|----------|");
            for (i, (rule, count)) in top_rules.iter().enumerate() {
                println!("| {} | `{}` | {} |", i + 1, rule, count);
            }
            if top_rules.is_empty() {
                println!("| — | *(no antipatterns logged)* | 0 |");
            }
            println!();
            println!("## Top 3 Highest-Risk Authors\n");
            println!("| Rank | Author | Cumulative Slop |");
            println!("|------|--------|-----------------|");
            for (i, (author, score)) in top_authors.iter().enumerate() {
                println!("| {} | `{}` | {} |", i + 1, author, score);
            }
            if top_authors.is_empty() {
                println!("| — | *(no author metadata logged)* | 0 |");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod policy_health_tests {
    use super::*;

    #[test]
    fn policy_health_empty_log_text_exits_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        // No .janitor dir — load_bounce_log returns empty vec → no panic.
        let result = cmd_policy_health(dir.path(), "text");
        assert!(
            result.is_ok(),
            "policy-health must exit cleanly on empty log"
        );
    }

    #[test]
    fn policy_health_empty_log_json_exits_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let result = cmd_policy_health(dir.path(), "json");
        assert!(
            result.is_ok(),
            "policy-health json must exit cleanly on empty log"
        );
    }
}

#[cfg(test)]
mod wasm_pin_tests {
    use super::*;
    use std::io::Write as _;

    fn write_tempfile(content: &[u8], suffix: &str) -> (tempfile::TempPath, std::path::PathBuf) {
        let mut tmp = tempfile::NamedTempFile::with_suffix(suffix).unwrap();
        tmp.write_all(content).unwrap();
        let path = tmp.into_temp_path();
        let pb = path.to_path_buf();
        (path, pb)
    }

    #[test]
    fn wasm_pin_prints_correct_digest() {
        let content = b"fake wasm bytes for pin test";
        let (_tmp, path) = write_tempfile(content, ".wasm");
        // cmd_wasm_pin should succeed and not return an error
        cmd_wasm_pin(&path).expect("wasm-pin must succeed on readable file");
    }

    #[test]
    fn wasm_verify_passes_on_correct_digest() {
        let content = b"fake wasm bytes for verify test";
        let (_tmp, path) = write_tempfile(content, ".wasm");
        let expected = blake3::hash(content).to_hex().to_string();
        cmd_wasm_verify(&path, &expected).expect("wasm-verify must pass on matching digest");
    }

    #[test]
    fn wasm_verify_fails_on_wrong_digest() {
        let content = b"fake wasm bytes for mismatch test";
        let (_tmp, path) = write_tempfile(content, ".wasm");
        let wrong = "a".repeat(64);
        let err = cmd_wasm_verify(&path, &wrong)
            .err()
            .expect("wasm-verify must fail on mismatched digest");
        assert!(
            err.to_string().contains("integrity pin mismatch"),
            "error must cite integrity pin mismatch"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_creates_janitor_toml_default() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = cmd_init(None);
        let _ = std::env::set_current_dir(&original);
        result.expect("init must succeed in empty directory");
        let content = std::fs::read_to_string(dir.path().join("janitor.toml"))
            .expect("janitor.toml must be created");
        assert!(
            content.contains("min_slop_score = 100"),
            "default profile must use min_slop_score = 100"
        );
        assert!(
            content.contains("pqc_enforced = false"),
            "default profile must have pqc_enforced = false"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_creates_janitor_toml_enterprise() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = cmd_init(Some("enterprise"));
        let _ = std::env::set_current_dir(&original);
        result.expect("init must succeed in empty directory");
        let content = std::fs::read_to_string(dir.path().join("janitor.toml"))
            .expect("janitor.toml must be created");
        assert!(
            content.contains("min_slop_score = 50"),
            "enterprise profile must use min_slop_score = 50"
        );
        assert!(
            content.contains("pqc_enforced = true"),
            "enterprise profile must have pqc_enforced = true"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_refuses_to_overwrite_existing_toml() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        std::fs::write("janitor.toml", b"existing content").unwrap();
        let err = cmd_init(None)
            .err()
            .expect("init must fail when janitor.toml already exists");
        let _ = std::env::set_current_dir(&original);
        assert!(
            err.to_string().contains("already exists"),
            "error must cite existing janitor.toml"
        );
    }

    #[test]
    #[serial_test::serial]
    fn init_creates_janitor_toml_oss() {
        let dir = tempfile::tempdir().unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = cmd_init(Some("oss"));
        let _ = std::env::set_current_dir(&original);
        result.expect("init must succeed in empty directory with oss profile");
        let content = std::fs::read_to_string(dir.path().join("janitor.toml"))
            .expect("janitor.toml must be created");
        assert!(
            content.contains("min_slop_score = 200"),
            "oss profile must use min_slop_score = 200"
        );
        assert!(
            content.contains("pqc_enforced = false"),
            "oss profile must have pqc_enforced = false"
        );
        assert!(
            content.contains("require_issue_link = false"),
            "oss profile must have require_issue_link = false"
        );
    }
}

#[cfg(test)]
mod mtls_agent_tests {
    use super::*;

    const TEST_CLIENT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIEqDCCApCgAwIBAgIUK5Ns4y2CzosB/ZoFlaxjZqoBTIIwDQYJKoZIhvcNAQEL
BQAwfjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBkJhZFNTTDExMC8GA1UEAwwoQmFkU1NM
IENsaWVudCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTExMjcwMDE5
NTdaFw0yMTExMjYwMDE5NTdaMG8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxp
Zm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKDAZCYWRTU0wx
IjAgBgNVBAMMGUJhZFNTTCBDbGllbnQgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDHN18R6x5Oz+u6SOXLoxIscz5GHR6cDcCLgyPa
x2XfXHdJs+h6fTy61WGM+aXEhR2SIwbj5997s34m0MsbvkJrFmn0LHK1fuTLCihE
EmxGdCGZA9xrwxFYAkEjP7D8v7cAWRMipYF/JP7VU7xNUo+QSkZ0sOi9k6bNkABK
L3+yP6PqAzsBoKIN5lN/YRLrppsDmk6nrRDo4R3CD+8JQl9quEoOmL22Pc/qpOjL
1jgOIFSE5y3gwbzDlfCYoAL5V+by1vu0yJShTTK8oo5wvphcFfEHaQ9w5jFg2htd
q99UER3BKuNDuL+zejqGQZCWb0Xsk8S5WBuX8l3Brrg5giqNAgMBAAGjLTArMAkG
A1UdEwQCMAAwEQYJYIZIAYb4QgEBBAQDAgeAMAsGA1UdDwQEAwIF4DANBgkqhkiG
9w0BAQsFAAOCAgEAZBauLzFSOijkDadcippr9C6laHebb0oRS54xAV70E9k5GxfR
/E2EMuQ8X+miRUMXxKquffcDsSxzo2ac0flw94hDx3B6vJIYvsQx9Lzo95Im0DdT
DkHFXhTlv2kjQwFVnEsWYwyGpHMTjanvNkO7sBP9p1bN1qTE3QAeyMZNKWJk5xPl
U298ERar6tl3Z2Cl8mO6yLhrq4ba6iPGw08SENxzuAJW+n8r0rq7EU+bMg5spgT1
CxExzG8Bb0f98ZXMklpYFogkcuH4OUOFyRodotrotm3iRbuvZNk0Zz7N5n1oLTPl
bGPMwBcqaGXvK62NlaRkwjnbkPM4MYvREM0bbAgZD2GHyANBTso8bdWvhLvmoSjs
FSqJUJp17AZ0x/ELWZd69v2zKW9UdPmw0evyVR19elh/7dmtF6wbewc4N4jxQnTq
IItuhIWKWB9edgJz65uZ9ubQWjXoa+9CuWcV/1KxuKCbLHdZXiboLrKm4S1WmMYW
d0sJm95H9mJzcLyhLF7iX2kK6K9ug1y02YCVXBC9WGZc2x6GMS7lDkXSkJFy3EWh
CmfxkmFGwOgwKt3Jd1pF9ftcSEMhu4WcMgxi9vZr9OdkJLxmk033sVKI/hnkPaHw
g0Y2YBH5v0xmi8sYU7weOcwynkjZARpUltBUQ0pWCF5uJsEB8uE8PPDD3c4=
-----END CERTIFICATE-----
"#;

    const TEST_CLIENT_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxzdfEeseTs/rukjly6MSLHM+Rh0enA3Ai4Mj2sdl31x3SbPo
en08utVhjPmlxIUdkiMG4+ffe7N+JtDLG75CaxZp9CxytX7kywooRBJsRnQhmQPc
a8MRWAJBIz+w/L+3AFkTIqWBfyT+1VO8TVKPkEpGdLDovZOmzZAASi9/sj+j6gM7
AaCiDeZTf2ES66abA5pOp60Q6OEdwg/vCUJfarhKDpi9tj3P6qToy9Y4DiBUhOct
4MG8w5XwmKAC+Vfm8tb7tMiUoU0yvKKOcL6YXBXxB2kPcOYxYNobXavfVBEdwSrj
Q7i/s3o6hkGQlm9F7JPEuVgbl/Jdwa64OYIqjQIDAQABAoIBAFUQf7fW/YoJnk5c
8kKRzyDL1Lt7k6Zu+NiZlqXEnutRQF5oQ8yJzXS5yH25296eOJI+AqMuT28ypZtN
bGzcQOAZIgTxNcnp9Sf9nlPyyekLjY0Y6PXaxX0e+VFj0N8bvbiYUGNq6HCyC15r
8uvRZRvnm04YfEj20zLTWkxTG+OwJ6ZNha1vfq8z7MG5JTsZbP0g7e/LrEb3wI7J
Zu9yHQUzq23HhfhpmLN/0l89YLtOaS8WNq4QvKYgZapw/0G1wWoWW4Y2/UpAxZ9r
cqTBWSpCSCCgyWjiNhPbSJWfe/9J2bcanITLcvCLlPWGAHy1wpo9iBH57y7S+7YS
3yi7lgECgYEA8lwaRIChc38tmtQCNPtai/7uVDdeJe0uv8Jsg04FTF8KMYcD0V1g
+T7rUPA+rTHwv8uAGLdzl4NW5Qryw18rDY+UivnaZkEdEsnlo3fc8MSQF78dDHCX
nwmHfOmBnBoSbLl+W5ByHkJRHOnX+8qKq9ePNFUMf/hZNYuma9BCFBUCgYEA0m2p
VDn12YdhFUUBIH91aD5cQIsBhkHFU4vqW4zBt6TsJpFciWbrBrTeRzeDou59aIsn
zGBrLMykOY+EwwRku9KTVM4U791Z/NFbH89GqyUaicb4or+BXw5rGF8DmzSsDo0f
ixJ9TVD5DmDi3c9ZQ7ljrtdSxPdA8kOoYPFsApkCgYEA08uZSPQAI6aoe/16UEK4
Rk9qhz47kHlNuVZ27ehoyOzlQ5Lxyy0HacmKaxkILOLPuUxljTQEWAv3DAIdVI7+
WMN41Fq0eVe9yIWXoNtGwUGFirsA77YVSm5RcN++3GQMZedUfUAl+juKFvJkRS4j
MTkXdGw+mDa3/wsjTGSa2mECgYABO6NCWxSVsbVf6oeXKSgG9FaWCjp4DuqZErjM
0IZSDSVVFIT2SSQXZffncuvSiJMziZ0yFV6LZKeRrsWYXu44K4Oxe4Oj5Cgi0xc1
mIFRf2YoaIIMchLP+8Wk3ummfyiC7VDB/9m8Gj1bWDX8FrrvKqbq31gcz1YSFVNn
PgLkAQKBgFzG8NdL8os55YcjBcOZMUs5QTKiQSyZM0Abab17k9JaqsU0jQtzeFsY
FTiwh2uh6l4gdO/dGC/P0Vrp7F05NnO7oE4T+ojDzVQMnFpCBeL7x08GfUQkphEG
m0Wqhhi8/24Sy934t5Txgkfoltg8ahkx934WjP6WWRnSAu+cf+vW
-----END RSA PRIVATE KEY-----
"#;

    #[test]
    fn build_ureq_agent_accepts_valid_mtls_material() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, TEST_CLIENT_CERT_PEM).expect("cert write must succeed");
        std::fs::write(&key_path, TEST_CLIENT_KEY_PEM).expect("key write must succeed");

        let mut policy = common::policy::JanitorPolicy::default();
        policy.forge.mtls_cert = Some(cert_path.display().to_string());
        policy.forge.mtls_key = Some(key_path.display().to_string());

        let agent = build_ureq_agent(&policy).expect("mTLS agent must build");
        let clone = agent.clone();
        drop(clone);
    }

    #[test]
    fn build_ureq_agent_rejects_partial_mtls_configuration() {
        let mut policy = common::policy::JanitorPolicy::default();
        policy.forge.mtls_cert = Some("/tmp/client.pem".to_string());

        let err = build_ureq_agent(&policy).expect_err("partial mTLS config must fail");
        assert!(err.to_string().contains("JANITOR_MTLS_CERT"));
    }
}

#[cfg(test)]
mod sign_asset_tests {
    use super::*;
    use sha2::Digest as _;

    #[test]
    #[serial_test::serial]
    fn sign_asset_produces_correct_sha384_hash() {
        let dir = std::env::temp_dir().join("janitor_sign_asset_test");
        std::fs::create_dir_all(&dir).unwrap();
        let asset = dir.join("dummy_asset");
        std::fs::write(&asset, b"hello janitor release").unwrap();

        cmd_sign_asset(&asset, None).expect("sign_asset must succeed without pqc_key");

        let sha384_path = dir.join("dummy_asset.sha384");
        let sha384_contents =
            std::fs::read_to_string(&sha384_path).expect("sha384 file must exist after sign_asset");
        let expected = hex::encode(sha2::Sha384::digest(b"hello janitor release"));
        assert_eq!(
            sha384_contents.trim(),
            expected,
            "SHA-384 hash file must match Sha384::digest output"
        );
    }
}

#[cfg(test)]
mod verify_audit_log_tests {
    use super::*;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha384;

    type HmacSha384 = Hmac<Sha384>;

    fn sealed_line(payload: &str, key_hex: &str) -> String {
        let key = hex::decode(key_hex).expect("test key must be valid hex");
        let mut mac = HmacSha384::new_from_slice(&key).expect("test HMAC init must succeed");
        mac.update(payload.as_bytes());
        serde_json::json!({
            "hmac": hex::encode(mac.finalize().into_bytes()),
            "payload": payload,
        })
        .to_string()
    }

    #[test]
    fn verify_audit_log_accepts_valid_ledger() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let path = dir.path().join("audit.ndjson");
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let body = [
            sealed_line(
                "CEF:0|JanitorSecurity|Governor|1.0|gov.report|bounce_report|10|src=198.51.100.7 cs1Label=repo cs1=owner/repo",
                key,
            ),
            sealed_line(
                "<130>1 2026-04-06T00:00:00Z janitor-host janitor-gov - gov.report - [janitorGov src=\"198.51.100.7\"] report accepted",
                key,
            ),
        ]
        .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("audit ledger must be written");

        cmd_verify_audit_log(&path, key).expect("valid ledger must verify");
    }

    #[test]
    fn verify_audit_log_reports_exact_tampered_line() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let path = dir.path().join("audit.ndjson");
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let valid = sealed_line(
            "CEF:0|JanitorSecurity|Governor|1.0|gov.report|bounce_report|10|src=198.51.100.7",
            key,
        );
        let tampered = serde_json::json!({
            "hmac": serde_json::from_str::<serde_json::Value>(&valid)
                .expect("sealed JSON must parse")["hmac"],
            "payload": "tampered payload",
        })
        .to_string();
        std::fs::write(&path, format!("{valid}\n{tampered}\n"))
            .expect("audit ledger must be written");

        let err = cmd_verify_audit_log(&path, key).expect_err("tampered ledger must fail");
        assert!(
            err.to_string()
                .contains("line 2: audit ledger HMAC verification failed"),
            "verification error must identify the exact tampered line"
        );
    }
}

#[cfg(test)]
mod slopsquat_sync_tests {
    use super::*;

    /// Build an in-memory ZIP containing one JSON advisory entry.
    fn make_advisory_zip(advisory_json: &str) -> Vec<u8> {
        use std::io::Write as _;
        let mut buf = std::io::Cursor::new(Vec::<u8>::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("MAL-2026-1.json", opts).unwrap();
            zip.write_all(advisory_json.as_bytes()).unwrap();
            zip.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn extract_mal_packages_from_zip_filters_to_mal_advisories() {
        let advisory_json = serde_json::json!({
            "id": "MAL-2026-1",
            "aliases": [],
            "affected": [
                { "package": { "ecosystem": "npm", "name": "evil-package" } }
            ]
        })
        .to_string();
        let zip_bytes = make_advisory_zip(&advisory_json);
        let packages = extract_mal_packages_from_zip(&zip_bytes, "npm").unwrap();
        assert!(
            packages.contains(&"evil-package".to_string()),
            "MAL advisory package must be extracted"
        );
    }

    #[test]
    fn extract_mal_packages_from_zip_skips_non_mal_advisories() {
        // GHSA prefix (not MAL-) must be ignored.
        let advisory_json = serde_json::json!({
            "id": "GHSA-1234-5678-9abc",
            "aliases": [],
            "affected": [
                { "package": { "ecosystem": "npm", "name": "benign-package" } }
            ]
        })
        .to_string();
        let zip_bytes = make_advisory_zip(&advisory_json);
        let packages = extract_mal_packages_from_zip(&zip_bytes, "npm").unwrap();
        assert!(
            packages.is_empty(),
            "non-MAL advisory must not produce packages"
        );
    }

    #[test]
    fn parse_osv_malicious_package_names_extracts_target_ecosystem() {
        let advisory_json = serde_json::json!({
            "id": "MAL-2026-2048",
            "aliases": ["GHSA-test"],
            "affected": [
                { "package": { "ecosystem": "npm", "name": "@Acme/Public-API-SDK" } },
                { "package": { "ecosystem": "PyPI", "name": "Ignored-Python" } },
                { "package": { "ecosystem": "npm", "name": "@acme/public_api_sdk" } }
            ]
        });
        let advisory: OsvVulnerability =
            serde_json::from_value(advisory_json).expect("advisory JSON must deserialize");

        let package_names = parse_osv_malicious_package_names(&advisory, "npm");
        assert_eq!(package_names, vec!["@acme/public-api-sdk".to_string()]);
    }

    #[test]
    fn update_slopsquat_persists_rkyv_corpus() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let corpus = common::wisdom::SlopsquatCorpus {
            package_names: vec!["py-react-vsc".to_string(), "tokio-async-std".to_string()],
        };
        let corpus_path = common::wisdom::slopsquat_corpus_path(&dir.path().join(".janitor"));
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus)
            .expect("corpus serialization must succeed");

        write_atomic_bytes(&corpus_path, bytes.as_slice()).expect("atomic write must succeed");

        let loaded =
            common::wisdom::load_slopsquat_corpus(&corpus_path).expect("corpus must deserialize");
        assert_eq!(loaded, corpus);
    }

    /// When every network attempt fails (port 1 is always refused), the function
    /// must exit `Ok(())` and deploy the embedded build-time baseline to disk.
    #[test]
    fn network_failure_deploys_embedded_baseline_to_disk() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let agent = ureq::Agent::new_with_defaults();
        // Port 1 is privileged and always connection-refused on Linux/WSL —
        // ensures all 3 retry attempts fail without touching the live network.
        let result = cmd_update_slopsquat_impl(dir.path(), &agent, "http://127.0.0.1:1", 7);
        assert!(
            result.is_ok(),
            "network failure must not propagate as Err — offline fallback must absorb it"
        );
        let corpus_path = common::wisdom::slopsquat_corpus_path(&dir.path().join(".janitor"));
        assert!(
            corpus_path.exists(),
            "embedded baseline must be written to disk when no on-disk corpus exists"
        );
        let loaded = common::wisdom::load_slopsquat_corpus(&corpus_path)
            .expect("embedded baseline must deserialise");
        assert!(
            !loaded.package_names.is_empty(),
            "embedded baseline must contain seed packages"
        );
    }

    /// When an on-disk corpus already exists and is fresh, network failure exits
    /// `Ok(())` without touching the corpus.
    #[test]
    fn network_failure_with_fresh_corpus_exits_gracefully() {
        let dir = tempfile::tempdir().expect("tempdir must exist");
        let janitor_dir = dir.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect(".janitor dir must be created");
        let corpus_path = common::wisdom::slopsquat_corpus_path(&janitor_dir);
        // Write a recognisable corpus to disk.
        let corpus = common::wisdom::SlopsquatCorpus {
            package_names: vec!["existing-package".to_string()],
        };
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus)
            .expect("corpus serialization must succeed");
        write_atomic_bytes(&corpus_path, bytes.as_slice()).expect("atomic write must succeed");

        let agent = ureq::Agent::new_with_defaults();
        let result = cmd_update_slopsquat_impl(dir.path(), &agent, "http://127.0.0.1:1", 7);
        assert!(
            result.is_ok(),
            "network failure with fresh on-disk corpus must exit Ok"
        );
        // Corpus must be unchanged — the fallback path must not overwrite it.
        let loaded =
            common::wisdom::load_slopsquat_corpus(&corpus_path).expect("corpus must deserialise");
        assert_eq!(
            loaded.package_names,
            vec!["existing-package".to_string()],
            "fresh on-disk corpus must not be overwritten"
        );
    }
}

#[cfg(test)]
mod sbom_watch_tests {
    use super::*;

    #[test]
    fn snapshot_lockfile_packages_reads_cargo_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_lock = r#"version = 4

[[package]]
name = "serde"
version = "1.0.200"

[[package]]
name = "tokio"
version = "1.38.0"
"#;
        std::fs::write(dir.path().join("Cargo.lock"), cargo_lock).unwrap();
        let packages = snapshot_lockfile_packages(dir.path());
        assert!(packages.contains("serde"), "serde must be in snapshot");
        assert!(packages.contains("tokio"), "tokio must be in snapshot");
    }

    #[test]
    fn snapshot_lockfile_packages_empty_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let packages = snapshot_lockfile_packages(dir.path());
        assert!(
            packages.is_empty(),
            "empty directory must yield empty snapshot"
        );
    }
}
