use anyhow::Context as _;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

mod daemon;
mod export;
mod report;

#[derive(Parser)]
#[command(name = "janitor")]
#[command(about = "Code Integrity Protocol — Automated Dead Symbol Detection & Cleanup")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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
        /// Output format: `text` (default) or `json` for machine-readable output.
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
    /// Reads the patch from `--patch <file>` or from stdin.
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
    },
    /// Launch the Ratatui TUI dashboard from a saved symbol registry.
    Dashboard {
        /// Project root (reads .janitor/symbols.rkyv).
        path: PathBuf,
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
        /// Output format: `markdown` (default) or `json`.
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
    /// Synchronise the local Wisdom Registry with The Governor.
    ///
    /// Downloads the latest `wisdom.rkyv` from `https://api.thejanitor.app/v1/wisdom.rkyv`
    /// and overwrites `.janitor/wisdom.rkyv` in the project root.
    UpdateWisdom {
        /// Project root (writes .janitor/wisdom.rkyv).
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
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Output CSV file path.
        #[arg(long, short = 'o', default_value = "bounce_export.csv")]
        out: PathBuf,
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
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("warning: .env: {}", e);
    }

    let _root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cli = Cli::parse();

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
        Commands::Dashboard { path } => cmd_dashboard(path)?,
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
        } => cmd_bounce(
            path,
            patch.as_deref(),
            registry.as_deref(),
            format,
            repo.as_deref(),
            base.as_deref(),
            head.as_deref(),
            *pr_number,
            author.as_deref(),
            pr_body.as_deref(),
        )?,
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
        Commands::UpdateWisdom { path } => cmd_update_wisdom(path)?,
        Commands::Export { repo, out } => export::cmd_export(repo, out)?,
        Commands::Pardon { symbol, repo } => cmd_pardon(symbol, repo)?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

fn cmd_scan(
    project_root: &Path,
    library: bool,
    verbose: bool,
    format: &str,
    exclude_segments: &[&str],
) -> anyhow::Result<()> {
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
                pb_g.finish_with_message(format!("Dissected {} files, {} symbols", files, symbols));
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

    if format == "json" {
        // Machine-readable output for Governor SaaS / GitHub Checks integration.
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

        let json_out = serde_json::json!({
            "schema_version": "6.5.0",
            "slop_score": slop_score,
            "dead_symbols": result.dead.iter().map(|e| serde_json::json!({
                "id": e.qualified_name,
                "structural_hash": e.structural_hash.unwrap_or(0),
                "reason": "DEAD_SYMBOL",
                "byte_range": [e.start_byte, e.end_byte],
            })).collect::<Vec<_>>(),
            "merkle_root": merkle_root,
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
        eprintln!("warning: could not save symbols.rkyv: {}", e);
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
    println!("| True duplicates  : {:>20} |", true_dups);
    println!("| Structural pats. : {:>20} |", patterns);
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
                    "\n  [HARD-GATE] {:016x}: C++/C#/GLSL deduplication is strictly advisory \
                     to prevent SIMD/Template corruption.",
                    hash
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
                .map_err(|e| anyhow::anyhow!("{}", e))?;
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
                "Pre-flight verification FAILED: {}.\n\
                 Pre-existing failures — Janitor did not cause them. Proceeding.",
                e
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

        let impl_block = format!("\ndef {}({}):\n{}", impl_name, params_str, original_body);
        let call_args = params_to_call_args(&params_str);
        let proxy_body = if call_args.is_empty() {
            format!("    return {}()\n", impl_name)
        } else {
            format!("    return {}({})\n", impl_name, call_args)
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
                println!("APPLIED + VERIFIED: {}", file_path_str);
            }
            Err(e) => {
                if baseline_passed {
                    eprintln!(
                        "TEST FAILED (Janitor caused regression): {}. Rolling back...",
                        e
                    );
                    deleter.restore_all()?;
                    return Err(e);
                } else {
                    eprintln!(
                        "Tests failed: {} (pre-existing failures — not caused by Janitor).",
                        e
                    );
                    deleter.commit()?;
                    println!(
                        "APPLIED (pre-existing failures not resolved): {}",
                        file_path_str
                    );
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
                    "Pre-flight verification FAILED: {}.\n\
                     Pre-existing failures detected — Janitor did not cause them.\n\
                     Proceeding with cleanup; post-cleanup failures will be compared against this baseline.",
                    e
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
            .map_err(|e| anyhow::anyhow!("{}", e))?;
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
                .with_context(|| format!("reading {} for shadow simulation", file_str))?;
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
                eprintln!("Shadow verification FAILED: {}", e);
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
                eprintln!("Cleanup error in {}: {}. Restoring backup...", file_str, e);
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
            println!("Post-cleanup verification ({})...", runner_display);
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
                            "Post-cleanup verification FAILED (Janitor caused regression): {}. Restoring...",
                            e
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
                            "Post-cleanup verification FAILED: {} (pre-existing failures — not caused by Janitor).",
                            e
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
        println!("Removed {} symbols from {}", n, file_str);
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
    use common::registry::{MappedRegistry, SymbolRegistry};

    let rkyv_path = project_root.join(".janitor").join("symbols.rkyv");

    if !rkyv_path.exists() {
        println!(
            "No symbol registry found. Run `janitor scan {}` first.",
            project_root.display()
        );
        return Ok(());
    }

    let mapped = MappedRegistry::open(&rkyv_path)
        .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {}", e))?;

    let registry: SymbolRegistry = rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
        .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;

    dashboard::draw_dashboard(&registry).map_err(|e| anyhow::anyhow!("TUI error: {}", e))
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
        .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {}", e))?;

    let registry: SymbolRegistry = rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
        .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;

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

    let label = format!("{}%", health_pct);
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
                eprintln!(
                    "warning: git not available ({}). Falling back to ghost restore.",
                    e
                );
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
            .map_err(|e| anyhow::anyhow!("{}", e))?;
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
        println!("{} file(s) restored from .janitor/ghost/.", restored);
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
        Err(e) => Err(anyhow::anyhow!("Failed to spawn cargo test: {}", e)),
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
        Err(e) => Err(anyhow::anyhow!("Failed to spawn go test: {}", e)),
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
        Err(e) => Err(anyhow::anyhow!("Failed to spawn npm test: {}", e)),

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
        Err(e) => Err(anyhow::anyhow!("Failed to spawn scons: {}", e)),
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
        .map_err(|e| anyhow::anyhow!("Failed to spawn test command `{}`: {}", cmd, e))?;
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
) -> anyhow::Result<()> {
    use common::registry::{MappedRegistry, SymbolRegistry};
    use forge::slop_filter::{bounce_git, PRBouncer, PatchBouncer};
    use std::io::Read as _;

    // Load symbol registry — empty registry is safe (bounce degrades to clone-only analysis).
    let rkyv_path = registry_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| project_root.join(".janitor").join("symbols.rkyv"));
    let registry: SymbolRegistry = if rkyv_path.exists() {
        let mapped = MappedRegistry::open(&rkyv_path)
            .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {}", e))?;
        rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?
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
        SymbolRegistry::new()
    };

    // Determine analysis mode and compute score + merkle root + MinHash sketch.
    // `bounce_blobs` carries the per-file byte content of the PR for the
    // O(1)-scoped zombie dep scan performed below (no full-repo WalkDir).
    let (mut score, merkle_root, min_hashes_vec, bounce_blobs) = match (repo, base, head) {
        (Some(repo_path), Some(base_sha), Some(head_sha)) => {
            // Git-native mode: shadow_git blob extraction.
            // bounce_git now returns (SlopScore, HashMap<PathBuf, Vec<u8>>).
            let (score, blobs) = bounce_git(repo_path, base_sha, head_sha, &registry)?;
            let merkle_key = format!("{repo_path:?}:{base_sha}:{head_sha}");
            let merkle_root = blake3::hash(merkle_key.as_bytes()).to_hex().to_string();
            // Derive MinHash from the deterministic merkle key (no raw patch in git mode).
            let sig = forge::pr_collider::PrDeltaSignature::from_bytes(merkle_root.as_bytes());
            (score, merkle_root, sig.min_hashes.to_vec(), blobs)
        }
        _ => {
            // Patch mode: read diff from file or stdin.
            let patch = match patch_file {
                Some(pf) => std::fs::read_to_string(pf)
                    .with_context(|| format!("reading patch file: {}", pf.display()))?,
                None => {
                    let mut s = String::new();
                    std::io::stdin()
                        .read_to_string(&mut s)
                        .context("reading patch from stdin")?;
                    s
                }
            };
            let mut score = PatchBouncer.bounce(&patch, &registry)?;
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
                if scanner.is_pr_unlinked(body) {
                    score.unlinked_pr = 1;
                }
            }

            // Extract per-file blobs from the unified diff for the zombie dep scan.
            let blobs = forge::slop_filter::extract_patch_blobs(&patch);

            (score, merkle_root, sig.min_hashes.to_vec(), blobs)
        }
    };

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

    if format == "json" {
        let json_out = serde_json::json!({
            "schema_version": "6.8.0",
            "slop_score": score.score() as f64,
            "dead_symbols_added": score.dead_symbols_added,
            "logic_clones_found": score.logic_clones_found,
            "zombie_symbols_added": score.zombie_symbols_added,
            "antipatterns_found": score.antipatterns_found,
            "comment_violations": score.comment_violations,
            "unlinked_pr": score.unlinked_pr,
            "merkle_root": merkle_root,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json_out)
                .map_err(|e| anyhow::anyhow!("JSON serialization failed: {}", e))?
        );
    } else {
        println!("+------------------------------------------+");
        println!("| JANITOR BOUNCE                           |");
        println!("+------------------------------------------+");
        println!("| Slop score       : {:>20} |", score.score());
        println!("| Dead syms added  : {:>20} |", score.dead_symbols_added);
        println!("| Logic clones     : {:>20} |", score.logic_clones_found);
        println!("| Zombie syms added: {:>20} |", score.zombie_symbols_added);
        println!("| Antipatterns     : {:>20} |", score.antipatterns_found);
        println!("| Comment violations: {:>19} |", score.comment_violations);
        println!("| Unlinked PR      : {:>20} |", score.unlinked_pr);
        println!("+------------------------------------------+");
        println!("  Merkle root: {}...", &merkle_root[..32]);
        println!();
        if score.is_clean() {
            println!("PATCH CLEAN — no slop detected.");
        } else {
            println!("PATCH FLAGGED — slop score: {}", score.score());
        }
    }

    // Persist to bounce_log.ndjson for `janitor report` aggregation.
    // PR-scoped zombie dep scan — O(PR-diff bytes), no full-tree WalkDir.
    let zombie_deps = anatomist::manifest::find_zombie_deps_in_blobs(&bounce_blobs);
    let janitor_dir = project_root.join(".janitor");
    let log_entry = report::BounceLogEntry {
        pr_number,
        author: author.map(|s| s.to_owned()),
        timestamp: utc_now_iso8601(),
        slop_score: score.score(),
        dead_symbols_added: score.dead_symbols_added,
        logic_clones_found: score.logic_clones_found,
        zombie_symbols_added: score.zombie_symbols_added,
        antipatterns: score.antipattern_details,
        comment_violations: score.comment_violation_details,
        min_hashes: min_hashes_vec,
        zombie_deps,
    };
    report::append_bounce_log(&janitor_dir, &log_entry);

    Ok(())
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
// report
// ---------------------------------------------------------------------------

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

    let data = report::aggregate_global(repo_logs);

    let content = if format == "json" {
        serde_json::to_string_pretty(&report::render_global_json(&data, &gauntlet_str))
            .context("serializing global report JSON")?
    } else {
        report::render_global_markdown(&data, &gauntlet_str)
    };

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
        None => print!("{}", content),
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
                    eprintln!("  Dissected {} files, {} symbols", files, symbols);
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
        let data = report::aggregate(entries, top);
        if format == "json" {
            serde_json::to_string_pretty(&report::render_json(&data, &repo_name))
                .context("serializing report JSON")?
        } else {
            report::render_markdown(&data, &repo_name)
        }
    };

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
        None => print!("{}", content),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// update-wisdom
// ---------------------------------------------------------------------------

/// Downloads the latest Wisdom Registry from The Governor and writes it to
/// `<project_root>/.janitor/wisdom.rkyv`.
///
/// On any network or I/O failure the function returns an error — no partial
/// write is left on disk (the download is buffered before overwriting).
fn cmd_update_wisdom(project_root: &Path) -> anyhow::Result<()> {
    use std::io::Read as _;
    const WISDOM_URL: &str = "https://api.thejanitor.app/v1/wisdom.rkyv";

    let response = ureq::get(WISDOM_URL)
        .call()
        .map_err(|e| anyhow::anyhow!("update-wisdom: GET {} failed: {}", WISDOM_URL, e))?;

    let mut bytes: Vec<u8> = Vec::new();
    response
        .into_reader()
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("update-wisdom: reading response body failed: {}", e))?;

    let janitor_dir = project_root.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .with_context(|| format!("creating {}", janitor_dir.display()))?;

    let wisdom_path = janitor_dir.join("wisdom.rkyv");
    std::fs::write(&wisdom_path, &bytes)
        .with_context(|| format!("writing {}", wisdom_path.display()))?;

    println!("\u{1f9e0} Wisdom Registry synchronized with The Governor.");
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
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
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
        Err(e) => Err(anyhow::anyhow!("Failed to spawn pytest: {}", e)),
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
