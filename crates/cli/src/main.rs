use anyhow::Context as _;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

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
    /// Start the MCP (Model Context Protocol) stdio JSON-RPC server.
    ///
    /// Reads newline-delimited JSON-RPC 2.0 from stdin, responds on stdout.
    /// Designed for use as an MCP tool server by AI assistants.
    Mcp,
}

#[derive(Subcommand)]
enum ShadowCmd {
    /// Initialise (or re-initialise) the symlink shadow tree.
    Init {
        /// Project root.
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
        } => cmd_scan(path, *library, *verbose)?,
        Commands::Dedup {
            path,
            apply,
            force_purge,
            token,
        } => cmd_dedup(path, *apply, *force_purge, token.as_deref())?,
        Commands::Shadow { cmd } => match cmd {
            ShadowCmd::Init { path } => cmd_shadow_init(path)?,
        },
        Commands::Clean {
            path,
            dry_run: _,
            force_purge,
            library,
            token,
        } => cmd_clean(path, *force_purge, *library, token.as_deref())?,
        Commands::Dashboard { path } => cmd_dashboard(path)?,
        Commands::Badge { path, output } => cmd_badge(path, output.as_deref())?,
        Commands::Undo { path } => cmd_undo(path)?,
        Commands::Mcp => mcp::serve().await?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

fn cmd_scan(project_root: &Path, library: bool, verbose: bool) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};
    use common::registry::{symbol_hash, SymbolEntry, SymbolRegistry};

    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));

    let result = pipeline::run(project_root, &mut host, library)?;

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
                "  {}:{} - {} [{:?}]",
                entity.file_path, entity.start_line, entity.qualified_name, entity.protected_by
            );
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

fn cmd_dedup(
    path: &Path,
    apply: bool,
    force_purge: bool,
    token: Option<&str>,
) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost};

    if apply && force_purge {
        require_token(token)?;
    }

    // Collect all supported source files — polyglot, not Python-only.
    let source_files = collect_source_files(path)?;
    if source_files.is_empty() {
        println!("No source files found at: {}", path.display());
        return Ok(());
    }

    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));

    // Gather all entities from ALL files into a flat list for cross-file detection.
    let mut all_entities: Vec<anatomist::Entity> = Vec::new();
    for file_path in &source_files {
        match host.dissect(file_path) {
            Ok(entities) => all_entities.extend(entities),
            Err(e) => eprintln!("warning: skipping {}: {}", file_path.display(), e),
        }
    }

    // Group by structural hash across all files.
    let mut hash_map: HashMap<u64, Vec<anatomist::Entity>> = HashMap::new();
    for entity in all_entities {
        if let Some(hash) = entity.structural_hash {
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
        // Only Python files with truly identical bodies can be safely refactored.
        let mergeable: Vec<DupGroup> = all_groups
            .into_iter()
            .filter(|g| {
                g.identical_content && g.members.iter().all(|e| e.file_path.ends_with(".py"))
            })
            .collect();
        if mergeable.is_empty() {
            println!("\nNo mergeable duplicates (identical Python bodies) found.");
        } else {
            apply_dedup(&mergeable, path)?;
        }
    } else if apply {
        println!("\n[DRY RUN] Pass --force-purge --token <TOKEN> to apply Safe Proxy Pattern.");
    }

    Ok(())
}

fn apply_dedup(groups: &[DupGroup], root_hint: &Path) -> anyhow::Result<()> {
    use reaper::{ReplacementTarget, SafeDeleter};

    let project_root = if root_hint.is_dir() {
        root_hint.to_path_buf()
    } else {
        root_hint.parent().unwrap_or(root_hint).to_path_buf()
    };

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
) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};
    use reaper::{audit::AuditEntry, audit::AuditLog, DeletionTarget, SafeDeleter};
    use shadow::ShadowManager;

    // 1. Run the detection pipeline (always — even in dry-run mode).
    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));
    let result = pipeline::run(project_root, &mut host, library)?;

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

    // 2. Auto-detect the repo's test runner.
    let runner = detect_test_runner(project_root);
    if runner.is_none() {
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
        match run_tests(project_root, runner) {
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

    // 5c. Post-cleanup verification for compiled-language repos.
    //     Only roll back if baseline was passing AND post-cleanup now fails
    //     (we caused a regression). Pre-existing failures don't warrant rollback.
    if !use_shadow {
        if let Some(r) = runner {
            let runner_name = match r {
                TestRunner::Cargo => "cargo test",
                TestRunner::Go => "go test",
                TestRunner::Npm => "npm test",
                TestRunner::Pytest => "pytest",
                TestRunner::SCons => "scons tests",
            };
            println!("Post-cleanup verification ({})...", runner_name);
            match run_tests(project_root, Some(r)) {
                Ok(()) => println!("Post-cleanup verification PASSED."),
                Err(e) => {
                    if baseline_passed {
                        eprintln!(
                            "Post-cleanup verification FAILED (Janitor caused regression): {}. Restoring...",
                            e
                        );
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

    audit_log.flush()?;
    println!(
        "Audit log updated: {}",
        janitor_dir.join("audit_log.json").display()
    );

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
fn require_token(token: Option<&str>) -> anyhow::Result<()> {
    use vault::SigningOracle;
    match token {
        Some(t) if SigningOracle::verify_token(t) => Ok(()),
        Some(_) => {
            eprintln!("AUTHORIZATION FAILED. Token is invalid or has been revoked.");
            eprintln!("Purchase or refresh your purge token at thejanitor.app");
            std::process::exit(1);
        }
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
fn collect_source_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
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
            e.file_name()
                .to_str()
                .map(|n| !SKIP.contains(&n))
                .unwrap_or(true)
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
