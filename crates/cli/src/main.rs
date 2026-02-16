use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "janitor")]
#[command(
    about = "Code Integrity Protocol — Automated Dead Symbol Detection & Surgical Artifact Excision"
)]
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
        /// Python file or directory to analyse.
        path: PathBuf,
        /// Rewrite duplicates using the Safe Proxy Pattern (requires --force-purge and --token).
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
    /// Shadow-simulate deletion, verify tests, then physically delete dead symbols.
    ///
    /// Default: dry-run. Pass --force-purge to execute physical excision.
    /// A valid --token is required when --force-purge is set.
    Clean {
        /// Project root.
        path: PathBuf,
        /// Dry-run mode (default): scan and report without deleting anything.
        #[arg(long)]
        dry_run: bool,
        /// Execute physical excision. Requires --token.
        #[arg(long)]
        force_purge: bool,
        /// Ed25519 purge token (required with --force-purge).
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
    /// Undo the last excision. Uses git stash if inside a VCS repo, otherwise
    /// restores files from .janitor/ghost/.
    Undo {
        /// Project root.
        path: PathBuf,
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
            token,
        } => cmd_clean(path, *force_purge, token.as_deref())?,
        Commands::Dashboard { path } => cmd_dashboard(path)?,
        Commands::Badge { path, output } => cmd_badge(path, output.as_deref())?,
        Commands::Undo { path } => cmd_undo(path)?,
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
    file_path: PathBuf,
    members: Vec<anatomist::Entity>,
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

    let py_files = collect_py_files(path)?;
    if py_files.is_empty() {
        println!("No Python files found at: {}", path.display());
        return Ok(());
    }

    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));

    let mut all_groups: Vec<DupGroup> = Vec::new();

    for file_path in &py_files {
        let entities = match host.dissect(file_path) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("warning: skipping {}: {}", file_path.display(), e);
                continue;
            }
        };

        let mut hash_groups: HashMap<u64, Vec<anatomist::Entity>> = HashMap::new();
        for entity in entities {
            if let Some(hash) = entity.structural_hash {
                hash_groups.entry(hash).or_default().push(entity);
            }
        }

        for (hash, members) in hash_groups {
            if members.len() >= 2 {
                all_groups.push(DupGroup {
                    hash,
                    file_path: file_path.clone(),
                    members,
                });
            }
        }
    }

    if all_groups.is_empty() {
        println!("No duplicate functions found.");
        return Ok(());
    }

    println!("+------------------------------------------+");
    println!("| JANITOR DEDUP                            |");
    println!("+------------------------------------------+");
    println!("| Duplicate groups : {:>20} |", all_groups.len());
    println!("+------------------------------------------+");

    for group in &all_groups {
        println!("\n  Hash: {:016x}", group.hash);
        for entity in &group.members {
            println!(
                "    {}:{} - {}",
                entity.file_path, entity.start_line, entity.qualified_name
            );
        }
    }

    if apply && force_purge {
        apply_dedup(&all_groups, path)?;
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

    let mut by_file: HashMap<&Path, (Vec<ReplacementTarget>, Vec<String>)> = HashMap::new();

    for group in groups {
        let file_path = group.file_path.as_path();
        let source = std::fs::read(file_path)?;

        let canon = &group.members[0];
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

        let entry = by_file.entry(file_path).or_default();
        entry.1.push(impl_block);

        for member in &group.members {
            let (member_body_start, _) = extract_function_parts(&source, member)?;
            entry.0.push(ReplacementTarget {
                qualified_name: member.qualified_name.clone(),
                start_byte: member_body_start,
                end_byte: member.end_byte,
                replacement: proxy_body.clone(),
            });
        }
    }

    for (file_path, (mut replacements, impl_blocks)) in by_file {
        let mut deleter = SafeDeleter::new(&project_root)?;
        deleter.replace_symbols(file_path, &mut replacements)?;

        let mut current = std::fs::read_to_string(file_path)?;
        for block in &impl_blocks {
            current.push_str(block);
        }
        std::fs::write(file_path, &current)?;

        match run_pytest(&project_root) {
            Ok(()) => {
                deleter.commit()?;
                println!("APPLIED + VERIFIED: {}", file_path.display());
            }
            Err(e) => {
                eprintln!("PYTEST FAILED: {}. Rolling back...", e);
                deleter.restore_all()?;
                return Err(e);
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

fn cmd_clean(project_root: &Path, force_purge: bool, token: Option<&str>) -> anyhow::Result<()> {
    use anatomist::{heuristics::pytest::PytestFixtureHeuristic, parser::ParserHost, pipeline};
    use reaper::{audit::AuditEntry, audit::AuditLog, DeletionTarget, SafeDeleter};
    use shadow::ShadowManager;

    // 1. Run the detection pipeline (always — even in dry-run mode).
    let mut host = ParserHost::new()?;
    host.register_heuristic(Box::new(PytestFixtureHeuristic));
    let result = pipeline::run(project_root, &mut host, false)?;

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
    println!("  Would excise:");
    for entity in &result.dead {
        println!(
            "    {}:{} - {}",
            entity.file_path, entity.start_line, entity.qualified_name
        );
    }

    if !force_purge {
        println!(
            "\n[DRY RUN] No files modified.\n\
             Pass --force-purge --token <TOKEN> to execute surgical excision."
        );
        return Ok(());
    }

    // --force-purge path: verify token first.
    require_token(token)?;

    // 2. Initialise (or open existing) shadow tree.
    let shadow_path = project_root.join(".janitor").join("shadow_src");
    let manager = if shadow_path.exists() {
        ShadowManager::open(project_root, &shadow_path)?
    } else {
        ShadowManager::initialize(project_root, &shadow_path)?
    };

    // 3. Collect unique files and unmap their shadow entries.
    let mut dead_files: Vec<PathBuf> = result
        .dead
        .iter()
        .map(|e| PathBuf::from(&e.file_path))
        .collect();
    dead_files.sort();
    dead_files.dedup();

    let mut unmapped: Vec<PathBuf> = Vec::new();
    for abs in &dead_files {
        let rel = abs
            .strip_prefix(manager.source_root())
            .unwrap_or(abs.as_path());
        match manager.unmap(rel) {
            Ok(()) => unmapped.push(rel.to_path_buf()),
            Err(e) => eprintln!("warning: unmap {}: {}", abs.display(), e),
        }
    }

    // 4. Shadow simulation: run tests against the shadow tree.
    println!("Shadow simulation: {}", manager.shadow_root().display());
    match run_pytest(manager.shadow_root()) {
        Ok(()) => {
            println!("Shadow verification PASSED. Executing physical excision...");
        }
        Err(e) => {
            eprintln!("Shadow verification FAILED: {}. Restoring...", e);
            for rel in &unmapped {
                manager.remap(rel).ok();
            }
            return Err(e);
        }
    }

    // 5. Physical excision via SafeDeleter + AuditLog.
    let janitor_dir = project_root.join(".janitor");
    let mut audit_log = AuditLog::new(&janitor_dir);

    let mut by_file: HashMap<&str, Vec<&anatomist::Entity>> = HashMap::new();
    for entity in &result.dead {
        by_file
            .entry(entity.file_path.as_str())
            .or_default()
            .push(entity);
    }

    for (file_str, entities) in &by_file {
        let file_path = Path::new(file_str);
        let file_bytes = std::fs::read(file_path).unwrap_or_default();

        let mut deleter = SafeDeleter::new(project_root)?;
        let mut targets: Vec<DeletionTarget> = entities
            .iter()
            .map(|e| DeletionTarget {
                qualified_name: e.qualified_name.clone(),
                start_byte: e.start_byte,
                end_byte: e.end_byte,
            })
            .collect();

        // Record audit entry before deletion (pre-excision hash).
        for entity in entities.iter() {
            audit_log.record(AuditEntry::new(
                *file_str,
                entity.qualified_name.as_str(),
                &file_bytes,
                "DEAD_SYMBOL",
                entity.start_line,
                entity.end_line,
            ));
        }

        match deleter.delete_symbols(file_path, &mut targets) {
            Ok(n) => {
                deleter.commit()?;
                println!("Excised {} symbols from {}", n, file_str);
            }
            Err(e) => {
                eprintln!("Excision error in {}: {}. Restoring backup...", file_str, e);
                deleter.restore_all()?;
            }
        }
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

fn collect_py_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    use walkdir::WalkDir;
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let files = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file() && e.path().extension().and_then(|x| x.to_str()) == Some("py")
        })
        .map(|e| e.path().to_path_buf())
        .collect();
    Ok(files)
}

fn run_pytest(dir: &Path) -> anyhow::Result<()> {
    let status = std::process::Command::new("pytest")
        .args(["--tb=short", "-q"])
        .current_dir(dir)
        .status();

    match status {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("note: pytest not found — skipping verification");
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("Failed to spawn pytest: {}", e)),
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(anyhow::anyhow!(
            "pytest exited with code {}",
            s.code().unwrap_or(-1)
        )),
    }
}
