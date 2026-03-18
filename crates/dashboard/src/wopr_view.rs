//! # WOPR Defcon Interface — Multi-Tenant Command Center
//!
//! Omni-WOPR: interactive Fallout-style tactical terminal for multi-repository
//! surveillance.  Two operating modes:
//!
//! ## TargetSelection
//! Scans a gauntlet base directory for cloned repositories and renders them as
//! a navigable target list.  Repositories with a `bounce_log.ndjson` modified
//! within the last 10 seconds are tagged `[ ACTIVE STRIKE ]` (blinking).
//!
//! Keys: `↑` / `↓` to navigate · `Enter` to lock on · `q` to quit.
//!
//! ## ActiveSurveillance
//! Full-screen per-repo view:
//! - Top pane: top-10 C++ compile-time silos (transitive reach ranking).
//! - Bottom pane: live PR delta feed from `.janitor/bounce_log.ndjson`.
//!
//! Poll intervals:
//! - Log feed: re-checked every 2 s; reloaded only when mtime changes.
//! - C++ graph: retried every 5 s until at least one node is found; then cached.
//!
//! Keys: `Esc` / `Backspace` to return to target selection · `q` to quit.

use std::{
    error::Error,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table},
    Terminal,
};

// ─── Timing constants ─────────────────────────────────────────────────────────

/// How often the selection list rescans for new/removed targets and active status.
const TARGET_SCAN_INTERVAL: Duration = Duration::from_secs(2);

/// A `bounce_log.ndjson` modified within this window is considered an active strike.
const ACTIVE_STRIKE_WINDOW: Duration = Duration::from_secs(10);

/// How often to check whether `bounce_log.ndjson` has been modified.
const LOG_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often to retry the C++ graph build while it has produced no nodes.
const GRAPH_RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum time to block waiting for a terminal event on each iteration.
const TICK: Duration = Duration::from_millis(100);

// ─── PR log entry ─────────────────────────────────────────────────────────────

struct WoprEntry {
    pr_number: u64,
    slop_score: u32,
    /// True when `antipattern_details` contains `architecture:compile_time_bloat`.
    is_threat: bool,
    /// True when `antipattern_details` contains `architecture:graph_entanglement`.
    is_entangled: bool,
    /// Non-zero when a `deflation_bonus:severed=N` marker is present.
    edges_severed: usize,
}

// ─── Target list ──────────────────────────────────────────────────────────────

/// One scanned repository entry in the target-selection screen.
struct Target {
    /// Display name — `<owner>/<repo>` for two-level paths, bare name otherwise.
    name: String,
    /// Absolute path to the repository root.
    path: PathBuf,
    /// `true` when `bounce_log.ndjson` was modified within [`ACTIVE_STRIKE_WINDOW`].
    is_active: bool,
}

/// Returns `true` when the `bounce_log.ndjson` at `log_path` was modified
/// within [`ACTIVE_STRIKE_WINDOW`] of now.
fn log_active(log_path: &Path) -> bool {
    std::fs::metadata(log_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|d| d < ACTIVE_STRIKE_WINDOW)
        .unwrap_or(false)
}

/// Scan `base_dir` for cloned repositories (depth 1 and 2).
///
/// A directory is considered a repository when it contains a `.git` entry.
/// At depth 2 (`<owner>/<repo>`) the display name includes the owner prefix.
fn scan_targets(base_dir: &Path) -> Vec<Target> {
    let mut targets = Vec::new();

    let Ok(level1) = std::fs::read_dir(base_dir) else {
        return targets;
    };

    for e1 in level1.flatten() {
        let p1 = e1.path();
        if !p1.is_dir() {
            continue;
        }

        // Depth-1 repo: <base>/<repo>/.git
        if p1.join(".git").exists() {
            let name = p1
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let log_path = p1.join(".janitor").join("bounce_log.ndjson");
            targets.push(Target {
                is_active: log_active(&log_path),
                name,
                path: p1,
            });
            continue;
        }

        // Depth-2 repos: <base>/<owner>/<repo>/.git
        let Ok(level2) = std::fs::read_dir(&p1) else {
            continue;
        };
        for e2 in level2.flatten() {
            let p2 = e2.path();
            if !p2.is_dir() || !p2.join(".git").exists() {
                continue;
            }
            let owner = p1.file_name().unwrap_or_default().to_string_lossy();
            let repo = p2.file_name().unwrap_or_default().to_string_lossy();
            let name = format!("{owner}/{repo}");
            let log_path = p2.join(".janitor").join("bounce_log.ndjson");
            targets.push(Target {
                is_active: log_active(&log_path),
                name,
                path: p2,
            });
        }
    }

    targets.sort_by(|a, b| a.name.cmp(&b.name));
    targets
}

// ─── Selection state ──────────────────────────────────────────────────────────

/// State for the `TargetSelection` mode.
struct SelectionState {
    base_dir: PathBuf,
    targets: Vec<Target>,
    /// Ratatui stateful list cursor.
    list_state: ListState,
    /// When the target list was last rescanned.
    last_scan: Instant,
}

impl SelectionState {
    fn new(base_dir: PathBuf) -> Self {
        let targets = scan_targets(&base_dir);
        let mut list_state = ListState::default();
        if !targets.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            base_dir,
            targets,
            list_state,
            last_scan: Instant::now(),
        }
    }

    /// Path of the currently highlighted target, or `None` if the list is empty.
    fn selected_path(&self) -> Option<PathBuf> {
        let idx = self.list_state.selected()?;
        self.targets.get(idx).map(|t| t.path.clone())
    }

    fn move_up(&mut self) {
        if self.targets.is_empty() {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        let prev = if i == 0 {
            self.targets.len() - 1
        } else {
            i - 1
        };
        self.list_state.select(Some(prev));
    }

    fn move_down(&mut self) {
        if self.targets.is_empty() {
            return;
        }
        let i = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some((i + 1) % self.targets.len()));
    }

    /// Rescan the gauntlet directory, preserving cursor position by name.
    fn rescan(&mut self) {
        let current_name = self
            .list_state
            .selected()
            .and_then(|i| self.targets.get(i))
            .map(|t| t.name.clone());

        self.targets = scan_targets(&self.base_dir);
        self.last_scan = Instant::now();

        let new_idx = current_name
            .and_then(|n| self.targets.iter().position(|t| t.name == n))
            .unwrap_or(0);

        if self.targets.is_empty() {
            self.list_state.select(None);
        } else {
            self.list_state
                .select(Some(new_idx.min(self.targets.len() - 1)));
        }
    }

    /// Called every tick: rescan if the interval has elapsed.
    fn tick(&mut self) {
        if Instant::now().duration_since(self.last_scan) >= TARGET_SCAN_INTERVAL {
            self.rescan();
        }
    }
}

// ─── Surveillance state ───────────────────────────────────────────────────────

/// State for the `ActiveSurveillance` mode (single-repo view).
struct WoprState {
    path: PathBuf,
    log_path: PathBuf,
    /// Top-10 C++ silos: `(label, direct_includes, transitive_reach)`.
    ranked: Vec<(String, usize, usize)>,
    entries: Vec<WoprEntry>,
    /// `true` once the graph build produced at least one node.
    graph_ready: bool,
    log_mtime: Option<SystemTime>,
    last_log_check: Instant,
    last_graph_attempt: Instant,
}

impl WoprState {
    fn new(path: PathBuf) -> Self {
        let log_path = path.join(".janitor").join("bounce_log.ndjson");
        let now = Instant::now();
        let far_past = now
            .checked_sub(LOG_POLL_INTERVAL + Duration::from_secs(1))
            .unwrap_or(now);
        Self {
            path,
            log_path,
            ranked: Vec::new(),
            entries: Vec::new(),
            graph_ready: false,
            log_mtime: None,
            last_log_check: far_past,
            last_graph_attempt: far_past,
        }
    }

    fn try_build_graph(&mut self) {
        self.last_graph_attempt = Instant::now();

        // Load the pre-computed silo ranking written by `janitor hyper-drive`.
        // The file is absent when hyper-drive has not yet run — poll every 5s
        // until it appears.
        let json_path = self.path.join(".janitor").join("wopr_graph.json");
        let Ok(json_str) = std::fs::read_to_string(&json_path) else {
            return;
        };
        let Ok(ranked) = serde_json::from_str::<Vec<(String, usize, usize)>>(&json_str) else {
            return;
        };
        self.ranked = ranked;
        self.graph_ready = true;
    }

    fn poll_log(&mut self) {
        self.last_log_check = Instant::now();

        let current_mtime = std::fs::metadata(&self.log_path)
            .and_then(|m| m.modified())
            .ok();

        if current_mtime == self.log_mtime {
            return;
        }
        self.log_mtime = current_mtime;
        self.entries = load_log(&self.log_path);
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_log_check) >= LOG_POLL_INTERVAL {
            self.poll_log();
        }
        if !self.graph_ready && now.duration_since(self.last_graph_attempt) >= GRAPH_RETRY_INTERVAL
        {
            self.try_build_graph();
        }
    }
}

// ─── Top-level mode ───────────────────────────────────────────────────────────

enum WoprMode {
    Selection(SelectionState),
    Surveillance(WoprState),
}

/// Top-level application container.
struct WoprApp {
    base_dir: PathBuf,
    mode: WoprMode,
}

impl WoprApp {
    fn new(base_dir: PathBuf) -> Self {
        let sel = SelectionState::new(base_dir.clone());
        Self {
            base_dir,
            mode: WoprMode::Selection(sel),
        }
    }

    /// Transition from Selection → Surveillance for `path`.
    fn enter_surveillance(&mut self, path: PathBuf) {
        let mut state = WoprState::new(path);
        state.try_build_graph();
        state.poll_log();
        self.mode = WoprMode::Surveillance(state);
    }

    /// Transition from Surveillance → Selection (fresh scan).
    fn return_to_selection(&mut self) {
        self.mode = WoprMode::Selection(SelectionState::new(self.base_dir.clone()));
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Launch the WOPR Defcon Interface multi-tenant command center.
///
/// `base_dir` is the gauntlet root (e.g. `~/dev/gauntlet/`).  The dashboard
/// opens in target-selection mode; pressing `Enter` on a highlighted repository
/// enters per-repo surveillance mode.
pub fn draw_wopr(base_dir: &Path) -> Result<(), Box<dyn Error>> {
    let mut app = WoprApp::new(base_dir.to_path_buf());

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    Ok(())
}

// ─── Main event loop ──────────────────────────────────────────────────────────

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut WoprApp,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    loop {
        // ── Draw (mode-dispatched) ─────────────────────────────────────────────
        match &mut app.mode {
            WoprMode::Selection(sel) => draw_selection(terminal, sel)?,
            WoprMode::Surveillance(state) => draw_surveillance(terminal, state)?,
        }

        // ── Events ────────────────────────────────────────────────────────────
        if event::poll(TICK)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),

                    // ── Selection navigation ───────────────────────────────────
                    KeyCode::Up => {
                        if let WoprMode::Selection(sel) = &mut app.mode {
                            sel.move_up();
                        }
                    }
                    KeyCode::Down => {
                        if let WoprMode::Selection(sel) = &mut app.mode {
                            sel.move_down();
                        }
                    }

                    // ── Enter surveillance ────────────────────────────────────
                    KeyCode::Enter => {
                        // Extract path before mutating app.mode.
                        let path_opt = if let WoprMode::Selection(sel) = &app.mode {
                            sel.selected_path()
                        } else {
                            None
                        };
                        if let Some(path) = path_opt {
                            app.enter_surveillance(path);
                        }
                    }

                    // ── Return to selection ───────────────────────────────────
                    KeyCode::Esc | KeyCode::Backspace => {
                        if matches!(app.mode, WoprMode::Surveillance(_)) {
                            app.return_to_selection();
                        }
                    }

                    _ => {}
                }
            }
        }

        // ── Tick (periodic refresh) ────────────────────────────────────────────
        match &mut app.mode {
            WoprMode::Selection(sel) => sel.tick(),
            WoprMode::Surveillance(state) => state.tick(),
        }
    }
}

// ─── Selection screen ─────────────────────────────────────────────────────────

fn draw_selection<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    sel: &mut SelectionState,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let green = Style::default().fg(Color::LightGreen);
    let muted_green = Style::default().fg(Color::Green);
    let thick_border = Style::default().fg(Color::Green);
    let strike_style = Style::default()
        .fg(Color::LightGreen)
        .add_modifier(Modifier::BOLD | Modifier::SLOW_BLINK);

    // Build items before draw closure to release the borrow on `sel.targets`.
    let items: Vec<ListItem> = sel
        .targets
        .iter()
        .map(|t| {
            if t.is_active {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("  {}", t.name), green),
                    Span::styled("  [ ACTIVE STRIKE ]", strike_style),
                ]))
            } else {
                ListItem::new(Line::from(Span::styled(
                    format!("  {}", t.name),
                    muted_green,
                )))
            }
        })
        .collect();

    let empty = items.is_empty();

    // `items` is now owned; we can take a separate mutable borrow of list_state.
    let list_state = &mut sel.list_state;

    terminal.draw(|f| {
        let area = f.area();

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);

        // ── Title ─────────────────────────────────────────────────────────────
        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                "  WOPR DEFCON INTERFACE",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  //  OMNI-TARGETING SYSTEM", muted_green),
            Span::styled("  //  v7.2 R&D", Style::default().fg(Color::DarkGray)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(thick_border)
                .style(Style::default().bg(Color::Black)),
        );
        f.render_widget(title, chunks[0]);

        // ── Target list ───────────────────────────────────────────────────────
        let placeholder: Vec<ListItem> = vec![ListItem::new(Line::from(Span::styled(
            "  NO TARGETS DETECTED IN GAUNTLET DIRECTORY",
            Style::default().fg(Color::DarkGray),
        )))];

        let list = List::new(if empty { placeholder } else { items })
            .block(
                Block::default()
                    .title("[ SELECT TACTICAL TARGET ]")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(thick_border)
                    .style(Style::default().bg(Color::Black)),
            )
            .style(green)
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, chunks[1], list_state);

        // ── Footer ────────────────────────────────────────────────────────────
        let footer = Paragraph::new("  ↑/↓ navigate  ·  Enter lock-on  ·  q quit")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(footer, chunks[2]);
    })?;

    Ok(())
}

// ─── Surveillance screen ──────────────────────────────────────────────────────

fn draw_surveillance<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    state: &mut WoprState,
) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let ranked = &state.ranked;
    let entries = &state.entries;
    let graph_ready = state.graph_ready;

    terminal.draw(|f| {
        let area = f.area();

        let green = Style::default().fg(Color::LightGreen);
        let green_bg = Style::default().fg(Color::LightGreen).bg(Color::Black);
        let muted_green = Style::default().fg(Color::Green);
        let thick_border = Style::default().fg(Color::Green);

        // Layout: title (3) | silos (55%) | delta feed (rest) | footer (1)
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Percentage(55),
                Constraint::Min(5),
                Constraint::Length(1),
            ])
            .split(area);

        // ── Title bar ─────────────────────────────────────────────────────────
        let repo_name = state.path.file_name().unwrap_or_default().to_string_lossy();
        let title = Paragraph::new(Line::from(vec![
            Span::styled(
                "  WOPR DEFCON INTERFACE",
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  //  COMPILE-TIME DOMINATION GRID", muted_green),
            Span::styled(
                format!("  //  TARGET: {repo_name}"),
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(thick_border)
                .style(Style::default().bg(Color::Black)),
        );
        f.render_widget(title, chunks[0]);

        // ── Global Compile-Time Silos ─────────────────────────────────────────
        let header = Row::new(vec![
            Cell::from("HEADER PATH").style(
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
            Cell::from("DIRECT IMPORTS").style(
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
            Cell::from("TRANSITIVE BLAST RADIUS").style(
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            ),
        ])
        .height(1);

        let silo_rows: Vec<Row> = if ranked.is_empty() {
            let msg = if graph_ready {
                "  NO C++ FILES DETECTED IN TARGET PATH"
            } else {
                "  AWAITING HYPER-DRIVE GRAPH GENERATION..."
            };
            vec![Row::new(vec![Cell::from(msg)]).style(Style::default().fg(Color::DarkGray))]
        } else {
            ranked
                .iter()
                .map(|(label, direct, blast)| {
                    Row::new(vec![
                        Cell::from(label.clone()),
                        Cell::from(direct.to_string()),
                        Cell::from(blast.to_string()),
                    ])
                    .style(green_bg)
                })
                .collect()
        };

        let silos_table = Table::new(
            silo_rows,
            [
                Constraint::Percentage(60),
                Constraint::Percentage(15),
                Constraint::Percentage(25),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title("[ GLOBAL COMPILE-TIME SILOS ]")
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(thick_border)
                .style(Style::default().bg(Color::Black)),
        )
        .style(green);
        f.render_widget(silos_table, chunks[1]);

        // ── PR Delta Feed ─────────────────────────────────────────────────────
        let feed_items: Vec<ListItem> = if entries.is_empty() {
            vec![ListItem::new(Line::from(Span::styled(
                "  AWAITING SIGNAL ... NO BOUNCE LOG ENTRIES FOUND",
                Style::default().fg(Color::DarkGray),
            )))]
        } else {
            entries
                .iter()
                .rev()
                .take(20)
                .map(|e| {
                    if e.is_entangled {
                        ListItem::new(Line::from(Span::styled(
                            format!(
                                "  [!] TOPOLOGY ALERT: PR #{} SEVERELY ENTANGLED C++ GRAPH \
                                 (CLUSTERING > 0.75)",
                                e.pr_number
                            ),
                            Style::default()
                                .fg(Color::Magenta)
                                .add_modifier(Modifier::BOLD),
                        )))
                    } else if e.is_threat {
                        ListItem::new(Line::from(Span::styled(
                            format!(
                                "  [!] THREAT DETECTED: PR #{} INCREASED BLAST RADIUS BY {}pts",
                                e.pr_number, e.slop_score
                            ),
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        )))
                    } else if e.edges_severed > 0 {
                        ListItem::new(Line::from(Span::styled(
                            format!(
                                "  [+] DEFCON LOWERED: PR #{} SEVERED {} EDGES",
                                e.pr_number, e.edges_severed
                            ),
                            Style::default()
                                .fg(Color::LightGreen)
                                .add_modifier(Modifier::BOLD),
                        )))
                    } else {
                        ListItem::new(Line::from(Span::styled(
                            format!("  [ ] PR #{} — score: {}", e.pr_number, e.slop_score),
                            muted_green,
                        )))
                    }
                })
                .collect()
        };

        let delta_feed = List::new(feed_items)
            .block(
                Block::default()
                    .title("[ PR DELTA FEED ]")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(thick_border)
                    .style(Style::default().bg(Color::Black)),
            )
            .style(green);
        f.render_widget(delta_feed, chunks[2]);

        // ── Footer ────────────────────────────────────────────────────────────
        let footer = Paragraph::new("  Esc/Backspace return  ·  q quit")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(footer, chunks[3]);
    })?;

    Ok(())
}

// ─── Log parsing ──────────────────────────────────────────────────────────────

fn load_log(path: &Path) -> Vec<WoprEntry> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content.lines().filter_map(parse_log_line).collect()
}

fn parse_log_line(line: &str) -> Option<WoprEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let pr_number = v["pr_number"].as_u64()?;
    let slop_score = v["slop_score"].as_u64().unwrap_or(0) as u32;

    let details = v["antipattern_details"].as_array();

    let is_threat = details
        .map(|arr| {
            arr.iter().any(|d| {
                d.as_str()
                    .map(|s| s.contains("architecture:compile_time_bloat"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let is_entangled = details
        .map(|arr| {
            arr.iter().any(|d| {
                d.as_str()
                    .map(|s| s.contains("architecture:graph_entanglement"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    let edges_severed = details
        .and_then(|arr| {
            arr.iter().find_map(|d| {
                let s = d.as_str()?;
                s.strip_prefix("deflation_bonus:severed=")
                    .and_then(|n| n.parse::<usize>().ok())
            })
        })
        .unwrap_or(0);

    Some(WoprEntry {
        pr_number,
        slop_score,
        is_threat,
        is_entangled,
        edges_severed,
    })
}
