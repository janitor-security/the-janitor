use common::registry::SymbolRegistry;
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
    widgets::{BarChart, Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use std::{error::Error, io};

pub fn draw_dashboard(registry: &SymbolRegistry) -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Run app
    let res = run_app(&mut terminal, registry);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    registry: &SymbolRegistry,
) -> io::Result<()> {
    // Calculate stats once
    let total_symbols = registry.len() as u64;
    let dead_candidates_iter = registry.entries.iter().filter(|e| e.protected_by.is_none());

    let dead_count = dead_candidates_iter.clone().count() as u64;

    let mut dead_entries: Vec<_> = dead_candidates_iter.collect();
    // Sort by size (descending)
    dead_entries.sort_by_key(|e| std::cmp::Reverse(e.end_byte.saturating_sub(e.start_byte)));
    let top_10_dead: Vec<_> = dead_entries.iter().take(10).collect();

    let density = if total_symbols > 0 {
        ((total_symbols - dead_count) as f64 / total_symbols as f64) * 100.0
    } else {
        100.0
    };

    let sovereign_status_color = if density > 90.0 {
        Color::Green
    } else {
        Color::Red
    };

    let sovereign_status_text = if density > 90.0 {
        "SOVEREIGN"
    } else {
        "VULNERABLE"
    };

    loop {
        terminal.draw(|f| {
            let size = f.size();

            // Layout:
            // Top: Status
            // Middle: Bar Chart (Left) + Top 10 List (Right)
            // Bottom: Help text
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints(
                    [
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(1),
                    ]
                    .as_ref(),
                )
                .split(size);

            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
                .split(chunks[1]);

            // Status Block
            let status = Paragraph::new(vec![Line::from(vec![
                Span::raw("Sovereign Status: "),
                Span::styled(
                    format!("{} ({:.1}%)", sovereign_status_text, density),
                    Style::default()
                        .fg(sovereign_status_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ])])
            .block(Block::default().borders(Borders::ALL).title("Status"));
            f.render_widget(status, chunks[0]);

            // Bar Chart
            let bar_data = [("Total", total_symbols), ("Dead", dead_count)];
            // Convert to u64 for BarChart
            let barchart = BarChart::default()
                .block(Block::default().title("Overview").borders(Borders::ALL))
                .data(&bar_data)
                .bar_width(10)
                .bar_style(Style::default().fg(Color::Yellow))
                .value_style(Style::default().fg(Color::Black).bg(Color::Yellow));
            f.render_widget(barchart, main_chunks[0]);

            // Top 10 List
            let items: Vec<ListItem> = top_10_dead
                .iter()
                .map(|e| {
                    let size = e.end_byte.saturating_sub(e.start_byte);
                    ListItem::new(format!("{} ({} bytes) - {}", e.name, size, e.file_path))
                })
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .title("Top 10 Largest Dead Functions")
                        .borders(Borders::ALL),
                )
                .style(Style::default().fg(Color::White))
                .highlight_style(Style::default().add_modifier(Modifier::ITALIC));
            f.render_widget(list, main_chunks[1]);

            // Footer
            let footer =
                Paragraph::new("Press 'q' to exit").style(Style::default().fg(Color::DarkGray));
            f.render_widget(footer, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if let KeyCode::Char('q') = key.code {
                return Ok(());
            }
        }
    }
}
