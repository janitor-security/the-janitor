pub mod safe_delete;
pub mod test_fingerprint;

pub use safe_delete::{DeletionTarget, ReplacementTarget, SafeDeleter};

use aho_corasick::AhoCorasick;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Errors from reaper operations.
#[derive(Debug, thiserror::Error)]
pub enum ReaperError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Ingests liveness signals from log files to determine symbol usage.
///
/// Implementations process logs line-by-line via `BufReader` — never
/// loading the entire file into memory. This satisfies the 8GB RAM constraint.
pub trait LivenessTracker {
    /// Processes a log file and returns the count of liveness signals found.
    ///
    /// A "liveness signal" is any evidence that a symbol was invoked at runtime
    /// (function call, import, attribute access logged in the trace).
    fn ingest_log(&mut self, log_path: &Path) -> Result<u64, ReaperError>;
}

/// Simple log-based liveness tracker backed by an Aho-Corasick automaton.
///
/// Searches log lines for symbol qualified names (substring match).
/// Marks symbols as alive if their name appears in any log line.
///
/// # Memory
/// - `pattern_ids`: O(N) where N = total symbols
/// - `alive`: O(K) where K = symbols found in logs
///
/// # Performance
/// - O(N) where N = total bytes in log — each byte processed exactly once per line.
pub struct SimpleLogTracker {
    automaton: AhoCorasick,
    pattern_ids: Vec<u64>,
    alive: HashSet<u64>,
}

impl SimpleLogTracker {
    /// Creates a new tracker from symbol (id, qualified_name) pairs.
    ///
    /// # Examples
    /// ```
    /// # use reaper::SimpleLogTracker;
    /// let tracker = SimpleLogTracker::new(vec![
    ///     (1, "module.foo".into()),
    ///     (2, "module.bar".into()),
    /// ]);
    /// assert_eq!(tracker.alive_count(), 0);
    /// ```
    pub fn new(symbols: impl IntoIterator<Item = (u64, String)>) -> Self {
        let pairs: Vec<(u64, String)> = symbols.into_iter().collect();
        let pattern_ids: Vec<u64> = pairs.iter().map(|(id, _)| *id).collect();
        let patterns: Vec<&str> = pairs.iter().map(|(_, name)| name.as_str()).collect();
        let automaton =
            AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");
        Self {
            automaton,
            pattern_ids,
            alive: HashSet::new(),
        }
    }

    /// Returns the set of alive symbol IDs.
    pub fn alive_set(&self) -> &HashSet<u64> {
        &self.alive
    }

    /// Returns the count of alive symbols.
    pub fn alive_count(&self) -> usize {
        self.alive.len()
    }
}

impl LivenessTracker for SimpleLogTracker {
    fn ingest_log(&mut self, log_path: &Path) -> Result<u64, ReaperError> {
        let file = File::open(log_path)?;
        let reader = BufReader::new(file);
        let mut signal_count = 0u64;

        for line in reader.lines() {
            let line = line?;
            for mat in self.automaton.find_iter(&line) {
                let id = self.pattern_ids[mat.pattern().as_usize()];
                if self.alive.insert(id) {
                    signal_count += 1;
                }
            }
        }

        Ok(signal_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_empty_log() {
        let tmp = std::env::temp_dir().join("test_log_empty.txt");
        fs::write(&tmp, "").ok();

        let mut tracker = SimpleLogTracker::new(vec![(1, "foo".into())]);
        let signals = tracker.ingest_log(&tmp).unwrap();

        assert_eq!(signals, 0);
        assert_eq!(tracker.alive_count(), 0);

        fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_single_match() {
        let tmp = std::env::temp_dir().join("test_log_single.txt");
        fs::write(&tmp, "INFO: module.foo called\n").ok();

        let mut tracker = SimpleLogTracker::new(vec![(1, "module.foo".into())]);
        let signals = tracker.ingest_log(&tmp).unwrap();

        assert_eq!(signals, 1);
        assert_eq!(tracker.alive_count(), 1);
        assert!(tracker.alive_set().contains(&1));

        fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_no_match() {
        let tmp = std::env::temp_dir().join("test_log_nomatch.txt");
        fs::write(&tmp, "INFO: something else happened\n").ok();

        let mut tracker = SimpleLogTracker::new(vec![(1, "module.foo".into())]);
        let signals = tracker.ingest_log(&tmp).unwrap();

        assert_eq!(signals, 0);
        assert_eq!(tracker.alive_count(), 0);

        fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_duplicate_match_counts_once() {
        let tmp = std::env::temp_dir().join("test_log_dup.txt");
        fs::write(&tmp, "module.foo\nmodule.foo\nmodule.foo\n").ok();

        let mut tracker = SimpleLogTracker::new(vec![(1, "module.foo".into())]);
        let signals = tracker.ingest_log(&tmp).unwrap();

        assert_eq!(signals, 1); // Only counts the first time
        assert_eq!(tracker.alive_count(), 1);

        fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_multiple_symbols() {
        let tmp = std::env::temp_dir().join("test_log_multi.txt");
        fs::write(&tmp, "module.foo\nmodule.bar\n").ok();

        let mut tracker = SimpleLogTracker::new(vec![
            (1, "module.foo".into()),
            (2, "module.bar".into()),
            (3, "module.baz".into()),
        ]);
        let signals = tracker.ingest_log(&tmp).unwrap();

        assert_eq!(signals, 2);
        assert_eq!(tracker.alive_count(), 2);
        assert!(tracker.alive_set().contains(&1));
        assert!(tracker.alive_set().contains(&2));
        assert!(!tracker.alive_set().contains(&3));

        fs::remove_file(tmp).ok();
    }
}
