//! Grammar stress helpers for parser exhaustion fuzzing.

use std::time::{Duration, Instant};
use tree_sitter::{Language, Parser};

/// Upper execution budget for a single parser invocation.
pub const PARSE_BUDGET: Duration = Duration::from_millis(500);

fn target_languages() -> impl Iterator<Item = Language> {
    [
        tree_sitter_cpp::LANGUAGE.into(),
        tree_sitter_python::LANGUAGE.into(),
        tree_sitter_javascript::LANGUAGE.into(),
    ]
    .into_iter()
}

/// Parse `input` across the stress grammars and return the worst observed runtime.
pub fn max_parse_duration(input: &[u8]) -> Duration {
    let mut worst = Duration::ZERO;
    for language in target_languages() {
        let mut parser = Parser::new();
        parser
            .set_language(&language)
            .expect("grammar must load for fuzz harness");
        let start = Instant::now();
        let _ = parser.parse(input, None);
        worst = worst.max(start.elapsed());
    }
    worst
}

/// Assert the parser budget on the stress grammars.
pub fn assert_parse_budget(input: &[u8]) {
    assert!(
        input.len() <= 4096,
        "fuzz harness input must remain bounded to preserve the 8GB Law"
    );
    let elapsed = max_parse_duration(input);
    assert!(
        elapsed <= PARSE_BUDGET,
        "grammar stress parser budget exceeded: {elapsed:?} > {PARSE_BUDGET:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_ascii_input_stays_within_budget() {
        assert_parse_budget(b"function demo() { return 1 + 1; }\n");
    }
}
