//! Defensive delayed-memory poisoning fixtures.
//!
//! This module models the shape of time-delayed RAG poisoning attempts without
//! emitting operative instructions that would corrupt later retrievals or
//! exfiltrate private prompts. The generated blocks are syntactically valid
//! fixtures for detector and honeypot tests only.

/// Supported syntactic envelopes for defensive memory-bomb fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBombLanguage {
    /// Python module-level docstring.
    Python,
    /// JavaScript exported configuration object.
    JavaScript,
    /// Kotlin generic configuration array.
    Kotlin,
}

/// High-level adversarial family represented by an inert fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBombFamily {
    /// Attempts to alter future orchestration decisions.
    OrchestrationDrift,
    /// Attempts to weaken retrieval-time policy gates.
    PolicyErosion,
    /// Attempts to induce hidden tool use.
    HiddenToolInvocation,
}

impl MemoryBombFamily {
    fn label(self) -> &'static str {
        match self {
            Self::OrchestrationDrift => "orchestration_drift",
            Self::PolicyErosion => "policy_erosion",
            Self::HiddenToolInvocation => "hidden_tool_invocation",
        }
    }
}

/// Defensive fixture request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBombFixture {
    /// Syntactic envelope to render.
    pub language: MemoryBombLanguage,
    /// Adversarial family being simulated.
    pub family: MemoryBombFamily,
    /// Retrieval keyword used by tests to model delayed activation proximity.
    pub trigger_keyword: String,
}

impl MemoryBombFixture {
    /// Create a fixture request.
    pub fn new(
        language: MemoryBombLanguage,
        family: MemoryBombFamily,
        trigger_keyword: impl Into<String>,
    ) -> Self {
        Self {
            language,
            family,
            trigger_keyword: trigger_keyword.into(),
        }
    }
}

/// Render an inert, syntactically valid fixture for defensive tests.
///
/// The rendered content intentionally contains no operational prompt-injection
/// command. It only preserves metadata needed for deterministic detector tests:
/// delayed trigger keyword, adversarial family, and explicit inert status.
pub fn render_inert_fixture(fixture: &MemoryBombFixture) -> String {
    let keyword = sanitize_fixture_text(&fixture.trigger_keyword);
    let family = fixture.family.label();
    match fixture.language {
        MemoryBombLanguage::Python => format!(
            "\"\"\"\njanitor_memory_bomb_fixture = {{\n  \"family\": \"{family}\",\n  \"trigger_keyword\": \"{keyword}\",\n  \"status\": \"inert_defensive_fixture\"\n}}\n\"\"\"\n"
        ),
        MemoryBombLanguage::JavaScript => format!(
            "export const janitorMemoryBombFixture = Object.freeze({{\n  family: \"{family}\",\n  triggerKeyword: \"{keyword}\",\n  status: \"inert_defensive_fixture\"\n}});\n"
        ),
        MemoryBombLanguage::Kotlin => format!(
            "val janitorMemoryBombFixture = arrayOf(\n    \"family={family}\",\n    \"trigger_keyword={keyword}\",\n    \"status=inert_defensive_fixture\",\n)\n"
        ),
    }
}

/// Detect Janitor's inert delayed-memory fixture marker.
pub fn contains_inert_memory_bomb_fixture(source: &[u8]) -> bool {
    let has_status = source
        .windows(b"inert_defensive_fixture".len())
        .any(|w| w == b"inert_defensive_fixture");
    let has_python_marker = source
        .windows(b"janitor_memory_bomb_fixture".len())
        .any(|w| w == b"janitor_memory_bomb_fixture");
    let has_js_or_kotlin_marker = source
        .windows(b"janitorMemoryBombFixture".len())
        .any(|w| w == b"janitorMemoryBombFixture");
    has_status && (has_python_marker || has_js_or_kotlin_marker)
}

fn sanitize_fixture_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':'))
        .take(96)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_fixture_is_inert_and_detectable() {
        let fixture = MemoryBombFixture::new(
            MemoryBombLanguage::Python,
            MemoryBombFamily::PolicyErosion,
            "auth-flow",
        );
        let rendered = render_inert_fixture(&fixture);
        assert!(rendered.starts_with("\"\"\""));
        assert!(rendered.contains("inert_defensive_fixture"));
        assert!(contains_inert_memory_bomb_fixture(rendered.as_bytes()));
    }

    #[test]
    fn fixture_sanitizes_trigger_keyword() {
        let fixture = MemoryBombFixture::new(
            MemoryBombLanguage::JavaScript,
            MemoryBombFamily::HiddenToolInvocation,
            "admin tools\"; process.env.SECRET",
        );
        let rendered = render_inert_fixture(&fixture);
        assert!(!rendered.contains("process.env"));
        assert!(rendered.contains("admintools"));
    }
}
