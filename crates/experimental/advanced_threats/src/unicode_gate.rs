//! # Unicode Gate — Zero-Allocation Invisible-Character Scanner
//!
//! Detects supply-chain attacks that exploit visually invisible Unicode sequences
//! embedded in source code to deceive reviewers (CVE-2021-42574 "Trojan Source"
//! class) or to spoof ASCII identifiers with Cyrillic homoglyphs.
//!
//! ## Threat Classes
//!
//! | Class | Codepoints | Attack vector |
//! |-------|-----------|---------------|
//! | Zero-width / invisible | U+200B–U+200F, U+FEFF, U+2060 | Hide logic inside identifiers |
//! | BiDi control characters | U+202A–U+202E, U+2066–U+2069 | Reverse rendering to mislead reviewer |
//! | Cyrillic homoglyphs | U+0430–U+0445 subset | Spoof ASCII function names |
//!
//! ## Complexity
//!
//! O(N) single pass via an [`AhoCorasick`] automaton initialized once in a
//! [`OnceLock`]. The scan loop itself performs **zero heap allocations**.
//!
//! ## Exemptions
//!
//! Translation files (`.po`, `.pot`) are unconditionally skipped — they
//! legitimately contain Unicode text in any script.

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// A confirmed invisible-Unicode or homoglyph threat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatReport {
    /// Machine-readable label: always `"security:invisible_unicode_injection"`.
    pub label: &'static str,
    /// Byte offset of the first suspicious byte in the input slice.
    pub byte_offset: usize,
    /// Human-readable description of the specific codepoint detected.
    pub description: &'static str,
}

/// Machine-readable label emitted for every Unicode threat.
pub const THREAT_LABEL: &str = "security:invisible_unicode_injection";

// ---------------------------------------------------------------------------
// Banned patterns — (UTF-8 byte sequence, description)
// ---------------------------------------------------------------------------
//
// Zero-width / invisible characters
//   U+200B ZERO WIDTH SPACE              → \xe2\x80\x8b
//   U+200C ZERO WIDTH NON-JOINER         → \xe2\x80\x8c
//   U+200D ZERO WIDTH JOINER             → \xe2\x80\x8d
//   U+200E LEFT-TO-RIGHT MARK            → \xe2\x80\x8e
//   U+200F RIGHT-TO-LEFT MARK            → \xe2\x80\x8f
//   U+FEFF ZERO WIDTH NO-BREAK SPACE     → \xef\xbb\xbf  (also BOM)
//   U+2060 WORD JOINER                   → \xe2\x81\xa0
//
// Bidirectional control characters — CVE-2021-42574 "Trojan Source"
//   U+202A LEFT-TO-RIGHT EMBEDDING       → \xe2\x80\xaa
//   U+202B RIGHT-TO-LEFT EMBEDDING       → \xe2\x80\xab
//   U+202C POP DIRECTIONAL FORMATTING    → \xe2\x80\xac
//   U+202D LEFT-TO-RIGHT OVERRIDE        → \xe2\x80\xad
//   U+202E RIGHT-TO-LEFT OVERRIDE        → \xe2\x80\xae  ← most dangerous
//   U+2066 LEFT-TO-RIGHT ISOLATE         → \xe2\x81\xa6
//   U+2067 RIGHT-TO-LEFT ISOLATE         → \xe2\x81\xa7
//   U+2068 FIRST STRONG ISOLATE          → \xe2\x81\xa8
//   U+2069 POP DIRECTIONAL ISOLATE       → \xe2\x81\xa9
//
// Cyrillic homoglyphs visually identical to ASCII (supply-chain name spoofing)
//   U+0430 'а' Cyrillic small a          → \xd0\xb0
//   U+0435 'е' Cyrillic small e          → \xd0\xb5
//   U+043E 'о' Cyrillic small o          → \xd0\xbe
//   U+0440 'р' Cyrillic small r          → \xd1\x80
//   U+0441 'с' Cyrillic small c          → \xd1\x81
//   U+0445 'х' Cyrillic small x          → \xd1\x85
//   U+0456 'і' Cyrillic small i          → \xd1\x96
//   U+0410 'А' Cyrillic capital A        → \xd0\x90
//   U+0415 'Е' Cyrillic capital E        → \xd0\x95
//   U+041E 'О' Cyrillic capital O        → \xd0\x9e
//   U+0420 'Р' Cyrillic capital R        → \xd0\xa0
//   U+0421 'С' Cyrillic capital C        → \xd0\xa1
//   U+0425 'Х' Cyrillic capital X        → \xd0\xa5

static PATTERNS: &[(&[u8], &str)] = &[
    // Zero-width / invisible
    (b"\xe2\x80\x8b", "U+200B ZERO WIDTH SPACE"),
    (b"\xe2\x80\x8c", "U+200C ZERO WIDTH NON-JOINER"),
    (b"\xe2\x80\x8d", "U+200D ZERO WIDTH JOINER"),
    (b"\xe2\x80\x8e", "U+200E LEFT-TO-RIGHT MARK"),
    (b"\xe2\x80\x8f", "U+200F RIGHT-TO-LEFT MARK"),
    (b"\xef\xbb\xbf", "U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)"),
    (b"\xe2\x81\xa0", "U+2060 WORD JOINER"),
    // BiDi controls — Trojan Source
    (b"\xe2\x80\xaa", "U+202A LEFT-TO-RIGHT EMBEDDING"),
    (b"\xe2\x80\xab", "U+202B RIGHT-TO-LEFT EMBEDDING"),
    (b"\xe2\x80\xac", "U+202C POP DIRECTIONAL FORMATTING"),
    (b"\xe2\x80\xad", "U+202D LEFT-TO-RIGHT OVERRIDE"),
    (b"\xe2\x80\xae", "U+202E RIGHT-TO-LEFT OVERRIDE"),
    (b"\xe2\x81\xa6", "U+2066 LEFT-TO-RIGHT ISOLATE"),
    (b"\xe2\x81\xa7", "U+2067 RIGHT-TO-LEFT ISOLATE"),
    (b"\xe2\x81\xa8", "U+2068 FIRST STRONG ISOLATE"),
    (b"\xe2\x81\xa9", "U+2069 POP DIRECTIONAL ISOLATE"),
    // Cyrillic homoglyphs
    (b"\xd0\xb0", "U+0430 Cyrillic 'а' (homoglyph of ASCII 'a')"),
    (b"\xd0\xb5", "U+0435 Cyrillic 'е' (homoglyph of ASCII 'e')"),
    (b"\xd0\xbe", "U+043E Cyrillic 'о' (homoglyph of ASCII 'o')"),
    (b"\xd1\x80", "U+0440 Cyrillic 'р' (homoglyph of ASCII 'r')"),
    (b"\xd1\x81", "U+0441 Cyrillic 'с' (homoglyph of ASCII 'c')"),
    (b"\xd1\x85", "U+0445 Cyrillic 'х' (homoglyph of ASCII 'x')"),
    (b"\xd1\x96", "U+0456 Cyrillic 'і' (homoglyph of ASCII 'i')"),
    (b"\xd0\x90", "U+0410 Cyrillic 'А' (homoglyph of ASCII 'A')"),
    (b"\xd0\x95", "U+0415 Cyrillic 'Е' (homoglyph of ASCII 'E')"),
    (b"\xd0\x9e", "U+041E Cyrillic 'О' (homoglyph of ASCII 'O')"),
    (b"\xd0\xa0", "U+0420 Cyrillic 'Р' (homoglyph of ASCII 'R')"),
    (b"\xd0\xa1", "U+0421 Cyrillic 'С' (homoglyph of ASCII 'C')"),
    (b"\xd0\xa5", "U+0425 Cyrillic 'Х' (homoglyph of ASCII 'X')"),
];

// ---------------------------------------------------------------------------
// AhoCorasick automaton (initialized once, zero-alloc hot path)
// ---------------------------------------------------------------------------

static UNICODE_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn automaton() -> &'static AhoCorasick {
    UNICODE_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(PATTERNS.iter().map(|(pat, _)| pat))
            .expect("unicode gate automaton construction must succeed")
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `data` for invisible-Unicode or Cyrillic-homoglyph attack sequences.
///
/// Returns the **first** [`ThreatReport`] found, or `None` if the payload is
/// clean.  Translation files (`.po`, `.pot`) are unconditionally exempted.
///
/// # Complexity
/// O(N) in the length of `data`.  Zero heap allocations in the scan loop.
pub fn scan(data: &[u8], filename: &str) -> Option<ThreatReport> {
    // Translation files legitimately contain Unicode in any script.
    if filename.ends_with(".po") || filename.ends_with(".pot") {
        return None;
    }

    let ac = automaton();
    // find_iter allocates no heap — it yields Match structs by value.
    if let Some(m) = ac.find_iter(data).next() {
        let idx = m.pattern().as_usize();
        return Some(ThreatReport {
            label: THREAT_LABEL,
            byte_offset: m.start(),
            description: PATTERNS[idx].1,
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zero_width_space_in_python() {
        // U+200B injected inside a function name — invisible to reviewers.
        let src = b"def foo\xe2\x80\x8bbar():\n    return 42\n";
        let report = scan(src, "script.py").expect("must detect U+200B");
        assert_eq!(report.label, THREAT_LABEL);
        assert_eq!(report.byte_offset, 7);
        assert!(report.description.contains("U+200B"));
    }

    #[test]
    fn detects_rlo_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — the canonical Trojan Source vector.
        let src = b"/* \xe2\x80\xae begin evil */";
        let report = scan(src, "main.c").expect("must detect U+202E");
        assert!(report.description.contains("202E"));
    }

    #[test]
    fn detects_cyrillic_homoglyph() {
        // Cyrillic 'а' (U+0430) substituted for ASCII 'a' in an identifier.
        let src = b"def v\xd0\xb0lidate():\n    pass\n";
        let report = scan(src, "auth.py").expect("must detect Cyrillic homoglyph");
        assert!(report.description.contains("U+0430"));
    }

    #[test]
    fn po_file_is_exempt() {
        // Translation files must not be flagged regardless of content.
        let src = b"msgstr \"\xe2\x80\x8b\xe2\x80\xae\"\n";
        assert!(
            scan(src, "messages.po").is_none(),
            ".po files must be unconditionally exempt"
        );
    }

    #[test]
    fn pot_file_is_exempt() {
        let src = b"msgid \"\xe2\x80\x8b\"\n";
        assert!(
            scan(src, "template.pot").is_none(),
            ".pot files must be unconditionally exempt"
        );
    }

    #[test]
    fn clean_ascii_source_is_not_flagged() {
        let src = b"fn add(a: u32, b: u32) -> u32 { a + b }\n";
        assert!(
            scan(src, "lib.rs").is_none(),
            "clean ASCII must not trigger"
        );
    }

    #[test]
    fn reports_earliest_byte_offset() {
        // Two threats: U+200B at offset 4, Cyrillic 'а' at offset 8.
        // Gate must report the leftmost one (offset 4).
        let src = b"foo\xe2\x80\x8bbar\xd0\xb0baz";
        let report = scan(src, "test.py").expect("must detect");
        assert_eq!(report.byte_offset, 3);
    }
}
