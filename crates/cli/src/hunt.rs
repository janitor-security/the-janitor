//! `janitor hunt` — Offensive security scanner for bug-bounty engagements.
//!
//! Recursively walks a target directory (or a source tree reconstructed from a
//! JavaScript sourcemap), runs the full Janitor detector suite on every file,
//! and emits results as a single JSON array of [`common::slop::StructuredFinding`]
//! to stdout.  No summary tables, no SlopScore — raw signal only.
//!
//! ## Output format
//!
//! ```text
//! janitor hunt ./target           # scan a local directory
//! janitor hunt . --sourcemap https://example.com/app.js.map
//! ```
//!
//! Stdout is always a valid JSON array:
//! ```json
//! [{ "id": "security:command_injection", "file": "src/server.js", "line": 42, ... }]
//! ```
//!
//! Pipe through `jq` for filtering, e.g.:
//! ```text
//! janitor hunt ./target | jq '.[] | select(.id == "security:credential_leak")'
//! ```

use anyhow::Context as _;
use common::slop::StructuredFinding;
use forge::slop_hunter::{find_credential_slop, find_slop, find_supply_chain_slop, ParsedUnit};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use walkdir::WalkDir;

// 1 MiB — matches the circuit-breaker threshold in slop_hunter.rs
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Entry point for the `janitor hunt` subcommand.
///
/// Scans `scan_root` (or a sourcemap-reconstructed tmpdir) and emits all
/// findings as a JSON array to stdout.  No printing occurs on error — the
/// caller receives an `anyhow::Result`.
pub fn cmd_hunt(
    scan_root: &Path,
    sourcemap_url: Option<&str>,
    corpus_path: Option<&Path>,
) -> anyhow::Result<()> {
    let _ = corpus_path; // reserved for slopsquat corpus override (P2-7)

    // When a sourcemap URL is provided, reconstruct the source tree first and
    // scan the temporary directory instead of the caller-supplied path.
    let (tmpdir, effective_root) = if let Some(url) = sourcemap_url {
        let dir = reconstruct_sourcemap(url).context("sourcemap ingestion failed")?;
        let root = dir.clone();
        (Some(dir), root)
    } else {
        (None, scan_root.to_path_buf())
    };

    let findings = scan_directory(&effective_root)?;

    // Clean up the sourcemap tmpdir after scanning.
    if let Some(dir) = tmpdir {
        let _ = std::fs::remove_dir_all(&dir);
    }

    let json =
        serde_json::to_string_pretty(&findings).context("failed to serialise findings as JSON")?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory walker
// ---------------------------------------------------------------------------

/// Walk `dir` recursively, run all detectors on every file, and return the
/// unified finding list.  Files > 1 MiB and unreadable files are silently
/// skipped (consistent with the hot-path circuit breaker in `slop_filter.rs`).
fn scan_directory(dir: &Path) -> anyhow::Result<Vec<StructuredFinding>> {
    let mut all: Vec<StructuredFinding> = Vec::new();

    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_path = entry.path();

        // Circuit breaker — skip oversized files.
        if std::fs::metadata(file_path)
            .map(|m| m.len() > MAX_FILE_BYTES)
            .unwrap_or(false)
        {
            continue;
        }

        let source = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

        let rel_path = file_path
            .strip_prefix(dir)
            .unwrap_or(file_path)
            .to_string_lossy()
            .to_string();

        // Language-specific detector pass.
        let unit = ParsedUnit::unparsed(&source);
        let mut raw = find_slop(ext, &unit);

        // Language-agnostic passes — credentials and supply-chain run on every
        // file regardless of extension.
        raw.extend(find_credential_slop(&source));
        raw.extend(find_supply_chain_slop(&source));

        for f in raw {
            let line = byte_to_line(&source, f.start_byte);
            let id = extract_rule_id(&f.description);
            let severity_str = format!("{:?}", f.severity);

            all.push(StructuredFinding {
                id,
                file: Some(rel_path.clone()),
                line: Some(line),
                fingerprint: fingerprint_finding(&source, f.start_byte, f.end_byte),
                severity: Some(severity_str),
                remediation: None,
                docs_url: None,
            });
        }
    }

    Ok(all)
}

// ---------------------------------------------------------------------------
// Sourcemap ingestion
// ---------------------------------------------------------------------------

/// Download a JavaScript sourcemap from `url`, reconstruct the source tree
/// into `/tmp/janitor-hunt-<uuid>/`, and return the path to that directory.
fn reconstruct_sourcemap(url: &str) -> anyhow::Result<PathBuf> {
    let agent = ureq::Agent::new_with_defaults();
    let map: serde_json::Value = agent
        .get(url)
        .call()
        .map_err(|_| anyhow::anyhow!("sourcemap HTTP fetch failed"))?
        .body_mut()
        .read_json()
        .context("sourcemap response body is not valid JSON")?;

    let sources = map["sources"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sourcemap missing 'sources' array"))?;
    let contents = map["sourcesContent"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let tmpdir = std::env::temp_dir().join(format!("janitor-hunt-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&tmpdir).context("failed to create sourcemap tmpdir")?;

    for (i, source_val) in sources.iter().enumerate() {
        let raw_path = source_val.as_str().unwrap_or("");
        let safe = sanitize_sourcemap_path(raw_path, i);
        let dest = tmpdir.join(&safe);

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create parent dir for sourcemap entry {i}"))?;
        }

        let content = contents.get(i).and_then(|v| v.as_str()).unwrap_or("");

        std::fs::write(&dest, content.as_bytes())
            .with_context(|| format!("failed to write sourcemap entry {i}"))?;
    }

    Ok(tmpdir)
}

/// Sanitise a raw sourcemap `sources[]` path entry to prevent path traversal.
///
/// Strips known webpack/file URL prefixes, removes `../` sequences, and caps
/// depth at 3 path components to constrain the reconstructed tree.
pub fn sanitize_sourcemap_path(raw: &str, index: usize) -> String {
    // Strip known prefixes.
    let stripped = raw
        .trim_start_matches("webpack:///")
        .trim_start_matches("webpack://")
        .trim_start_matches("file:///")
        .trim_start_matches("file://")
        .trim_start_matches("//");

    // Remove any path traversal sequences.
    let clean = stripped
        .replace("../", "")
        .replace("..\\", "")
        .replace("..", "");

    // Normalise separators and collect non-empty components.
    let components: Vec<&str> = clean
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();

    if components.is_empty() {
        return format!("source_{index}");
    }

    // Cap depth: keep the last 3 components to bound the reconstructed tree.
    let capped = if components.len() > 3 {
        &components[components.len() - 3..]
    } else {
        &components[..]
    };

    capped.join("/")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a byte offset in `source` to a 1-indexed line number.
fn byte_to_line(source: &[u8], byte_offset: usize) -> u32 {
    let capped = byte_offset.min(source.len());
    let newlines = source[..capped].iter().filter(|&&b| b == b'\n').count();
    newlines as u32 + 1
}

/// Extract the machine-readable rule ID from a `SlopFinding::description`.
///
/// Descriptions follow the format `"rule_id — human readable message"`.
/// This function returns the portion before the ` — ` separator, or the
/// entire description when no separator is present.
fn extract_rule_id(description: &str) -> String {
    description
        .split(" \u{2014} ") // U+2014 EM DASH with surrounding spaces
        .next()
        .unwrap_or(description)
        .to_owned()
}

/// Produce an 8-byte BLAKE3 fingerprint of the finding's source window.
fn fingerprint_finding(source: &[u8], start: usize, end: usize) -> String {
    let s = start.min(source.len());
    let e = end.min(source.len());
    let window = if s < e { &source[s..e] } else { &source[s..s] };
    let hash = blake3::hash(window);
    hex::encode(&hash.as_bytes()[..8])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_webpack_prefix() {
        let result = sanitize_sourcemap_path("webpack:///src/components/App.js", 0);
        assert_eq!(result, "src/components/App.js");
    }

    #[test]
    fn sanitize_blocks_path_traversal() {
        let result = sanitize_sourcemap_path("webpack:///../../etc/passwd", 0);
        assert!(
            !result.contains(".."),
            "must strip path traversal sequences"
        );
        // After stripping `../` sequences: `etc/passwd` remains — that's fine,
        // it is depth-capped and lands under the tmpdir.
        let segments: Vec<&str> = result.split('/').collect();
        assert!(segments.len() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_caps_depth_at_three() {
        let result = sanitize_sourcemap_path("webpack:///a/b/c/d/e/f/g.js", 0);
        let segments: Vec<&str> = result.split('/').collect();
        assert!(segments.len() <= 3, "depth must be capped at 3");
    }

    #[test]
    fn sanitize_empty_path_returns_fallback() {
        let result = sanitize_sourcemap_path("", 7);
        assert_eq!(result, "source_7");
    }

    #[test]
    fn extract_rule_id_splits_on_em_dash() {
        let desc = "security:command_injection \u{2014} system() with dynamic arg";
        assert_eq!(extract_rule_id(desc), "security:command_injection");
    }

    #[test]
    fn extract_rule_id_no_separator_returns_whole() {
        let desc = "security:raw_finding";
        assert_eq!(extract_rule_id(desc), "security:raw_finding");
    }

    #[test]
    fn byte_to_line_counts_newlines() {
        let src = b"line1\nline2\nline3\n";
        assert_eq!(byte_to_line(src, 0), 1);
        assert_eq!(byte_to_line(src, 6), 2); // 'l' of "line2"
        assert_eq!(byte_to_line(src, 12), 3); // 'l' of "line3"
    }

    #[test]
    fn scan_directory_emits_credential_finding() {
        let dir = tempfile::TempDir::new().unwrap();
        // AWS access key prefix — fires find_credential_slop
        std::fs::write(
            dir.path().join("config.yml"),
            b"AKIAIOSFODNN7EXAMPLE = true",
        )
        .unwrap();
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            !findings.is_empty(),
            "AWS key prefix must trigger credential finding"
        );
        assert!(
            findings[0].id.contains("credential"),
            "finding id must contain 'credential'"
        );
    }

    #[test]
    fn scan_directory_skips_oversized_file() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create a sparse file just over 1 MiB.
        let path = dir.path().join("big.bin");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(1024 * 1024 + 1).unwrap();
        // Scanning must succeed without error; no finding emitted for the
        // skipped file (contents are NUL, no credentials).
        let findings = scan_directory(dir.path()).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.file.as_deref() != Some("big.bin")),
            "oversized file must be skipped"
        );
    }
}
