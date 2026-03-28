//! # API Migration Guard
//!
//! Detects deprecated API usage when a dependency is bumped across a major
//! version boundary in the same patch.
//!
//! ## How it works
//!
//! [`scan_migration_regressions`] inspects a unified diff for:
//!
//! 1. **Version bump signal** — a `Cargo.toml` or `Cargo.lock` section showing
//!    the dependency removed at `from_major.x` and added at `to_major.x`.
//! 2. **Forbidden pattern scan** — if and only if the bump is detected, added
//!    lines in `.rs` files are scanned with AhoCorasick for API patterns that
//!    were removed or changed in the new major version.
//!
//! The guard fires **only** when both conditions are true.  A dependency bump
//! with no forbidden patterns produces no findings.  Code that uses deprecated
//! patterns without a version bump is not flagged — the patterns may be
//! intentional in the old API.
//!
//! ## Active rules
//!
//! | Dep   | From | To | Forbidden patterns                          |
//! |-------|------|----|---------------------------------------------|
//! | ureq  | 2    | 3  | `.set(`, `.timeout(`, `Error::Status`       |
//!
//! ## Severity
//!
//! Each match contributes 50 pts (`Critical` tier) — a breaking API regression
//! that will fail to compile post-bump is equivalent in severity to a memory-
//! unsafe C call or an open CIDR rule.

use aho_corasick::AhoCorasick;

// ---------------------------------------------------------------------------
// DepMigrationRule
// ---------------------------------------------------------------------------

/// A rule that activates when a dependency is bumped across a major version boundary.
pub struct DepMigrationRule {
    /// Dependency name as it appears in `Cargo.toml` / `Cargo.lock`.
    pub dep_name: &'static str,
    /// The major version being replaced (bumped FROM).
    pub from_major: u64,
    /// The major version being adopted (bumped TO).
    pub to_major: u64,
    /// API call patterns that were valid in `from_major` but are removed or
    /// renamed in `to_major`.  Used to build the AhoCorasick automaton.
    pub forbidden_patterns: &'static [&'static str],
}

/// The canonical set of active migration rules.
///
/// Extend this slice to add support for new dependency version boundaries.
/// Each rule is a zero-cost `&'static` reference — no heap allocation at
/// module load time.
pub static MIGRATION_RULES: &[DepMigrationRule] = &[
    // ── ureq 2 → 3 ──────────────────────────────────────────────────────────
    // ureq 3.0 removed the `.set()` header builder, the `.timeout()` builder,
    // and the `ureq::Error::Status` variant (replaced by `Error::StatusCode`).
    // Code retaining these call sites after the bump will fail to compile.
    DepMigrationRule {
        dep_name: "ureq",
        from_major: 2,
        to_major: 3,
        forbidden_patterns: &[".set(", ".timeout(", "Error::Status"],
    },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan a unified diff for API migration regressions.
///
/// Returns one human-readable finding string per forbidden pattern match.
/// Returns an empty `Vec` when no active migration rule fires.
///
/// # Arguments
/// - `patch`: a unified diff (`git diff` / `gh pr diff` output).
///
/// # Finding format
/// `"migration:<dep> `<pattern>` (added line <n>)"`
pub fn scan_migration_regressions(patch: &str) -> Vec<String> {
    let mut findings: Vec<String> = Vec::new();

    for rule in MIGRATION_RULES {
        if !detect_major_bump(patch, rule) {
            continue;
        }

        // Build AhoCorasick automaton from this rule's forbidden patterns.
        // `expect` is safe: patterns are static string literals validated at
        // compile time — they are never empty and always valid.
        let ac = AhoCorasick::new(rule.forbidden_patterns)
            .expect("migration guard: static patterns must compile");

        // Scan only added (+) lines inside Rust source sections.
        let mut in_rust_file = false;
        let mut added_line: u32 = 0;

        for line in patch.lines() {
            if line.starts_with("diff ") {
                // `diff --git a/path/foo.rs b/path/foo.rs` — b-path is the
                // last token; checking `ends_with` on the full line is safe.
                in_rust_file = line.ends_with(".rs");
                added_line = 0;
                continue;
            }
            if !in_rust_file {
                continue;
            }
            if line.starts_with("@@") {
                added_line = 0;
                continue;
            }
            if line.starts_with('+') && !line.starts_with("+++") {
                let src = &line[1..];
                for mat in ac.find_iter(src) {
                    let pattern = rule.forbidden_patterns[mat.pattern().as_usize()];
                    findings.push(format!(
                        "migration:{} `{}` (added line {})",
                        rule.dep_name, pattern, added_line,
                    ));
                }
                added_line += 1;
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Internal: version-bump detection
// ---------------------------------------------------------------------------

/// Returns `true` when the diff shows `dep_name` bumped from `from_major.x`
/// to `to_major.x` within a `Cargo.toml` or `Cargo.lock` section.
///
/// Handles two formats:
///
/// **Cargo.toml inline** (version on same line as dep name):
/// ```toml
/// -ureq = { version = "2", features = ["json"] }
/// +ureq = { version = "3", features = ["json"] }
/// ```
///
/// **Cargo.lock multi-line** (`name` and `version` on separate lines):
/// ```toml
/// -name = "ureq"
/// -version = "2.10.1"
/// +name = "ureq"
/// +version = "3.0.0"
/// ```
fn detect_major_bump(patch: &str, rule: &DepMigrationRule) -> bool {
    // Pre-compute version prefix strings once per rule invocation.
    let from_ver = format!("\"{}.", rule.from_major);
    let to_ver = format!("\"{}.", rule.to_major);
    let dep_key = format!("\"{}\"", rule.dep_name);

    let mut in_cargo = false;
    let mut saw_old = false;
    let mut saw_new = false;
    // State for Cargo.lock's multi-line `name = "x"\nversion = "y"` format.
    let mut rem_dep = false; // just saw  `-name = "dep"`
    let mut add_dep = false; // just saw  `+name = "dep"`

    for line in patch.lines() {
        if line.starts_with("diff ") {
            in_cargo = line.contains("Cargo.toml") || line.contains("Cargo.lock");
            rem_dep = false;
            add_dep = false;
            continue;
        }
        if !in_cargo {
            continue;
        }

        let is_add = line.starts_with('+') && !line.starts_with("+++");
        let is_rem = line.starts_with('-') && !line.starts_with("---");
        // Context lines are irrelevant — skip them to avoid false state resets.
        let body = if is_add || is_rem {
            &line[1..]
        } else {
            continue;
        };

        if body.contains(rule.dep_name) {
            // ── Cargo.toml inline: `dep_name = "2.x"` ──────────────────────
            if is_rem && body.contains(&from_ver) {
                saw_old = true;
            }
            if is_add && body.contains(&to_ver) {
                saw_new = true;
            }
            // ── Cargo.lock `name = "dep"` line ─────────────────────────────
            let trimmed = body.trim();
            if trimmed.starts_with("name") && trimmed.contains(&dep_key) {
                rem_dep = is_rem;
                add_dep = is_add;
            }
        } else {
            // ── Cargo.lock `version = "x.y.z"` line (follows name line) ────
            let trimmed = body.trim();
            if trimmed.starts_with("version") {
                if rem_dep && is_rem && trimmed.contains(&from_ver) {
                    saw_old = true;
                }
                if add_dep && is_add && trimmed.contains(&to_ver) {
                    saw_new = true;
                }
                rem_dep = false;
                add_dep = false;
            } else if !body.trim().is_empty() {
                // Any other added/removed content resets the name-pending state.
                rem_dep = false;
                add_dep = false;
            }
        }
    }

    saw_old && saw_new
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// No Cargo.lock change — migration guard must be silent.
    #[test]
    fn test_no_cargo_change_no_findings() {
        let patch = r#"diff --git a/src/main.rs b/src/main.rs
--- a/src/main.rs
+++ b/src/main.rs
@@ -1,3 +1,4 @@
 fn main() {}
+    let resp = agent.get("http://example.com").call().unwrap();
"#;
        assert!(scan_migration_regressions(patch).is_empty());
    }

    /// ureq 2→3 bump in Cargo.toml inline form + forbidden patterns in Rust source.
    #[test]
    fn test_ureq_v3_inline_bump_flags_deprecated_api() {
        let patch = r#"diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -5,1 +5,1 @@
-ureq = { version = "2.10", features = ["json"] }
+ureq = { version = "3.0", features = ["json"] }
diff --git a/src/client.rs b/src/client.rs
--- a/src/client.rs
+++ b/src/client.rs
@@ -1,3 +1,5 @@
 use ureq;
+fn call() {
+    let resp = ureq::agent().get(url).set("X-Token", token).call();
+    match err { ureq::Error::Status(code, _) => {} }
+}
"#;
        let findings = scan_migration_regressions(patch);
        assert!(
            !findings.is_empty(),
            "deprecated ureq 2 API must be flagged"
        );
        assert!(
            findings.iter().any(|f| f.contains(".set(")),
            "`.set(` must be flagged"
        );
        assert!(
            findings.iter().any(|f| f.contains("Error::Status")),
            "`Error::Status` must be flagged"
        );
    }

    /// ureq 2→3 bump in Cargo.lock multi-line form + deprecated patterns.
    #[test]
    fn test_ureq_v3_lockfile_bump_flags_deprecated_api() {
        let patch = r#"diff --git a/Cargo.lock b/Cargo.lock
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -10,6 +10,6 @@
 [[package]]
-name = "ureq"
-version = "2.10.1"
+name = "ureq"
+version = "3.0.0"
 source = "registry+https://github.com/rust-lang/crates.io-index"
diff --git a/src/http.rs b/src/http.rs
--- a/src/http.rs
+++ b/src/http.rs
@@ -1,2 +1,3 @@
 use ureq;
+    let _ = req.timeout(std::time::Duration::from_secs(5));
"#;
        let findings = scan_migration_regressions(patch);
        assert!(
            findings.iter().any(|f| f.contains(".timeout(")),
            "`.timeout(` must be flagged after Cargo.lock ureq 2→3 bump"
        );
    }

    /// ureq 2→3 bump detected but no deprecated patterns in added Rust code.
    #[test]
    fn test_ureq_v3_bump_no_forbidden_patterns_is_clean() {
        let patch = r#"diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -5,1 +5,1 @@
-ureq = { version = "2.10", features = ["json"] }
+ureq = { version = "3.0", features = ["json"] }
diff --git a/src/client.rs b/src/client.rs
--- a/src/client.rs
+++ b/src/client.rs
@@ -1,2 +1,3 @@
 use ureq;
+    let resp = ureq::get("http://example.com").call().unwrap();
"#;
        assert!(
            scan_migration_regressions(patch).is_empty(),
            "new ureq v3 API with no deprecated calls must be clean"
        );
    }

    /// ureq stays at 2.x — deprecated patterns in Rust source must NOT be flagged.
    #[test]
    fn test_ureq_v2_unchanged_no_findings() {
        let patch = r#"diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -5,1 +5,1 @@
-ureq = { version = "2.9", features = ["json"] }
+ureq = { version = "2.10", features = ["json"] }
diff --git a/src/client.rs b/src/client.rs
--- a/src/client.rs
+++ b/src/client.rs
@@ -1,2 +1,3 @@
 use ureq;
+    let resp = req.set("X-Token", token).call();
"#;
        assert!(
            scan_migration_regressions(patch).is_empty(),
            "ureq 2.9→2.10 patch-level bump must not trigger migration guard"
        );
    }
}
