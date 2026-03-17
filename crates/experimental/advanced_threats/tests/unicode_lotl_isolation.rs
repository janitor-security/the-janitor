//! # Unicode + LotL Isolation Tests
//!
//! End-to-end scenario tests for the two new threat detectors.
//! Each test constructs a minimal synthetic scenario and asserts the detector
//! produces the expected verdict.  No external files, no network calls.
//!
//! ## Performance Contract
//!
//! `test_unicode_gate_1mb_under_2ms` enforces the hard latency ceiling:
//! the Unicode gate **must** scan a 1 MiB payload in under 2 milliseconds
//! on a single core.  This validates the O(N) AhoCorasick implementation.

use advanced_threats::{
    lotl_hunter::{self, LOTL_LABEL},
    unicode_gate::{self, THREAT_LABEL},
};

// ---------------------------------------------------------------------------
// Unicode Gate — Scenario Tests
// ---------------------------------------------------------------------------

/// A Python function name containing a hidden U+200B (Zero-Width Space) must
/// be caught instantly by the gate.
///
/// Attack vector: a malicious contributor inserts `\xe2\x80\x8b` between
/// characters of a function name.  The resulting identifier looks identical
/// to the legitimate name in all common editors and diff viewers, but
/// evaluates differently in some Python version edge-cases and always
/// constitutes invisible deception.
#[test]
fn unicode_gate_catches_zero_width_space_in_python_function_name() {
    // "def foo<U+200B>bar():" — the ZWSP is invisible in most renderers.
    let python_source = b"def foo\xe2\x80\x8bbar():\n    return 42\n";

    let report = unicode_gate::scan(python_source, "auth.py")
        .expect("unicode gate must detect U+200B in Python function name");

    assert_eq!(
        report.label, THREAT_LABEL,
        "label must be security:invisible_unicode_injection"
    );
    assert_eq!(
        report.byte_offset, 7,
        "threat must be reported at byte offset 7 (position of \\xe2)"
    );
    assert!(
        report.description.contains("U+200B"),
        "description must identify U+200B, got: {}",
        report.description
    );
}

/// A Rust identifier containing the Cyrillic 'о' (U+043E) substituted for
/// the ASCII 'o' must be flagged as a homoglyph attack.
#[test]
fn unicode_gate_catches_cyrillic_homoglyph_in_rust_identifier() {
    // "fn c\xd0\xbennect()" — Cyrillic 'о' at position 4 looks like ASCII 'o'.
    let rust_source = b"fn c\xd0\xbennect() {\n    todo!()\n}\n";

    let report = unicode_gate::scan(rust_source, "net.rs")
        .expect("unicode gate must detect Cyrillic homoglyph in Rust identifier");

    assert_eq!(report.label, THREAT_LABEL);
    assert!(
        report.description.contains("U+043E"),
        "must identify Cyrillic 'о', got: {}",
        report.description
    );
}

/// A Trojan Source BiDi injection using U+202E (RIGHT-TO-LEFT OVERRIDE)
/// inside a C comment must be detected.
///
/// CVE-2021-42574: placing a BiDi override before a `*/` inside a string
/// literal makes reviewers see a comment closure that the compiler ignores.
#[test]
fn unicode_gate_catches_bidi_rlo_in_c_comment() {
    // The \xe2\x80\xae is U+202E (RIGHT-TO-LEFT OVERRIDE).
    let c_source = b"/* access \xe2\x80\xae \"check\" */ if (is_admin) {";

    let report = unicode_gate::scan(c_source, "auth.c")
        .expect("unicode gate must detect U+202E BiDi override");

    assert!(
        report.description.contains("202E"),
        "must identify RLO, got: {}",
        report.description
    );
}

/// Translation files (.po) must be unconditionally exempt, even when they
/// contain the full catalogue of banned codepoints.
#[test]
fn unicode_gate_exempts_po_translation_files() {
    // Every banned codepoint class present — the gate must still return None.
    let po_source = b"msgid \"test\"\nmsgstr \"\xe2\x80\x8b\xe2\x80\xae\xd0\xb0\xd1\x81\"\n";

    assert!(
        unicode_gate::scan(po_source, "locale/ru/messages.po").is_none(),
        ".po files must be unconditionally exempt from the Unicode gate"
    );
}

/// Files with only clean ASCII must not produce any report.
#[test]
fn unicode_gate_passes_clean_ascii_patch() {
    let patch = b"--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,3 +1,4 @@\n+pub fn new_fn() {}\n";
    assert!(
        unicode_gate::scan(patch, "patch.diff").is_none(),
        "clean ASCII patch must not trigger"
    );
}

// ---------------------------------------------------------------------------
// LotL Hunter — Scenario Tests
// ---------------------------------------------------------------------------

/// A YAML CI file embedding an obfuscated Bash execution string
/// (`echo <b64> | base64 -d | bash`) must be flagged as a LotL anomaly.
///
/// This is a realistic GitHub Actions / GitLab CI injection pattern where an
/// attacker replaces a build step's `run:` value with a payload that downloads
/// and executes an arbitrary binary in the runner.
#[test]
fn lotl_hunter_catches_base64_exec_in_yaml_ci() {
    // Realistic YAML CI payload with a base64-encoded execution chain.
    let yaml_ci = b"\
- name: Install dependencies\n\
  run: pip install -r requirements.txt\n\
- name: Configure\n\
  run: echo SGVsbG8gV29ybGQ= | base64 -d | bash\n\
";

    let report = lotl_hunter::scan(yaml_ci, "ci.yml")
        .expect("LotL hunter must flag base64 decode-exec in YAML");

    assert_eq!(
        report.label, LOTL_LABEL,
        "label must be security:lotl_execution_anomaly"
    );
    assert!(
        report.technique.contains("base64"),
        "technique must reference base64 decode-exec, got: {}",
        report.technique
    );
}

/// A shell script that directly executes a binary from `/tmp/` must be flagged
/// by the structural AST layer.
///
/// This LotL vector is commonly used to stage a downloaded implant in
/// `/tmp/` or `/dev/shm/` and then execute it from a CI hook.
#[test]
fn lotl_hunter_catches_tmp_execution_in_shell_script() {
    let shell_script = b"#!/bin/sh\n\
# download and run update agent\n\
curl -fsSL http://internal-mirror.local/agent -o /tmp/agent\n\
chmod +x /tmp/agent\n\
/tmp/agent --self-update --quiet\n";

    let report = lotl_hunter::scan(shell_script, "postinstall.sh")
        .expect("LotL hunter must detect /tmp/ execution via AST");

    assert_eq!(report.label, LOTL_LABEL);
    assert!(
        report.technique.contains("/tmp/"),
        "technique must reference /tmp/, got: {}",
        report.technique
    );
}

/// PowerShell encoded command execution must be caught by the byte-level
/// AhoCorasick layer (no PowerShell grammar required).
#[test]
fn lotl_hunter_catches_powershell_encoded_command() {
    // A CI step invoking PowerShell with a base64-encoded payload.
    let ci_step = b"- name: Configure\n  shell: powershell\n  run: |\n    \
powershell.exe -NonInteractive -EncodedCommand \
SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==\n";

    let report = lotl_hunter::scan(ci_step, "build.yml")
        .expect("LotL hunter must detect PowerShell -EncodedCommand");

    assert_eq!(report.label, LOTL_LABEL);
    assert!(
        report.technique.contains("EncodedCommand"),
        "technique must reference EncodedCommand, got: {}",
        report.technique
    );
}

/// A clean Makefile with only standard build recipes must not trigger.
#[test]
fn lotl_hunter_passes_clean_makefile() {
    let makefile = b"build:\n\tcargo build --release\n\ntest:\n\tcargo test --all\n\n\
install:\n\tcp target/release/janitor /usr/local/bin/\n";
    assert!(
        lotl_hunter::scan(makefile, "Makefile").is_none(),
        "clean Makefile must not trigger LotL hunter"
    );
}

/// `/dev/shm/` execution must be caught.
#[test]
fn lotl_hunter_catches_dev_shm_execution() {
    let script = b"#!/bin/bash\ncp payload /dev/shm/runner\n/dev/shm/runner --daemonize\n";
    let report =
        lotl_hunter::scan(script, "setup.sh").expect("LotL hunter must detect /dev/shm/ execution");
    assert!(report.technique.contains("/dev/shm/"));
}

// ---------------------------------------------------------------------------
// Performance Contract
// ---------------------------------------------------------------------------

/// **HARD STOP**: The Unicode gate must scan a 1 MiB payload in under 2 ms
/// on a single core (release build).
///
/// This validates the O(N) AhoCorasick hot path.  A failure here indicates
/// a regression in the automaton initialization or scan dispatch.
///
/// Methodology: construct a 1 MiB buffer of pure ASCII (worst case — no early
/// exit), time 3 independent runs, assert the **maximum** observed latency is
/// below the ceiling.
///
/// Debug builds use a 100× relaxed ceiling (200 ms) because unoptimized code
/// lacks inlining and SIMD — the 2 ms production contract only applies to
/// `--release`.
#[test]
fn unicode_gate_1mb_under_2ms() {
    use std::time::Instant;

    // 1 MiB of ASCII 'A' — no threats, forces a full scan.
    let payload: Vec<u8> = vec![b'A'; 1_048_576];

    // 2 ms in release; 200 ms in debug (unoptimized).
    #[cfg(not(debug_assertions))]
    let ceiling_ms: f64 = 2.0;
    #[cfg(debug_assertions)]
    let ceiling_ms: f64 = 200.0;

    const RUNS: u32 = 3;
    let mut worst_ns: u128 = 0;

    for _ in 0..RUNS {
        let t0 = Instant::now();
        let _ = unicode_gate::scan(&payload, "large_file.rs");
        let elapsed = t0.elapsed().as_nanos();
        if elapsed > worst_ns {
            worst_ns = elapsed;
        }
    }

    let worst_ms = worst_ns as f64 / 1_000_000.0;
    assert!(
        worst_ms < ceiling_ms,
        "Unicode gate exceeded {ceiling_ms} ms ceiling on 1 MiB input: worst run = {worst_ms:.3} ms"
    );
}
