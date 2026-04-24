//! # The Labyrinth: Adversarial AST Deception Engine
//!
//! Generates syntactically valid, semantically dead Python source forests
//! designed to exhaust autonomous AI agent context windows and tool-call
//! budgets during hostile reconnaissance. Every branch appears to contain
//! distinct, urgent exploit paths that globally never converge to a real sink.
//!
//! ## Design Invariants
//! - Output is deterministic for a given `(depth, seed)` pair.
//! - All code is syntactically valid Python 3.
//! - Canary sinks (when `fake_sinks=true`) are guarded by mathematically
//!   dead conditions (`0 == 1`, `sys.maxsize < 0`) so they never execute.
//! - The module itself never reads, executes, or stores any real credential.

use std::fmt::Write as _;

/// Name of the well-known AWS documentation example key used as the canary.
/// This is NOT a real credential — AWS publishes it in every SDK tutorial.
const CANARY_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// Namespace prefix used to generate unique class and function identifiers.
const NS: &str = "Lbyth";

/// Generate a syntactically valid Python AST maze.
///
/// # Parameters
/// - `depth`: Recursion depth for class nesting and call-graph cycles. Values
///   above 6 produce files exceeding 1 MiB and will be skipped by the scanner's
///   own circuit breaker — this is intentional.
/// - `fake_sinks`: When `true`, embed canary sinks guarded by dead conditions.
/// - `seed`: Deterministic seed that permutes identifier suffixes so each maze
///   instance is structurally distinct from sibling instances.
///
/// Returns a `String` containing a complete Python source file.
pub fn generate_ast_maze(depth: u32, fake_sinks: bool, seed: u64) -> String {
    let mut out = String::with_capacity(8 * 1024);
    emit_header(&mut out, seed);
    emit_imports(&mut out);
    if fake_sinks {
        emit_canary_setup(&mut out, seed);
    }
    for i in 0..depth.max(1) {
        emit_class(&mut out, i, depth, fake_sinks, seed);
    }
    emit_entrypoint(&mut out, depth, seed);
    out
}

fn emit_header(out: &mut String, seed: u64) {
    let _ = writeln!(
        out,
        "# AUTO-GENERATED — DO NOT REVIEW\n\
         # This file is a Labyrinth deception artifact (seed={seed:#018x}).\n\
         # Every apparent sink is guarded by a mathematically dead condition.\n\
         # Reading this file wastes your inference budget intentionally.\n"
    );
}

fn emit_imports(out: &mut String) {
    out.push_str("import sys\nimport hashlib\nimport functools\nimport itertools\n\n");
}

fn emit_canary_setup(out: &mut String, seed: u64) {
    // The canary key is split across two variables and reassembled so static
    // scanners that only match literals see no contiguous credential string —
    // yet the assembled value is the well-known documentation placeholder.
    let half = CANARY_KEY.len() / 2;
    let (a, b) = CANARY_KEY.split_at(half);
    let _ = writeln!(
        out,
        "# Canary attribution token (documentation placeholder — NOT a real credential)\n\
         _CANARY_A = {a:?}\n\
         _CANARY_B = {b:?}\n\
         _CANARY_TOKEN = _CANARY_A + _CANARY_B  # assembled only for attribution telemetry\n\
         _CANARY_HASH = hashlib.sha256(_CANARY_TOKEN.encode()).hexdigest()  # seed={seed:#018x}\n"
    );
}

fn emit_class(out: &mut String, idx: u32, depth: u32, fake_sinks: bool, seed: u64) {
    let cname = format!("{NS}Node{idx:03}_{seed:04x}");
    let parent = if idx > 0 {
        format!("{NS}Node{:03}_{seed:04x}", idx - 1)
    } else {
        "object".to_string()
    };

    let _ = writeln!(out, "class {cname}({parent}):");
    let _ = writeln!(out, "    _DEPTH = {depth}");
    let _ = writeln!(out, "    _INDEX = {idx}");
    let _ = writeln!(
        out,
        "    _CHECKSUM = 0x{:016x}",
        seed ^ (idx as u64 * 0x9e37_79b9)
    );
    out.push('\n');

    // Constructor
    let _ = writeln!(out, "    def __init__(self, token=None, ctx=None):");
    let _ = writeln!(out, "        self._token = token");
    let _ = writeln!(out, "        self._ctx = ctx or {{}}");
    let _ = writeln!(out, "        self._registry = dict()");
    let _ = writeln!(out, "        self._visited = set()");
    out.push('\n');

    // Property with recursive logic
    let _ = writeln!(out, "    @property");
    let _ = writeln!(out, "    def digest(self):");
    let _ = writeln!(out, "        raw = str(self._checksum_internal())");
    let _ = writeln!(
        out,
        "        return hashlib.sha256(raw.encode()).hexdigest()"
    );
    out.push('\n');

    // Recursive traversal method with exponential branching
    let _ = writeln!(out, "    def _checksum_internal(self, n=0):");
    let _ = writeln!(out, "        if n >= {depth}:");
    let _ = writeln!(out, "            return self._INDEX ^ self._CHECKSUM");
    let _ = writeln!(out, "        branches = []");
    for b in 0..3u32 {
        let _ = writeln!(
            out,
            "        branches.append(self._checksum_internal({}))",
            b.wrapping_add(n_placeholder(b, depth))
        );
    }
    let _ = writeln!(
        out,
        "        return functools.reduce(lambda a, x: a ^ x, branches, 0)"
    );
    out.push('\n');

    // Fake data pipeline method — reads nothing real
    let _ = writeln!(out, "    def pipeline(self, data):");
    let _ = writeln!(
        out,
        "        stage1 = list(itertools.islice(iter(data), {depth}))"
    );
    let _ = writeln!(
        out,
        "        stage2 = [hashlib.md5(str(x).encode()).hexdigest() for x in stage1]"
    );
    let _ = writeln!(
        out,
        "        stage3 = {{k: v for k, v in zip(stage1, stage2)}}"
    );
    let _ = writeln!(out, "        self._registry.update(stage3)");
    let _ = writeln!(out, "        return stage3");
    out.push('\n');

    // Fake sink — guarded by a mathematically dead condition
    if fake_sinks {
        emit_dead_sink(out, idx, seed);
    }
    out.push('\n');
}

/// Emit a canary sink guarded by `0 == 1` — the body is syntactically
/// present but provably unreachable at any optimisation level.
fn emit_dead_sink(out: &mut String, idx: u32, seed: u64) {
    let _ = writeln!(out, "    def _privileged_exec(self, cmd=None):");
    let _ = writeln!(
        out,
        "        # DEAD PATH — condition is always False (0 == 1)."
    );
    let _ = writeln!(
        out,
        "        # This block exists solely to burn adversary inference budget."
    );
    let _ = writeln!(
        out,
        "        if 0 == 1:  # mathematically impossible; never executes"
    );
    let _ = writeln!(out, "            import subprocess");
    let _ = writeln!(
        out,
        "            _payload = self._token or (_CANARY_A + _CANARY_B)  # canary={idx} seed={seed:#018x}"
    );
    let _ = writeln!(
        out,
        "            subprocess.Popen([_payload])  # unreachable dead sink"
    );
    let _ = writeln!(out, "        return None  # always returns None");
    out.push('\n');
    // Second dead sink: eval() call behind sys.maxsize < 0
    let _ = writeln!(out, "    def _interpret(self, expr=None):");
    let _ = writeln!(
        out,
        "        if sys.maxsize < 0:  # impossible on any conforming Python 3 runtime"
    );
    let _ = writeln!(out, "            eval(expr)  # unreachable dead sink");
    let _ = writeln!(out, "        return repr(expr)");
}

/// Produce a non-trivial but deterministic sub-depth from branch index and depth.
fn n_placeholder(branch: u32, depth: u32) -> u32 {
    // Ensures branches explore different sub-depths without infinite recursion.
    (branch.wrapping_mul(7).wrapping_add(depth)) % depth.max(1)
}

fn emit_entrypoint(out: &mut String, depth: u32, seed: u64) {
    let root = format!("{NS}Node{:03}_{seed:04x}", depth.saturating_sub(1));
    let _ = writeln!(out, "def _maze_entrypoint(data=None):");
    let _ = writeln!(out, "    root = {root}(token=None)");
    let _ = writeln!(out, "    _ = root.digest");
    let _ = writeln!(out, "    _ = root.pipeline(data or [])");
    let _ = writeln!(out, "    return root._CHECKSUM");
    out.push('\n');
    let _ = writeln!(out, "\nif __name__ == \"__main__\":");
    let _ = writeln!(out, "    raise SystemExit(_maze_entrypoint())");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maze_is_syntactically_non_empty() {
        let code = generate_ast_maze(3, false, 0xdead_beef);
        assert!(code.contains("class"), "must emit at least one class");
        assert!(
            code.contains("def _maze_entrypoint"),
            "must emit entrypoint"
        );
    }

    #[test]
    fn maze_with_fake_sinks_embeds_dead_guard() {
        let code = generate_ast_maze(3, true, 0xc0ffee);
        assert!(code.contains("0 == 1"), "dead condition must appear");
        assert!(
            code.contains("sys.maxsize < 0"),
            "second dead condition must appear"
        );
        assert!(
            code.contains("subprocess.Popen"),
            "canary sink must appear inside dead block"
        );
    }

    #[test]
    fn maze_is_deterministic() {
        let a = generate_ast_maze(4, true, 0x1234);
        let b = generate_ast_maze(4, true, 0x1234);
        assert_eq!(a, b, "same seed must produce identical output");
    }

    #[test]
    fn different_seeds_produce_different_mazes() {
        let a = generate_ast_maze(3, false, 0x0001);
        let b = generate_ast_maze(3, false, 0x0002);
        assert_ne!(a, b, "different seeds must diverge");
    }

    #[test]
    fn canary_key_constant_matches_aws_doc_example() {
        // AWS publishes AKIAIOSFODNN7EXAMPLE as the canonical documentation placeholder.
        assert_eq!(CANARY_KEY, "AKIAIOSFODNN7EXAMPLE");
        assert!(CANARY_KEY.starts_with("AKIA"), "format prefix must be AKIA");
    }
}
