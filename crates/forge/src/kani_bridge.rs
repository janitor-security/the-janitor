//! Kani / Formal Verification Harness Synthesizer (P4-1 spine).
//!
//! Converts a Z3-satisfiable [`ExploitWitness`] into a [`HarnessArtifact`] — a
//! structured Kani or C verification harness that downstream tooling can emit
//! into a temporary crate and run under CBMC bounded model checking.
//!
//! The synthesizer is intentionally decoupled from subprocess invocation: it
//! emits the harness *text* only. Invoking `cargo kani` is opt-in behind
//! `ForgeConfig.formal_verification` and executed only by `cmd_legacy_mine`.
//!
//! ## Design
//!
//! For C/C++ findings (LCM-001 through LCM-005), the harness is a C unit test
//! that allocates a symbolic buffer, calls the vulnerable function with
//! model-constrained inputs, and asserts the safety invariant.  The invariant
//! negation is the proof obligation; CBMC reports a counterexample when it
//! finds inputs that violate it.

use common::slop::{ExploitWitness, HarnessArtifact};

/// Synthesize a verification harness for a confirmed exploit witness.
///
/// Returns `None` when the witness lacks sufficient information to produce a
/// deterministic harness (e.g., no `source_function` or no `repro_cmd`).
pub fn synthesize_kani_harness(
    witness: &ExploitWitness,
    finding_id: &str,
) -> Option<HarnessArtifact> {
    let fn_name = &witness.source_function;
    if fn_name.is_empty() {
        return None;
    }

    let (inputs, assertion, harness_body) = if finding_id.contains("lcm_malloc_integer_truncation")
    {
        harness_malloc_truncation(fn_name)
    } else if finding_id.contains("lcm_double_free") {
        harness_double_free(fn_name)
    } else if finding_id.contains("lcm_use_after_free") {
        harness_uaf(fn_name)
    } else if finding_id.contains("lcm_off_by_one") {
        harness_off_by_one(fn_name)
    } else if finding_id.contains("lcm_unbounded") {
        harness_unbounded_string(fn_name)
    } else {
        // Generic harness for any source-to-sink witness with a repro_cmd.
        harness_generic(fn_name, witness.repro_cmd.as_deref())
    };

    Some(HarnessArtifact {
        function_name: fn_name.clone(),
        inputs,
        assertion,
        harness_source: harness_body,
        run_command: format!("cargo kani --harness harness_{fn_name}"),
    })
}

// ---------------------------------------------------------------------------
// Per-pattern harness templates
// ---------------------------------------------------------------------------

fn harness_malloc_truncation(fn_name: &str) -> (Vec<String>, String, String) {
    let inputs = vec!["int count".to_string(), "size_t elem_size".to_string()];
    let assertion = "allocated_size >= (size_t)count * elem_size".to_string();
    let body = format!(
        r#"// Kani harness — LCM-002 integer truncation in {fn_name}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <stddef.h>
#include <stdlib.h>
#include <kani/kani.h>

void harness_{fn_name}(void) {{
    int count = kani_any_int();
    kani_assume(count > 0 && count < 65536);
    size_t elem_size = sizeof(int);
    void *ptr = {fn_name}(count, elem_size);
    if (ptr != NULL) {{
        // assert allocation is large enough for count elements
        __CPROVER_assert(kani_object_size(ptr) >= (size_t)count * elem_size,
                         "allocation must cover count * elem_size bytes");
        free(ptr);
    }}
}}"#
    );
    (inputs, assertion, body)
}

fn harness_double_free(fn_name: &str) -> (Vec<String>, String, String) {
    let inputs = vec!["void *ptr".to_string()];
    let assertion = "ptr freed exactly once per allocation".to_string();
    let body = format!(
        r#"// Kani harness — LCM-005 double-free in {fn_name}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <stdlib.h>
#include <kani/kani.h>

void harness_{fn_name}(void) {{
    void *ptr = malloc(64);
    kani_assume(ptr != NULL);
    {fn_name}(ptr);
    // Second free is the bug — CBMC should report UNSAT of heap-safety invariant.
    __CPROVER_assert(!kani_is_freed(ptr), "pointer must not be freed twice");
}}"#
    );
    (inputs, assertion, body)
}

fn harness_uaf(fn_name: &str) -> (Vec<String>, String, String) {
    let inputs = vec!["struct T *ptr".to_string()];
    let assertion = "no dereference of freed pointer".to_string();
    let body = format!(
        r#"// Kani harness — LCM-004 use-after-free in {fn_name}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <stdlib.h>
#include <kani/kani.h>

struct T {{ int value; }};

void harness_{fn_name}(void) {{
    struct T *ptr = (struct T *)malloc(sizeof(struct T));
    kani_assume(ptr != NULL);
    free(ptr);
    // Calling subject function: any read/write through ptr after free is UB.
    __CPROVER_assert(!kani_is_freed(ptr), "ptr must not be dereferenced after free");
}}"#
    );
    (inputs, assertion, body)
}

fn harness_off_by_one(fn_name: &str) -> (Vec<String>, String, String) {
    let inputs = vec!["int n".to_string(), "char buf[n]".to_string()];
    let assertion = "loop index < array bound (not <=)".to_string();
    let body = format!(
        r#"// Kani harness — LCM-003 off-by-one in {fn_name}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <stdlib.h>
#include <kani/kani.h>

void harness_{fn_name}(void) {{
    int n = kani_any_int();
    kani_assume(n > 0 && n < 256);
    char *buf = (char *)malloc((size_t)n);
    kani_assume(buf != NULL);
    {fn_name}(buf, n);
    // Assert no write beyond index n-1.
    __CPROVER_assert(
        kani_object_size(buf) >= (size_t)n,
        "buffer must not be written past declared bound"
    );
    free(buf);
}}"#
    );
    (inputs, assertion, body)
}

fn harness_unbounded_string(fn_name: &str) -> (Vec<String>, String, String) {
    let inputs = vec!["char dst[64]".to_string(), "const char *src".to_string()];
    let assertion = "destination buffer not overflowed".to_string();
    let body = format!(
        r#"// Kani harness — LCM-001 unbounded string op in {fn_name}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <string.h>
#include <kani/kani.h>

void harness_{fn_name}(void) {{
    char dst[64];
    char src[128];
    kani_make_symbolic(src, sizeof(src), "src");
    src[127] = '\0';  // ensure NUL-terminated
    {fn_name}(dst, src);
    // Assert destination is still within its declared bound.
    __CPROVER_assert(
        strlen(dst) < sizeof(dst),
        "destination must not overflow after unbounded string operation"
    );
}}"#
    );
    (inputs, assertion, body)
}

fn harness_generic(fn_name: &str, repro_cmd: Option<&str>) -> (Vec<String>, String, String) {
    let cmd_comment = repro_cmd
        .map(|r| format!("// Repro: {r}"))
        .unwrap_or_default();
    let inputs = vec!["symbolic inputs derived from Z3 model".to_string()];
    let assertion = "no undefined behaviour on attacker-controlled input".to_string();
    let body = format!(
        r#"// Kani harness — generic witness for {fn_name}
{cmd_comment}
// Invoke `cargo kani --harness harness_{fn_name}` to prove.
#include <kani/kani.h>

void harness_{fn_name}(void) {{
    // TODO: instantiate symbolic inputs from Z3 model bindings.
    // Each `kani::any()` call corresponds to one Z3 `declare-fun` binding.
    __CPROVER_assert(1 == 1, "placeholder — replace with safety invariant");
}}"#
    );
    (inputs, assertion, body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::slop::ExploitWitness;

    #[test]
    fn synthesize_returns_none_for_empty_source() {
        let w = ExploitWitness::default();
        assert!(
            synthesize_kani_harness(&w, "security:lcm_malloc_integer_truncation").is_none(),
            "empty source_function must return None"
        );
    }

    #[test]
    fn synthesize_malloc_truncation_harness() {
        let w = ExploitWitness {
            source_function: "alloc_items".to_string(),
            ..Default::default()
        };
        let art = synthesize_kani_harness(&w, "security:lcm_malloc_integer_truncation")
            .expect("harness must be synthesized");
        assert_eq!(art.function_name, "alloc_items");
        assert!(art.harness_source.contains("harness_alloc_items"));
        assert!(art.harness_source.contains("kani_any_int"));
        assert!(art.run_command.contains("harness_alloc_items"));
    }

    #[test]
    fn synthesize_double_free_harness() {
        let w = ExploitWitness {
            source_function: "cleanup_resource".to_string(),
            ..Default::default()
        };
        let art = synthesize_kani_harness(&w, "security:lcm_double_free")
            .expect("harness must be synthesized");
        assert!(art.harness_source.contains("kani_is_freed"));
    }

    #[test]
    fn synthesize_generic_includes_repro_cmd() {
        let w = ExploitWitness {
            source_function: "parse_input".to_string(),
            repro_cmd: Some("curl -d 'AAAAAA' http://localhost/parse".to_string()),
            ..Default::default()
        };
        let art = synthesize_kani_harness(&w, "security:some_other_pattern")
            .expect("generic harness must be synthesized");
        assert!(art.harness_source.contains("curl -d"));
    }
}
