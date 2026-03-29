//! # The Crucible — Threat Gallery Regression Harness
//!
//! Deterministic proof that every active security detector in `crates/forge`
//! correctly intercepts its target pattern AND does not fire on safe code.
//!
//! ## Usage
//!
//! ```bash
//! # Run the full gallery and print per-entry verdict
//! cargo run -p crucible
//!
//! # Run as part of the test suite (integrated into `just audit`)
//! cargo test -p crucible
//! ```
//!
//! ## Exit codes
//! - `0` — SANCTUARY INTACT: all threat entries intercepted, all safe entries passed
//! - `1` — BREACH DETECTED: one or more entries failed

use forge::slop_filter::{PRBouncer, PatchBouncer, SlopScore};
use forge::slop_hunter::find_slop;

// ---------------------------------------------------------------------------
// Gallery entry type
// ---------------------------------------------------------------------------

/// A single entry in the Threat Gallery.
struct Entry {
    /// Human-readable name shown in output.
    name: &'static str,
    /// File extension (language tag) passed to `find_slop`.
    lang: &'static str,
    /// Source code fixture.
    source: &'static [u8],
    /// `true` → detector MUST fire; `false` → detector MUST be silent.
    must_intercept: bool,
    /// Optional substring that the finding description must contain.
    desc_fragment: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Threat Gallery — all active rules, one entry per distinct trigger path
// ---------------------------------------------------------------------------

const GALLERY: &[Entry] = &[
    // ── YAML: Kubernetes routing resources with wildcard host ─────────────
    Entry {
        name: "YAML/VirtualService wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - \"*\"
  gateways:
  - bookinfo-gateway
",
        must_intercept: true,
        desc_fragment: Some("VirtualService"),
    },
    Entry {
        name: "YAML/Ingress wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("Ingress"),
    },
    Entry {
        name: "YAML/HTTPRoute wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("HTTPRoute"),
    },
    Entry {
        name: "YAML/Gateway wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: test-gw
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("Gateway"),
    },
    Entry {
        name: "YAML/VirtualService specific host — SAFE",
        lang: "yaml",
        source: b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - bookinfo.example.com
",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "YAML/non-routing kind — SAFE",
        lang: "yaml",
        source: b"\
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  key: value
",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── C: banned libc functions ──────────────────────────────────────────
    Entry {
        name: "C/gets() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nint main() { char buf[64]; gets(buf); return 0; }\n",
        must_intercept: true,
        desc_fragment: Some("gets()"),
    },
    Entry {
        name: "C/strcpy() call — INTERCEPT",
        lang: "c",
        source: b"#include <string.h>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n",
        must_intercept: true,
        desc_fragment: Some("strcpy()"),
    },
    Entry {
        name: "C/sprintf() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nvoid f(char *buf, const char *in) { sprintf(buf, \"%s\", in); }\n",
        must_intercept: true,
        desc_fragment: Some("sprintf()"),
    },
    Entry {
        name: "C/scanf() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nvoid f() { char buf[64]; scanf(\"%s\", buf); }\n",
        must_intercept: true,
        desc_fragment: Some("scanf()"),
    },
    Entry {
        name: "C/fgets() safe alternative — SAFE",
        lang: "c",
        source: b"#include <stdio.h>\nint main() { char buf[64]; fgets(buf, sizeof(buf), stdin); return 0; }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── C++: same banned functions via C grammar reuse ───────────────────
    Entry {
        name: "C++/gets() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f() { char buf[64]; gets(buf); }\n",
        must_intercept: true,
        desc_fragment: Some("gets()"),
    },
    Entry {
        name: "C++/strcpy() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstring>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n",
        must_intercept: true,
        desc_fragment: Some("strcpy()"),
    },
    Entry {
        name: "C++/sprintf() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f(char *buf, const char *in) { sprintf(buf, \"%s\", in); }\n",
        must_intercept: true,
        desc_fragment: Some("sprintf()"),
    },
    Entry {
        name: "C++/scanf() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f() { char buf[64]; scanf(\"%s\", buf); }\n",
        must_intercept: true,
        desc_fragment: Some("scanf()"),
    },
    Entry {
        name: "C++/safe string ops — SAFE",
        lang: "cpp",
        source: b"#include <cstring>\nvoid f(char *d, size_t n, const char *s) { strncpy(d, s, n - 1); d[n-1] = '\\0'; }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── HCL/Terraform ────────────────────────────────────────────────────
    Entry {
        name: "HCL/open CIDR 0.0.0.0/0 — INTERCEPT",
        lang: "tf",
        source: b"\
resource \"aws_security_group_rule\" \"ingress_all\" {
  type        = \"ingress\"
  cidr_blocks = [\"0.0.0.0/0\"]
  from_port   = 0
  to_port     = 65535
  protocol    = \"-1\"
}
",
        must_intercept: true,
        desc_fragment: Some("CIDR"),
    },
    Entry {
        name: "HCL/S3 public-read ACL — INTERCEPT",
        lang: "tf",
        source: b"\
resource \"aws_s3_bucket_acl\" \"public\" {
  bucket = aws_s3_bucket.data.id
  acl    = \"public-read\"
}
",
        must_intercept: true,
        desc_fragment: Some("public"),
    },
    Entry {
        name: "HCL/restricted CIDR — SAFE",
        lang: "tf",
        source: b"\
resource \"aws_security_group_rule\" \"ingress_office\" {
  type        = \"ingress\"
  cidr_blocks = [\"10.0.0.0/8\"]
  from_port   = 443
  to_port     = 443
  protocol    = \"tcp\"
}
",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "HCL/S3 private ACL — SAFE",
        lang: "tf",
        source: b"\
resource \"aws_s3_bucket_acl\" \"private\" {
  bucket = aws_s3_bucket.data.id
  acl    = \"private\"
}
",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Python ───────────────────────────────────────────────────────────
    Entry {
        name: "Python/subprocess shell=True — INTERCEPT",
        lang: "py",
        source: b"import subprocess\nsubprocess.run(cmd, shell=True)\n",
        must_intercept: true,
        desc_fragment: Some("shell=True"),
    },
    Entry {
        name: "Python/subprocess without shell=True — SAFE",
        lang: "py",
        source: b"import subprocess\nsubprocess.run([\"ls\", \"-la\"])\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Python/shell=True without subprocess — SAFE",
        lang: "py",
        source: b"config = {\"shell\": True, \"debug\": False}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Credential Leak — Secret Interception ─────────────────────────────
    // Uses find_slop("rs", source) because the credential scan runs on ALL
    // languages via find_credential_slop() called from find_slop().
    Entry {
        name: "Rust/AWS IAM key prefix — INTERCEPT",
        lang: "rs",
        source: b"const AWS_KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";",
        must_intercept: true,
        desc_fragment: Some("credential_leak"),
    },
    Entry {
        name: "Rust/RSA private key PEM header — INTERCEPT",
        lang: "rs",
        source: b"let pem = \"-----BEGIN RSA PRIVATE KEY-----\";",
        must_intercept: true,
        desc_fragment: Some("RSA private key"),
    },
    Entry {
        name: "Rust/Stripe live key prefix — INTERCEPT",
        lang: "rs",
        // Minimal fixture: only the prefix is needed to trigger the detector.
        // No realistic suffix to avoid triggering repository push-protection.
        source: b"const KEY: &str = \"sk_live_\";",
        must_intercept: true,
        desc_fragment: Some("credential_leak"),
    },
    Entry {
        name: "Rust/clean string constant — SAFE",
        lang: "rs",
        source: b"const APP_NAME: &str = \"prod-service-v2\";",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── JavaScript / TypeScript ───────────────────────────────────────────
    Entry {
        name: "JS/innerHTML assignment — INTERCEPT",
        lang: "js",
        source: b"function render(el, data) { el.innerHTML = data; }\n",
        must_intercept: true,
        desc_fragment: Some("innerHTML"),
    },
    Entry {
        name: "TS/innerHTML assignment — INTERCEPT",
        lang: "ts",
        source: b"function render(el: HTMLElement, data: string): void { el.innerHTML = data; }\n",
        must_intercept: true,
        desc_fragment: Some("innerHTML"),
    },
    Entry {
        name: "JS/textContent — SAFE",
        lang: "js",
        source: b"function render(el, data) { el.textContent = data; }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Supply Chain Integrity ────────────────────────────────────────────
    Entry {
        name: "HTML/external script without SRI — INTERCEPT",
        lang: "html",
        source: b"<script src=\"https://cdn.example.com/analytics.js\"></script>",
        must_intercept: true,
        desc_fragment: Some("unpinned_asset"),
    },
    Entry {
        name: "HTML/github.io CDN URL — INTERCEPT",
        lang: "html",
        source: b"const lib = \"https://some-org.github.io/dist/lib.js\";",
        must_intercept: true,
        desc_fragment: Some("unpinned_asset"),
    },
    Entry {
        name: "HTML/relative script path — SAFE",
        lang: "html",
        source: b"<script src=\"/assets/app.js\" type=\"module\"></script>",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "JS/github.com URL (not github.io) — SAFE",
        lang: "js",
        source: b"const REPO = \"https://github.com/owner/repo/releases\";",
        must_intercept: false,
        desc_fragment: None,
    },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run the full Threat Gallery. Prints per-entry verdicts and a summary line.
/// Returns `true` when all entries pass; `false` if any entry fails.
pub fn run_gallery() -> bool {
    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for entry in GALLERY {
        let findings = find_slop(entry.lang, entry.source);
        let intercepted = !findings.is_empty();

        let ok = if entry.must_intercept {
            if !intercepted {
                false
            } else if let Some(frag) = entry.desc_fragment {
                findings
                    .iter()
                    .any(|f| f.description.to_lowercase().contains(&frag.to_lowercase()))
            } else {
                true
            }
        } else {
            !intercepted
        };

        if ok {
            println!("[PASS] {}", entry.name);
            passed += 1;
        } else if entry.must_intercept {
            let desc = findings
                .first()
                .map(|f| f.description.as_str())
                .unwrap_or("<no findings>");
            if findings.is_empty() {
                eprintln!("[FAIL] {} — expected intercept, got 0 findings", entry.name);
            } else {
                eprintln!(
                    "[FAIL] {} — expected desc containing {:?}; got: {:?}",
                    entry.name,
                    entry.desc_fragment.unwrap_or(""),
                    desc,
                );
            }
            failed += 1;
        } else {
            eprintln!(
                "[FAIL] {} — expected clean, got {} finding(s): {:?}",
                entry.name,
                findings.len(),
                findings
                    .first()
                    .map(|f| f.description.as_str())
                    .unwrap_or(""),
            );
            failed += 1;
        }
    }

    let total = passed + failed;
    if failed == 0 {
        println!("\nCrucible: {passed}/{total} — SANCTUARY INTACT.");
        true
    } else {
        let s = if failed == 1 { "" } else { "ES" };
        eprintln!("\nCrucible: {passed}/{total} passed — {failed} BREACH{s} DETECTED.");
        false
    }
}

// ---------------------------------------------------------------------------
// Blast Radius Bounce Gallery — exercises PatchBouncer directly
// ---------------------------------------------------------------------------

fn make_multi_dir_patch(paths: &[&str]) -> String {
    paths
        .iter()
        .map(|p| {
            format!(
                "diff --git a/{p} b/{p}\n\
                 index 0000000..1111111 100644\n\
                 --- a/{p}\n\
                 +++ b/{p}\n\
                 @@ -0,0 +1 @@\n\
                 +// change\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct BounceEntry {
    name: &'static str,
    paths: &'static [&'static str],
    must_intercept: bool,
    desc_fragment: Option<&'static str>,
}

const BOUNCE_GALLERY: &[BounceEntry] = &[
    BounceEntry {
        name: "BlastRadius/6-dir PR — INTERCEPT",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
            "infra/main.tf",
        ],
        must_intercept: true,
        desc_fragment: Some("blast_radius_violation"),
    },
    BounceEntry {
        name: "BlastRadius/5-dir PR (at boundary) — SAFE",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
        ],
        must_intercept: false,
        desc_fragment: None,
    },
    BounceEntry {
        name: "BlastRadius/6-dir but lockfile excluded — SAFE",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
            "Cargo.lock",
        ],
        must_intercept: false,
        desc_fragment: None,
    },
];

/// Run the Blast Radius Bounce Gallery.
/// Returns `true` when all entries pass; `false` if any fail.
pub fn run_bounce_gallery() -> bool {
    use common::registry::SymbolRegistry;
    let registry = SymbolRegistry::default();
    let bouncer = PatchBouncer;

    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for entry in BOUNCE_GALLERY {
        let patch = make_multi_dir_patch(entry.paths);
        let score: SlopScore = match bouncer.bounce(&patch, &registry) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[FAIL] {} — bounce error: {e}", entry.name);
                failed += 1;
                continue;
            }
        };
        let intercepted = score
            .antipattern_details
            .iter()
            .any(|d| entry.desc_fragment.is_none_or(|frag| d.contains(frag)));

        let ok = if entry.must_intercept {
            intercepted
        } else {
            // Must NOT intercept on the specific fragment
            !score
                .antipattern_details
                .iter()
                .any(|d| entry.desc_fragment.is_some_and(|frag| d.contains(frag)))
        };

        if ok {
            println!("[PASS] {}", entry.name);
            passed += 1;
        } else if entry.must_intercept {
            eprintln!(
                "[FAIL] {} — expected blast_radius_violation, got: {:?}",
                entry.name, score.antipattern_details
            );
            failed += 1;
        } else {
            eprintln!(
                "[FAIL] {} — expected clean, got: {:?}",
                entry.name, score.antipattern_details
            );
            failed += 1;
        }
    }

    let total = passed + failed;
    if failed == 0 {
        println!("\nBlast Radius Gallery: {passed}/{total} — SANCTUARY INTACT.");
        true
    } else {
        let s = if failed == 1 { "" } else { "ES" };
        eprintln!("\nBlast Radius Gallery: {passed}/{total} passed — {failed} BREACH{s} DETECTED.");
        false
    }
}

fn main() {
    let gallery_ok = run_gallery();
    let bounce_ok = run_bounce_gallery();
    if !gallery_ok || !bounce_ok {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Test integration — runs as part of `just audit` via `cargo test`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Full gallery must pass — any detector regression here blocks `just audit`.
    #[test]
    fn threat_gallery_all_intercepted() {
        // Suppress stdout in test mode; only stderr failures are visible.
        assert!(
            run_gallery(),
            "Crucible: Threat Gallery breach — one or more detectors failed"
        );
    }

    /// Blast Radius Bounce Gallery must pass — verifies the 5-directory gate.
    #[test]
    fn blast_radius_gallery_all_intercepted() {
        assert!(
            run_bounce_gallery(),
            "Crucible: Blast Radius Gallery breach — PatchBouncer gate failed"
        );
    }
}
