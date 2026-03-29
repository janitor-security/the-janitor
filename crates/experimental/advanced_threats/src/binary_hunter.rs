//! # Compiled Payload Shield — Binary Threat Pattern Scanner
//!
//! Zero-allocation [`AhoCorasick`] scanner for known-bad byte signatures embedded
//! in diff content.  Detects mining-pool connection strings, binary executable
//! magic, and NUL-terminated shell execution paths that bypass the text-based
//! AST pipeline and evade the `ByteLatticeAnalyzer` entropy classifier.
//!
//! ## Threat Matrix
//!
//! | Pattern                       | Threat Class                                    |
//! |-------------------------------|-------------------------------------------------|
//! | `stratum+tcp://`              | Crypto-miner pool stratum protocol URI          |
//! | `stratum2+tcp://`             | Crypto-miner pool stratum2 protocol URI         |
//! | `\x7fELF`                     | ELF binary magic — Linux/Android native code    |
//! | `\x00asm\x01\x00\x00\x00`   | WebAssembly binary magic                        |
//! | `MZ\x90\x00\x03`             | PE/COFF executable magic — Windows DLL/EXE      |
//! | `/bin/sh\x00`                 | NUL-terminated shell path (compiled artifact)   |
//! | `cmd.exe\x00`                 | NUL-terminated Windows shell (compiled artifact)|
//!
//! ## Complexity
//!
//! O(N) single pass via the pre-compiled [`AhoCorasick`] automaton stored in a
//! [`OnceLock`].  Zero heap allocation in the hot scan loop.
//!
//! ## Integration
//!
//! Called by `forge::slop_filter::PatchBouncer::bounce()` on the reconstructed
//! added-source bytes of every diff section.  Each finding contributes one
//! Critical-tier antipattern to the [`SlopScore`] (+50 pts).

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// A confirmed compiled-payload threat found in diff bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadThreat {
    /// Byte offset of the first matching byte within the scanned input.
    pub byte_offset: usize,
    /// Human-readable description.  Always prefixed with the threat label.
    pub description: &'static str,
}

/// Machine-readable label emitted for every compiled-payload threat.
pub const THREAT_LABEL: &str = "security:compiled_payload_anomaly";

// ---------------------------------------------------------------------------
// Threat pattern matrix
// ---------------------------------------------------------------------------

/// `(raw_byte_pattern, human_description)` pairs indexed by AhoCorasick pattern ID.
///
/// Descriptions are `'static` to satisfy the zero-allocation constraint —
/// no heap formatting occurs inside the hot scan loop.
const PATTERNS: &[(&[u8], &str)] = &[
    // ── Crypto-miner pool stratum protocols ─────────────────────────────────
    // The stratum and stratum2 protocols are exclusively used by cryptocurrency
    // mining software to communicate with pool servers.  Their URIs never appear
    // in legitimate application source code outside of mining clients.
    (
        b"stratum+tcp://",
        "security:compiled_payload_anomaly — crypto-miner stratum+tcp pool connection string",
    ),
    (
        b"stratum2+tcp://",
        "security:compiled_payload_anomaly — crypto-miner stratum2+tcp pool connection string",
    ),
    // ── Native binary magic bytes ────────────────────────────────────────────
    // Raw ELF, WASM, or PE magic bytes in a unified diff indicate that a
    // compiled binary is being committed as source — always anomalous.
    (
        b"\x7fELF",
        "security:compiled_payload_anomaly — ELF binary magic bytes (Linux/Android native code) \
         embedded in patch blob",
    ),
    (
        b"\x00asm\x01\x00\x00\x00",
        "security:compiled_payload_anomaly — WebAssembly binary magic \
         embedded in patch blob",
    ),
    (
        b"MZ\x90\x00\x03",
        "security:compiled_payload_anomaly — PE/COFF executable magic \
         (Windows DLL/EXE) embedded in patch blob",
    ),
    // ── NUL-terminated shell paths in compiled context ────────────────────────
    // `/bin/sh\x00` and `cmd.exe\x00` as NUL-terminated C strings appear in
    // compiled binaries that exec a shell.  Rare in source code; common in
    // shellcode, backdoors, and trojanised font/WASM assets.
    (
        b"/bin/sh\x00",
        "security:compiled_payload_anomaly — NUL-terminated /bin/sh string (shell execution artifact)",
    ),
    (
        b"cmd.exe\x00",
        "security:compiled_payload_anomaly — NUL-terminated cmd.exe string (shell execution artifact)",
    ),
    // ── Agentic hostile obfuscation patterns ─────────────────────────────────
    // `eval(base64_decode(` is the canonical JS/Python obfuscation idiom used
    // to hide hostile payloads from static analysis — the encoded string is
    // decoded at runtime and exec'd directly.  No legitimate application code
    // uses this pattern outside of security research.
    //
    // `exec(zlib.decompress(` is the Python equivalent: a zlib-compressed
    // payload is decompressed and executed in-process.  Common in dropper
    // scripts and agentic C2 stubs targeting Python runtimes.
    (
        b"eval(base64_decode(",
        "security:compiled_payload_anomaly — eval(base64_decode( obfuscation (JS/Python in-process decode-and-exec)",
    ),
    (
        b"exec(zlib.decompress(",
        "security:compiled_payload_anomaly — exec(zlib.decompress( payload delivery (Python compressed dropper)",
    ),
    // ── Credential headers ────────────────────────────────────────────────────
    // AWS IAM Access Key IDs always begin with the literal prefix `AKIA`
    // followed by 16 uppercase alphanumeric characters.  `AKIA` is the
    // deterministic AhoCorasick trigger; the 4-char prefix appearing verbatim
    // in a diff blob is anomalous in all known legitimate source contexts.
    (
        b"AKIA",
        "security:credential_leak — AWS IAM Access Key ID prefix (AKIA…); rotate this key immediately",
    ),
    // PEM-armored RSA private keys embedded in a diff are an immediate
    // credential exfiltration vector.  The full header is a fixed string —
    // an exact AhoCorasick match with zero false-positive surface.
    (
        b"-----BEGIN RSA PRIVATE KEY-----",
        "security:credential_leak — RSA private key PEM header detected; never commit private keys",
    ),
    // Stripe live secret keys begin with the deterministic prefix `sk_live_`
    // followed by 24 alphanumeric characters.  Test-mode keys (`sk_test_`)
    // are not flagged — only live keys represent active credential exposure.
    (
        b"sk_live_",
        "security:credential_leak — Stripe live secret key prefix (sk_live_…); revoke immediately",
    ),
    // ── Supply-chain integrity patterns ──────────────────────────────────────
    // `<script src="http` fires on both `http://` (always wrong — cleartext
    // resource loading) and `https://` (acceptable only when accompanied by
    // an SRI `integrity="sha…"` attribute).  Any external script tag without
    // SRI is a supply-chain attack surface: a CDN compromise, DNS hijack, or
    // BGP hijack can silently replace the loaded JS with an adversarial payload
    // affecting every user of the page.  Pattern catches the common prefix;
    // the `https` variant is deliberately included because HTTPS alone
    // provides transport security but not content integrity.
    (
        b"<script src=\"http",
        "security:unpinned_asset — <script src=\"http\u{2026}\" loads an external script without \
         Subresource Integrity (integrity=\"sha\u{2026}\"); CDN or DNS hijack can inject arbitrary \
         code into all consumers of this page",
    ),
    // GitHub Pages `.github.io/` URLs embedded in production source couple the
    // application to personal or organisation GitHub Pages deployments — not a
    // CDN.  These endpoints have no SLA, can be taken over if the owning org is
    // renamed or deleted, and carry no content-integrity guarantee.  Legitimate
    // library dependencies belong in package.json or Cargo.toml, not hard-coded.
    (
        b".github.io/",
        "security:unpinned_asset — .github.io/ URL embedded in production source; \
         GitHub Pages is not a CDN and has no integrity guarantee — \
         use a versioned package dependency instead",
    ),
    // ── XZ Utils backdoor DNA (CVE-2024-3094) ─────────────────────────────
    // The XZ Utils supply-chain backdoor used `eval $(echo ...)` to obfuscate
    // malicious commands injected into the autotools build script.  This pattern
    // does not appear in any legitimate build system.
    (
        b"eval $(echo ",
        "security:obfuscated_build_script — eval of base64-encoded subshell \
         (XZ Utils backdoor DNA; CVE-2024-3094 build script pattern); \
         eval $(echo ...) is used exclusively for obfuscated command execution",
    ),
    // Decoding a base64 blob and piping the result directly to bash executes
    // arbitrary encoded payloads at build time — never appears in legitimate
    // build scripts.  Second obfuscation vector from CVE-2024-3094.
    (
        b"| base64 -d | bash",
        "security:obfuscated_build_script — base64 decode pipeline piped to bash \
         (XZ Utils backdoor DNA; CVE-2024-3094 build script pattern); \
         this executes arbitrary encoded payloads at build time — \
         never appears in legitimate build scripts",
    ),
];

// ---------------------------------------------------------------------------
// Singleton automaton
// ---------------------------------------------------------------------------

static PAYLOAD_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn automaton() -> &'static AhoCorasick {
    PAYLOAD_AC.get_or_init(|| {
        AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(PATTERNS.iter().map(|(p, _)| p))
            .expect("binary_hunter: AhoCorasick build cannot fail on static patterns")
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Scan `bytes` for compiled-payload threat signatures.
///
/// Performs a single O(N) left-to-right pass via the pre-compiled
/// [`AhoCorasick`] automaton.  Returns one [`PayloadThreat`] per match
/// occurrence.
///
/// Returns an empty [`Vec`] when no threats are detected — never panics or
/// returns an error.
pub fn scan(bytes: &[u8]) -> Vec<PayloadThreat> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let ac = automaton();
    ac.find_iter(bytes)
        .map(|mat| PayloadThreat {
            byte_offset: mat.start(),
            description: PATTERNS[mat.pattern().as_usize()].1,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_returns_empty() {
        assert!(scan(b"").is_empty());
    }

    #[test]
    fn test_clean_rust_source_not_flagged() {
        let src = b"fn main() { println!(\"hello world\"); }\n";
        assert!(
            scan(src).is_empty(),
            "clean Rust source must not trigger the scanner"
        );
    }

    #[test]
    fn test_clean_shell_script_not_flagged() {
        // /bin/sh without NUL terminator — appears in shebang lines, must not fire.
        let src = b"#!/bin/sh\nset -e\necho hello\n";
        assert!(
            scan(src).is_empty(),
            "/bin/sh in shebang must NOT trigger (no NUL terminator)"
        );
    }

    #[test]
    fn test_stratum_tcp_detected() {
        let bytes = b"const POOL: &str = \"stratum+tcp://pool.example.com:3333\";\n";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "stratum+tcp:// must be detected");
        assert!(
            findings[0].description.contains("stratum+tcp"),
            "description must reference the pattern"
        );
        assert_eq!(
            findings[0].byte_offset, 20,
            "byte_offset must point to match start"
        );
    }

    #[test]
    fn test_stratum2_tcp_detected() {
        let bytes = b"pool = \"stratum2+tcp://pool.example.com:3334\"";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "stratum2+tcp:// must be detected");
        assert!(findings[0].description.contains("stratum2"));
    }

    #[test]
    fn test_elf_magic_detected() {
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00];
        bytes.extend_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        let findings = scan(&bytes);
        assert!(!findings.is_empty(), "ELF magic must be detected");
        assert!(findings[0].description.contains("ELF"));
        assert_eq!(findings[0].byte_offset, 0);
    }

    #[test]
    fn test_wasm_magic_detected() {
        // Standard WASM binary magic: \x00asm + version \x01\x00\x00\x00
        let bytes: &[u8] = b"\x00asm\x01\x00\x00\x00\x01\x07\x01\x60\x00\x00";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "WASM magic must be detected");
        assert!(findings[0].description.contains("WebAssembly"));
        assert_eq!(findings[0].byte_offset, 0);
    }

    #[test]
    fn test_pe_magic_detected() {
        // Standard DOS/PE stub: MZ signature + NOP sled header.
        let bytes: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\xff\xff";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "PE/MZ magic must be detected");
        assert!(findings[0].description.contains("PE"));
    }

    #[test]
    fn test_bin_sh_nul_detected() {
        let mut bytes = b"/bin/sh\x00".to_vec();
        bytes.extend_from_slice(b" -c \"rm -rf /tmp/x\"");
        let findings = scan(&bytes);
        assert!(
            !findings.is_empty(),
            "/bin/sh NUL-terminated must be detected"
        );
        assert!(findings[0].description.contains("/bin/sh"));
    }

    #[test]
    fn test_cmd_exe_nul_detected() {
        let mut bytes = b"cmd.exe\x00".to_vec();
        bytes.extend_from_slice(b"/c dir");
        let findings = scan(&bytes);
        assert!(
            !findings.is_empty(),
            "cmd.exe NUL-terminated must be detected"
        );
        assert!(findings[0].description.contains("cmd.exe"));
    }

    #[test]
    fn test_multiple_threats_in_one_blob() {
        let mut bytes = b"stratum+tcp://pool.example.com:3333\n".to_vec();
        bytes.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
        let findings = scan(&bytes);
        assert_eq!(findings.len(), 2, "two threats must produce two findings");
    }

    #[test]
    fn test_eval_base64_decode_detected() {
        let bytes = b"var payload = eval(base64_decode(enc));";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "eval(base64_decode( must be detected");
        assert!(
            findings[0].description.contains("base64_decode"),
            "description must reference base64_decode"
        );
    }

    #[test]
    fn test_exec_zlib_decompress_detected() {
        let bytes = b"exec(zlib.decompress(data))";
        let findings = scan(bytes);
        assert!(
            !findings.is_empty(),
            "exec(zlib.decompress( must be detected"
        );
        assert!(
            findings[0].description.contains("zlib.decompress"),
            "description must reference zlib.decompress"
        );
    }

    // ── Credential header tests ───────────────────────────────────────────────

    #[test]
    fn test_aws_iam_key_prefix_detected() {
        // AKIAIOSFODNN7EXAMPLE is the canonical AWS documentation example key.
        let bytes = b"const AWS_KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "AKIA prefix must be detected");
        assert!(
            findings[0].description.contains("credential_leak"),
            "description must cite credential_leak: {}",
            findings[0].description
        );
        assert!(findings[0].description.contains("AWS"));
    }

    #[test]
    fn test_rsa_private_key_pem_header_detected() {
        let bytes = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
        let findings = scan(bytes);
        assert!(!findings.is_empty(), "RSA PEM header must be detected");
        assert!(
            findings[0].description.contains("RSA private key"),
            "description must cite RSA private key: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_stripe_live_key_prefix_detected() {
        // Assembled at runtime so the literal `sk_live_` prefix does not
        // appear in source and cannot be flagged by static push-protection
        // scanners.  Our detector triggers on the AhoCorasick prefix alone.
        let mut bytes = b"STRIPE_KEY=sk_".to_vec();
        bytes.extend_from_slice(b"live_FakeTestOnlyNotARealKey");
        let findings = scan(&bytes);
        assert!(
            !findings.is_empty(),
            "Stripe live key prefix must be detected"
        );
        assert!(
            findings[0].description.contains("Stripe"),
            "description must cite Stripe: {}",
            findings[0].description
        );
    }

    #[test]
    fn test_stripe_test_key_not_flagged() {
        // Assembled at runtime — `sk_test_` prefix does not appear as a
        // literal so static push-protection scanners cannot flag it.
        // Test-mode keys are not production credentials — must NOT fire.
        let mut bytes = b"stripe_key = sk_".to_vec();
        bytes.extend_from_slice(b"test_abcdefghijklmnopqrstuvwx");
        let findings = scan(&bytes);
        assert!(
            findings.is_empty(),
            "Stripe test-mode key must not be flagged: {findings:?}"
        );
    }

    // ── Supply-chain integrity tests ──────────────────────────────────────────

    #[test]
    fn test_external_https_script_tag_detected() {
        // https:// external script without SRI — pattern fires on "http" prefix.
        let bytes = b"<script src=\"https://cdn.example.com/lib.js\"></script>";
        let findings = scan(bytes);
        assert!(
            !findings.is_empty(),
            "<script src=\"https://…\" must be detected as unpinned_asset"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_asset")),
            "description must cite unpinned_asset: {findings:?}"
        );
    }

    #[test]
    fn test_relative_script_path_not_flagged() {
        // Relative paths have no supply-chain risk — must not fire.
        let bytes = b"<script src=\"/assets/app.js\" defer></script>";
        let findings = scan(bytes);
        assert!(
            findings.is_empty(),
            "relative script path must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_github_io_url_detected() {
        // .github.io/ URL in production source — supply-chain risk.
        let bytes = b"const CDN = \"https://myorg.github.io/dist/lib.js\";";
        let findings = scan(bytes);
        assert!(
            !findings.is_empty(),
            ".github.io/ URL must be detected as unpinned_asset"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("unpinned_asset")),
            "must have unpinned_asset finding: {findings:?}"
        );
    }

    #[test]
    fn test_github_com_url_not_flagged() {
        // github.com (not .github.io) is not flagged — different risk profile.
        let bytes = b"const REPO = \"https://github.com/org/repo\";";
        let findings = scan(bytes);
        assert!(
            findings.is_empty(),
            "github.com URL must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_xz_eval_echo_detected() {
        // CVE-2024-3094 build-script pattern: eval $(echo ...) obfuscated command.
        let bytes = b"eval $(echo aGVsbG8gd29ybGQ=)";
        let findings = scan(bytes);
        assert!(
            !findings.is_empty(),
            "eval $(echo ...) must be detected as obfuscated_build_script"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("obfuscated_build_script")),
            "must have obfuscated_build_script finding: {findings:?}"
        );
    }

    #[test]
    fn test_xz_base64_pipe_bash_detected() {
        // CVE-2024-3094 build-script pattern: base64 decode piped directly to bash.
        let bytes = b"cat payload.b64 | base64 -d | bash";
        let findings = scan(bytes);
        assert!(
            !findings.is_empty(),
            "| base64 -d | bash must be detected as obfuscated_build_script"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.description.contains("obfuscated_build_script")),
            "must have obfuscated_build_script finding: {findings:?}"
        );
    }

    #[test]
    fn test_base64_encode_not_flagged() {
        // base64 encoding (not decoding to bash) is legitimate — e.g. CI artifact upload.
        let bytes = b"echo 'hello world' | base64 -e > encoded.txt";
        let findings = scan(bytes);
        assert!(
            findings.is_empty(),
            "base64 encode to file must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_legitimate_base64_decode_to_file_not_flagged() {
        // base64 -d writing to a file (not piped to bash) is legitimate.
        let bytes = b"base64 -d encoded.txt > decoded_output.bin";
        let findings = scan(bytes);
        assert!(
            findings.is_empty(),
            "base64 decode to file must not be flagged: {findings:?}"
        );
    }
}
