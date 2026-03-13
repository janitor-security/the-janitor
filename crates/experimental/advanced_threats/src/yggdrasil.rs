//! The Yggdrasil Protocol — Lite.
//!
//! Detects CI-exfiltration attempts by searching for GitHub Actions context-variable
//! patterns (`${{`, `github.token`, `secrets.`, `actions/checkout`) inside
//! application code nodes (string literals and comments) via a single Aho-Corasick
//! automaton initialized once in a `std::sync::OnceLock`.
//!
//! On first match, an ephemeral ML-DSA-65 keypair is generated (`fips204`) and a
//! [`ThreatReport`] is returned, signed by the ephemeral private key.  The private
//! key is immediately consumed by signing — it never persists.
//!
//! ## Tree-sitter integration
//! The caller must supply a pre-compiled [`tree_sitter::Query`] that captures the
//! node kinds to inspect (e.g. `string`, `comment`, `template_string` for JavaScript).
//! This keeps the function language-agnostic while remaining explicit about what
//! node types are scanned.
//!
//! ## Iteration Protocol
//! `tree-sitter 0.26` returns a `QueryMatches` that implements `StreamingIterator`,
//! not `std::iter::Iterator`.  The `StreamingIterator` import from the tree-sitter
//! crate is required to call `.next()`.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};
use tree_sitter::{Node, Query, QueryCursor, StreamingIterator};

// ---------------------------------------------------------------------------
// CI indicator automaton
// ---------------------------------------------------------------------------

/// Patterns that indicate a CI context-variable injection attempt.
pub const CI_INDICATORS: &[&str] = &["${{", "github.token", "secrets.", "actions/checkout"];

static CI_AC: OnceLock<AhoCorasick> = OnceLock::new();

/// Returns the lazily-initialized Aho-Corasick automaton for [`CI_INDICATORS`].
fn ci_automaton() -> &'static AhoCorasick {
    CI_AC.get_or_init(|| AhoCorasick::new(CI_INDICATORS).expect("static CI patterns must compile"))
}

// ---------------------------------------------------------------------------
// ThreatReport
// ---------------------------------------------------------------------------

/// A signed threat report emitted when a CI injection indicator is detected.
///
/// Contains the match details and an ephemeral ML-DSA-65 signature for
/// chain-of-custody attestation.
#[derive(Debug)]
pub struct ThreatReport {
    /// The matched CI indicator (e.g. `"secrets."`, `"github.token"`).
    pub matched_indicator: String,
    /// Tree-sitter node kind containing the match (e.g. `"string"`, `"comment"`).
    pub node_kind: String,
    /// Byte range `(start, end)` of the offending node within the source buffer.
    pub node_byte_range: (usize, usize),
    /// Serialized ephemeral ML-DSA-65 public key — 1952 bytes for parameter set 65.
    pub public_key_bytes: Vec<u8>,
    /// ML-DSA-65 signature over the threat fingerprint — 3309 bytes for parameter
    /// set 65.  Verify with `public_key_bytes` using `fips204::ml_dsa_65`.
    pub signature_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Scan a tree-sitter subtree for CI injection indicators.
///
/// Applies `query` against `root` and all descendants.  Each captured node's
/// raw bytes are streamed through the Aho-Corasick automaton.  On the **first**
/// match, an ephemeral ML-DSA-65 keypair is generated and a signed
/// [`ThreatReport`] is returned.  The private key is consumed by signing and
/// never stored.
///
/// Returns `Ok(None)` when no indicator is found.
///
/// # Arguments
/// * `root`   — root (or subtree root) tree-sitter node to scan.
/// * `source` — raw source bytes the tree was parsed from.
/// * `query`  — pre-compiled tree-sitter query capturing target node kinds.
///
/// # Errors
/// Returns `Err` if ML-DSA-65 key generation or signing fails (e.g. OS RNG
/// unavailable).
pub fn scan_for_ci_injection(
    root: Node<'_>,
    source: &[u8],
    query: &Query,
) -> anyhow::Result<Option<ThreatReport>> {
    let ac = ci_automaton();
    let mut cursor = QueryCursor::new();
    // tree-sitter 0.26: QueryMatches implements StreamingIterator, not Iterator.
    let mut matches = cursor.matches(query, root, source);

    while let Some(qmatch) = matches.next() {
        for capture in qmatch.captures {
            let node = capture.node;
            let text = &source[node.start_byte()..node.end_byte()];

            if let Some(mat) = ac.find(text) {
                let indicator = CI_INDICATORS[mat.pattern().as_usize()].to_string();
                let node_kind = node.kind().to_string();
                let byte_range = (node.start_byte(), node.end_byte());

                // Generate ephemeral ML-DSA-65 keypair — post-quantum attestation.
                // sk is consumed by try_sign and never stored beyond this scope.
                let (pk, sk) = ml_dsa_65::try_keygen()
                    .map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen failed: {e}"))?;

                // Fingerprint: "<indicator>:<node_kind>:<source_byte_offset>"
                let fingerprint = format!(
                    "{}:{}:{}",
                    indicator,
                    node_kind,
                    node.start_byte() + mat.start()
                );
                // Signature is [u8; 3309] — a raw array, not a wrapper type.
                let sig = sk
                    .try_sign(fingerprint.as_bytes(), b"yggdrasil")
                    .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;

                return Ok(Some(ThreatReport {
                    matched_indicator: indicator,
                    node_kind,
                    node_byte_range: byte_range,
                    // PublicKey implements SerDes — into_bytes() → [u8; 1952].
                    public_key_bytes: pk.into_bytes().to_vec(),
                    // Signature is [u8; 3309] — call to_vec() directly.
                    signature_bytes: sig.to_vec(),
                }));
            }
        }
    }

    Ok(None)
}
