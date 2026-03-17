//! ML-DSA-65 signing oracle — produces `VetoBond` proofs of hallucinated FFI
//! symbols.
//!
//! ## Cryptographic model
//! Each [`sign_veto`] call generates a **fresh ephemeral ML-DSA-65 keypair**
//! via the OS entropy source, signs the hallucinated symbol name with an
//! empty context string, and bundles the verifying key + signature into a
//! [`VetoBond`].
//!
//! The verifying key is included in the bond so any downstream consumer can
//! independently verify the attestation without a shared-state key registry.
//! This is appropriate for the single-PR, stateless evaluation model.
//!
//! ## Security note
//! Ephemeral keys provide integrity (the bond cannot be forged without the
//! private key) but not long-term non-repudiation (the keypair is discarded
//! after signing).  For production use, a persistent signing key managed by
//! [`crate::vault`] would replace the ephemeral keypair.
//!
//! ## FIPS 204 parameters (ML-DSA-65)
//! - Public key:  1952 bytes
//! - Private key: 4032 bytes
//! - Signature:   3309 bytes
//! - Security category: NIST Level 3 (≥ AES-192 classical equivalent)

use anyhow::Result;
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer};

// ---------------------------------------------------------------------------
// VetoBond
// ---------------------------------------------------------------------------

/// Cryptographic proof that a Python call site targets a hallucinated symbol.
///
/// Contains:
/// - The hallucinated symbol name (human-readable label).
/// - The ML-DSA-65 verifying key bytes (1952 bytes).
/// - The ML-DSA-65 signature over `symbol_name || "phantom_ffi_gate_v1"`.
///   (3309 bytes).
#[derive(Debug, Clone)]
pub struct VetoBond {
    /// The Python-side symbol name that has no C++ backing.
    pub hallucinated_symbol: String,
    /// Serialised ML-DSA-65 verifying key (1952 bytes for ML-DSA-65).
    pub vk_bytes: Vec<u8>,
    /// ML-DSA-65 signature over `hallucinated_symbol` (3309 bytes for ML-DSA-65).
    pub sig_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Signing oracle
// ---------------------------------------------------------------------------

/// Sign `hallucinated_symbol` with a fresh ephemeral ML-DSA-65 keypair.
///
/// Generates a keypair using OS entropy, signs the symbol name, and returns
/// a [`VetoBond`] containing the verifying key and signature.
///
/// The context string `b"phantom_ffi_gate_v1"` binds the signature to this
/// protocol version — a verifier must supply the same context.
///
/// # Errors
/// Returns `Err` if the OS entropy source is unavailable or if the message
/// is too long (ML-DSA context is limited to 255 bytes; symbol names are
/// never that long in practice).
pub fn sign_veto(hallucinated_symbol: &str) -> Result<VetoBond> {
    let (pk, sk) = ml_dsa_65::try_keygen()
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 key generation failed: {e}"))?;

    let msg = hallucinated_symbol.as_bytes();
    // Context string: binds the signature to this protocol and version.
    // Must be ≤ 255 bytes per FIPS 204 §5.2.
    let ctx: &[u8] = b"phantom_ffi_gate_v1";

    let sig: [u8; ml_dsa_65::SIG_LEN] = sk
        .try_sign(msg, ctx)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {e}"))?;

    let vk_bytes: Vec<u8> = pk.into_bytes().to_vec();
    let sig_bytes: Vec<u8> = sig.to_vec();

    Ok(VetoBond {
        hallucinated_symbol: hallucinated_symbol.to_string(),
        vk_bytes,
        sig_bytes,
    })
}
