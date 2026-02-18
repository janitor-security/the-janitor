//! # The Vault: Ed25519 Token Verification
//!
//! Enforces the economic gate: destructive operations require a valid
//! PQC/Ed25519 token issued by thejanitor.app.
//!
//! ## Protocol
//! 1. The user purchases a license at thejanitor.app.
//! 2. The server signs the message `"JANITOR_PURGE_AUTHORIZED"` with its
//!    Ed25519 private key and returns the base64-encoded signature as a token.
//! 3. The tool embeds the corresponding verifying key and calls
//!    [`SigningOracle::verify_token`] before any destructive operation.

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use std::sync::OnceLock;

/// The message that all purge tokens must be a valid signature of.
const PURGE_MESSAGE: &[u8] = b"JANITOR_PURGE_AUTHORIZED";

/// Production verifying key (32 bytes).
///
/// **To rotate in production mode:**
/// 1. Run `cargo run -p mint-token -- generate` to create a real keypair.
/// 2. Paste the printed `VERIFYING_KEY_BYTES` array here.
/// 3. Store the private key at thejanitor.app — **never commit it**.
/// 4. Mint tokens with `cargo run -p mint-token -- mint --key <hex>`.
///
/// While this is all-zeros the fallback demo key is used (test/dev only).
const VERIFYING_KEY_BYTES: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

/// Demo signing-key seed (32 bytes).
///
/// Drives the fallback verification path when `VERIFYING_KEY_BYTES` has not
/// yet been populated (all-zeros).  Never leave this seed in a production
/// binary — replace `VERIFYING_KEY_BYTES` with a real public key instead.
const SIGNING_KEY_SEED: [u8; 32] = [
    0xf4, 0x1a, 0x8c, 0xe3, 0x55, 0x2b, 0xd9, 0x07, 0xa8, 0x3c, 0xe6, 0x71, 0x04, 0xbb, 0xf2, 0x19,
    0x7d, 0xc0, 0x48, 0xea, 0x93, 0x5f, 0x16, 0x2a, 0x60, 0xd3, 0x87, 0x4e, 0xc1, 0x29, 0x5a, 0xd8,
];

static VERIFYING_KEY: OnceLock<VerifyingKey> = OnceLock::new();

fn get_verifying_key() -> &'static VerifyingKey {
    VERIFYING_KEY.get_or_init(|| {
        if VERIFYING_KEY_BYTES == [0u8; 32] {
            // Demo / development fallback: derive from the embedded seed.
            SigningKey::from_bytes(&SIGNING_KEY_SEED).verifying_key()
        } else {
            // Production path: use the hardcoded public key bytes.
            VerifyingKey::from_bytes(&VERIFYING_KEY_BYTES)
                .expect("BUG: VERIFYING_KEY_BYTES contains invalid Ed25519 key bytes")
        }
    })
}

/// Token-based access control for destructive operations.
pub struct SigningOracle;

impl SigningOracle {
    /// Returns `true` iff `token` is a valid base64-encoded Ed25519 signature
    /// of `"JANITOR_PURGE_AUTHORIZED"` under the embedded verifying key.
    ///
    /// A token is obtained by purchasing a license at thejanitor.app.
    pub fn verify_token(token: &str) -> bool {
        use base64::Engine;

        // 1. Base64-decode the token.
        let decoded = match base64::engine::general_purpose::STANDARD.decode(token) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // 2. Must be exactly 64 bytes (Ed25519 signature length).
        let sig_bytes: [u8; 64] = match decoded.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);

        // 3. Verify against the embedded verifying key.
        get_verifying_key().verify(PURGE_MESSAGE, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::Signer;

    /// Private key seed that matches the `VERIFYING_KEY_BYTES` embedded in this
    /// crate.  Used solely by the test suite — never exposed in production.
    const TEST_SIGNING_KEY_SEED: [u8; 32] = [
        0x23, 0x70, 0xde, 0x11, 0x87, 0xe8, 0xd5, 0x7e, 0x42, 0x3d, 0x3e, 0xe0, 0x38, 0x64, 0x2c,
        0x41, 0x3e, 0x27, 0x23, 0x36, 0xd4, 0x26, 0x5c, 0x1b, 0xc4, 0x1c, 0x6c, 0x22, 0x9a, 0xc4,
        0xeb, 0xe5,
    ];

    fn make_token(seed: &[u8; 32], message: &[u8]) -> String {
        let sk = SigningKey::from_bytes(seed);
        let sig: Signature = sk.sign(message);
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    #[test]
    fn test_valid_token_accepted() {
        let token = make_token(&TEST_SIGNING_KEY_SEED, PURGE_MESSAGE);
        assert!(SigningOracle::verify_token(&token));
    }

    #[test]
    fn test_invalid_token_rejected() {
        assert!(!SigningOracle::verify_token("not-a-valid-token"));
        assert!(!SigningOracle::verify_token(""));
        assert!(!SigningOracle::verify_token("AAAA"));
    }

    #[test]
    fn test_wrong_message_rejected() {
        // Correct key, wrong message — must not pass verification.
        let token = make_token(&TEST_SIGNING_KEY_SEED, b"DIFFERENT_MESSAGE");
        assert!(!SigningOracle::verify_token(&token));
    }

    #[test]
    fn test_wrong_key_rejected() {
        // Sign with a different key — must not pass verification.
        let other_seed = [0x42u8; 32];
        let token = make_token(&other_seed, PURGE_MESSAGE);
        assert!(!SigningOracle::verify_token(&token));
    }
}
