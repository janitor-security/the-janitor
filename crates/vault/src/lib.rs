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
/// **To activate production mode:**
/// 1. Run `cargo run -p mint-token -- generate` to create a real keypair.
/// 2. Paste the printed `VERIFYING_KEY_BYTES` array here, replacing the zeros.
/// 3. Store the private key at thejanitor.app — never commit it.
/// 4. Mint tokens with `cargo run -p mint-token -- mint --key <hex>`.
///
/// While this is all-zeros the fallback demo key is used (test/dev only).
const VERIFYING_KEY_BYTES: [u8; 32] = [
    0x71, 0xbc, 0x61, 0xae, 0xe0, 0x6f, 0xac, 0x48, 0x5a, 0x97, 0xc4, 0x59, 0x3b, 0xd0, 0x2c, 0x43,
    0x92, 0x61, 0x48, 0xe1, 0x33, 0xb7, 0xc5, 0x9e, 0x19, 0x3a, 0x8d, 0x32, 0x15, 0x3e, 0x88, 0xe9,
];

/// Demo signing-key seed (32 bytes).
///
/// Drives the fallback verification path when `VERIFYING_KEY_BYTES` has not
/// yet been populated (all-zeros).  Never leave this seed in a production
/// binary — replace `VERIFYING_KEY_BYTES` with a real public key instead.
const SIGNING_KEY_SEED: [u8; 32] = [
    0xb8, 0x37, 0xb9, 0xce, 0x69, 0x7c, 0x17, 0x47, 0xe6, 0xb3, 0x75, 0x69, 0x9e, 0x4d, 0xf3, 0x0c,
    0xe0, 0x3b, 0xf0, 0x86, 0x02, 0x73, 0xe6, 0xc6, 0xd6, 0x7f, 0xb3, 0x49, 0x5e, 0xb0, 0x45, 0x6b,
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
        0x9d, 0x50, 0x02, 0x57, 0x38, 0x37, 0x5e, 0x05, 0xd5, 0x18, 0x4a, 0x96, 0xc0, 0x9f, 0x56,
        0xb6, 0x11, 0xac, 0x59, 0x79, 0x6d, 0xf9, 0x53, 0x87, 0x4a, 0xe6, 0x02, 0x58, 0xe8, 0x3a,
        0x97, 0x36,
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
