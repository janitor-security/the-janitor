//! # The Vault: Ed25519 Token Verification
//!
//! Enforces the economic gate: destructive operations require a valid
//! Ed25519 token issued by thejanitor.app.
//!
//! ## Protocol
//! 1. The user purchases a license at thejanitor.app.
//! 2. The server signs the message `"JANITOR_PURGE_AUTHORIZED"` with its
//!    Ed25519 private key and returns the base64-encoded signature as a token.
//! 3. The tool embeds the corresponding verifying key and calls
//!    [`SigningOracle::verify_token`] before any destructive operation.
//!    An `Err` return is a hard gate — the operation must not proceed.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::sync::OnceLock;

/// The message that all purge tokens must be a valid signature of.
const PURGE_MESSAGE: &[u8] = b"JANITOR_PURGE_AUTHORIZED";

/// Production verifying key (32 bytes).
///
/// **To rotate:**
/// 1. Run `cargo run -p mint-token -- generate` to create a real keypair.
/// 2. Paste the printed `VERIFYING_KEY_BYTES` array here.
/// 3. Store the private key at thejanitor.app — **never commit it**.
/// 4. Mint tokens with `cargo run -p mint-token -- mint --key <hex>`.
///
/// If this is all-zeros the binary refuses to start (production build flaw).
const VERIFYING_KEY_BYTES: [u8; 32] = [
    0x9c, 0x3e, 0x68, 0x22, 0xae, 0x35, 0x6e, 0x6e, 0x9a, 0x10, 0x7c, 0x43, 0x2b, 0x88, 0xd0, 0xa6,
    0x00, 0x45, 0x8f, 0x72, 0x8c, 0xd2, 0x53, 0xc2, 0x81, 0x76, 0x82, 0x1b, 0x27, 0xc7, 0xab, 0x64,
];

/// Errors returned by [`SigningOracle::verify_token`].
///
/// The caller (CLI) must treat every variant as a hard failure and abort the operation.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Token string could not be base64-decoded, or the decoded bytes are not 64 bytes.
    #[error("token is malformed (expected base64-encoded 64-byte Ed25519 signature)")]
    MalformedToken,

    /// Token decoded successfully but the Ed25519 signature does not match.
    #[error("token signature is invalid or has been revoked")]
    InvalidSignature,
}

static VERIFYING_KEY: OnceLock<Option<VerifyingKey>> = OnceLock::new();

fn get_verifying_key() -> Option<&'static VerifyingKey> {
    VERIFYING_KEY
        .get_or_init(|| {
            if VERIFYING_KEY_BYTES == [0u8; 32] {
                // Fail-closed at startup: a production binary with an unset verifying key is
                // a configuration flaw. Panicking here is intentional — it surfaces the error
                // loudly before any user data is touched.
                panic!(
                    "PRODUCTION BUILD FLAW: VERIFYING_KEY_BYTES is all-zeros. \
                     Run `cargo run -p mint-token -- generate`, paste the output into \
                     vault/src/lib.rs, and rebuild. Refusing to start."
                );
            }
            VerifyingKey::from_bytes(&VERIFYING_KEY_BYTES)
                .map_err(|e| eprintln!("vault: invalid Ed25519 verifying key bytes: {e}"))
                .ok()
        })
        .as_ref()
}

/// Token-based access control for destructive operations.
pub struct SigningOracle;

impl SigningOracle {
    /// Verifies that `token` is a valid base64-encoded Ed25519 signature of
    /// `"JANITOR_PURGE_AUTHORIZED"` under the embedded verifying key.
    ///
    /// # Errors
    /// - [`VaultError::MalformedToken`] — token is not valid base64 or is not 64 bytes.
    /// - [`VaultError::InvalidSignature`] — signature does not match the verifying key.
    ///
    /// A token is obtained by purchasing a license at thejanitor.app.
    pub fn verify_token(token: &str) -> Result<(), VaultError> {
        use base64::Engine;

        // 1. Base64-decode the token.
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(token)
            .map_err(|_| VaultError::MalformedToken)?;

        // 2. Must be exactly 64 bytes (Ed25519 signature length).
        let sig_bytes: [u8; 64] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::MalformedToken)?;
        let sig = Signature::from_bytes(&sig_bytes);

        // 3. Verify against the embedded verifying key.
        get_verifying_key()
            .ok_or(VaultError::InvalidSignature)?
            .verify(PURGE_MESSAGE, &sig)
            .map_err(|_| VaultError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signature, Signer, SigningKey};

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
        assert!(SigningOracle::verify_token(&token).is_ok());
    }

    #[test]
    fn test_invalid_token_rejected() {
        assert!(matches!(
            SigningOracle::verify_token("not-a-valid-token"),
            Err(VaultError::MalformedToken)
        ));
        assert!(matches!(
            SigningOracle::verify_token(""),
            Err(VaultError::MalformedToken)
        ));
        // "AAAA" decodes to 3 bytes — wrong length → MalformedToken
        assert!(matches!(
            SigningOracle::verify_token("AAAA"),
            Err(VaultError::MalformedToken)
        ));
    }

    #[test]
    fn test_wrong_message_rejected() {
        let token = make_token(&TEST_SIGNING_KEY_SEED, b"DIFFERENT_MESSAGE");
        assert!(matches!(
            SigningOracle::verify_token(&token),
            Err(VaultError::InvalidSignature)
        ));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let other_seed = [0x42u8; 32];
        let token = make_token(&other_seed, PURGE_MESSAGE);
        assert!(matches!(
            SigningOracle::verify_token(&token),
            Err(VaultError::InvalidSignature)
        ));
    }
}
