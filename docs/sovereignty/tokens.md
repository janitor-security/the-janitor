# Token Gate: Ed25519 Purge Authorization

**Crate**: `crates/vault`
**Guard**: `vault::SigningOracle::verify_token(token: &str) -> bool`

---

## Protocol

Destructive operations (`janitor clean`, `janitor dedup --apply`) require a valid **purge token** — a base64-encoded Ed25519 signature of the string `JANITOR_PURGE_AUTHORIZED`.

```
Token = Base64( Ed25519_Sign(SIGNING_KEY, "JANITOR_PURGE_AUTHORIZED") )
```

The binary embeds only the **verifying key** (32 bytes, `const VERIFYING_KEY_BYTES`). The signing key never leaves thejanitor.app.

---

## Verification Flow

```
┌─────────────┐        ┌──────────────────┐        ┌─────────────────┐
│  CLI flag   │        │  SigningOracle    │        │ VERIFYING_KEY   │
│ --token T   │──────▶ │  verify_token(T) │──────▶ │ BYTES (binary)  │
└─────────────┘        └────────┬─────────┘        └────────┬────────┘
                                │                           │
                          base64_decode(T)          VerifyingKey::
                                │                  from_bytes(...)
                          sig_bytes [64]                    │
                                │                           │
                                └──────── verify(msg, sig) ─┘
                                                │
                                        Ok → proceed
                                        Err → ACCESS DENIED
```

1. Base64-decode the token → 64-byte Ed25519 signature.
2. Construct `Signature::from_bytes(&sig_bytes)`.
3. Call `verifying_key.verify(b"JANITOR_PURGE_AUTHORIZED", &sig)`.
4. `Ok(())` → operation proceeds. Any error → process exits 1.

---

## Key Ceremony

Run once per deployment to generate a production keypair:

```sh
cargo run -p mint-token -- generate
```

**Output:**

```
╔═══════════════════════════════════════════════╗
║       NEW KEYPAIR — NEVER COMMIT PRIVATE KEY  ║
╚═══════════════════════════════════════════════╝

PRIVATE KEY (hex) — store at thejanitor.app only:
  9d50025738375e05d5184a96c09f56b611ac59796df953874ae60258e83a9736

PUBLIC KEY — paste into crates/vault/src/lib.rs:
  const VERIFYING_KEY_BYTES: [u8; 32] = [
      0x71, 0xbc, 0x61, 0xae, 0xe0, 0x6f, 0xac, 0x48,
      0x5a, 0x97, 0xc4, 0x59, 0x3b, 0xd0, 0x2c, 0x43,
      0x92, 0x61, 0x48, 0xe1, 0x33, 0xb7, 0xc5, 0x9e,
      0x19, 0x3a, 0x8d, 0x32, 0x15, 0x3e, 0x88, 0xe9,
  ];
```

**Activation steps:**

1. Paste the `VERIFYING_KEY_BYTES` block into `crates/vault/src/lib.rs`.
2. Rebuild: `just build`.
3. Store the private key hex securely — it is never embedded in the binary.

---

## Minting a Token

```sh
cargo run -p mint-token -- mint --key <64-hex-char-private-key>
```

Output is the Base64 token. Pass it to any destructive operation:

```sh
janitor clean /path/to/project --token "lS8SDsLx9dTO..."
janitor dedup /path/to/project --apply --token "lS8SDsLx9dTO..."
```

Tokens are **deterministic** for a given keypair: signing the same message with the same key always produces the same signature. Rotate keys to invalidate all previously issued tokens.

---

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Unforgeability** | Ed25519 — 128-bit security level. Signature invalid without the private key. |
| **Message binding** | Token is a signature of the exact string `JANITOR_PURGE_AUTHORIZED`. A token issued for any other message is rejected. |
| **Key isolation** | Binary embeds only the 32-byte verifying key. Private key is never present on the end-user machine. |
| **No network call** | Verification is fully offline — `VerifyingKey::verify()` is a pure local computation. |

---

## Fallback / Demo Mode

When `VERIFYING_KEY_BYTES` is all-zeros (the placeholder default), the vault derives a fallback verifying key from `SIGNING_KEY_SEED` for test and development purposes.

This mode is **never acceptable in production**. A binary with `VERIFYING_KEY_BYTES = [0u8; 32]` accepts tokens signed by the demo seed, which is public. Replace the bytes before shipping any release binary.

---

## Access Denied

On an invalid or missing token, the CLI prints:

```
ACCESS DENIED. Purchase PQC/Ed25519 Token at thejanitor.app
```

and exits with code `1`. No partial work is performed.
