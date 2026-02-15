//! # mint-token
//!
//! Keypair generation and purge-token minting for The Janitor.
//!
//! ## Usage
//!
//! **Generate** a new Ed25519 keypair and print the Rust snippet for `vault`:
//! ```sh
//! cargo run -p mint-token -- generate
//! ```
//!
//! **Mint** a purge token from an existing private key:
//! ```sh
//! cargo run -p mint-token -- mint --key <64-hex-chars>
//! ```

use anyhow::Context;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};

const PURGE_MESSAGE: &[u8] = b"JANITOR_PURGE_AUTHORIZED";

#[derive(Parser)]
#[command(
    name = "mint-token",
    about = "Janitor Ed25519 keypair generator and purge-token minter"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair.
    ///
    /// Prints the private key (hex) and the Rust const snippet to paste into
    /// `crates/vault/src/lib.rs`.
    Generate,

    /// Sign `JANITOR_PURGE_AUTHORIZED` and print the base64 token.
    ///
    /// Use the hex private key printed by `generate`.
    Mint {
        /// Hex-encoded 32-byte private key seed (64 hex chars).
        #[arg(long)]
        key: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Generate => cmd_generate(),
        Commands::Mint { key } => cmd_mint(&key),
    }
}

/// Generate a fresh keypair and print copy-pasteable Rust/CLI output.
fn cmd_generate() -> anyhow::Result<()> {
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let sk_hex = hex::encode(signing_key.to_bytes());
    let vk_bytes = verifying_key.to_bytes();

    // Build a Rust byte-array literal: 8 bytes per row.
    let rows: Vec<String> = vk_bytes
        .chunks(8)
        .map(|row| {
            row.iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .collect();
    let rust_array = rows.join(",\n        ");

    println!("╔═══════════════════════════════════════════════╗");
    println!("║       NEW KEYPAIR — NEVER COMMIT PRIVATE KEY  ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!();
    println!("PRIVATE KEY (hex) — store at thejanitor.app only:");
    println!("  {sk_hex}");
    println!();
    println!("PUBLIC KEY — paste into crates/vault/src/lib.rs:");
    println!("  const VERIFYING_KEY_BYTES: [u8; 32] = [");
    println!("      {rust_array},");
    println!("  ];");
    println!();
    println!("Mint a token: cargo run -p mint-token -- mint --key {sk_hex}");

    Ok(())
}

/// Sign `PURGE_MESSAGE` with the provided private key and print the base64 token.
fn cmd_mint(key_hex: &str) -> anyhow::Result<()> {
    let key_bytes = hex::decode(key_hex).context("private key must be valid hex")?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes (64 hex chars)"))?;

    let signing_key = SigningKey::from_bytes(&key_array);
    let sig = signing_key.sign(PURGE_MESSAGE);
    let token = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

    println!("╔═══════════════════════════════════════════════╗");
    println!("║            PURGE TOKEN (BASE64)               ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!("{token}");

    Ok(())
}
