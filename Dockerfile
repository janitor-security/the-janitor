# ============================================================
# Stage 1: Build
# rust:1.85-slim (Debian bookworm-slim base) — gcc included
# via the Rust toolchain layer; gcc is needed by the `cc`
# crate to compile tree-sitter grammar C sources.
# ============================================================
FROM rust:1.85-slim@sha256:3490aa77d179a59d67e94239cca96dd84030b564470859200f535b942bdffedf AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency layer: copy manifests first.
COPY Cargo.toml Cargo.lock ./
COPY crates/anatomist/Cargo.toml   crates/anatomist/Cargo.toml
COPY crates/cli/Cargo.toml         crates/cli/Cargo.toml
COPY crates/common/Cargo.toml      crates/common/Cargo.toml
COPY crates/dashboard/Cargo.toml   crates/dashboard/Cargo.toml
COPY crates/forge/Cargo.toml       crates/forge/Cargo.toml
COPY crates/lazarus/Cargo.toml     crates/lazarus/Cargo.toml
COPY crates/mcp/Cargo.toml         crates/mcp/Cargo.toml
COPY crates/oracle/Cargo.toml      crates/oracle/Cargo.toml
COPY crates/reaper/Cargo.toml      crates/reaper/Cargo.toml
COPY crates/shadow/Cargo.toml      crates/shadow/Cargo.toml
COPY crates/substrate/Cargo.toml   crates/substrate/Cargo.toml
COPY crates/vault/Cargo.toml       crates/vault/Cargo.toml

# Copy source and build only the CLI binary.
COPY crates/ crates/
RUN cargo build --release --package cli

# ============================================================
# Stage 2: Runtime — minimal Debian slim image
# Statically-linked glibc binary requires glibc at runtime.
# ============================================================
FROM debian:bookworm-slim@sha256:6458e6ce2b6448e31bfdced4be7d8aa88d389e6694ab09f5a718a694abe147f4 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/janitor /usr/local/bin/janitor

ENTRYPOINT ["janitor"]
CMD ["--help"]
