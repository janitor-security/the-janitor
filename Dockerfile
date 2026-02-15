# ============================================================
# Stage 1: Build
# Uses Debian-based Rust image to satisfy heavy workspace deps
# (z3 static link, llvm-sys, etc.). Only the `cli` binary is built.
# ============================================================
FROM rust:1.82-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    libclang-dev \
    llvm-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency layer: copy manifests first.
COPY Cargo.toml Cargo.lock ./
COPY crates/anatomist/Cargo.toml   crates/anatomist/Cargo.toml
COPY crates/cli/Cargo.toml         crates/cli/Cargo.toml
COPY crates/common/Cargo.toml      crates/common/Cargo.toml
COPY crates/oracle/Cargo.toml      crates/oracle/Cargo.toml
COPY crates/reaper/Cargo.toml      crates/reaper/Cargo.toml
COPY crates/shadow/Cargo.toml      crates/shadow/Cargo.toml
COPY crates/substrate/Cargo.toml   crates/substrate/Cargo.toml
COPY crates/supervisor/Cargo.toml  crates/supervisor/Cargo.toml
COPY crates/vault/Cargo.toml       crates/vault/Cargo.toml

# Copy source and build only the CLI binary.
COPY crates/ crates/
RUN cargo build --release --package cli

# ============================================================
# Stage 2: Runtime — minimal Alpine image (<20 MB)
# The janitor binary is statically linked against glibc;
# use debian:bookworm-slim for glibc compatibility.
# ============================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/cli /usr/local/bin/janitor

ENTRYPOINT ["janitor"]
CMD ["--help"]
