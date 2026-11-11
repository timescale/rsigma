# syntax=docker/dockerfile:1

# Pin the workspace MSRV image by digest for immutability. Dependabot updates
# the digest without changing the Rust version.
FROM rust:1.97.1-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder

# build-base: jemalloc-sys compiles C for the musl global allocator.
RUN apk add --no-cache musl-dev build-base

WORKDIR /build

# Layer 1: dependency compilation (cached unless manifests change)
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/rsigma-parser/Cargo.toml crates/rsigma-parser/Cargo.toml
COPY crates/rsigma-eval/Cargo.toml crates/rsigma-eval/Cargo.toml
COPY crates/rsigma-convert/Cargo.toml crates/rsigma-convert/Cargo.toml
COPY crates/rsigma-runtime/Cargo.toml crates/rsigma-runtime/Cargo.toml
COPY crates/rsigma-cli/Cargo.toml crates/rsigma-cli/Cargo.toml
COPY crates/rsigma-lsp/Cargo.toml crates/rsigma-lsp/Cargo.toml
RUN mkdir -p crates/rsigma-parser/src crates/rsigma-eval/src \
             crates/rsigma-convert/src crates/rsigma-runtime/src \
             crates/rsigma-cli/src crates/rsigma-lsp/src \
    && touch crates/rsigma-parser/src/lib.rs crates/rsigma-eval/src/lib.rs \
             crates/rsigma-convert/src/lib.rs crates/rsigma-runtime/src/lib.rs \
             crates/rsigma-lsp/src/lib.rs \
    && echo 'fn main() {}' > crates/rsigma-cli/src/main.rs \
    && echo 'fn main() {}' > crates/rsigma-lsp/src/main.rs \
    && cargo build --release --all-features --locked -p rsigma 2>/dev/null || true

# Layer 2: full source build
COPY . .
RUN cargo build --release --all-features --locked -p rsigma \
    && strip target/release/rsigma

# Runtime: bare minimum (zero CVEs, no shell, no package manager)
# For a shell-based alternative with DHI, swap with:
#   FROM docker/library/alpine:3.21
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/release/rsigma /rsigma

USER 65534:65534
ENTRYPOINT ["/rsigma"]
