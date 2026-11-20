# syntax=docker/dockerfile:1

# ---- Builder Stage ----
FROM rust:1-bookworm AS builder

WORKDIR /src

# Copy workspace manifests and source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Build the release binary (Linux builds exclude macOS/Windows GUI tray crates)
RUN cargo build --release --locked --bin aegis

# ---- Runtime Stage ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data

COPY --from=builder /src/target/release/aegis /usr/local/bin/aegis

ENV RUST_LOG=info

# DNS (UDP), HTTP/HTTPS Proxy, SOCKS5 Proxy, Web Dashboard & API
EXPOSE 53/udp 8080/tcp 1080/tcp 4242/tcp

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:4242/api/auth/status > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/aegis"]
CMD ["--lan", "--no-tray", "--data-dir", "/data", "--dns-addr", "0.0.0.0:53", "--update-lists"]
