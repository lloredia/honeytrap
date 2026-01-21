# Build stage
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY shared ./shared
COPY honeypots ./honeypots

RUN cargo build --release -p honeytrap-ssh

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /bin/false honeytrap && mkdir -p /data && chown honeytrap:honeytrap /data

COPY --from=builder /app/target/release/honeytrap-ssh /app/honeytrap-ssh

USER honeytrap
ENTRYPOINT ["/app/honeytrap-ssh"]
