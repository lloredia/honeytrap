# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /app

# aws-lc-rs (russh's crypto backend) builds with CMake.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY shared ./shared
COPY honeypots ./honeypots
COPY collector ./collector

RUN cargo build --locked --release -p honeytrap-ssh -p honeytrap-collector

FROM debian:bookworm-slim AS data-root
RUN mkdir -p /data/events /data/keys \
    && chown -R 65532:65532 /data

FROM gcr.io/distroless/cc-debian12:nonroot AS honeypot
COPY --from=data-root --chown=65532:65532 /data /data
COPY --from=builder --chown=65532:65532 /app/target/release/honeytrap-ssh /usr/local/bin/honeytrap-ssh
USER 65532:65532
WORKDIR /data
EXPOSE 2222
ENTRYPOINT ["/usr/local/bin/honeytrap-ssh"]
CMD ["--host", "0.0.0.0", "--port", "2222", "--host-key", "/data/keys/ssh_host_ed25519", "--events-file", "/data/events/ssh.jsonl", "--metrics-port", "9100"]

FROM gcr.io/distroless/cc-debian12:nonroot AS collector
COPY --from=data-root --chown=65532:65532 /data /data
COPY --from=builder --chown=65532:65532 /app/target/release/honeytrap-collector /usr/local/bin/honeytrap-collector
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/honeytrap-collector"]
CMD ["--events-file", "/data/events/ssh.jsonl", "--clickhouse-url", "http://clickhouse:8123", "--metrics-addr", "0.0.0.0:9108"]
