#!/usr/bin/env bash
# Run the collector and SSH honeypot on the host (no containers).
# The host key under data/keys is created on first start and reused after that.
# This script does not remove the key from your SSH known_hosts file.
set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "Missing .env. Run: cp .env.example .env" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${CLICKHOUSE_PASSWORD:-}" || "${CLICKHOUSE_PASSWORD}" == "change-me" ]]; then
  echo "Set CLICKHOUSE_PASSWORD in .env before starting the collector." >&2
  exit 1
fi

mkdir -p data/events data/keys

export CLICKHOUSE_PASSWORD
export CLICKHOUSE_USER="${CLICKHOUSE_USER:-honeytrap}"
export CLICKHOUSE_URL="${CLICKHOUSE_URL:-http://127.0.0.1:8123}"
export CLICKHOUSE_DB="${CLICKHOUSE_DB:-honeytrap}"

echo "Starting collector (password is taken from CLICKHOUSE_PASSWORD, not the command line)..."
nohup cargo run -p honeytrap-collector -- \
  --events-file ./data/events/live.jsonl \
  --clickhouse-url "${CLICKHOUSE_URL}" \
  --clickhouse-user "${CLICKHOUSE_USER}" \
  --database "${CLICKHOUSE_DB}" \
  --metrics-addr 127.0.0.1:9108 \
  > collector.log 2>&1 &

echo "Starting SSH honeypot on port ${SSH_PORT:-2222}."
echo "Host key: data/keys/ssh_host_ed25519 (kept across restarts)."
cargo run -p honeytrap-ssh -- \
  --host 0.0.0.0 \
  --port "${SSH_PORT:-2222}" \
  --host-key ./data/keys/ssh_host_ed25519 \
  --events-file ./data/events/live.jsonl
