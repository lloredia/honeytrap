#!/usr/bin/env bash
set -e

echo "🚀 Starting HoneyTrap Lab..."

echo "▶ Starting Collector..."
nohup cargo run -p honeytrap-collector -- \
  --events-file ./events.jsonl \
  --clickhouse-url http://localhost:8123 \
  --clickhouse-user honeytrap \
  --clickhouse-password honeytrap \
  --database honeytrap \
  --table events_raw \
  --metrics-addr 0.0.0.0:9110 \
  > collector.log 2>&1 &

sleep 2

echo "🔐 regenerating honeypot host key ===▶ SSH Honeypot..."
ssh-keygen -R "[localhost]:2222" >/dev/null 2>&1 &


sleep 5

echo "▶ Starting SSH Honeypot..."
cargo run -p honeytrap-ssh -- --port 2222
