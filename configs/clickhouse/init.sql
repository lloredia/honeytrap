-- HoneyTrap ClickHouse Schema
CREATE DATABASE IF NOT EXISTS honeytrap;

CREATE TABLE IF NOT EXISTS honeytrap.events
(
    id UUID,
    session_id UUID,
    timestamp DateTime64(3),
    protocol String,
    category String,
    severity String,
    source_ip String,
    source_port UInt16,
    honeypot_id String,
    event_json String,
    created_at DateTime64(3) DEFAULT now64(3)
)
ENGINE = MergeTree()
ORDER BY (timestamp, session_id);
