CREATE DATABASE IF NOT EXISTS honeytrap;

CREATE TABLE IF NOT EXISTS honeytrap.events_raw
(
  ts DateTime64(3, 'UTC'),
  id UUID,
  session_id UUID,

  honeypot_id String,

  protocol LowCardinality(String),
  category LowCardinality(String),
  severity LowCardinality(String),

  source_ip IPv6,
  source_port UInt16,
  dest_ip IPv6,
  dest_port UInt16,

  -- useful dimensions
  tags Array(LowCardinality(String)),

  -- optional enrichments (may be empty)
  country_code LowCardinality(String),
  country_name String,
  city String,
  asn UInt32,
  asn_org String,

  -- optional extracted fields
  username String,
  auth_method LowCardinality(String),
  auth_success UInt8,
  command String,
  command_name String,

  raw_data String,

  -- keep full event JSON for reprocessing / future fields
  event_json String
)
ENGINE = MergeTree
PARTITION BY toDate(ts)
ORDER BY (ts, protocol, category, source_ip, honeypot_id);
