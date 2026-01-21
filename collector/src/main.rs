use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use honeytrap_shared::events::HoneypotEvent;
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::time::{interval, sleep, Instant};
use tracing::{debug, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(name = "honeytrap-collector", about = "Collect honeypot events and store in ClickHouse")]
struct Args {
    /// Path to JSONL events file (one JSON event per line)
    #[arg(long, default_value = "data/events/ssh.jsonl")]
    events_file: String,

    /// ClickHouse HTTP base URL (no trailing slash)
    #[arg(long, default_value = "http://localhost:8123")]
    clickhouse_url: String,

    /// ClickHouse user
    #[arg(long, default_value = "honeytrap")]
    clickhouse_user: String,

    /// ClickHouse password
    #[arg(long, default_value = "honeytrap")]
    clickhouse_password: String,

    /// Database name
    #[arg(long, default_value = "honeytrap")]
    database: String,

    /// Table name
    #[arg(long, default_value = "events_raw")]
    table: String,

    /// Batch size for inserts
    #[arg(long, default_value_t = 500)]
    batch_size: usize,

    /// Flush interval (ms) even if batch not full
    #[arg(long, default_value_t = 1000)]
    flush_ms: u64,

    /// Prometheus metrics listen address
    #[arg(long, default_value = "0.0.0.0:9108")]
    metrics_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = Args::parse();

    // Prometheus metrics
    PrometheusBuilder::new()
        .with_http_listener(args.metrics_addr.parse::<SocketAddr>().context("invalid --metrics-addr")?)
        .install()
        .context("failed to start prometheus exporter")?;

    info!(
        events_file = %args.events_file,
        clickhouse_url = %args.clickhouse_url,
        db = %args.database,
        table = %args.table,
        "collector starting"
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build reqwest client")?;

    run_loop(args, client).await
}

async fn run_loop(args: Args, client: Client) -> Result<()> {
    // Ensure directory exists (helps on fresh clone)
    if let Some(parent) = std::path::Path::new(&args.events_file).parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    // Create file if missing (tailer expects it)
    if tokio::fs::metadata(&args.events_file).await.is_err() {
        tokio::fs::write(&args.events_file, b"").await.ok();
    }

    let mut offset: u64 = 0;
    let mut batch: Vec<String> = Vec::with_capacity(args.batch_size);

    let mut ticker = interval(Duration::from_millis(args.flush_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Open file each iteration if needed (handles rotation/truncation)
        let mut file = tokio::fs::File::open(&args.events_file)
            .await
            .with_context(|| format!("failed to open events file: {}", args.events_file))?;

        let meta = file.metadata().await?;
        let len = meta.len();

        // Handle truncation/rotation: if file shrank, reset offset
        if len < offset {
            warn!(old_offset = offset, new_len = len, "events file truncated; resetting offset");
            offset = 0;
        }

        file.seek(std::io::SeekFrom::Start(offset)).await?;

        let mut reader = BufReader::new(file);
        let mut line = String::new();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        flush_batch(&args, &client, &mut batch).await?;
                    }
                }

                read = reader.read_line(&mut line) => {
                    let n = read?;
                    if n == 0 {
                        // EOF: record current position and break to reopen after a short sleep
                        offset = reader.stream_position().await.unwrap_or(offset);
                        sleep(Duration::from_millis(200)).await;
                        break;
                    }

                    // Trim newline(s)
                    let raw = line.trim_end_matches(&['\r','\n'][..]).to_string();
                    line.clear();

                    if raw.is_empty() {
                        continue;
                    }

                    counter!("collector_lines_total").increment(1);

                    match serde_json::from_str::<HoneypotEvent>(&raw) {
                        Ok(event) => {
                            counter!("collector_events_parsed_total",
                                "protocol" => event.protocol.to_string(),
                                "category" => format!("{:?}", event.category),
                            ).increment(1);

                            let row = flatten_event_to_clickhouse_row(&event, &raw)?;
                            batch.push(row);

                            if batch.len() >= args.batch_size {
                                flush_batch(&args, &client, &mut batch).await?;
                            }
                        }
                        Err(e) => {
                            counter!("collector_parse_errors_total").increment(1);
                            warn!(error=%e, "failed to parse event json line");
                            debug!(bad_line=%raw, "bad json line");
                        }
                    }
                }
            }
        }
    }
}

fn flatten_event_to_clickhouse_row(event: &HoneypotEvent, raw_json: &str) -> Result<String> {
    // ClickHouse expects DateTime64(3) like: "YYYY-MM-DD HH:MM:SS.mmm"
    let ts = format_ts(event.timestamp);

    // IPs: store as IPv6 (IPv4 mapped) to match schema column IPv6
    let source_ip = to_ipv6_string(&event.source.ip);
    let dest_ip = to_ipv6_string(&event.destination.ip);

    let (country_code, country_name, city, asn, asn_org) = (
        event.source.country_code.clone().unwrap_or_default(),
        event.source.country_name.clone().unwrap_or_default(),
        event.source.city.clone().unwrap_or_default(),
        event.source.asn.unwrap_or(0),
        event.source.asn_org.clone().unwrap_or_default(),
    );

    let (username, auth_method, auth_success) = match &event.credentials {
        Some(c) => (
            c.username.clone(),
            c.auth_method.clone(),
            if c.success { 1u8 } else { 0u8 },
        ),
        None => (String::new(), String::new(), 0u8),
    };

    let (command, command_name) = match &event.command {
        Some(cmd) => (cmd.command.clone(), cmd.command_name.clone().unwrap_or_default()),
        None => (String::new(), String::new()),
    };

    let raw_data = event.raw_data.clone().unwrap_or_default();

    // Build a JSON object matching honeytrap.events_raw columns
    let row = serde_json::json!({
        "ts": ts,
        "id": event.id.to_string(),
        "session_id": event.session_id.to_string(),

        "honeypot_id": event.destination.honeypot_id,

        "protocol": event.protocol.to_string(),
        "category": format!("{:?}", event.category).to_lowercase(), // matches snake_case enum; safe for query
        "severity": format!("{:?}", event.severity).to_lowercase(),

        "source_ip": source_ip,
        "source_port": event.source.port,
        "dest_ip": dest_ip,
        "dest_port": event.destination.port,

        "tags": event.tags,

        "country_code": country_code,
        "country_name": country_name,
        "city": city,
        "asn": asn,
        "asn_org": asn_org,

        "username": username,
        "auth_method": auth_method,
        "auth_success": auth_success,
        "command": command,
        "command_name": command_name,

        "raw_data": raw_data,

        "event_json": raw_json
    });

    Ok(serde_json::to_string(&row)?)
}

async fn flush_batch(args: &Args, client: &Client, batch: &mut Vec<String>) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let start = Instant::now();
    let payload = batch.join("\n") + "\n";

    let query = format!(
        "INSERT INTO {}.{} FORMAT JSONEachRow",
        args.database, args.table
    );

    let url = format!(
        "{}/?user={}&password={}&query={}",
        args.clickhouse_url,
        urlencoding::encode(&args.clickhouse_user),
        urlencoding::encode(&args.clickhouse_password),
        urlencoding::encode(&query),
    );

    let resp = client
        .post(url)
        .body(payload)
        .send()
        .await
        .context("clickhouse insert request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        counter!("collector_clickhouse_insert_failures_total").increment(1);
        return Err(anyhow!("clickhouse insert failed: {}: {}", status, body));
    }

    let elapsed = start.elapsed().as_secs_f64();
    histogram!("collector_clickhouse_insert_latency_seconds").record(elapsed);
    counter!("collector_clickhouse_inserts_total").increment(1);
    counter!("collector_events_inserted_total").increment(batch.len() as u64);

    info!(rows = batch.len(), secs = elapsed, "flushed batch to clickhouse");
    batch.clear();
    Ok(())
}

fn format_ts(ts: DateTime<Utc>) -> String {
    // 3-digit millis
    ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

fn to_ipv6_string(ip_str: &str) -> String {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_ipv6_mapped().to_string(),
        Ok(IpAddr::V6(v6)) => v6.to_string(),
        Err(_) => {
            // If it's not parseable, store as "::" so inserts don't fail; also emit metric
            counter!("collector_bad_ip_total").increment(1);
            "::".to_string()
        }
    }
}
