use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Client;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::time::{interval, sleep, Instant};
use tracing::{debug, info, warn};

mod processor;

use processor::{event_to_clickhouse_row, is_safe_ident, metrics_addr, parse_event_line};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "honeytrap-collector",
    about = "Tail honeypot JSONL events and store them in ClickHouse"
)]
struct Args {
    /// Path to JSONL events file (one JSON event per line).
    #[arg(
        long,
        default_value = "data/events/ssh.jsonl",
        env = "HONEYTRAP_EVENTS_FILE"
    )]
    events_file: String,

    /// ClickHouse HTTP base URL (no trailing slash).
    #[arg(long, default_value = "http://127.0.0.1:8123", env = "CLICKHOUSE_URL")]
    clickhouse_url: String,

    /// ClickHouse user.
    #[arg(long, default_value = "honeytrap", env = "CLICKHOUSE_USER")]
    clickhouse_user: String,

    /// Database name.
    #[arg(long, default_value = "honeytrap", env = "CLICKHOUSE_DB")]
    database: String,

    /// Table name.
    #[arg(long, default_value = "events_raw")]
    table: String,

    /// Batch size for inserts.
    #[arg(long, default_value_t = 500)]
    batch_size: usize,

    /// Flush interval in milliseconds, even if the batch is not full.
    #[arg(long, default_value_t = 1000)]
    flush_ms: u64,

    /// Prometheus metrics listen address.
    #[arg(long, default_value = "0.0.0.0:9108", env = "COLLECTOR_METRICS_ADDR")]
    metrics_addr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let args = Args::parse();
    // The password is read from the environment so it never appears in argv.
    let clickhouse_password = clickhouse_password_from_env()?;

    if !is_safe_ident(&args.database) || !is_safe_ident(&args.table) {
        anyhow::bail!("database and table must be alphanumeric identifiers");
    }

    PrometheusBuilder::new()
        .with_http_listener(metrics_addr(&args.metrics_addr)?)
        .install()
        .context("failed to start prometheus exporter")?;

    info!(
        events_file = %args.events_file,
        clickhouse_url = %args.clickhouse_url,
        db = %args.database,
        table = %args.table,
        user = %args.clickhouse_user,
        "collector starting"
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    run_loop(args, clickhouse_password, client).await
}

fn clickhouse_password_from_env() -> Result<String> {
    password_from_value(std::env::var("CLICKHOUSE_PASSWORD").ok())
}

fn password_from_value(value: Option<String>) -> Result<String> {
    match value {
        Some(password) if !password.is_empty() => Ok(password),
        Some(_) => anyhow::bail!("CLICKHOUSE_PASSWORD is empty"),
        None => anyhow::bail!("CLICKHOUSE_PASSWORD is not set"),
    }
}

async fn run_loop(args: Args, clickhouse_password: String, client: Client) -> Result<()> {
    if let Some(parent) = std::path::Path::new(&args.events_file).parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }

    if tokio::fs::metadata(&args.events_file).await.is_err() {
        tokio::fs::write(&args.events_file, b"").await.ok();
    }

    let mut offset: u64 = 0;
    let mut batch: Vec<String> = Vec::with_capacity(args.batch_size);

    let mut ticker = interval(Duration::from_millis(args.flush_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let mut file = tokio::fs::File::open(&args.events_file)
            .await
            .with_context(|| format!("failed to open events file: {}", args.events_file))?;

        let len = file.metadata().await?.len();
        if len < offset {
            warn!(
                old_offset = offset,
                new_len = len,
                "events file truncated; resetting offset"
            );
            offset = 0;
        }

        file.seek(std::io::SeekFrom::Start(offset)).await?;

        let mut reader = BufReader::new(file);
        let mut line = String::new();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if !batch.is_empty() {
                        flush_batch(&args, &clickhouse_password, &client, &mut batch).await?;
                    }
                }

                read = reader.read_line(&mut line) => {
                    let n = read?;
                    if n == 0 {
                        offset = reader.stream_position().await.unwrap_or(offset);
                        sleep(Duration::from_millis(200)).await;
                        break;
                    }

                    let raw = line.trim_end_matches(['\r', '\n']).to_string();
                    line.clear();

                    if raw.is_empty() {
                        continue;
                    }

                    counter!("collector_lines_total").increment(1);

                    match parse_event_line(&raw) {
                        Ok(event) => {
                            counter!(
                                "collector_events_parsed_total",
                                "protocol" => event.protocol.to_string(),
                                "category" => format!("{:?}", event.category),
                            )
                            .increment(1);

                            let row = event_to_clickhouse_row(&event, &raw)?;
                            batch.push(row);

                            if batch.len() >= args.batch_size {
                                flush_batch(&args, &clickhouse_password, &client, &mut batch).await?;
                            }
                        }
                        Err(err) => {
                            counter!("collector_parse_errors_total").increment(1);
                            warn!(error = %err, "failed to parse event json line");
                            debug!(bad_line = %raw, "bad json line");
                        }
                    }
                }
            }
        }
    }
}

async fn flush_batch(
    args: &Args,
    clickhouse_password: &str,
    client: &Client,
    batch: &mut Vec<String>,
) -> Result<()> {
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
        "{}/?query={}",
        args.clickhouse_url.trim_end_matches('/'),
        urlencoding::encode(&query),
    );

    let resp = client
        .post(url)
        .basic_auth(&args.clickhouse_user, Some(clickhouse_password))
        .body(payload)
        .send()
        .await
        .context("clickhouse insert request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        counter!("collector_clickhouse_insert_failures_total").increment(1);
        return Err(anyhow!("clickhouse insert failed: {status}: {body}"));
    }

    let elapsed = start.elapsed().as_secs_f64();
    histogram!("collector_clickhouse_insert_latency_seconds").record(elapsed);
    counter!("collector_clickhouse_inserts_total").increment(1);
    counter!("collector_events_inserted_total").increment(batch.len() as u64);

    info!(
        rows = batch.len(),
        secs = elapsed,
        "flushed batch to clickhouse"
    );
    batch.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_is_not_a_cli_flag() {
        let parsed = Args::try_parse_from([
            "honeytrap-collector",
            "--clickhouse-password",
            "should-not-work",
        ]);
        assert!(parsed.is_err());
    }

    #[test]
    fn password_must_come_from_a_non_empty_value() {
        assert!(password_from_value(None).is_err());
        assert!(password_from_value(Some(String::new())).is_err());
        assert_eq!(
            password_from_value(Some("s3cret".to_string())).unwrap(),
            "s3cret"
        );
    }
}
