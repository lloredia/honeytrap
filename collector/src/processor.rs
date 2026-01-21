//! Event processor

use crate::clickhouse::ClickHouseClient;
use anyhow::Result;
use honeytrap_shared::HoneypotEvent;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

pub async fn run(events_file: PathBuf, ch_client: ClickHouseClient) -> Result<()> {
    while !events_file.exists() {
        info!("Waiting for events file: {:?}", events_file);
        sleep(Duration::from_secs(5)).await;
    }

    let mut file = File::open(&events_file)?;
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    info!("Processing events from: {:?}", events_file);

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => sleep(Duration::from_millis(100)).await,
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match serde_json::from_str::<HoneypotEvent>(line) {
                    Ok(event) => {
                        debug!("Processing event {}", event.id);
                        if let Err(e) = ch_client.insert_event(&event).await {
                            error!("Insert failed: {}", e);
                        }
                    }
                    Err(e) => warn!("Parse error: {}", e),
                }
            }
            Err(e) => {
                error!("Read error: {}", e);
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
