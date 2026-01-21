//! SSH Server implementation

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use russh::server::{Config, Server};
use russh_keys::key::KeyPair;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use honeytrap_shared::{
    DestinationInfo, EventCategory, HoneypotEvent, Protocol, Severity, SourceInfo,
};

use crate::config::SshHoneypotConfig;
use crate::handler::SshHandler;

/// Event sender type
pub type EventSender = mpsc::UnboundedSender<HoneypotEvent>;

/// SSH Honeypot Server
pub struct SshHoneypotServer {
    config: Arc<SshHoneypotConfig>,
    event_tx: EventSender,
    sessions_per_ip: Arc<DashMap<String, usize>>,
}

impl SshHoneypotServer {
    pub fn new(config: SshHoneypotConfig, event_tx: EventSender) -> Self {
        Self {
            config: Arc::new(config),
            event_tx,
            sessions_per_ip: Arc::new(DashMap::new()),
        }
    }
}

impl Server for SshHoneypotServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        let peer_addr = peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
        let ip = peer_addr.ip().to_string();

        let mut session_count = self.sessions_per_ip.entry(ip.clone()).or_insert(0);
        *session_count += 1;

        if *session_count > self.config.max_sessions_per_ip {
            warn!(
                ip = %ip,
                count = *session_count,
                max = self.config.max_sessions_per_ip,
                "Rate limiting IP - too many sessions"
            );
        }

        let session_id = Uuid::new_v4();
        info!(
            session_id = %session_id,
            peer_addr = %peer_addr,
            "New SSH connection"
        );

        let source = SourceInfo::new(ip.clone(), peer_addr.port());
        let destination = DestinationInfo {
            ip: self.config.host.clone(),
            port: self.config.port,
            honeypot_id: self.config.honeypot_id.clone(),
        };

        let event = HoneypotEvent::new(
            session_id,
            Protocol::Ssh,
            EventCategory::Connection,
            source,
            destination.clone(),
        )
        .with_severity(Severity::Low)
        .with_tag("connection_opened");

        let category = format!("{:?}", event.category);

        let _ = self.event_tx.send(event);

        metrics::counter!(
            "honeytrap_events_captured_total",
            "category" => category
        )
        .increment(1);

        SshHandler::new(
            session_id,
            peer_addr,
            self.config.clone(),
            self.event_tx.clone(),
            self.sessions_per_ip.clone(),
        )
    }
}

/// Run the SSH honeypot server
pub async fn run(config: SshHoneypotConfig) -> Result<()> {
    let key_pair = generate_host_key()?;

    let ssh_config = Config {
        inactivity_timeout: Some(Duration::from_secs(config.session_timeout_secs)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![key_pair],
        ..Default::default()
    };

    let ssh_config = Arc::new(ssh_config);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<HoneypotEvent>();

    tokio::spawn(async move {
        process_events(&mut event_rx).await;
    });

    let mut server = SshHoneypotServer::new(config.clone(), event_tx);

    let addr = format!("{}:{}", config.host, config.port);
    info!(addr = %addr, "SSH honeypot listening");

    server
        .run_on_address(ssh_config, &addr)
        .await
        .context("Failed to run SSH server")?;

    Ok(())
}

fn generate_host_key() -> Result<KeyPair> {
    info!("Generating new Ed25519 host key");
    KeyPair::generate_ed25519().context("Failed to generate Ed25519 key")
}

async fn process_events(event_rx: &mut mpsc::UnboundedReceiver<HoneypotEvent>) {
    info!("Event processor started");

    // Open events file for appending
    let events_file = Path::new("./events.jsonl");
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_file)
        .await
    {
        Ok(f) => {
            info!("Writing events to: {:?}", events_file);
            Some(f)
        }
        Err(e) => {
            error!(
                "Failed to open events file: {} - events will only be logged to stdout",
                e
            );
            None
        }
    };

    while let Some(event) = event_rx.recv().await {
        let event_json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(e) => {
                error!(error = %e, "Failed to serialize event");
                continue;
            }
        };

        // Log to stdout
        info!(
            session_id = %event.session_id,
            category = ?event.category,
            source_ip = %event.source.ip,
            "Event captured"
        );

        // Write to file
        if let Some(ref mut f) = file {
            let line = format!("{}\n", event_json);
            if let Err(e) = f.write_all(line.as_bytes()).await {
                error!("Failed to write event to file: {}", e);
            }
            let _ = f.flush().await;
        }

        metrics::counter!(
            "honeytrap_events_captured_total",
            "category" => format!("{:?}", event.category)
        )
        .increment(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SshHoneypotConfig::default();
        assert_eq!(config.port, 2222);
        assert!(config.allow_all_auth);
    }
}