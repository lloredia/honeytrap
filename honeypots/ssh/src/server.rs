//! SSH server.
//!
//! Accepts TCP connections, enforces session limits, and writes captured
//! events as JSONL. The host key is loaded from disk and created once so the
//! fingerprint stays stable across restarts.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use std::borrow::Cow;

use anyhow::{Context, Result};
use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
use russh::server::Config;
use russh::SshId;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use honeytrap_shared::{
    DestinationInfo, EventCategory, HoneypotEvent, Protocol, Severity, SourceInfo,
};

use crate::config::SshHoneypotConfig;
use crate::handler::SshHandler;
use crate::limits::{LimitKind, SessionLimits};

/// Bounded so a connection flood cannot grow the process without limit.
const EVENT_QUEUE_CAPACITY: usize = 1024;

/// Event sender type. `try_send` drops events when the queue is full.
pub type EventSender = mpsc::Sender<HoneypotEvent>;

/// Run the SSH honeypot until the process is stopped.
pub async fn run(config: SshHoneypotConfig) -> Result<()> {
    run_with_ready(config, None).await
}

/// Same as [`run`], but notifies `ready` with the bound address once listening.
pub async fn run_with_ready(
    mut config: SshHoneypotConfig,
    ready: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let key_pair = load_or_create_host_key(&config.host_key_path)?;
    let fingerprint = key_pair
        .public_key()
        .fingerprint(russh::keys::HashAlg::Sha256);
    info!(path = %config.host_key_path.display(), fingerprint = %fingerprint, "SSH host key ready");

    let listener = TcpListener::bind(format!("{}:{}", config.host, config.port))
        .await
        .with_context(|| format!("bind {}:{}", config.host, config.port))?;
    let local = listener.local_addr().context("listener address")?;
    config.port = local.port();

    if config.metrics_port != 0 {
        start_metrics(config.metrics_port)?;
    }

    let ssh_config = Arc::new(build_ssh_config(&config, key_pair));
    let (event_tx, mut event_rx) = mpsc::channel::<HoneypotEvent>(EVENT_QUEUE_CAPACITY);
    let events_file = config.events_file.clone();
    tokio::spawn(async move {
        process_events(&mut event_rx, &events_file).await;
    });

    info!(addr = %local, "SSH honeypot listening");
    if let Some(tx) = ready {
        let _ = tx.send(local);
    }

    let limits = SessionLimits::new(config.max_concurrent_sessions, config.max_sessions_per_ip);
    let config = Arc::new(config);

    loop {
        let (stream, peer) = listener.accept().await.context("accept connection")?;
        let ip = peer.ip().to_string();
        let permit = match limits.try_acquire(&ip) {
            Ok(permit) => permit,
            Err(kind) => {
                let reason = match kind {
                    LimitKind::Global => "global",
                    LimitKind::PerIp => "per_ip",
                };
                warn!(%ip, reason, active = limits.active(), "rejecting connection");
                metrics::counter!("honeytrap_connections_rejected_total", "reason" => reason)
                    .increment(1);
                drop(stream);
                continue;
            }
        };

        let session_id = uuid::Uuid::new_v4();
        info!(%session_id, %peer, "new SSH connection");
        emit_connection_event(&event_tx, session_id, &peer, &config);

        let handler = SshHandler::new(
            session_id,
            peer,
            Arc::clone(&config),
            event_tx.clone(),
            permit,
        );
        let ssh_config = Arc::clone(&ssh_config);
        tokio::spawn(async move {
            if let Err(err) = russh::server::run_stream(ssh_config, stream, handler).await {
                warn!(error = %err, "SSH session ended");
            }
        });
    }
}

fn build_ssh_config(config: &SshHoneypotConfig, key_pair: PrivateKey) -> Config {
    let banner: &'static str = Box::leak(config.banner.clone().into_boxed_str());
    Config {
        server_id: SshId::Standard(Cow::Borrowed(banner)),
        inactivity_timeout: Some(Duration::from_secs(config.idle_timeout_secs)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![key_pair],
        max_auth_attempts: config.max_auth_attempts,
        maximum_packet_size: 16_384,
        ..Default::default()
    }
}

fn start_metrics(port: u16) -> Result<()> {
    let addr = format!("0.0.0.0:{port}");
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(addr.parse::<std::net::SocketAddr>()?)
        .install()
        .context("start Prometheus exporter")?;
    info!(%addr, "metrics exporter listening");
    Ok(())
}

fn emit_connection_event(
    event_tx: &EventSender,
    session_id: uuid::Uuid,
    peer: &SocketAddr,
    config: &SshHoneypotConfig,
) {
    let event = HoneypotEvent::new(
        session_id,
        Protocol::Ssh,
        EventCategory::Connection,
        SourceInfo::new(peer.ip().to_string(), peer.port()),
        DestinationInfo {
            ip: config.host.clone(),
            port: config.port,
            honeypot_id: config.honeypot_id.clone(),
        },
    )
    .with_severity(Severity::Low)
    .with_tag("connection_opened");

    if event_tx.try_send(event).is_err() {
        metrics::counter!("honeytrap_events_dropped_total").increment(1);
    }
}

/// Load the Ed25519 host key at `path`, or generate and persist it.
pub fn load_or_create_host_key(path: &Path) -> Result<PrivateKey> {
    if path.exists() {
        info!(path = %path.display(), "loading persisted SSH host key");
        return russh::keys::load_secret_key(path, None)
            .with_context(|| format!("load host key {}", path.display()));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }

    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .context("generate Ed25519 host key")?;
    let encoded = key.to_openssh(LineEnding::LF).context("encode host key")?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("create host key {}", path.display()))?;
    file.write_all(encoded.as_bytes())
        .context("write host key")?;
    file.flush().context("flush host key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    info!(path = %path.display(), "generated new SSH host key");
    Ok(key)
}

async fn process_events(event_rx: &mut mpsc::Receiver<HoneypotEvent>, events_file: &Path) {
    info!(path = %events_file.display(), "event processor started");

    if let Some(parent) = events_file.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                error!(error = %err, "failed to create events directory");
            }
        }
    }

    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_file)
        .await
    {
        Ok(file) => Some(file),
        Err(err) => {
            error!(error = %err, "failed to open events file");
            None
        }
    };

    while let Some(event) = event_rx.recv().await {
        let event_json = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                error!(error = %err, "failed to serialize event");
                continue;
            }
        };

        info!(
            session_id = %event.session_id,
            category = ?event.category,
            source_ip = %event.source.ip,
            "event captured"
        );

        if let Some(handle) = file.as_mut() {
            let line = format!("{event_json}\n");
            if let Err(err) = handle.write_all(line.as_bytes()).await {
                error!(error = %err, "failed to write event");
            }
            let _ = handle.flush().await;
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
    fn default_config_keeps_the_lab_port() {
        let config = SshHoneypotConfig::default();
        assert_eq!(config.port, 2222);
        assert!(config.allow_all_auth);
        assert!(config.max_concurrent_sessions >= config.max_sessions_per_ip);
        assert!(config.idle_timeout_secs <= config.session_timeout_secs);
    }

    #[test]
    fn host_key_is_stable_across_loads() {
        let dir = std::env::temp_dir().join(format!("honeytrap-hostkey-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ssh_host_ed25519");
        let first = load_or_create_host_key(&path).unwrap();
        let second = load_or_create_host_key(&path).unwrap();
        let first_pub = first.public_key().to_openssh().unwrap();
        let second_pub = second.public_key().to_openssh().unwrap();
        assert_eq!(first_pub, second_pub);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
