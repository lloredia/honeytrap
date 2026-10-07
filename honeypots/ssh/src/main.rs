//! HoneyTrap SSH honeypot.
//!
//! The shell in this binary is emulated. Attacker commands are logged and
//! answered from fixtures. They are never executed on the host.

mod config;
mod handler;
mod limits;
mod sanitize;
mod server;
mod session;
mod shell;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "honeytrap-ssh")]
#[command(about = "SSH honeypot that captures credentials and commands without executing them")]
struct Args {
    #[arg(long, default_value = "0.0.0.0", env = "HONEYTRAP_HOST")]
    host: String,

    #[arg(short, long, default_value_t = 2222, env = "SSH_PORT")]
    port: u16,

    #[arg(
        long,
        default_value = "./data/keys/ssh_host_ed25519",
        env = "SSH_HOST_KEY"
    )]
    host_key: PathBuf,

    #[arg(long, default_value = "./events.jsonl", env = "HONEYTRAP_EVENTS_FILE")]
    events_file: PathBuf,

    #[arg(long, default_value = "ssh-01", env = "HONEYPOT_ID")]
    honeypot_id: String,

    #[arg(long, default_value = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")]
    banner: String,

    #[arg(long, default_value = "true")]
    allow_all_auth: bool,

    #[arg(long, default_value_t = 64, env = "HONEYTRAP_MAX_SESSIONS")]
    max_sessions: usize,

    #[arg(long, default_value_t = 4, env = "HONEYTRAP_MAX_SESSIONS_PER_IP")]
    max_sessions_per_ip: usize,

    #[arg(long, default_value_t = 300)]
    session_timeout: u64,

    #[arg(long, default_value_t = 60)]
    idle_timeout: u64,

    #[arg(long, default_value_t = 512)]
    max_line_length: usize,

    #[arg(long, default_value_t = 4096)]
    max_input_bytes: usize,

    #[arg(long, default_value_t = 9100, env = "METRICS_PORT")]
    metrics_port: u16,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!(
        host = %args.host,
        port = %args.port,
        honeypot_id = %args.honeypot_id,
        "starting HoneyTrap SSH honeypot"
    );

    let config = config::SshHoneypotConfig {
        host: args.host,
        port: args.port,
        host_key_path: args.host_key,
        events_file: args.events_file,
        honeypot_id: args.honeypot_id,
        banner: args.banner,
        allow_all_auth: args.allow_all_auth,
        max_concurrent_sessions: args.max_sessions,
        max_sessions_per_ip: args.max_sessions_per_ip,
        session_timeout_secs: args.session_timeout,
        idle_timeout_secs: args.idle_timeout,
        max_line_length: args.max_line_length,
        max_input_bytes: args.max_input_bytes,
        max_auth_attempts: 20,
        max_stored_commands: 128,
        metrics_port: args.metrics_port,
    };

    server::run(config).await
}

#[cfg(test)]
mod ssh_client_test {
    use std::sync::Arc;
    use std::time::Duration;

    use russh::client::{self, Handler};
    use russh::ChannelMsg;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use crate::config::SshHoneypotConfig;
    use crate::server;

    struct AcceptHostKey;

    impl Handler for AcceptHostKey {
        type Error = anyhow::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[tokio::test]
    async fn ssh_client_session_emits_events_and_emulated_output() {
        let dir = std::env::temp_dir().join(format!("honeytrap-it-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let events_file = dir.join("events.jsonl");
        let host_key = dir.join("ssh_host_ed25519");

        let config = SshHoneypotConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            host_key_path: host_key,
            events_file: events_file.clone(),
            honeypot_id: "ssh-test".to_string(),
            metrics_port: 0,
            max_concurrent_sessions: 8,
            max_sessions_per_ip: 4,
            ..SshHoneypotConfig::default()
        };

        let (ready_tx, ready_rx) = oneshot::channel();
        tokio::spawn(async move {
            if let Err(err) = server::run_with_ready(config, Some(ready_tx)).await {
                panic!("honeypot stopped: {err}");
            }
        });

        let addr = timeout(Duration::from_secs(5), ready_rx)
            .await
            .expect("honeypot ready timeout")
            .expect("honeypot did not report its address");

        let client_config = Arc::new(client::Config::default());
        let mut session = client::connect(client_config, addr, AcceptHostKey)
            .await
            .expect("ssh connect");
        let authed = session
            .authenticate_password("root", "not-a-real-secret")
            .await
            .expect("auth");
        assert!(authed.success(), "honeypot should accept the password");

        let mut channel = session.channel_open_session().await.expect("open session");
        channel
            .exec(true, b"uname -a".as_slice())
            .await
            .expect("exec");

        let mut output = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, channel.wait()).await {
                Ok(Some(ChannelMsg::Data { data })) => output.extend_from_slice(&data),
                Ok(Some(ChannelMsg::Eof | ChannelMsg::Close | ChannelMsg::ExitStatus { .. })) => {
                    break
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("Linux server 5.15.0-91-generic"),
            "expected emulated uname, got {text:?}"
        );

        let logged = timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(body) = std::fs::read_to_string(&events_file) {
                    if body.contains("uname -a") && body.contains("authentication") {
                        return body;
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("events were not written");

        assert!(logged.contains("not-a-real-secret"));
        assert!(logged.contains("connection_opened"));
        for line in logged.lines() {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("jsonl line");
            assert!(parsed.get("id").is_some());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
