//! HoneyTrap SSH Honeypot

mod config;
mod handler;
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
#[command(about = "SSH Honeypot for capturing attacker credentials and commands")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    #[arg(short, long, default_value = "2222")]
    port: u16,

    #[arg(long, default_value = "./ssh_host_key")]
    host_key: PathBuf,

    #[arg(long, default_value = "ssh-01")]
    honeypot_id: String,

    #[arg(long, default_value = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")]
    banner: String,

    #[arg(long, default_value = "true")]
    allow_all_auth: bool,

    #[arg(long, default_value = "5")]
    max_sessions_per_ip: usize,

    #[arg(long, default_value = "300")]
    session_timeout: u64,

    #[arg(long, default_value = "9100")]
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
        "Starting HoneyTrap SSH Honeypot"
    );

    let config = config::SshHoneypotConfig {
        host: args.host,
        port: args.port,
        host_key_path: args.host_key,
        honeypot_id: args.honeypot_id,
        banner: args.banner,
        allow_all_auth: args.allow_all_auth,
        max_sessions_per_ip: args.max_sessions_per_ip,
        session_timeout_secs: args.session_timeout,
        metrics_port: args.metrics_port,
    };

    server::run(config).await
}
