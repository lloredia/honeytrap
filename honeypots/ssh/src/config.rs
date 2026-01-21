//! SSH Honeypot Configuration

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SshHoneypotConfig {
    pub host: String,
    pub port: u16,
    pub host_key_path: PathBuf,
    pub honeypot_id: String,
    pub banner: String,
    pub allow_all_auth: bool,
    pub max_sessions_per_ip: usize,
    pub session_timeout_secs: u64,
    pub metrics_port: u16,
}

impl Default for SshHoneypotConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 2222,
            host_key_path: PathBuf::from("./ssh_host_key"),
            honeypot_id: "ssh-01".to_string(),
            banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string(),
            allow_all_auth: true,
            max_sessions_per_ip: 5,
            session_timeout_secs: 300,
            metrics_port: 9100,
        }
    }
}
