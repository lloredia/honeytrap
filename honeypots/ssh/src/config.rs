//! SSH Honeypot Configuration

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct SshHoneypotConfig {
    pub host: String,
    pub port: u16,
    pub host_key_path: PathBuf,
    pub events_file: PathBuf,
    pub honeypot_id: String,
    pub banner: String,
    pub allow_all_auth: bool,
    pub max_concurrent_sessions: usize,
    pub max_sessions_per_ip: usize,
    pub session_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_line_length: usize,
    pub max_input_bytes: usize,
    pub max_auth_attempts: usize,
    pub max_stored_commands: usize,
    pub metrics_port: u16,
}

impl Default for SshHoneypotConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 2222,
            host_key_path: PathBuf::from("./data/keys/ssh_host_ed25519"),
            events_file: PathBuf::from("./events.jsonl"),
            honeypot_id: "ssh-01".to_string(),
            banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string(),
            allow_all_auth: true,
            max_concurrent_sessions: 64,
            max_sessions_per_ip: 4,
            session_timeout_secs: 300,
            idle_timeout_secs: 60,
            max_line_length: 512,
            max_input_bytes: 4096,
            max_auth_attempts: 20,
            max_stored_commands: 128,
            metrics_port: 9100,
        }
    }
}
