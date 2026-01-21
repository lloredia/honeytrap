//! SSH Session State

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use honeytrap_shared::{CommandExecution, Credentials};

#[derive(Debug)]
pub struct SessionState {
    pub session_id: Uuid,
    pub source_ip: String,
    pub source_port: u16,
    pub started_at: DateTime<Utc>,
    pub username: Option<String>,
    pub auth_attempts: Vec<AuthAttempt>,
    pub commands: Vec<CommandExecution>,
    pub cwd: String,
    pub env: HashMap<String, String>,
    pub authenticated: bool,
    pub channels: HashMap<u32, ChannelState>,
}

impl SessionState {
    pub fn new(session_id: Uuid, source_ip: String, source_port: u16) -> Self {
        Self {
            session_id,
            source_ip,
            source_port,
            started_at: Utc::now(),
            username: None,
            auth_attempts: Vec::new(),
            commands: Vec::new(),
            cwd: "/root".to_string(),
            env: default_env(),
            authenticated: false,
            channels: HashMap::new(),
        }
    }

    pub fn record_auth_attempt(&mut self, attempt: AuthAttempt) {
        self.auth_attempts.push(attempt);
    }

    pub fn record_command(&mut self, command: CommandExecution) {
        self.commands.push(command);
    }

    pub fn authenticate(&mut self, username: String) {
        self.authenticated = true;
        self.username = Some(username.clone());
        self.env.insert("USER".to_string(), username);
    }

    pub fn duration_secs(&self) -> f64 {
        (Utc::now() - self.started_at).num_milliseconds() as f64 / 1000.0
    }
}

fn default_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env.insert("HOME".to_string(), "/root".to_string());
    env.insert("SHELL".to_string(), "/bin/bash".to_string());
    env.insert("USER".to_string(), "root".to_string());
    env
}

#[derive(Debug, Clone)]
pub struct AuthAttempt {
    pub timestamp: DateTime<Utc>,
    pub username: String,
    pub auth_type: AuthType,
    pub password: Option<String>,
    pub public_key: Option<String>,
    pub success: bool,
}

impl AuthAttempt {
    pub fn password(username: String, password: String, success: bool) -> Self {
        Self {
            timestamp: Utc::now(),
            username,
            auth_type: AuthType::Password,
            password: Some(password),
            public_key: None,
            success,
        }
    }

    pub fn public_key(username: String, key: String, success: bool) -> Self {
        Self {
            timestamp: Utc::now(),
            username,
            auth_type: AuthType::PublicKey,
            password: None,
            public_key: Some(key),
            success,
        }
    }
}

impl From<&AuthAttempt> for Credentials {
    fn from(attempt: &AuthAttempt) -> Self {
        Credentials {
            username: attempt.username.clone(),
            password: attempt.password.clone(),
            ssh_key: attempt.public_key.clone(),
            auth_method: attempt.auth_type.to_string(),
            success: attempt.success,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Password,
    PublicKey,
}

impl std::fmt::Display for AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthType::Password => write!(f, "password"),
            AuthType::PublicKey => write!(f, "publickey"),
        }
    }
}

#[derive(Debug)]
pub struct ChannelState {
    pub channel_id: u32,
    pub pty_requested: bool,
    pub shell_active: bool,
    pub command_buffer: String,
}

impl ChannelState {
    pub fn new(channel_id: u32) -> Self {
        Self {
            channel_id,
            pty_requested: false,
            shell_active: false,
            command_buffer: String::new(),
        }
    }
}
