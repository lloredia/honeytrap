//! SSH Connection Handler

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec};
use tracing::{debug, info, warn};
use uuid::Uuid;

use honeytrap_shared::{
    CommandExecution, Credentials, DestinationInfo, EventCategory, HoneypotEvent, Protocol,
    Severity, SourceInfo,
};

use crate::config::SshHoneypotConfig;
use crate::server::EventSender;
use crate::session::{AuthAttempt, ChannelState, SessionState};
use crate::shell::FakeShell;

/// SSH connection handler
pub struct SshHandler {
    state: Arc<Mutex<SessionState>>,
    config: Arc<SshHoneypotConfig>,
    event_tx: EventSender,
    sessions_per_ip: Arc<DashMap<String, usize>>,
    shell: Arc<Mutex<FakeShell>>,
}

impl SshHandler {
    pub fn new(
        session_id: Uuid,
        peer_addr: SocketAddr,
        config: Arc<SshHoneypotConfig>,
        event_tx: EventSender,
        sessions_per_ip: Arc<DashMap<String, usize>>,
    ) -> Self {
        let state = SessionState::new(session_id, peer_addr.ip().to_string(), peer_addr.port());

        Self {
            state: Arc::new(Mutex::new(state)),
            config,
            event_tx,
            sessions_per_ip,
            shell: Arc::new(Mutex::new(FakeShell::new())),
        }
    }

    fn send_event(&self, event: HoneypotEvent) {
        if let Err(e) = self.event_tx.send(event) {
            warn!(error = %e, "Failed to send event");
        }
    }

    fn create_base_event(&self, category: EventCategory) -> HoneypotEvent {
        let state = self.state.lock();

        let source = SourceInfo::new(state.source_ip.clone(), state.source_port);
        let destination = DestinationInfo {
            ip: self.config.host.clone(),
            port: self.config.port,
            honeypot_id: self.config.honeypot_id.clone(),
        };

        HoneypotEvent::new(
            state.session_id,
            Protocol::Ssh,
            category,
            source,
            destination,
        )
    }
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        let state = self.state.lock();

        if let Some(mut count) = self.sessions_per_ip.get_mut(&state.source_ip) {
            *count = count.saturating_sub(1);
        }

        let event = self
            .create_base_event(EventCategory::Connection)
            .with_severity(Severity::Low)
            .with_tag("connection_closed")
            .with_metadata("duration_secs", serde_json::json!(state.duration_secs()))
            .with_metadata(
                "auth_attempts",
                serde_json::json!(state.auth_attempts.len()),
            )
            .with_metadata("commands_executed", serde_json::json!(state.commands.len()));

        let _ = self.event_tx.send(event);

        info!(
            session_id = %state.session_id,
            source_ip = %state.source_ip,
            duration = state.duration_secs(),
            auth_attempts = state.auth_attempts.len(),
            commands = state.commands.len(),
            "SSH session ended"
        );

        metrics::gauge!("honeytrap_ssh_active_sessions").decrement(1.0);
    }
}

#[async_trait]
impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!(user = %user, password = %password, "Password authentication attempt");

        let success = self.config.allow_all_auth;
        let attempt = AuthAttempt::password(user.to_string(), password.to_string(), success);

        {
            let mut state = self.state.lock();
            state.record_auth_attempt(attempt.clone());
            if success {
                state.authenticate(user.to_string());
            }
        }

        let event = self
            .create_base_event(EventCategory::Authentication)
            .with_severity(if success {
                Severity::High
            } else {
                Severity::Medium
            })
            .with_credentials(Credentials {
                username: user.to_string(),
                password: Some(password.to_string()),
                ssh_key: None,
                auth_method: "password".to_string(),
                success,
            })
            .with_tag("password_auth");

        self.send_event(event);

        if success {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        let key_str = format!("{:?}", public_key);
        info!(user = %user, key_type = ?public_key.name(), "Public key authentication attempt");

        let success = self.config.allow_all_auth;
        let attempt = AuthAttempt::public_key(user.to_string(), key_str.clone(), success);

        {
            let mut state = self.state.lock();
            state.record_auth_attempt(attempt);
            if success {
                state.authenticate(user.to_string());
            }
        }

        let event = self
            .create_base_event(EventCategory::Authentication)
            .with_severity(if success {
                Severity::High
            } else {
                Severity::Medium
            })
            .with_credentials(Credentials {
                username: user.to_string(),
                password: None,
                ssh_key: Some(key_str),
                auth_method: "publickey".to_string(),
                success,
            })
            .with_tag("publickey_auth");

        self.send_event(event);

        if success {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        debug!("Channel opened");

        {
            let mut state = self.state.lock();
            state.channels.insert(0, ChannelState::new(0));
        }

        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(term = %term, cols = col_width, rows = row_height, "PTY requested");

        {
            let mut state = self.state.lock();
            if let Some(ch) = state.channels.get_mut(&0) {
                ch.pty_requested = true;
            }
        }

        session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Shell requested");

        {
            let mut state = self.state.lock();
            if let Some(ch) = state.channels.get_mut(&0) {
                ch.shell_active = true;
            }
        }

        let username = {
            let state = self.state.lock();
            state.username.clone().unwrap_or_else(|| "root".to_string())
        };

        let prompt = self.shell.lock().get_prompt(&username);
        session.data(channel, CryptoVec::from_slice(prompt.as_bytes()));
        session.channel_success(channel);

        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let input = String::from_utf8_lossy(data);
        debug!(data = %input, "Received data");

        let (shell_active, username) = {
            let state = self.state.lock();
            let shell_active = state
                .channels
                .get(&0)
                .map(|ch| ch.shell_active)
                .unwrap_or(false);
            let username = state.username.clone().unwrap_or_else(|| "root".to_string());
            (shell_active, username)
        };

        if shell_active {
            let mut shell = self.shell.lock();

            for byte in data {
                match byte {
                    b'\r' | b'\n' => {
                        let command = {
                            let state = self.state.lock();
                            state
                                .channels
                                .get(&0)
                                .map(|c| c.command_buffer.clone())
                                .unwrap_or_default()
                        };

                        if !command.trim().is_empty() {
                            let output = shell.execute(&command);

                            let cmd_exec = CommandExecution {
                                command: command.clone(),
                                command_name: command.split_whitespace().next().map(String::from),
                                arguments: Some(
                                    command
                                        .split_whitespace()
                                        .skip(1)
                                        .map(String::from)
                                        .collect(),
                                ),
                                output: Some(output.clone()),
                                working_directory: Some(shell.cwd().to_string()),
                            };

                            {
                                let mut state = self.state.lock();
                                state.record_command(cmd_exec.clone());
                            }

                            let event = self
                                .create_base_event(EventCategory::Command)
                                .with_severity(Severity::High)
                                .with_command(cmd_exec)
                                .with_tag("shell_command");

                            self.send_event(event);

                            session.data(channel, CryptoVec::from_slice(b"\r\n"));
                            session.data(channel, CryptoVec::from_slice(output.as_bytes()));
                        }

                        {
                            let mut state = self.state.lock();
                            if let Some(ch) = state.channels.get_mut(&0) {
                                ch.command_buffer.clear();
                            }
                        }

                        let prompt = shell.get_prompt(&username);
                        session.data(channel, CryptoVec::from_slice(b"\r\n"));
                        session.data(channel, CryptoVec::from_slice(prompt.as_bytes()));
                    }
                    0x7f | 0x08 => {
                        let mut state = self.state.lock();
                        if let Some(ch) = state.channels.get_mut(&0) {
                            if !ch.command_buffer.is_empty() {
                                ch.command_buffer.pop();
                                session.data(channel, CryptoVec::from_slice(b"\x08 \x08"));
                            }
                        }
                    }
                    0x03 => {
                        {
                            let mut state = self.state.lock();
                            if let Some(ch) = state.channels.get_mut(&0) {
                                ch.command_buffer.clear();
                            }
                        }
                        let prompt = shell.get_prompt(&username);
                        session.data(channel, CryptoVec::from_slice(b"^C\r\n"));
                        session.data(channel, CryptoVec::from_slice(prompt.as_bytes()));
                    }
                    0x04 => {
                        info!("Ctrl+D received, closing session");
                        session.data(channel, CryptoVec::from_slice(b"\r\nlogout\r\n"));
                        session.close(channel);
                    }
                    _ => {
                        if *byte >= 0x20 && *byte < 0x7f {
                            {
                                let mut state = self.state.lock();
                                if let Some(ch) = state.channels.get_mut(&0) {
                                    ch.command_buffer.push(*byte as char);
                                }
                            }
                            session.data(channel, CryptoVec::from_slice(&[*byte]));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        info!(command = %command, "Exec request");

        let output = {
            let mut shell = self.shell.lock();
            shell.execute(&command)
        };

        let cmd_exec = CommandExecution {
            command: command.clone(),
            command_name: command.split_whitespace().next().map(String::from),
            arguments: Some(
                command
                    .split_whitespace()
                    .skip(1)
                    .map(String::from)
                    .collect(),
            ),
            output: Some(output.clone()),
            working_directory: None,
        };

        {
            let mut state = self.state.lock();
            state.record_command(cmd_exec.clone());
        }

        let event = self
            .create_base_event(EventCategory::Command)
            .with_severity(Severity::High)
            .with_command(cmd_exec)
            .with_tag("exec_command");

        self.send_event(event);

        session.data(channel, CryptoVec::from_slice(output.as_bytes()));
        session.channel_success(channel);
        session.exit_status_request(channel, 0);
        session.eof(channel);
        session.close(channel);

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!(cols = col_width, rows = row_height, "Window change");
        Ok(())
    }
}
