//! SSH Connection Handler
//!
//! The handler records credentials and feeds keystrokes to [`FakeShell`].
//! It never invokes a real shell.

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use russh::server::{Auth, ChannelOpenHandle, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use tracing::{debug, info, warn};
use uuid::Uuid;

use honeytrap_shared::{
    CommandExecution, Credentials, DestinationInfo, EventCategory, HoneypotEvent, Protocol,
    Severity, SourceInfo,
};

use crate::config::SshHoneypotConfig;
use crate::limits::SessionPermit;
use crate::sanitize;
use crate::server::EventSender;
use crate::session::{AuthAttempt, ChannelState, SessionState};
use crate::shell::FakeShell;

/// SSH connection handler
pub struct SshHandler {
    state: Arc<Mutex<SessionState>>,
    config: Arc<SshHoneypotConfig>,
    event_tx: EventSender,
    shell: Arc<Mutex<FakeShell>>,
    _permit: SessionPermit,
}

impl SshHandler {
    pub fn new(
        session_id: Uuid,
        peer_addr: SocketAddr,
        config: Arc<SshHoneypotConfig>,
        event_tx: EventSender,
        permit: SessionPermit,
    ) -> Self {
        let state = SessionState::new(session_id, peer_addr.ip().to_string(), peer_addr.port());

        Self {
            state: Arc::new(Mutex::new(state)),
            config,
            event_tx,
            shell: Arc::new(Mutex::new(FakeShell::new())),
            _permit: permit,
        }
    }

    fn send_event(&self, event: HoneypotEvent) {
        if self.event_tx.try_send(event).is_err() {
            metrics::counter!("honeytrap_events_dropped_total").increment(1);
            warn!("event queue full; dropping event");
        }
    }

    fn create_base_event(&self, category: EventCategory) -> HoneypotEvent {
        let state = self.state.lock();
        event_from_state(&state, &self.config, category)
    }

    fn ensure_session_alive(&self) -> Result<(), anyhow::Error> {
        let state = self.state.lock();
        if state.session_expired(self.config.session_timeout_secs) {
            anyhow::bail!("session timeout");
        }
        Ok(())
    }

    fn record_command(&self, command: &str, output: &str, cwd: Option<String>, tag: &'static str) {
        let safe_command = sanitize::for_log(command, self.config.max_line_length);
        let safe_output = sanitize::for_log(output, self.config.max_line_length);
        let cmd_exec = CommandExecution {
            command: safe_command.clone(),
            command_name: safe_command.split_whitespace().next().map(String::from),
            arguments: Some(
                safe_command
                    .split_whitespace()
                    .skip(1)
                    .map(String::from)
                    .collect(),
            ),
            output: Some(safe_output),
            working_directory: cwd.map(|dir| sanitize::for_log(&dir, 256)),
        };

        {
            let mut state = self.state.lock();
            state.record_command(cmd_exec.clone(), self.config.max_stored_commands);
        }

        let event = self
            .create_base_event(EventCategory::Command)
            .with_severity(Severity::High)
            .with_command(cmd_exec)
            .with_tag(tag);
        self.send_event(event);
    }
}

fn event_from_state(
    state: &SessionState,
    config: &SshHoneypotConfig,
    category: EventCategory,
) -> HoneypotEvent {
    let source = SourceInfo::new(state.source_ip.clone(), state.source_port);
    let destination = DestinationInfo {
        ip: config.host.clone(),
        port: config.port,
        honeypot_id: config.honeypot_id.clone(),
    };
    HoneypotEvent::new(
        state.session_id,
        Protocol::Ssh,
        category,
        source,
        destination,
    )
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        let snapshot = {
            let state = self.state.lock();
            (
                state.session_id,
                state.source_ip.clone(),
                state.source_port,
                state.duration_secs(),
                state.auth_attempts.len(),
                state.commands.len(),
            )
        };
        let (session_id, source_ip, source_port, duration, auth_attempts, commands) = snapshot;

        let source = SourceInfo::new(source_ip.clone(), source_port);
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
            destination,
        )
        .with_severity(Severity::Low)
        .with_tag("connection_closed")
        .with_metadata("duration_secs", serde_json::json!(duration))
        .with_metadata("auth_attempts", serde_json::json!(auth_attempts))
        .with_metadata("commands_executed", serde_json::json!(commands));

        let _ = self.event_tx.try_send(event);

        info!(
            session_id = %session_id,
            source_ip = %sanitize::for_log(&source_ip, 64),
            duration,
            auth_attempts,
            commands,
            "SSH session ended"
        );
    }
}

impl Handler for SshHandler {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.ensure_session_alive()?;
        let user = sanitize::for_log(user, 64);
        let password = sanitize::for_log(password, 256);
        info!(user = %user, password = %password, "password authentication attempt");

        let success = self.config.allow_all_auth;
        let attempt = AuthAttempt::password(user.clone(), password.clone(), success);
        {
            let mut state = self.state.lock();
            state.record_auth_attempt(attempt, self.config.max_auth_attempts);
            if success {
                state.authenticate(user.clone());
            }
        }

        metrics::counter!(
            "honeytrap_auth_attempts_total",
            "method" => "password",
            "result" => if success { "success" } else { "failure" }
        )
        .increment(1);

        let event = self
            .create_base_event(EventCategory::Authentication)
            .with_severity(if success {
                Severity::High
            } else {
                Severity::Medium
            })
            .with_credentials(Credentials {
                username: user,
                password: Some(password),
                ssh_key: None,
                auth_method: "password".to_string(),
                success,
            })
            .with_tag("password_auth");
        self.send_event(event);

        if success {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.ensure_session_alive()?;
        let user = sanitize::for_log(user, 64);
        let key_str = sanitize::for_log(&format!("{:?}", public_key), 512);
        info!(user = %user, "public key authentication attempt");

        let success = self.config.allow_all_auth;
        let attempt = AuthAttempt::public_key(user.clone(), key_str.clone(), success);
        {
            let mut state = self.state.lock();
            state.record_auth_attempt(attempt, self.config.max_auth_attempts);
            if success {
                state.authenticate(user.clone());
            }
        }

        metrics::counter!(
            "honeytrap_auth_attempts_total",
            "method" => "publickey",
            "result" => if success { "success" } else { "failure" }
        )
        .increment(1);

        let event = self
            .create_base_event(EventCategory::Authentication)
            .with_severity(if success {
                Severity::High
            } else {
                Severity::Medium
            })
            .with_credentials(Credentials {
                username: user,
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
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ensure_session_alive()?;
        let id = channel.id();
        debug!(%id, "channel opened");
        let accept = {
            let mut state = self.state.lock();
            if state.channels.len() >= 4 {
                warn!("rejecting extra session channel");
                false
            } else {
                state.channels.insert(id, ChannelState::new());
                true
            }
        };
        if accept {
            reply.accept().await;
        }
        Ok(())
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
        self.ensure_session_alive()?;
        debug!(term = %sanitize::for_log(term, 32), cols = col_width, rows = row_height, "PTY requested");
        let mut state = self.state.lock();
        if let Some(ch) = state.channels.get_mut(&channel) {
            ch.pty_requested = true;
        }
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ensure_session_alive()?;
        info!("shell requested");
        let username = {
            let mut state = self.state.lock();
            if let Some(ch) = state.channels.get_mut(&channel) {
                ch.shell_active = true;
            }
            state.username.clone().unwrap_or_else(|| "root".to_string())
        };
        let prompt = self.shell.lock().get_prompt(&username);
        send_channel(session, channel, prompt.as_bytes());
        let _ = session.channel_success(channel);
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ensure_session_alive()?;
        if data.len() > self.config.max_input_bytes {
            warn!(bytes = data.len(), "closing session after oversized input");
            send_channel(session, channel, b"\r\ninput too large\r\n");
            let _ = session.close(channel);
            return Ok(());
        }

        let shell_active = {
            let state = self.state.lock();
            state
                .channels
                .get(&channel)
                .map(|ch| ch.shell_active)
                .unwrap_or(false)
        };
        if !shell_active {
            return Ok(());
        }

        let username = {
            let state = self.state.lock();
            state.username.clone().unwrap_or_else(|| "root".to_string())
        };
        let mut shell = self.shell.lock();
        for byte in data {
            self.handle_shell_byte(channel, *byte, &username, &mut shell, session);
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ensure_session_alive()?;
        if data.len() > self.config.max_input_bytes {
            send_channel(session, channel, b"input too large\n");
            let _ = session.exit_status_request(channel, 1);
            let _ = session.eof(channel);
            let _ = session.close(channel);
            return Ok(());
        }

        let command = String::from_utf8_lossy(data);
        let command = command.trim();
        info!(command = %sanitize::for_log(command, self.config.max_line_length), "exec request");

        let (output, cwd) = {
            let mut shell = self.shell.lock();
            let output = shell.execute(command);
            (output, shell.cwd().to_string())
        };
        self.record_command(command, &output, Some(cwd), "exec_command");

        send_channel(session, channel, output.as_bytes());
        let _ = session.channel_success(channel);
        let _ = session.exit_status_request(channel, 0);
        let _ = session.eof(channel);
        let _ = session.close(channel);
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
        debug!(cols = col_width, rows = row_height, "window change");
        Ok(())
    }
}

fn send_channel(session: &mut Session, channel: ChannelId, data: &[u8]) {
    if let Err(err) = session.data(channel, data.to_vec()) {
        warn!(error = %err, "failed to write channel data");
    }
}

impl SshHandler {
    fn handle_shell_byte(
        &self,
        channel: ChannelId,
        byte: u8,
        username: &str,
        shell: &mut FakeShell,
        session: &mut Session,
    ) {
        match byte {
            b'\r' | b'\n' => self.finish_line(channel, username, shell, session),
            0x7f | 0x08 => {
                let mut state = self.state.lock();
                if let Some(ch) = state.channels.get_mut(&channel) {
                    if !ch.command_buffer.is_empty() {
                        ch.command_buffer.pop();
                        if ch.command_buffer.len() < self.config.max_line_length {
                            ch.line_overflow = false;
                        }
                        send_channel(session, channel, b"\x08 \x08");
                    }
                }
            }
            0x03 => {
                {
                    let mut state = self.state.lock();
                    if let Some(ch) = state.channels.get_mut(&channel) {
                        ch.command_buffer.clear();
                        ch.line_overflow = false;
                    }
                }
                let prompt = shell.get_prompt(username);
                send_channel(session, channel, b"^C\r\n");
                send_channel(session, channel, prompt.as_bytes());
            }
            0x04 => {
                info!("Ctrl+D received, closing session");
                send_channel(session, channel, b"\r\nlogout\r\n");
                let _ = session.close(channel);
            }
            _ => self.push_printable(channel, byte, session),
        }
    }

    fn finish_line(
        &self,
        channel: ChannelId,
        username: &str,
        shell: &mut FakeShell,
        session: &mut Session,
    ) {
        let (command, overflow) = {
            let mut state = self.state.lock();
            state
                .channels
                .get_mut(&channel)
                .map(|ch| {
                    let overflow = ch.line_overflow;
                    ch.line_overflow = false;
                    (std::mem::take(&mut ch.command_buffer), overflow)
                })
                .unwrap_or_default()
        };

        if overflow {
            send_channel(session, channel, b"\r\nline too long\r\n");
        } else if !command.trim().is_empty() {
            let output = shell.execute(&command);
            let cwd = shell.cwd().to_string();
            self.record_command(&command, &output, Some(cwd), "shell_command");
            send_channel(session, channel, b"\r\n");
            send_channel(session, channel, output.as_bytes());
        }

        let prompt = shell.get_prompt(username);
        send_channel(session, channel, b"\r\n");
        send_channel(session, channel, prompt.as_bytes());
    }

    fn push_printable(&self, channel: ChannelId, byte: u8, session: &mut Session) {
        if !(0x20..0x7f).contains(&byte) {
            return;
        }
        let mut state = self.state.lock();
        if let Some(ch) = state.channels.get_mut(&channel) {
            if ch.command_buffer.len() >= self.config.max_line_length {
                ch.line_overflow = true;
                return;
            }
            ch.command_buffer.push(byte as char);
            send_channel(session, channel, &[byte]);
        }
    }
}
