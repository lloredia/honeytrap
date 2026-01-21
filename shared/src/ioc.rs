//! IOC extraction

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
