//! ClickHouse client

use anyhow::{Context, Result};
use honeytrap_shared::HoneypotEvent;
use reqwest::Client;
use tracing::{debug, error, info};

#[derive(Clone)]
pub struct ClickHouseClient {
    client: Client,
    url: String,
    database: String,
    user: String,
    password: String,
}

impl ClickHouseClient {
    pub fn new(url: &str, database: &str, user: &str, password: &str) -> Self {
        Self {
            client: Client::new(),
            url: url.to_string(),
            database: database.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        }
    }

    pub async fn ping(&self) -> Result<()> {
        let response = self
            .client
            .get(&self.url)
            .query(&[("query", "SELECT 1")])
            .basic_auth(&self.user, Some(&self.password))
            .send()
            .await
            .context("Failed to connect to ClickHouse")?;

        if response.status().is_success() {
            Ok(())
        } else {
            anyhow::bail!("ClickHouse ping failed")
        }
    }

    pub async fn init_schema(&self) -> Result<()> {
        self.execute_query(&format!("CREATE DATABASE IF NOT EXISTS {}", self.database))
            .await?;

        self.execute_query(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {}.events (
                id UUID,
                session_id UUID,
                timestamp DateTime64(3),
                protocol String,
                category String,
                severity String,
                source_ip String,
                source_port UInt16,
                dest_ip String,
                dest_port UInt16,
                honeypot_id String,
                username String DEFAULT '',
                password String DEFAULT '',
                command String DEFAULT '',
                tags Array(String) DEFAULT [],
                created_at DateTime64(3) DEFAULT now64(3)
            )
            ENGINE = MergeTree()
            ORDER BY (timestamp, session_id)
        "#,
            self.database
        ))
        .await?;

        info!("ClickHouse schema initialized");
        Ok(())
    }

    async fn execute_query(&self, query: &str) -> Result<()> {
        let response = self
            .client
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.password))
            .body(query.to_string())
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error = response.text().await.unwrap_or_default();
            anyhow::bail!("Query failed: {}", error)
        }
    }

    pub async fn insert_event(&self, event: &HoneypotEvent) -> Result<()> {
        let username = event
            .credentials
            .as_ref()
            .map(|c| &c.username)
            .cloned()
            .unwrap_or_default();
        let password = event
            .credentials
            .as_ref()
            .and_then(|c| c.password.clone())
            .unwrap_or_default();
        let command = event
            .command
            .as_ref()
            .map(|c| &c.command)
            .cloned()
            .unwrap_or_default();

        let query = format!(
            r#"
            INSERT INTO {}.events (id, session_id, timestamp, protocol, category, severity, source_ip, source_port, dest_ip, dest_port, honeypot_id, username, password, command)
            VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, '{}', {}, '{}', '{}', '{}', '{}')
        "#,
            self.database,
            event.id,
            event.session_id,
            event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            format!("{:?}", event.protocol).to_lowercase(),
            format!("{:?}", event.category).to_lowercase(),
            format!("{:?}", event.severity).to_lowercase(),
            event.source.ip,
            event.source.port,
            event.destination.ip,
            event.destination.port,
            event.destination.honeypot_id,
            escape(&username),
            escape(&password),
            escape(&command)
        );

        self.execute_query(&query).await
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
