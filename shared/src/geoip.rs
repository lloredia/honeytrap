//! GeoIP enrichment for source IP addresses

use std::net::IpAddr;
use thiserror::Error;

use crate::SourceInfo;

#[derive(Error, Debug)]
pub enum GeoIpError {
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("IP address not found in database")]
    NotFound,
}

/// GeoIP lookup service (stub - requires MaxMind database)
pub struct GeoIpService {
    enabled: bool,
}

impl Default for GeoIpService {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpService {
    pub fn new() -> Self {
        Self { enabled: false }
    }

    pub fn is_available(&self) -> bool {
        self.enabled
    }

    /// Enrich a SourceInfo with geolocation data
    pub fn enrich(&self, source: &mut SourceInfo) {
        let ip: IpAddr = match source.ip.parse() {
            Ok(ip) => ip,
            Err(_) => return,
        };

        if is_private_ip(&ip) {
            return;
        }

        // TODO: Implement with MaxMind database
    }
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}
