//! Connection admission control.
//!
//! Counters live here so the accept loop can refuse work before the SSH
//! handshake allocates session state.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use metrics::gauge;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    Global,
    PerIp,
}

/// Tracks global and per-IP session counts.
pub struct SessionLimits {
    max_global: usize,
    max_per_ip: usize,
    global: Arc<AtomicUsize>,
    per_ip: Arc<DashMap<String, usize>>,
}

/// Held for the lifetime of an accepted session. Dropping it releases the slot.
pub struct SessionPermit {
    ip: String,
    global: Arc<AtomicUsize>,
    per_ip: Arc<DashMap<String, usize>>,
}

impl SessionLimits {
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            max_global: max_global.max(1),
            max_per_ip: max_per_ip.max(1),
            global: Arc::new(AtomicUsize::new(0)),
            per_ip: Arc::new(DashMap::new()),
        }
    }

    pub fn try_acquire(&self, ip: &str) -> Result<SessionPermit, LimitKind> {
        let prev = self.global.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max_global {
            self.global.fetch_sub(1, Ordering::AcqRel);
            return Err(LimitKind::Global);
        }

        let mut entry = self.per_ip.entry(ip.to_string()).or_insert(0);
        if *entry >= self.max_per_ip {
            drop(entry);
            self.global.fetch_sub(1, Ordering::AcqRel);
            return Err(LimitKind::PerIp);
        }
        *entry += 1;
        drop(entry);

        gauge!("honeytrap_active_sessions").increment(1.0);

        Ok(SessionPermit {
            ip: ip.to_string(),
            global: Arc::clone(&self.global),
            per_ip: Arc::clone(&self.per_ip),
        })
    }

    pub fn active(&self) -> usize {
        self.global.load(Ordering::Acquire)
    }
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.global.fetch_sub(1, Ordering::AcqRel);
        if let Some(mut count) = self.per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                drop(count);
                self.per_ip.remove(&self.ip);
            }
        }
        gauge!("honeytrap_active_sessions").decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_limit_rejects_without_leaking_slots() {
        let limits = SessionLimits::new(2, 10);
        let a = limits.try_acquire("203.0.113.10").unwrap();
        let b = limits.try_acquire("203.0.113.11").unwrap();
        assert!(matches!(
            limits.try_acquire("198.51.100.5"),
            Err(LimitKind::Global)
        ));
        assert_eq!(limits.active(), 2);
        drop(a);
        drop(b);
        assert_eq!(limits.active(), 0);
        assert!(limits.try_acquire("203.0.113.10").is_ok());
    }

    #[test]
    fn per_ip_limit_is_independent_of_other_addresses() {
        let limits = SessionLimits::new(10, 1);
        let held = limits.try_acquire("203.0.113.10").unwrap();
        assert!(matches!(
            limits.try_acquire("203.0.113.10"),
            Err(LimitKind::PerIp)
        ));
        assert!(limits.try_acquire("198.51.100.8").is_ok());
        drop(held);
        assert!(limits.try_acquire("203.0.113.10").is_ok());
    }
}
