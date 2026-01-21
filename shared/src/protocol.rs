//! Protocol parsing utilities

/// SSH protocol constants
pub mod ssh {
    pub const BANNERS: &[&str] = &[
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
    ];
}

/// HTTP protocol utilities
pub mod http {
    pub const SERVER_BANNERS: &[&str] = &["Apache/2.4.52 (Ubuntu)", "nginx/1.22.1"];
}
