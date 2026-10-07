//! Escape attacker-controlled strings before they reach logs or JSONL.
//!
//! Serde already escapes JSON strings. This helper also strips raw control
//! characters so a credential or command cannot inject extra log lines.

/// Render `input` as a single-line escaped string, truncated to `max_chars`.
pub fn for_log(input: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(input.len().min(max_chars.saturating_mul(2)));
    for (count, ch) in input.chars().enumerate() {
        if count >= max_chars {
            out.push_str("...");
            break;
        }
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || c == '\u{7f}' => {
                out.push_str(&format!("\\u{{{:04x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newlines_and_controls_are_escaped() {
        let escaped = for_log("root\npassword\r\x1b[31mred", 64);
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
        assert!(!escaped.contains('\u{1b}'));
        assert!(escaped.contains("\\n"));
        assert!(escaped.contains("\\r"));
        assert!(escaped.contains("\\u{001b}"));
    }

    #[test]
    fn truncates_long_input() {
        let escaped = for_log(&"a".repeat(50), 8);
        assert_eq!(escaped, "aaaaaaaa...");
    }

    #[test]
    fn json_event_stays_one_line() {
        let command = for_log("uname\n\"$(id)\"", 64);
        let json = serde_json::json!({ "command": command });
        let line = serde_json::to_string(&json).unwrap();
        assert!(!line.contains('\n'));
        assert!(line.contains("\\\\n") || line.contains("\\n"));
    }
}
