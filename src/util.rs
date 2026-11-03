//! Small time / formatting helpers shared across modules.
use chrono::{Datelike, Local, TimeZone};

use crate::model::Ts;

/// Unix seconds -> RFC3339 local string (or empty on failure).
pub fn ts_to_rfc3339(ts: Ts) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.to_rfc3339())
        .unwrap_or_default()
}

/// Unix seconds -> local hour-of-day (0..23).
pub fn ts_hour(ts: Ts) -> usize {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.hour() as usize)
        .unwrap_or(0)
}

/// Current unix seconds.
pub fn now_ts() -> Ts {
    Local::now().timestamp()
}

/// Today's date string YYYY-MM-DD (local).
pub fn today() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

/// Date string YYYY-MM-DD for a unix timestamp (local).
pub fn date_of(ts: Ts) -> String {
    Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(today)
}

/// Today minus `days` -> YYYY-MM-DD.
pub fn date_minus_days(days: u32) -> String {
    let d = Local::now().date_naive() - chrono::Duration::days(days as i64);
    d.format("%Y-%m-%d").to_string()
}

/// Parse "YYYY-MM-DD" into (y, m, d); None if malformed.
pub fn parse_date(s: &str) -> Option<(i32, u32, u32)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}
