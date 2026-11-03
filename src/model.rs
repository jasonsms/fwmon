//! Shared data model: raw events, per-IP aggregation, hourly histogram, alerts.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Ts = i64;

/// One captured inbound NEW connection event (minimal fields).
#[derive(Debug, Clone)]
pub struct RawEvent {
    pub ts: Ts,
    pub src: String,
    pub dport: u16,
    pub proto: String,
    /// inferred disposition: true = accepted (reached exposed port), false = dropped.
    pub accept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortCount {
    pub dport: u16,
    pub n: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpFlags {
    pub scan: bool,
    pub flood: bool,
    pub bruteforce: bool,
    pub repeat: bool,
}

/// In-memory, accumulating per-source-IP aggregate.
#[derive(Debug, Clone, Default)]
pub struct IpAggLive {
    pub src: String,
    pub events: u64,
    pub accept: u64,
    pub dropped: u64,
    pub first_seen: Ts,
    pub last_seen: Ts,
    pub ports: BTreeMap<u16, u64>,
    pub proto: BTreeMap<String, u64>,
    pub hourly: [u64; 24],
    pub flags: IpFlags,
}

impl IpAggLive {
    pub fn new(src: &str) -> Self {
        IpAggLive {
            src: src.to_string(),
            ..Default::default()
        }
    }

    /// Serialise to the on-disk / API schema (top_ports = descending by count).
    pub fn to_json(&self, max_ports: usize) -> serde_json::Value {
        let mut ports: Vec<PortCount> = self
            .ports
            .iter()
            .map(|(dport, n)| PortCount {
                dport: *dport,
                n: *n,
            })
            .collect();
        ports.sort_by(|a, b| b.n.cmp(&a.n).then(a.dport.cmp(&b.dport)));
        ports.truncate(max_ports);
        serde_json::json!({
            "src": self.src,
            "events": self.events,
            "accept": self.accept,
            "drop": self.dropped,
            "first_seen": crate::util::ts_to_rfc3339(self.first_seen),
            "last_seen": crate::util::ts_to_rfc3339(self.last_seen),
            "top_ports": ports,
            "proto": self.proto,
            "hourly": self.hourly,
            "flags": self.flags,
        })
    }
}

/// Global per-hour histogram (date + 24 buckets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HourlyHist {
    pub date: String,
    pub new_total: [u64; 24],
    pub new_drop: [u64; 24],
    /// computed at snapshot time: distinct sources active in each hour.
    #[serde(skip)]
    pub unique_src: [u64; 24],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub ts: Ts,
    #[serde(rename = "type")]
    pub kind: String,
    pub severity: String,
    pub src: String,
    pub metric: String,
    pub value: u64,
    pub threshold: u64,
    pub window: String,
    pub detail: String,
}

impl Alert {
    pub fn severity_rank(&self) -> u8 {
        match self.severity.as_str() {
            "info" => 0,
            "warn" => 1,
            "high" => 2,
            "critical" => 3,
            _ => 1,
        }
    }
}
