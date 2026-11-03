//! In-memory, bounded per-source aggregation + global hourly histogram.
use std::collections::{HashMap, HashSet};

use crate::model::{HourlyHist, IpAggLive, RawEvent};
use crate::util;

pub struct Aggregator {
    pub ips: HashMap<String, IpAggLive>,
    pub hourly: HourlyHist,
    pub max_ips: usize,
    pub max_ports: usize,
    /// events dropped due to cap / limit (surface in health).
    pub dropped: u64,
}

impl Aggregator {
    pub fn new(max_ips: usize, max_ports: usize) -> Self {
        Aggregator {
            ips: HashMap::new(),
            hourly: HourlyHist {
                date: util::today(),
                ..Default::default()
            },
            max_ips: max_ips.max(1),
            max_ports: max_ports.max(1),
            dropped: 0,
        }
    }

    /// Record one event. `accept` = inferred disposition.
    pub fn record(&mut self, ev: &RawEvent) {
        let hour = util::ts_hour(ev.ts);
        *self.hourly.new_total[hour] += 1;
        if !ev.accept {
            *self.hourly.new_drop[hour] += 1;
        }

        if !self.ips.contains_key(&ev.src) && self.ips.len() >= self.max_ips {
            // Cap reached: evict the least-recently-seen source to stay bounded.
            if let Some(victim) = self
                .ips
                .iter()
                .min_by_key(|(_, agg)| agg.last_seen)
                .map(|(k, _)| k.clone())
            {
                self.ips.remove(&victim);
                self.dropped += 1;
            }
        }

        let max_ports = self.max_ports;
        let agg = self
            .ips
            .entry(ev.src.clone())
            .or_insert_with(|| IpAggLive::new(&ev.src));
        agg.events += 1;
        if ev.accept {
            agg.accept += 1;
        } else {
            agg.dropped += 1;
        }
        if agg.first_seen == 0 || ev.ts < agg.first_seen {
            agg.first_seen = ev.ts;
        }
        if ev.ts > agg.last_seen {
            agg.last_seen = ev.ts;
        }
        *agg.ports.entry(ev.dport).or_insert(0) += 1;
        *agg.proto.entry(ev.proto.clone()).or_insert(0) += 1;
        agg.hourly[hour] += 1;

        // Keep the per-IP port map from growing without bound.
        if agg.ports.len() > max_ports * 2 {
            let mut entries: Vec<(u16, u64)> = agg.ports.iter().map(|(k, v)| (*k, *v)).collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));
            let keep: HashSet<u16> = entries.into_iter().take(max_ports).map(|(k, _)| k).collect();
            agg.ports.retain(|k, _| keep.contains(k));
        }
    }

    /// Compute distinct-source counts per hour (exact, from per-IP hourly buckets).
    fn compute_unique(&mut self) {
        let mut unique = [0u64; 24];
        for agg in self.ips.values() {
            for h in 0..24 {
                if agg.hourly[h] > 0 {
                    unique[h] += 1;
                }
            }
        }
        self.hourly.unique_src = unique;
    }

    /// Snapshot the global hourly histogram (fills unique_src).
    pub fn hourly_json(&mut self) -> serde_json::Value {
        self.compute_unique();
        serde_json::json!({
            "date": self.hourly.date,
            "new_total": self.hourly.new_total,
            "new_drop": self.hourly.new_drop,
            "unique_src": self.hourly.unique_src,
        })
    }

    /// Snapshot all per-IP aggregates as a JSON array, sorted by events desc.
    pub fn ips_json(&self) -> Vec<serde_json::Value> {
        let mut v: Vec<serde_json::Value> = self
            .ips
            .values()
            .map(|a| a.to_json(self.max_ports))
            .collect();
        v.sort_by_key(|x| {
            std::cmp::Reverse(x.get("events").and_then(|e| e.as_u64()).unwrap_or(0))
        });
        v
    }

    /// Reset for a new day (clears per-IP + hourly, keeps caps).
    pub fn reset_daily(&mut self, new_date: &str) {
        self.ips.clear();
        self.hourly = HourlyHist {
            date: new_date.to_string(),
            ..Default::default()
        };
    }

    /// Restore a previously-persisted per-IP map (resume today's data after restart).
    pub fn load_ips(&mut self, items: &[serde_json::Value]) {
        for it in items {
            let src = match it.get("src").and_then(|s| s.as_str()) {
                Some(s) if !s.is_empty() => s.to_string(),
                _ => continue,
            };
            let mut agg = IpAggLive::new(&src);
            agg.events = it.get("events").and_then(|v| v.as_u64()).unwrap_or(0);
            agg.accept = it.get("accept").and_then(|v| v.as_u64()).unwrap_or(0);
            agg.dropped = it.get("drop").and_then(|v| v.as_u64()).unwrap_or(0);
            if let Some(h) = it.get("hourly").and_then(|v| v.as_array()) {
                for i in 0..24.min(h.len()) {
                    agg.hourly[i] = h[i].as_u64().unwrap_or(0);
                }
            }
            if let Some(p) = it.get("top_ports").and_then(|v| v.as_array()) {
                for pc in p {
                    let d = pc.get("dport").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let n = pc.get("n").and_then(|v| v.as_u64()).unwrap_or(0);
                    if n > 0 {
                        agg.ports.insert(d, n);
                    }
                }
            }
            if let Some(pr) = it.get("proto").and_then(|v| v.as_object()) {
                for (k, v) in pr {
                    agg.proto.insert(k.clone(), v.as_u64().unwrap_or(0));
                }
            }
            self.ips.insert(src, agg);
        }
    }
}
