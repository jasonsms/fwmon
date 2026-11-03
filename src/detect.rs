//! Detection engine: R1 scan, R2 flood, R3 brute-force, R4 spike, R5 drop-anomaly, R6 repeat.
use std::collections::{HashMap, HashSet, VecDeque};

use crate::config::Thresholds;
use crate::model::{Alert, Ts};

const MINUTE: i64 = 60;

pub struct Detector {
    scan: HashMap<String, Vec<(Ts, u16)>>,
    rate: HashMap<String, Vec<Ts>>,
    exposed: HashMap<String, Vec<Ts>>,
    global_events: Vec<Ts>,
    global_drops: Vec<Ts>,
    baseline_events: VecDeque<u64>,
    baseline_drops: VecDeque<u64>,
    last_alert: HashMap<String, Ts>,
    prior_counts: HashMap<String, u32>,
    max_ips: usize,
    scan_window: i64,
    bf_window: i64,
}

impl Detector {
    pub fn new(max_ips: usize, scan_window: i64, bf_window: i64) -> Self {
        Detector {
            scan: HashMap::new(),
            rate: HashMap::new(),
            exposed: HashMap::new(),
            global_events: Vec::new(),
            global_drops: Vec::new(),
            baseline_events: VecDeque::new(),
            baseline_drops: VecDeque::new(),
            last_alert: HashMap::new(),
            prior_counts: HashMap::new(),
            max_ips: max_ips.max(1),
            scan_window: scan_window.max(60),
            bf_window: bf_window.max(30),
        }
    }

    pub fn seed_prior(&mut self, counts: HashMap<String, u32>) {
        self.prior_counts = counts;
    }

    /// Feed one event into the rolling windows.
    pub fn observe(&mut self, src: &str, dport: u16, is_exposed: bool, ts: Ts, accept: bool) {
        let scan_window = self.scan_window;
        let bf_window = self.bf_window;

        let sc = self.scan.entry(src.to_string()).or_default();
        sc.push((ts, dport));
        sc.retain(|(t, _)| *t >= ts - scan_window);

        let ra = self.rate.entry(src.to_string()).or_default();
        ra.push(ts);
        ra.retain(|t| *t >= ts - MINUTE * 3);

        if is_exposed {
            let ex = self.exposed.entry(src.to_string()).or_default();
            ex.push(ts);
            ex.retain(|t| *t >= ts - bf_window);
        }

        self.global_events.push(ts);
        self.global_events.retain(|t| *t >= ts - MINUTE * 2);
        if !accept {
            self.global_drops.push(ts);
            self.global_drops.retain(|t| *t >= ts - MINUTE * 2);
        }

        // Bound memory: clear the oldest-heavy maps if they grow past 2x cap.
        let cap = self.max_ips;
        if self.scan.len() > cap * 2 {
            self.scan.clear();
        }
        if self.rate.len() > cap * 2 {
            self.rate.clear();
        }
        if self.exposed.len() > cap {
            self.exposed.clear();
        }
    }

    /// Run all rules; returns new alerts (debounce-filtered, capped).
    pub fn check(&mut self, now: Ts, th: &Thresholds) -> Vec<Alert> {
        let mut out = Vec::new();

        // R1 scan: distinct destination ports within the window.
        let scan_win = th.scan_window as i64;
        for (src, win) in self.scan.iter() {
            let cutoff = now - scan_win;
            let mut set: HashSet<u16> = HashSet::new();
            for (t, p) in win.iter() {
                if *t >= cutoff {
                    set.insert(*p);
                }
            }
            if set.len() as u64 >= th.scan_ports {
                out.push(self.alert(now, "scan", "warn", src, "distinct_ports",
                    set.len() as u64, th.scan_ports, format!("{scan_win}s"),
                    "端口扫描：单源短时间内命中多个不同端口"));
            }
        }

        // R2 flood: >= flood_per_min new connections in the last minute.
        for (src, win) in self.rate.iter() {
            let c = win.iter().filter(|t| **t >= now - MINUTE).count() as u64;
            if c >= th.flood_per_min {
                out.push(self.alert(now, "flood", "high", src, "new_conn_per_min",
                    c, th.flood_per_min, "60s".into(),
                    "连接泛洪：单源新建连接速率过高"));
            }
        }

        // R3 brute-force on the exposed port.
        let bf_win = th.bruteforce_window as i64;
        for (src, win) in self.exposed.iter() {
            let c = win.iter().filter(|t| **t >= now - bf_win).count() as u64;
            if c >= th.bruteforce_count {
                out.push(self.alert(now, "bruteforce", "high", src, "exposed_conn",
                    c, th.bruteforce_count, format!("{bf_win}s"),
                    "暴力连接：单源反复连接放行端口"));
            }
        }

        // R4 spike + R5 drop-anomaly (global, vs rolling baseline).
        let cur_events = self.global_events.iter().filter(|t| **t >= now - MINUTE).count() as u64;
        let cur_drops = self.global_drops.iter().filter(|t| **t >= now - MINUTE).count() as u64;
        let base_events = mean(&self.baseline_events);
        let base_drops = mean(&self.baseline_drops);
        self.baseline_events.push_back(cur_events);
        self.baseline_drops.push_back(cur_drops);
        while self.baseline_events.len() > 30 {
            self.baseline_events.pop_front();
        }
        while self.baseline_drops.len() > 30 {
            self.baseline_drops.pop_front();
        }
        if base_events > 0 && cur_events >= th.spike_factor * base_events {
            out.push(self.alert(now, "spike", "warn", "*", "new_conn_per_min",
                cur_events, th.spike_factor * base_events, "60s".into(),
                "流量突增：全局新建连接显著高于基线"));
        }
        if base_drops > 0 && cur_drops >= th.drop_factor * base_drops {
            out.push(self.alert(now, "drop_anomaly", "info", "*", "drop_per_min",
                cur_drops, th.drop_factor * base_drops, "60s".into(),
                "丢弃异常：被丢弃入站连接显著增多"));
        }

        // R6 repeat: seen on >= repeat_days distinct days and currently active.
        let repeat_need = th.repeat_days.saturating_sub(1);
        for (src, cnt) in self.prior_counts.iter() {
            if *cnt < repeat_need {
                continue;
            }
            let active = self
                .rate
                .get(src)
                .map(|w| w.iter().any(|t| *t >= now - MINUTE * 5))
                .unwrap_or(false);
            if active {
                out.push(self.alert(now, "repeat", "warn", src, "seen_days",
                    u64::from(*cnt) + 1, th.repeat_days, "days".into(),
                    "惯犯：该源在多个不同日期反复出现"));
            }
        }

        // Debounce + cap.
        let mut kept: Vec<Alert> = Vec::new();
        for a in out {
            let key = format!("{}|{}", a.kind, a.src);
            let last = self.last_alert.get(&key).copied().unwrap_or(0);
            if now - last >= th.cooldown as i64 {
                self.last_alert.insert(key, now);
                kept.push(a);
            }
        }
        kept.truncate(50);
        kept
    }

    #[allow(clippy::too_many_arguments)]
    fn alert(
        &self,
        now: Ts,
        kind: &str,
        severity: &str,
        src: &str,
        metric: &str,
        value: u64,
        threshold: u64,
        window: String,
        detail: &str,
    ) -> Alert {
        Alert {
            ts: now,
            kind: kind.to_string(),
            severity: severity.to_string(),
            src: src.to_string(),
            metric: metric.to_string(),
            value,
            threshold,
            window,
            detail: detail.to_string(),
        }
    }
}

fn mean(q: &VecDeque<u64>) -> u64 {
    if q.is_empty() {
        return 0;
    }
    let sum: u64 = q.iter().sum();
    sum / q.len() as u64
}
