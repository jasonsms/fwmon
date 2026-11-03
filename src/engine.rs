//! Core state + event pipeline: ingest -> aggregate -> (periodic) storage + detection.
use std::collections::HashMap;

use crate::aggregate::Aggregator;
use crate::alert::AlertSink;
use crate::config::Config;
use crate::conntrack::{self, ConnEvent, LocalAddrs};
use crate::detect::Detector;
use crate::model::RawEvent;
use crate::storage::Storage;
use crate::util;

pub struct Core {
    pub cfg: Config,
    pub storage: Storage,
    pub agg: Aggregator,
    pub det: Detector,
    pub alerts: AlertSink,
    pub local: LocalAddrs,
    pub raw_bytes: u64,
    pub current_date: String,
    pub started: i64,
    pub conntrack_alive: bool,
}

impl Core {
    pub fn new(cfg: Config) -> Self {
        let storage = Storage::new(
            cfg.tmp_dir.clone(),
            cfg.data_dir.clone(),
            cfg.raw_max_mb,
            cfg.retention_days,
            cfg.max_total_mb,
        );
        storage.ensure_dirs();

        let agg = Aggregator::new(cfg.agg_max_ips, cfg.agg_max_ports);
        let det = Detector::new(
            cfg.agg_max_ips,
            cfg.thresholds.scan_window as i64,
            cfg.thresholds.bruteforce_window as i64,
        );
        let alerts = AlertSink::new(500);

        let mut core = Core {
            cfg,
            storage,
            agg,
            det,
            alerts,
            local: conntrack::local_addresses(),
            raw_bytes: 0,
            current_date: util::today(),
            started: util::now_ts(),
            conntrack_alive: false,
        };
        core.resume();
        core
    }

    /// Resume today's aggregate (if any) and seed repeat-offender history.
    fn resume(&mut self) {
        if let Some((ips, _hourly)) = self.storage.load_today() {
            self.agg.load_ips(&ips);
        }
        let prior: HashMap<String, u32> = self
            .storage
            .load_prior_ip_date_counts(self.cfg.thresholds.repeat_days as usize);
        self.det.seed_prior(prior);
    }

    /// Parse + filter + record one `conntrack -E` line.
    pub fn ingest_line(&mut self, line: &str) {
        if let Some(ev) = conntrack::parse_line(line) {
            if ev.is_new && self.local.is_inbound(&ev.src, &ev.dst) {
                self.on_event(ev);
            }
        }
    }

    /// Record one already-classified inbound NEW event.
    pub fn on_event(&mut self, ev: ConnEvent) {
        let ts = util::now_ts();
        let is_icmp = ev.proto != "tcp" && ev.proto != "udp";
        let accept = is_icmp || ev.dport == self.cfg.exposed_port;
        let raw = RawEvent {
            ts,
            src: ev.src.clone(),
            dport: ev.dport,
            proto: ev.proto.clone(),
            accept,
        };
        self.agg.record(&raw);
        self.det
            .observe(&ev.src, ev.dport, ev.dport == self.cfg.exposed_port, ts, accept);

        // Append a capped raw sample line to /tmp (RAM).
        let line = serde_json::json!({
            "t": ts, "src": ev.src.clone(), "dport": ev.dport, "proto": ev.proto.clone(),
            "v": if accept { 1u8 } else { 0u8 },
        })
        .to_string();
        if !self.storage.append_raw(&line, &mut self.raw_bytes) {
            self.agg.dropped += 1;
        }
    }

    /// Periodic work: persist snapshot, run detection, handle day rollover.
    pub fn tick(&mut self) {
        // Day rollover: roll up the just-ended day, then reset for the new day.
        let today = util::today();
        if today != self.current_date {
            self.rollup_current();
            self.current_date = today.clone();
            self.agg.reset_daily(&today);
            self.storage.prune();
        }

        // Persist today's snapshot to /tmp for restart resume.
        let agg_json = serde_json::Value::Array(self.agg.ips_json());
        let hourly_json = self.agg.hourly_json();
        self.storage.save_today(&agg_json, &hourly_json);
        self.write_panel();

        // Detection.
        let now = util::now_ts();
        let th = self.cfg.thresholds.clone();
        let alerts = self.det.check(now, &th);
        for a in alerts {
            self.alerts.record(a, &self.cfg);
        }
    }

    fn rollup_current(&mut self) {
        let agg_json = serde_json::Value::Array(self.agg.ips_json());
        let hourly_json = self.agg.hourly_json();
        let date = self.current_date.clone();
        if let Err(e) = self.storage.rollup(&date, &agg_json, &hourly_json) {
            eprintln!("[fwmon] rollup {date} failed: {e}");
        }
    }

    /// Write a combined JSON snapshot for the LuCI panel (read via LuCI fs.read).
    fn write_panel(&mut self) {
        let mut events = 0u64;
        let mut accept = 0u64;
        let mut dropped = 0u64;
        for a in self.agg.ips.values() {
            events += a.events;
            accept += a.accept;
            dropped += a.dropped;
        }
        let hourly = self.agg.hourly_json();
        let ips = serde_json::Value::Array(self.agg.ips_json());
        let alerts = serde_json::json!(self.alerts.list(100));
        let panel = serde_json::json!({
            "generated": util::now_ts(),
            "health": {
                "enabled": self.cfg.enabled,
                "conntrack_alive": self.conntrack_alive,
                "date": self.current_date,
                "tracked_ips": self.agg.ips.len(),
                "agg_dropped": self.agg.dropped,
                "raw_bytes": self.raw_bytes,
                "exposed_port": self.cfg.exposed_port,
                "local_known": !self.local.is_empty(),
            },
            "summary": {
                "date": self.current_date,
                "events": events,
                "unique_ips": self.agg.ips.len(),
                "accept": accept,
                "drop": dropped,
                "hourly": hourly,
            },
            "ips": ips,
            "alerts": alerts,
        });
        let path = self.storage.tmp_dir.join("panel.json");
        if let Ok(s) = serde_json::to_string(&panel) {
            let _ = std::fs::write(path, s);
        }
    }

    /// Graceful shutdown: final rollup + persist.
    pub fn shutdown(&mut self) {
        self.rollup_current();
        self.write_panel();
        self.storage.prune();
    }

    /// Refresh the local address set (called occasionally).
    pub fn refresh_local(&mut self) {
        self.local = conntrack::local_addresses();
    }
}
