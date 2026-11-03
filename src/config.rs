//! Configuration: load from OpenWrt UCI (/etc/config/fwmon) with sane defaults.
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Thresholds {
    pub scan_ports: u64,
    pub scan_window: u64,
    pub flood_per_min: u64,
    pub flood_sustain: u64,
    pub bruteforce_count: u64,
    pub bruteforce_window: u64,
    pub spike_factor: u64,
    pub drop_factor: u64,
    pub repeat_days: u64,
    pub cooldown: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            scan_ports: 15,
            scan_window: 300,
            flood_per_min: 300,
            flood_sustain: 120,
            bruteforce_count: 60,
            bruteforce_window: 120,
            spike_factor: 5,
            drop_factor: 3,
            repeat_days: 3,
            cooldown: 600,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: bool,
    pub listen_port: u16,
    pub exposed_port: u16,
    pub raw_max_mb: u64,
    pub agg_max_ips: usize,
    pub agg_max_ports: usize,
    pub retention_days: u32,
    pub max_total_mb: u64,
    pub flush_interval: u64,
    pub auto_block: bool,
    pub block_ttl: u64,
    pub notify: bool,
    pub pushplus_token: String,
    pub notify_min_severity: String,
    pub data_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub thresholds: Thresholds,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: true,
            listen_port: 8099,
            exposed_port: 443,
            raw_max_mb: 30,
            agg_max_ips: 20_000,
            agg_max_ports: 32,
            retention_days: 90,
            max_total_mb: 200,
            flush_interval: 60,
            auto_block: false,
            block_ttl: 3600,
            notify: false,
            pushplus_token: String::new(),
            notify_min_severity: "warn".into(),
            data_dir: PathBuf::from("/overlay/fwmon"),
            tmp_dir: PathBuf::from("/tmp/fwmon"),
            thresholds: Thresholds::default(),
        }
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn opt<T: std::str::FromStr>(map: &HashMap<String, String>, key: &str, default: T) -> T {
    map.get(key)
        .and_then(|v| v.trim().parse::<T>().ok())
        .unwrap_or(default)
}

fn opt_str(map: &HashMap<String, String>, key: &str, default: &str) -> String {
    map.get(key)
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| default.to_string())
}

/// Parse a UCI file into `section_name -> { key -> value }`.
fn parse_uci(text: &str) -> HashMap<String, HashMap<String, String>> {
    let mut sections: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut current: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("config ") {
            // config <type> '<name>'   or   config <type>
            let rest = rest.trim();
            let mut name = rest.split_whitespace().next().unwrap_or("").to_string();
            if let Some(q) = rest.find('\'') {
                if let Some(end) = rest[q + 1..].find('\'') {
                    name = rest[q + 1..q + 1 + end].to_string();
                }
            }
            current = Some(name.clone());
            sections.entry(name).or_default();
        } else if let Some(rest) = line.strip_prefix("option ") {
            if let Some(cur) = current.as_ref() {
                let rest = rest.trim();
                let mut parts = rest.splitn(2, char::is_whitespace);
                let key = parts.next().unwrap_or("").to_string();
                let mut val = parts.next().unwrap_or("").trim().to_string();
                if val.starts_with('\'') || val.starts_with('"') {
                    let quote = val.chars().next().unwrap();
                    val = val.trim_matches(quote).to_string();
                }
                if let Some(sec) = sections.get_mut(cur) {
                    sec.insert(key, val);
                }
            }
        }
    }
    sections
}

impl Config {
    /// Load from a UCI file path (defaults to /etc/config/fwmon, or $FWMON_CONFIG).
    pub fn load(path: Option<&str>) -> Self {
        let path: PathBuf = match path {
            Some(p) => PathBuf::from(p),
            None => std::env::var("FWMON_CONFIG")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/config/fwmon")),
        };
        let mut cfg = Config::default();
        if let Ok(text) = fs::read_to_string(&path) {
            let sections = parse_uci(&text);
            let main = sections.get("main").cloned().unwrap_or_default();
            cfg.enabled = match main.get("enabled") {
                Some(v) => parse_bool(v),
                None => true,
            };
            cfg.listen_port = opt(&main, "listen_port", cfg.listen_port);
            cfg.exposed_port = opt(&main, "exposed_port", cfg.exposed_port);
            cfg.raw_max_mb = opt(&main, "raw_max_mb", cfg.raw_max_mb);
            cfg.agg_max_ips = opt(&main, "agg_max_ips", cfg.agg_max_ips);
            cfg.agg_max_ports = opt(&main, "agg_max_ports", cfg.agg_max_ports);
            cfg.retention_days = opt(&main, "retention_days", cfg.retention_days);
            cfg.max_total_mb = opt(&main, "max_total_mb", cfg.max_total_mb);
            cfg.flush_interval = opt(&main, "flush_interval", cfg.flush_interval).max(5);
            cfg.auto_block = match main.get("auto_block") {
                Some(v) => parse_bool(v),
                None => false,
            };
            cfg.block_ttl = opt(&main, "block_ttl", cfg.block_ttl);
            cfg.notify = match main.get("notify") {
                Some(v) => parse_bool(v),
                None => false,
            };
            cfg.pushplus_token = opt_str(&main, "pushplus_token", "");
            cfg.notify_min_severity = opt_str(&main, "notify_min_severity", "warn");
            if let Some(v) = main.get("data_dir") {
                if !v.trim().is_empty() {
                    cfg.data_dir = PathBuf::from(v.trim());
                }
            }
            if let Some(v) = main.get("tmp_dir") {
                if !v.trim().is_empty() {
                    cfg.tmp_dir = PathBuf::from(v.trim());
                }
            }
            let t = sections.get("thresholds").cloned().unwrap_or_default();
            let mut th = cfg.thresholds.clone();
            th.scan_ports = opt(&t, "scan_ports", th.scan_ports);
            th.scan_window = opt(&t, "scan_window", th.scan_window);
            th.flood_per_min = opt(&t, "flood_per_min", th.flood_per_min);
            th.flood_sustain = opt(&t, "flood_sustain", th.flood_sustain);
            th.bruteforce_count = opt(&t, "bruteforce_count", th.bruteforce_count);
            th.bruteforce_window = opt(&t, "bruteforce_window", th.bruteforce_window);
            th.spike_factor = opt(&t, "spike_factor", th.spike_factor);
            th.drop_factor = opt(&t, "drop_factor", th.drop_factor);
            th.repeat_days = opt(&t, "repeat_days", th.repeat_days);
            th.cooldown = opt(&t, "cooldown", th.cooldown);
            cfg.thresholds = th;
        }
        cfg
    }

    /// Best-effort: regenerate and write the UCI file so settings persist.
    pub fn save_uci(&self, path: &str) -> std::io::Result<()> {
        let t = &self.thresholds;
        let text = format!(
            "config fwmon 'main'\n\
             \toption enabled '{enabled}'\n\
             \toption listen_port '{listen_port}'\n\
             \toption exposed_port '{exposed_port}'\n\
             \toption raw_max_mb '{raw_max_mb}'\n\
             \toption agg_max_ips '{agg_max_ips}'\n\
             \toption agg_max_ports '{agg_max_ports}'\n\
             \toption retention_days '{retention_days}'\n\
             \toption max_total_mb '{max_total_mb}'\n\
             \toption flush_interval '{flush_interval}'\n\
             \toption auto_block '{auto_block}'\n\
             \toption block_ttl '{block_ttl}'\n\
             \toption notify '{notify}'\n\
             \toption pushplus_token '{pushplus_token}'\n\
             \toption notify_min_severity '{notify_min_severity}'\n\
             \toption data_dir '{data_dir}'\n\
             \toption tmp_dir '{tmp_dir}'\n\
             \n\
             config detect 'thresholds'\n\
             \toption scan_ports '{scan_ports}'\n\
             \toption scan_window '{scan_window}'\n\
             \toption flood_per_min '{flood_per_min}'\n\
             \toption flood_sustain '{flood_sustain}'\n\
             \toption bruteforce_count '{bruteforce_count}'\n\
             \toption bruteforce_window '{bruteforce_window}'\n\
             \toption spike_factor '{spike_factor}'\n\
             \toption drop_factor '{drop_factor}'\n\
             \toption repeat_days '{repeat_days}'\n\
             \toption cooldown '{cooldown}'\n",
            enabled = if self.enabled { "1" } else { "0" },
            listen_port = self.listen_port,
            exposed_port = self.exposed_port,
            raw_max_mb = self.raw_max_mb,
            agg_max_ips = self.agg_max_ips,
            agg_max_ports = self.agg_max_ports,
            retention_days = self.retention_days,
            max_total_mb = self.max_total_mb,
            flush_interval = self.flush_interval,
            auto_block = if self.auto_block { "1" } else { "0" },
            block_ttl = self.block_ttl,
            notify = if self.notify { "1" } else { "0" },
            pushplus_token = self.pushplus_token,
            notify_min_severity = self.notify_min_severity,
            data_dir = self.data_dir.to_string_lossy(),
            tmp_dir = self.tmp_dir.to_string_lossy(),
            scan_ports = t.scan_ports,
            scan_window = t.scan_window,
            flood_per_min = t.flood_per_min,
            flood_sustain = t.flood_sustain,
            bruteforce_count = t.bruteforce_count,
            bruteforce_window = t.bruteforce_window,
            spike_factor = t.spike_factor,
            drop_factor = t.drop_factor,
            repeat_days = t.repeat_days,
            cooldown = t.cooldown,
        );
        std::fs::write(path, text)
    }
}
