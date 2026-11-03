//! Layered storage: /tmp (RAM) raw + today's aggregate, daily gzip rollup to eMMC.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

pub struct Storage {
    pub tmp_dir: PathBuf,
    pub data_dir: PathBuf,
    pub raw_max_bytes: u64,
    pub retention_days: u32,
    pub max_total_bytes: u64,
}

impl Storage {
    pub fn new(
        tmp_dir: PathBuf,
        data_dir: PathBuf,
        raw_max_mb: u64,
        retention_days: u32,
        max_total_mb: u64,
    ) -> Self {
        Storage {
            tmp_dir,
            data_dir,
            raw_max_bytes: raw_max_mb * 1024 * 1024,
            retention_days,
            max_total_bytes: max_total_mb * 1024 * 1024,
        }
    }

    pub fn ensure_dirs(&self) {
        let _ = fs::create_dir_all(&self.tmp_dir);
        let _ = fs::create_dir_all(&self.data_dir);
    }

    fn raw_path(&self) -> PathBuf {
        self.tmp_dir.join("raw-today.jsonl")
    }
    fn agg_path(&self) -> PathBuf {
        self.tmp_dir.join("agg-today.json")
    }
    fn hourly_path(&self) -> PathBuf {
        self.tmp_dir.join("hourly-today.json")
    }

    /// Append one raw sample line; enforce the byte cap (drop + signal).
    pub fn append_raw(&self, line: &str, raw_bytes: &mut u64) -> bool {
        let path = self.raw_path();
        let add = line.len() as u64 + 1;
        if *raw_bytes + add > self.raw_max_bytes {
            return false;
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            if f.write_all(line.as_bytes()).is_ok() && f.write_all(b"\n").is_ok() {
                *raw_bytes += add;
                return true;
            }
        }
        false
    }

    pub fn raw_size(&self) -> u64 {
        fs::metadata(self.raw_path()).map(|m| m.len()).unwrap_or(0)
    }

    /// Persist today's aggregates to /tmp (RAM) so a restart can resume.
    pub fn save_today(&self, agg_json: &serde_json::Value, hourly_json: &serde_json::Value) {
        if let Ok(s) = serde_json::to_string(agg_json) {
            let _ = fs::write(self.agg_path(), s);
        }
        if let Ok(s) = serde_json::to_string(hourly_json) {
            let _ = fs::write(self.hourly_path(), s);
        }
    }

    /// Load today's persisted aggregates if present -> (ips_array, hourly_obj).
    pub fn load_today(&self) -> Option<(Vec<serde_json::Value>, serde_json::Value)> {
        let agg_txt = fs::read_to_string(self.agg_path()).ok()?;
        let agg: serde_json::Value = serde_json::from_str(&agg_txt).ok()?;
        let ips = agg.as_array().cloned().unwrap_or_default();
        let hourly = fs::read_to_string(self.hourly_path())
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .unwrap_or(serde_json::Value::Null);
        Some((ips, hourly))
    }

    fn rollup_path(&self, date: &str) -> PathBuf {
        self.data_dir.join(format!("fwmon-{date}.json.gz"))
    }

    /// Compress the day's aggregate into a single gzip file on eMMC, then clear raw.
    pub fn rollup(
        &self,
        date: &str,
        agg_json: &serde_json::Value,
        hourly_json: &serde_json::Value,
    ) -> std::io::Result<()> {
        let payload = serde_json::json!({
            "date": date,
            "generated": crate::util::now_ts(),
            "hourly": hourly_json,
            "ips": agg_json,
        });
        let bytes = serde_json::to_vec(&payload).map_err(std::io::Error::other)?;
        let tmp = self.data_dir.join(format!(".fwmon-{date}.json.gz.tmp"));
        {
            let f = fs::File::create(&tmp)?;
            let mut gz = GzEncoder::new(f, Compression::default());
            gz.write_all(&bytes)?;
            gz.finish()?;
        }
        let final_path = self.rollup_path(date);
        fs::rename(&tmp, &final_path)?;
        // Daily rollup done: drop the RAM raw sample for that day.
        let _ = fs::remove_file(self.raw_path());
        Ok(())
    }

    /// Read the most recent previous rollup (to seed "known" IPs for repeat detection).
    pub fn load_latest_rollup_ips(&self) -> Option<(String, Vec<String>)> {
        let mut files = self.list_rollups()?;
        files.sort();
        files.pop(); // drop today's (if any)
        let latest = files.pop()?;
        let date = date_from_name(&latest)?;
        let ips = self.read_rollup_ips(&latest)?;
        Some((date, ips))
    }

    fn list_rollups(&self) -> Option<Vec<PathBuf>> {
        let mut out = Vec::new();
        let rd = fs::read_dir(&self.data_dir).ok()?;
        for e in rd.flatten() {
            let p = e.path();
            if p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("fwmon-") && n.ends_with(".json.gz"))
                .unwrap_or(false)
            {
                out.push(p);
            }
        }
        Some(out)
    }

    fn read_rollup_ips(&self, path: &Path) -> Option<Vec<String>> {
        let f = fs::File::open(path).ok()?;
        let gz = GzDecoder::new(f);
        let reader = BufReader::new(gz);
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let v: serde_json::Value = serde_json::from_str(&line).ok()?;
        let ips = v
            .get("ips")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|it| it.get("src").and_then(|s| s.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        Some(ips)
    }

    /// Count, per source IP, how many distinct prior days it appeared in
    /// (up to `limit` most-recent prior rollups). Used by repeat-offender detection.
    pub fn load_prior_ip_date_counts(&self, limit: usize) -> std::collections::HashMap<String, u32> {
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        let today = crate::util::today();
        let Some(mut files) = self.list_rollups() else {
            return counts;
        };
        files.sort();
        // Exclude today's own rollup (if any) — only prior days count.
        files.retain(|p| date_from_name(p).as_deref() != Some(today.as_str()));
        let start = files.len().saturating_sub(limit.max(1));
        for p in &files[start..] {
            if let Some(ips) = self.read_rollup_ips(p) {
                for ip in ips {
                    *counts.entry(ip).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    /// Delete rollups outside the retention window and enforce the total-size cap.
    pub fn prune(&self) {
        let cutoff = crate::util::date_minus_days(self.retention_days);
        let Some(mut files) = self.list_rollups() else { return };
        files.sort();
        let mut kept: Vec<PathBuf> = Vec::new();
        for p in files {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let date = date_from_name(&p).unwrap_or_default();
            if !date.is_empty() && date < cutoff {
                let _ = fs::remove_file(&p);
                continue;
            }
            kept.push(p);
        }
        // Enforce total size by dropping oldest first.
        let mut total: u64 = kept
            .iter()
            .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .sum();
        while total > self.max_total_bytes && kept.len() > 1 {
            if let Some(oldest) = kept.first().cloned() {
                if let Ok(md) = fs::metadata(&oldest) {
                    total = total.saturating_sub(md.len());
                }
                let _ = fs::remove_file(&oldest);
                kept.remove(0);
            } else {
                break;
            }
        }
    }
}

fn date_from_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let core = name.strip_prefix("fwmon-")?.strip_suffix(".json.gz")?;
    if crate::util::parse_date(core).is_some() {
        Some(core.to_string())
    } else {
        None
    }
}
