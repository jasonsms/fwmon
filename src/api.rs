//! Localhost-only JSON API for the LuCI panel.
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::engine::Core;
use crate::util;

pub type Shared = Arc<Mutex<Core>>;

pub fn serve(state: Shared) {
    let port = state.lock().map(|c| c.cfg.listen_port).unwrap_or(8099);
    let server = match Server::http(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[fwmon] api listen 127.0.0.1:{port} failed: {e}");
            return;
        }
    };
    eprintln!("[fwmon] api listening on 127.0.0.1:{port}");
    for request in server.incoming_requests() {
        route(request, &state);
    }
}

fn route(mut request: Request, state: &Shared) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query) = split_url(&url);
    let q = parse_query(&query);
    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let response = match (method, path.as_str()) {
        (Method::Get, "/api/health") => health(state),
        (Method::Get, "/api/summary") => summary(state, &q),
        (Method::Get, "/api/ips") => ips(state, &q),
        (Method::Get, p) if p.starts_with("/api/ips/") && !p.ends_with("/block") && !p.ends_with("/unblock") => {
            let src = p.trim_start_matches("/api/ips/").to_string();
            ip_detail(state, &src)
        }
        (Method::Post, p) if p.ends_with("/block") => {
            let src = p.trim_start_matches("/api/ips/").trim_end_matches("/block").to_string();
            block(state, &src, true)
        }
        (Method::Post, p) if p.ends_with("/unblock") => {
            let src = p.trim_start_matches("/api/ips/").trim_end_matches("/unblock").to_string();
            block(state, &src, false)
        }
        (Method::Get, "/api/alerts") => alerts(state, &q),
        (Method::Get, "/api/config") => get_config(state),
        (Method::Put, "/api/config") | (Method::Post, "/api/config") => put_config(state, &body),
        _ => json(404, &serde_json::json!({"code":404, "message":"not found"})),
    };
    let _ = request.respond(response);
}

fn json(status: u16, v: &serde_json::Value) -> Response<String> {
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json; charset=utf-8"[..])
        .unwrap();
    Response::from_string(v.to_string())
        .with_header(header)
        .with_status_code(status)
}

fn ok(v: serde_json::Value) -> Response<String> {
    json(200, &serde_json::json!({"code":0, "data": v}))
}

fn split_url(url: &str) -> (String, String) {
    match url.find('?') {
        Some(i) => (url[..i].to_string(), url[i + 1..].to_string()),
        None => (url.to_string(), String::new()),
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("").to_string();
        let v = it.next().unwrap_or("").to_string();
        map.insert(k, v);
    }
    map
}

fn qnum(q: &HashMap<String, String>, key: &str, default: usize) -> usize {
    q.get(key)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .max(1)
}

fn health(state: &Shared) -> Response<String> {
    let c = state.lock().unwrap();
    ok(serde_json::json!({
        "enabled": c.cfg.enabled,
        "conntrack_alive": c.conntrack_alive,
        "uptime_s": util::now_ts() - c.started,
        "date": c.current_date,
        "tracked_ips": c.agg.ips.len(),
        "agg_dropped": c.agg.dropped,
        "raw_bytes": c.raw_bytes,
        "raw_max_bytes": c.cfg.raw_max_mb * 1024 * 1024,
        "local_known": !c.local.is_empty(),
        "exposed_port": c.cfg.exposed_port,
    }))
}

fn summary(state: &Shared, q: &HashMap<String, String>) -> Response<String> {
    let mut c = state.lock().unwrap();
    let _ = q;
    let mut events = 0u64;
    let mut accept = 0u64;
    let mut drop = 0u64;
    for a in c.agg.ips.values() {
        events += a.events;
        accept += a.accept;
        drop += a.dropped;
    }
    let hourly = c.agg.hourly_json();
    ok(serde_json::json!({
        "date": c.current_date,
        "events": events,
        "unique_ips": c.agg.ips.len(),
        "accept": accept,
        "drop": drop,
        "hourly": hourly,
    }))
}

fn ips(state: &Shared, q: &HashMap<String, String>) -> Response<String> {
    let c = state.lock().unwrap();
    let limit = qnum(q, "limit", 200);
    let mut v = c.agg.ips_json();
    v.truncate(limit);
    ok(serde_json::json!({ "date": c.current_date, "total": c.agg.ips.len(), "items": v }))
}

fn ip_detail(state: &Shared, src: &str) -> Response<String> {
    let c = state.lock().unwrap();
    match c.agg.ips.get(src) {
        Some(a) => ok(a.to_json(c.cfg.agg_max_ports)),
        None => json(404, &serde_json::json!({"code":404, "message":"source not found"})),
    }
}

fn alerts(state: &Shared, q: &HashMap<String, String>) -> Response<String> {
    let c = state.lock().unwrap();
    let limit = qnum(q, "limit", 100);
    let items = c.alerts.list(limit);
    ok(serde_json::json!({ "items": items }))
}

fn get_config(state: &Shared) -> Response<String> {
    let c = state.lock().unwrap();
    let cfg = &c.cfg;
    ok(serde_json::json!({
        "enabled": cfg.enabled,
        "listen_port": cfg.listen_port,
        "exposed_port": cfg.exposed_port,
        "raw_max_mb": cfg.raw_max_mb,
        "agg_max_ips": cfg.agg_max_ips,
        "agg_max_ports": cfg.agg_max_ports,
        "retention_days": cfg.retention_days,
        "max_total_mb": cfg.max_total_mb,
        "flush_interval": cfg.flush_interval,
        "auto_block": cfg.auto_block,
        "block_ttl": cfg.block_ttl,
        "notify": cfg.notify,
        "pushplus_token": cfg.pushplus_token,
        "notify_min_severity": cfg.notify_min_severity,
        "data_dir": cfg.data_dir.display().to_string(),
        "tmp_dir": cfg.tmp_dir.display().to_string(),
        "thresholds": {
            "scan_ports": cfg.thresholds.scan_ports,
            "scan_window": cfg.thresholds.scan_window,
            "flood_per_min": cfg.thresholds.flood_per_min,
            "flood_sustain": cfg.thresholds.flood_sustain,
            "bruteforce_count": cfg.thresholds.bruteforce_count,
            "bruteforce_window": cfg.thresholds.bruteforce_window,
            "spike_factor": cfg.thresholds.spike_factor,
            "drop_factor": cfg.thresholds.drop_factor,
            "repeat_days": cfg.thresholds.repeat_days,
            "cooldown": cfg.thresholds.cooldown,
        },
    }))
}

fn put_config(state: &Shared, body: &str) -> Response<String> {
    let mut c = state.lock().unwrap();
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json(400, &serde_json::json!({"code":400, "message":"invalid json"})),
    };
    // Apply a subset of fields; unspecified fields are preserved.
    if let Some(x) = v.get("exposed_port").and_then(|x| x.as_u64()) {
        c.cfg.exposed_port = x as u16;
    }
    if let Some(x) = v.get("notify").and_then(|x| x.as_bool()) {
        c.cfg.notify = x;
    }
    if let Some(x) = v.get("pushplus_token").and_then(|x| x.as_str()) {
        c.cfg.pushplus_token = x.to_string();
    }
    if let Some(x) = v.get("notify_min_severity").and_then(|x| x.as_str()) {
        c.cfg.notify_min_severity = x.to_string();
    }
    if let Some(x) = v.get("auto_block").and_then(|x| x.as_bool()) {
        c.cfg.auto_block = x;
    }
    if let Some(x) = v.get("retention_days").and_then(|x| x.as_u64()) {
        c.cfg.retention_days = x as u32;
    }
    if let Some(x) = v.get("enabled").and_then(|x| x.as_bool()) {
        c.cfg.enabled = x;
    }
    if let Some(t) = v.get("thresholds").and_then(|x| x.as_object()) {
        macro_rules! set {
            ($k:ident) => {
                if let Some(x) = t.get(stringify!($k)).and_then(|x| x.as_u64()) {
                    c.cfg.thresholds.$k = x;
                }
            };
        }
        set!(scan_ports);
        set!(scan_window);
        set!(flood_per_min);
        set!(flood_sustain);
        set!(bruteforce_count);
        set!(bruteforce_window);
        set!(spike_factor);
        set!(drop_factor);
        set!(repeat_days);
        set!(cooldown);
    }
    // Persist best-effort to the UCI file.
    let path = std::env::var("FWMON_CONFIG").unwrap_or_else(|_| "/etc/config/fwmon".into());
    if let Err(e) = c.cfg.save_uci(&path) {
        eprintln!("[fwmon] save config failed: {e}");
    }
    ok(serde_json::json!({"saved": true}))
}

fn block(state: &Shared, src: &str, enable: bool) -> Response<String> {
    let c = state.lock().unwrap();
    if !c.cfg.auto_block {
        return json(400, &serde_json::json!({"code":400, "message":"auto-block disabled"}));
    }
    let action = if enable { "add" } else { "delete" };
    let cmd = format!(
        "nft {action} element inet fwmon fwmon_block {{ {src} }} 2>/dev/null || true"
    );
    let _ = std::process::Command::new("sh").arg("-c").arg(&cmd).status();
    ok(serde_json::json!({"src": src, "blocked": enable}))
}
