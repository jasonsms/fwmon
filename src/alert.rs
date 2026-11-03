//! Alert ring buffer + WeChat PushPlus notification (minimal HTTP client).
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::config::Config;
use crate::model::Alert;

pub struct AlertSink {
    pub alerts: VecDeque<Alert>,
    cap: usize,
}

impl AlertSink {
    pub fn new(cap: usize) -> Self {
        AlertSink {
            alerts: VecDeque::new(),
            cap: cap.max(1),
        }
    }

    /// Store an alert and (optionally) push a WeChat notification.
    pub fn record(&mut self, alert: Alert, cfg: &Config) {
        if should_notify(&alert, cfg) {
            let title = format!("[fwmon] {} · {}", alert.severity, alert.kind);
            let content = format!(
                "源 IP：{}\n指标：{}={}（阈值 {}）\n窗口：{}\n时间：{}\n{}",
                alert.src,
                alert.metric,
                alert.value,
                alert.threshold,
                alert.window,
                crate::util::ts_to_rfc3339(alert.ts),
                alert.detail
            );
            let _ = pushplus_send(&cfg.pushplus_token, &title, &content);
        }
        self.alerts.push_front(alert);
        while self.alerts.len() > self.cap {
            self.alerts.pop_back();
        }
    }

    pub fn list(&self, limit: usize) -> Vec<Alert> {
        self.alerts.iter().take(limit).cloned().collect()
    }
}

fn should_notify(alert: &Alert, cfg: &Config) -> bool {
    if !cfg.notify || cfg.pushplus_token.trim().is_empty() {
        return false;
    }
    let min_rank = match cfg.notify_min_severity.as_str() {
        "info" => 0,
        "high" => 2,
        "critical" => 3,
        _ => 1, // warn
    };
    alert.severity_rank() >= min_rank
}

/// Minimal HTTP POST (JSON) to PushPlus. Returns true on HTTP 200.
pub fn pushplus_send(token: &str, title: &str, content: &str) -> bool {
    let body = serde_json::json!({
        "token": token,
        "title": title,
        "content": content,
        "template": "html",
    })
    .to_string();
    http_post_json("www.pushplus.plus", "/send", &body).is_some()
}

fn http_post_json(host: &str, path: &str, body: &str) -> Option<String> {
    let mut stream = TcpStream::connect((host, 80)).ok()?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok()?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10))).ok()?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).ok()?;
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Some(resp)
    } else {
        // PushPlus returns 200 with a JSON body; non-200 means failure.
        None
    }
}
