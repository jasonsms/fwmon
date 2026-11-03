//! Parse `conntrack -E` event lines and classify inbound direction.
use std::collections::HashSet;
use std::process::Command;

/// A parsed conntrack event (original-direction tuple).
#[derive(Debug, Clone)]
pub struct ConnEvent {
    pub is_new: bool,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub dport: u16,
}

/// Set of local (router / LAN) addresses used to decide inbound vs outbound.
#[derive(Debug, Clone, Default)]
pub struct LocalAddrs {
    set: HashSet<String>,
}

impl LocalAddrs {
    pub fn is_local(&self, ip: &str) -> bool {
        self.set.contains(ip)
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Inbound = destination is ours and source is external.
    /// Falls back to "source is not ours" when the local set is unknown.
    pub fn is_inbound(&self, src: &str, dst: &str) -> bool {
        if self.is_empty() {
            return !self.is_local(src);
        }
        self.is_local(dst) && !self.is_local(src)
    }
}

/// Collect local addresses via `ip -j addr show` (IPv4 + IPv6).
pub fn local_addresses() -> LocalAddrs {
    let mut set = HashSet::new();
    let out = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .ok();
    if let Some(out) = out {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
            if let Some(arr) = v.as_array() {
                for iface in arr {
                    if let Some(info) = iface.get("addr_info").and_then(|a| a.as_array()) {
                        for addr in info {
                            if let Some(local) = addr.get("local").and_then(|l| l.as_str()) {
                                if !local.is_empty() {
                                    set.insert(local.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    LocalAddrs { set }
}

fn first_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{}=", key);
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix(&prefix) {
            return Some(v.to_string());
        }
    }
    None
}

/// Parse a single `conntrack -E -n` output line.
/// Format: `[NEW] tcp 6 120 SYN_SENT src=A dst=B sport=.. dport=.. [UNREPLIED] src=B dst=A ...`
pub fn parse_line(line: &str) -> Option<ConnEvent> {
    let line = line.trim();
    let open = line.find('[')?;
    let close = line.find(']')?;
    if close <= open {
        return None;
    }
    let kind = &line[open + 1..close];
    let rest = &line[close + 1..];
    let proto = rest
        .split_whitespace()
        .next()
        .unwrap_or("other")
        .to_ascii_lowercase();
    let src = first_kv(rest, "src")?;
    let dst = first_kv(rest, "dst").unwrap_or_default();
    let dport = first_kv(rest, "dport")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(0);
    Some(ConnEvent {
        is_new: kind.eq_ignore_ascii_case("NEW"),
        proto,
        src,
        dst,
        dport,
    })
}
