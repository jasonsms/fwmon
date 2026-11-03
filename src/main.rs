//! fwmon — OpenWrt inbound (L4) connection monitor.
//! Reads `conntrack -E`, aggregates per source IP, detects scans/floods/brute-force,
//! stores raw in RAM and a daily aggregate on eMMC, and serves a local JSON API.
mod aggregate;
mod alert;
mod api;
mod config;
mod conntrack;
mod detect;
mod engine;
mod model;
mod storage;
mod util;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Config;
use crate::engine::Core;

fn main() {
    let mut config_path: Option<String> = None;
    let mut replay_path: Option<String> = None;
    let mut print_config = false;
    let mut selftest = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--config" => config_path = args.next(),
            "--replay" => replay_path = args.next(),
            "--print-config" => print_config = true,
            "--selftest" => selftest = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: fwmon [--config <uci>] [--replay <file>] [--print-config] [--selftest]"
                );
                return;
            }
            other => eprintln!("[fwmon] unknown arg: {other}"),
        }
    }

    if selftest {
        run_selftest();
        return;
    }

    let cfg = Config::load(config_path.as_deref());
    if print_config {
        println!("{cfg:#?}");
        return;
    }

    let core = Arc::new(Mutex::new(Core::new(cfg)));
    let running = Arc::new(AtomicBool::new(true));

    {
        let running = running.clone();
        if ctrlc::set_handler(move || running.store(false, Ordering::SeqCst)).is_err() {
            eprintln!("[fwmon] warning: could not install signal handler");
        }
    }

    // conntrack reader (or replay feeder)
    {
        let core = core.clone();
        let running = running.clone();
        std::thread::spawn(move || match replay_path {
            Some(path) => run_replay(&path, &core),
            None => run_conntrack(&core, &running),
        });
    }

    // local JSON API
    {
        let core = core.clone();
        std::thread::spawn(move || api::serve(core));
    }

    // main control loop: periodic tick + graceful shutdown.
    let flush = {
        let c = core.lock().unwrap();
        c.cfg.flush_interval.max(5)
    };
    let mut since = 0u64;
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
        since += 1;
        if since % flush == 0 {
            if let Ok(mut c) = core.lock() {
                c.tick();
            }
        }
        if since % 300 == 0 {
            if let Ok(mut c) = core.lock() {
                c.refresh_local();
            }
        }
    }

    if let Ok(mut c) = core.lock() {
        c.shutdown();
    }
    eprintln!("[fwmon] shutdown complete");
}

/// Continuously read `conntrack -E` and ingest inbound NEW events.
fn run_conntrack(core: &Arc<Mutex<Core>>, running: &Arc<AtomicBool>) {
    loop {
        if !running.load(Ordering::SeqCst) {
            return;
        }
        let child = Command::new("conntrack")
            .args(["-E", "-n"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                if let Ok(mut c) = core.lock() {
                    c.conntrack_alive = false;
                }
                eprintln!("[fwmon] spawn conntrack failed: {e}; retry in 5s");
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        if let Ok(mut c) = core.lock() {
            c.conntrack_alive = true;
        }
        if let Some(out) = child.stdout.take() {
            let reader = BufReader::new(out);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        if let Ok(mut c) = core.lock() {
                            c.ingest_line(&l);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        // EOF or error: mark dead and retry after a short delay.
        if let Ok(mut c) = core.lock() {
            c.conntrack_alive = false;
        }
        let _ = child.wait();
        if !running.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Feed lines from a file (one `conntrack -E` line per row) — used for offline testing.
fn run_replay(path: &str, core: &Arc<Mutex<Core>>) {
    let Ok(file) = std::fs::File::open(path) else {
        eprintln!("[fwmon] replay file not found: {path}");
        return;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().filter_map(|l| l.ok()) {
        if let Ok(mut c) = core.lock() {
            c.ingest_line(&line);
        }
    }
    if let Ok(mut c) = core.lock() {
        c.conntrack_alive = false;
    }
    eprintln!("[fwmon] replay finished");
}

/// Quick parse/aggregate sanity check (no root / conntrack required).
fn run_selftest() {
    let samples = [
        "[NEW] tcp 6 120 SYN_SENT src=2409:8a00::1 dst=2409:8a00::2 sport=54321 dport=443 [UNREPLIED] src=2409:8a00::2 dst=2409:8a00::1 sport=443 dport=54321",
        "[NEW] tcp 6 120 SYN_SENT src=2409:8a00::1 dst=2409:8a00::2 sport=54322 dport=22 [UNREPLIED] src=2409:8a00::2 dst=2409:8a00::1 sport=22 dport=54322",
        "[UPDATE] tcp 6 60 ESTABLISHED src=2409:8a00::2 dst=2409:8a00::1 sport=443 dport=54321",
    ];
    for s in samples {
        match conntrack::parse_line(s) {
            Some(ev) => println!(
                "parsed: is_new={} proto={} src={} dst={} dport={}",
                ev.is_new, ev.proto, ev.src, ev.dst, ev.dport
            ),
            None => println!("parsed: (skip)"),
        }
    }
    println!("selftest ok");
}
