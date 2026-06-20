use serde_json::{json, Value};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const BLACKLIST: &[&str] = &["nc", "ncat", "netcat", "socat", "mimikatz", "msfconsole", "msfvenom"];
const SUSPICIOUS_PREFIXES: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

pub fn spawn(config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut known: HashSet<i32> = snapshot_pids();
        let interval = Duration::from_secs(config.interval_seconds);
        tracing::info!("Process monitor started (interval={}s)", config.interval_seconds);
        loop {
            tokio::time::sleep(interval).await;
            let current = snapshot_pids();
            let new_pids: Vec<i32> = current.difference(&known).copied().collect();
            known = current;
            for pid in new_pids {
                if let Some(evt) = inspect(pid) {
                    if tx.send(evt).await.is_err() { return; }
                }
            }
        }
    })
}

fn snapshot_pids() -> HashSet<i32> {
    procfs::process::all_processes()
        .map(|iter| iter.flatten().map(|p| p.pid).collect())
        .unwrap_or_default()
}

fn inspect(pid: i32) -> Option<Value> {
    let proc = procfs::process::Process::new(pid).ok()?;
    let name = proc.stat().ok().map(|s| s.comm).unwrap_or_default();
    let cmdline = proc.cmdline().unwrap_or_default();
    let exe  = proc.exe().ok().map(|p| p.to_string_lossy().into_owned());
    let cwd  = proc.cwd().ok().map(|p| p.to_string_lossy().into_owned());

    let (severity, title) = if is_blacklisted(&name, &cmdline) {
        ("high", format!("Blacklisted process: {} (PID {})", name, pid))
    } else if suspicious_path(exe.as_deref(), cwd.as_deref()) {
        ("medium", format!("Process from suspicious path: {} (PID {})", name, pid))
    } else {
        return None;
    };

    Some(json!({
        "event_type": "new_process",
        "severity":   severity,
        "title":      title,
        "payload": {
            "pid":      pid,
            "name":     name,
            "cmdline":  cmdline,
            "exe":      exe,
            "cwd":      cwd,
        }
    }))
}

fn is_blacklisted(name: &str, cmdline: &[String]) -> bool {
    let n = name.to_lowercase();
    if BLACKLIST.contains(&n.as_str()) { return true; }
    if n == "wget" || n == "curl" {
        return cmdline.iter().any(|a| SUSPICIOUS_PREFIXES.iter().any(|p| a.starts_with(p)));
    }
    false
}

fn suspicious_path(exe: Option<&str>, cwd: Option<&str>) -> bool {
    [exe, cwd].iter().flatten().any(|p| SUSPICIOUS_PREFIXES.iter().any(|pre| p.starts_with(pre)))
}
