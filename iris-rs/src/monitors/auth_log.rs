use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const AUTH_LOG: &str = "/var/log/auth.log";
const BRUTE_THRESHOLD: usize = 5;
const BRUTE_WINDOW: Duration = Duration::from_secs(60);
const BRUTE_COOLDOWN: Duration = Duration::from_secs(300);

pub fn spawn(_config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let patterns = Patterns::new();
        let mut brute = BruteForceTracker::default();

        if Path::new(AUTH_LOG).exists() {
            tail_file(AUTH_LOG, &patterns, &mut brute, &tx).await;
        } else {
            tail_journalctl(&patterns, &mut brute, &tx).await;
        }
    })
}

async fn tail_file(path: &str, pat: &Patterns, brute: &mut BruteForceTracker, tx: &mpsc::Sender<Value>) {
    tracing::info!("Auth monitor: tailing {}", path);
    let Ok(file) = tokio::fs::File::open(path).await else {
        tracing::warn!("Auth monitor: cannot open {}", path);
        return;
    };
    let mut reader = BufReader::new(file);
    // Seek to end — only watch new lines
    let _ = reader.seek(SeekFrom::End(0)).await;

    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => tokio::time::sleep(Duration::from_millis(500)).await,
            Ok(_) => { if let Some(e) = handle_line(&line, pat, brute) { let _ = tx.send(e).await; } }
            Err(e) => { tracing::error!("Auth log read error: {}", e); break; }
        }
    }
}

async fn tail_journalctl(pat: &Patterns, brute: &mut BruteForceTracker, tx: &mpsc::Sender<Value>) {
    tracing::info!("Auth monitor: tailing journalctl");
    let Ok(mut child) = tokio::process::Command::new("journalctl")
        .args(["-f", "-u", "ssh", "--output=short-iso", "--no-pager"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn() else {
            tracing::warn!("Auth monitor: journalctl not found; auth monitoring disabled");
            return;
        };

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(e) = handle_line(&line, pat, brute) {
            if tx.send(e).await.is_err() { break; }
        }
    }
    let _ = child.kill().await;
}

fn handle_line(line: &str, pat: &Patterns, brute: &mut BruteForceTracker) -> Option<Value> {
    if let Some(c) = pat.accepted.captures(line) {
        return Some(auth_event("ssh_login_success", "info",
            &c["user"], Some(&c["ip"]),
            format!("SSH login: {} from {}", &c["user"], &c["ip"]),
            Some(&c["method"]), line));
    }
    if let Some(c) = pat.failed.captures(line) {
        let ip = &c["ip"];
        if brute.record(ip) {
            return Some(auth_event("brute_force", "high",
                &c["user"], Some(ip),
                format!("Brute-force SSH from {}", ip),
                Some("brute_force"), line));
        }
        return Some(auth_event("ssh_login_failure", "medium",
            &c["user"], Some(ip),
            format!("SSH failed: {} from {}", &c["user"], ip),
            None, line));
    }
    if let Some(c) = pat.invalid.captures(line) {
        let ip = &c["ip"];
        if brute.record(ip) {
            return Some(auth_event("brute_force", "high",
                &c["user"], Some(ip),
                format!("Brute-force SSH from {}", ip),
                Some("brute_force"), line));
        }
        return Some(auth_event("ssh_invalid_user", "medium",
            &c["user"], Some(ip),
            format!("SSH invalid user {} from {}", &c["user"], ip),
            None, line));
    }
    if let Some(c) = pat.sudo.captures(line) {
        let command = &c["command"];
        // Defense evasion: tampering with the monitoring agent itself (MITRE T1562.001).
        // Surface as HIGH so it's never lost in routine sudo noise.
        if is_agent_tamper(command) {
            return Some(auth_event("agent_tamper", "high",
                &c["user"], None,
                format!("Iris agent tampered with by {}: {}", &c["user"], command),
                Some("agent_tamper"), line));
        }
        return Some(auth_event("sudo_command", "low",
            &c["user"], None,
            format!("sudo by {}: {}", &c["user"], command),
            None, line));
    }
    if let Some(c) = pat.su.captures(line) {
        return Some(auth_event("su_session", "low",
            &c["user"], None,
            format!("su session for {}", &c["user"]),
            None, line));
    }
    None
}

/// True if a sudo command stops, disables, masks or kills the Iris agent —
/// a classic attempt to blind the monitoring before doing something worse.
fn is_agent_tamper(command: &str) -> bool {
    let c = command.to_lowercase();
    if !(c.contains("horus-iris") || c.contains("horus_iris")) {
        return false;
    }
    ["stop", "disable", "mask", "kill", "rm ", "remove", "uninstall"]
        .iter()
        .any(|verb| c.contains(verb))
}

fn auth_event(subtype: &str, severity: &str, user: &str, ip: Option<&str>, title: String, method: Option<&str>, line: &str) -> Value {
    json!({
        "event_type": "auth_event",
        "severity":   severity,
        "title":      title,
        "payload": {
            "subtype":    subtype,
            "user":       user,
            "source_ip":  ip,
            "method":     method,
            "raw_line":   line.trim(),
        }
    })
}

struct Patterns {
    accepted: Regex,
    failed:   Regex,
    invalid:  Regex,
    sudo:     Regex,
    su:       Regex,
}

impl Patterns {
    fn new() -> Self {
        Self {
            accepted: Regex::new(r"Accepted (?P<method>password|publickey|keyboard-interactive) for (?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            failed:   Regex::new(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            invalid:  Regex::new(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            sudo:     Regex::new(r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)").unwrap(),
            su:       Regex::new(r"su:\s+(?:Successful su for|pam_unix.*session opened for user) (?P<user>\S+)").unwrap(),
        }
    }
}

#[derive(Default)]
struct BruteForceTracker {
    failures: HashMap<String, VecDeque<Instant>>,
    alerted:  HashMap<String, Instant>,
}

impl BruteForceTracker {
    fn record(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        let dq = self.failures.entry(ip.to_string()).or_default();
        dq.push_back(now);
        while dq.front().map_or(false, |t| now.duration_since(*t) > BRUTE_WINDOW) {
            dq.pop_front();
        }
        if dq.len() >= BRUTE_THRESHOLD {
            let last = self.alerted.get(ip).copied().unwrap_or(Instant::now() - BRUTE_COOLDOWN * 2);
            if now.duration_since(last) > BRUTE_COOLDOWN {
                self.alerted.insert(ip.to_string(), now);
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::is_agent_tamper;

    #[test]
    fn detects_agent_tamper() {
        assert!(is_agent_tamper("/usr/bin/systemctl stop horus-iris"));
        assert!(is_agent_tamper("/bin/systemctl disable horus-iris.service"));
        assert!(is_agent_tamper("/usr/bin/systemctl mask horus-iris"));
        assert!(is_agent_tamper("pkill -f horus-iris"));
        // unrelated sudo commands are not tamper
        assert!(!is_agent_tamper("/usr/bin/apt install nginx"));
        assert!(!is_agent_tamper("/usr/bin/systemctl restart nginx"));
        assert!(!is_agent_tamper("/usr/bin/systemctl status horus-iris")); // read-only, fine
    }
}
