//! Journald monitor; streams `journalctl -f -o json` and emits security events.
//!
//! Replaces the old auth_log poller. Zero polling, zero RAM growth: the kernel streams
//! events as they happen. Covers SSH, sudo, su, user/group changes, and any high-priority
//! system message. Brute-force detection and agent-tamper detection live here.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const BRUTE_THRESHOLD: usize = 5;
const BRUTE_WINDOW: Duration = Duration::from_secs(60);
const BRUTE_COOLDOWN: Duration = Duration::from_secs(300);

const SECURITY_IDENTIFIERS: &[&str] = &[
    "sshd", "sudo", "su", "su-l", "login", "passwd",
    "useradd", "userdel", "usermod", "groupadd", "chpasswd",
];

pub fn spawn(_config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pat = Patterns::new();
        let mut brute = BruteForceTracker::default();

        let mut child = match tokio::process::Command::new("journalctl")
            .args([
                "-f", "-o", "json", "--no-pager",
                "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_COMM,PRIORITY,_PID,_UID",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => {
                tracing::warn!("journalctl not found; journald monitor disabled");
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return,
        };
        let mut lines = BufReader::new(stdout).lines();
        tracing::info!("Journald monitor started");

        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(rec) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(evt) = handle(&rec, &pat, &mut brute) {
                if tx.send(evt).await.is_err() {
                    break;
                }
            }
        }
        let _ = child.kill().await;
    })
}

/// journald JSON fields can be strings, numbers, or (for non-UTF8) arrays. We only act on
/// the string form, which is what security-relevant text fields always are.
fn field<'a>(rec: &'a Value, key: &str) -> &'a str {
    rec.get(key).and_then(Value::as_str).unwrap_or("")
}

fn handle(rec: &Value, pat: &Patterns, brute: &mut BruteForceTracker) -> Option<Value> {
    let ident = {
        let i = field(rec, "SYSLOG_IDENTIFIER");
        if i.is_empty() { field(rec, "_COMM") } else { i }
    };
    let msg = field(rec, "MESSAGE");
    let priority: i64 = field(rec, "PRIORITY").parse().unwrap_or(6);

    if !SECURITY_IDENTIFIERS.contains(&ident) && priority > 3 {
        return None;
    }

    match ident {
        "sshd" => {
            if let Some(c) = pat.ssh_accepted.captures(msg) {
                return Some(auth("ssh_login_success", "low",
                    format!("SSH login: {} from {}", &c["user"], &c["ip"]),
                    json!({"subtype": "ssh_login_success", "user": &c["user"],
                           "source_ip": &c["ip"], "method": &c["method"]})));
            }
            if let Some(c) = pat.ssh_failed.captures(msg) {
                let ip = c["ip"].to_string();
                if brute.record(&ip) {
                    return Some(auth("brute_force", "high",
                        format!("Brute-force SSH from {}", ip),
                        json!({"subtype": "brute_force", "user": &c["user"], "source_ip": ip})));
                }
                return Some(auth("ssh_login_failure", "medium",
                    format!("SSH failed login: {} from {}", &c["user"], ip),
                    json!({"subtype": "ssh_login_failure", "user": &c["user"], "source_ip": ip})));
            }
            if let Some(c) = pat.ssh_invalid.captures(msg) {
                let ip = c["ip"].to_string();
                brute.record(&ip);
                return Some(auth("ssh_invalid_user", "medium",
                    format!("SSH invalid user {} from {}", &c["user"], ip),
                    json!({"subtype": "ssh_invalid_user", "user": &c["user"], "source_ip": ip})));
            }
        }
        "sudo" => {
            if let Some(c) = pat.sudo.captures(msg) {
                let command = c["command"].trim();
                // Defense evasion: tampering with the monitoring agent (MITRE T1562.001).
                if is_agent_tamper(command) {
                    return Some(auth("agent_tamper", "high",
                        format!("Iris agent tampered with: {}", command),
                        json!({"subtype": "agent_tamper", "user": &c["user"], "command": command})));
                }
                let short: String = command.chars().take(120).collect();
                return Some(auth("sudo_command", "low",
                    format!("sudo: {}: {}", &c["user"], short),
                    json!({"subtype": "sudo_command", "user": &c["user"], "command": command})));
            }
        }
        "su" | "su-l" => {
            if let Some(c) = pat.su.captures(msg) {
                return Some(auth("su_session", "low",
                    format!("su session for {}", &c["user"]),
                    json!({"subtype": "su_session", "user": &c["user"]})));
            }
        }
        "useradd" | "userdel" | "usermod" | "groupadd" | "chpasswd" => {
            let short: String = msg.chars().take(120).collect();
            return Some(auth("user_change", "high",
                format!("User/group change: {}: {}", ident, short),
                json!({"subtype": "user_change", "identifier": ident,
                       "message": msg.chars().take(200).collect::<String>()})));
        }
        _ => {}
    }

    // Emergency/alert/critical/error from any source → surface as a log anomaly.
    if priority <= 3 {
        let short: String = msg.chars().take(200).collect();
        let sev = if priority <= 2 { "high" } else { "medium" };
        return Some(json!({
            "event_type": "log_anomaly",
            "severity": sev,
            "title": short,
            "payload": {"identifier": ident, "priority": priority, "pid": field(rec, "_PID")},
        }));
    }
    None
}

fn auth(subtype: &str, severity: &str, title: String, mut payload: Value) -> Value {
    if let Value::Object(ref mut m) = payload {
        m.entry("subtype").or_insert_with(|| json!(subtype));
    }
    json!({"event_type": "auth_event", "severity": severity, "title": title, "payload": payload})
}

/// True if a sudo command stops, disables, masks or removes the Iris agent; a classic
/// attempt to blind monitoring before doing something worse.
fn is_agent_tamper(command: &str) -> bool {
    let c = command.to_lowercase();
    if !(c.contains("horus-iris") || c.contains("horus_iris")) {
        return false;
    }
    ["stop", "disable", "mask", "kill", "rm ", "remove", "uninstall"]
        .iter()
        .any(|verb| c.contains(verb))
}

struct Patterns {
    ssh_accepted: Regex,
    ssh_failed: Regex,
    ssh_invalid: Regex,
    sudo: Regex,
    su: Regex,
}

impl Patterns {
    fn new() -> Self {
        Self {
            ssh_accepted: Regex::new(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            ssh_failed: Regex::new(r"Failed \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            ssh_invalid: Regex::new(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)").unwrap(),
            sudo: Regex::new(r"(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)").unwrap(),
            su: Regex::new(r"(?:Successful su for|session opened for user) (?P<user>\S+)").unwrap(),
        }
    }
}

#[derive(Default)]
struct BruteForceTracker {
    failures: HashMap<String, VecDeque<Instant>>,
    alerted: HashMap<String, Instant>,
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
            let last = self.alerted.get(ip).copied().unwrap_or(now - BRUTE_COOLDOWN * 2);
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
    use super::*;

    #[test]
    fn detects_agent_tamper() {
        assert!(is_agent_tamper("/usr/bin/systemctl stop horus-iris"));
        assert!(is_agent_tamper("/bin/systemctl disable horus-iris.service"));
        assert!(is_agent_tamper("pkill -f horus-iris"));
        assert!(!is_agent_tamper("/usr/bin/apt install nginx"));
        assert!(!is_agent_tamper("/usr/bin/systemctl status horus-iris"));
    }

    #[test]
    fn parses_ssh_brute_force() {
        let pat = Patterns::new();
        let mut brute = BruteForceTracker::default();
        let rec = json!({
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 1.2.3.4 port 22 ssh2",
            "PRIORITY": "5",
        });
        // First 4 failures: medium; 5th trips brute-force high.
        let mut last = None;
        for _ in 0..5 {
            last = handle(&rec, &pat, &mut brute);
        }
        let evt = last.unwrap();
        assert_eq!(evt["severity"], "high");
        assert_eq!(evt["payload"]["subtype"], "brute_force");
    }

    #[test]
    fn ignores_routine_low_priority_noise() {
        let pat = Patterns::new();
        let mut brute = BruteForceTracker::default();
        let rec = json!({
            "SYSLOG_IDENTIFIER": "CRON",
            "MESSAGE": "pam_unix(cron:session): session opened",
            "PRIORITY": "6",
        });
        assert!(handle(&rec, &pat, &mut brute).is_none());
    }
}
