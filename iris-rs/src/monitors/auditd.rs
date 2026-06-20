//! Auditd monitor; tails /var/log/audit/audit.log, groups records by serial number, and
//! emits events for exec / file-change / network audit keys written by the installer.
//!
//! Replaces the old inotify FIM, procfs process poller, and TCP poller. Zero inotify watches
//! (the cause of the /home OOM), zero polling: the kernel audit subsystem does it all.
//! Requires the auditd rules the installer writes to /etc/audit/rules.d/horus.rules.

use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const AUDIT_LOG: &str = "/var/log/audit/audit.log";
const MAX_OPEN_GROUPS: usize = 500;

const SUSPICIOUS_PORTS: &[u16] = &[4444, 5555, 1337, 31337, 6666, 9001];
const BLACKLISTED_CMDS: &[&str] = &["nc", "ncat", "netcat", "socat", "mimikatz", "msfconsole", "msfvenom"];
const SUSPICIOUS_PATHS: &[&str] = &["/tmp/", "/dev/shm/", "/var/tmp/"];

pub fn spawn(_config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if !std::path::Path::new(AUDIT_LOG).exists() {
            tracing::warn!("auditd log {} not found; auditd monitor disabled (install auditd)", AUDIT_LOG);
            return;
        }

        let mut child = match tokio::process::Command::new("tail")
            .args(["-f", "-n", "0", AUDIT_LOG])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("auditd monitor: cannot tail {}: {}", AUDIT_LOG, e);
                return;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => return,
        };
        let mut lines = BufReader::new(stdout).lines();
        let parser = Parser::new();
        // serial → (type → fields)
        let mut groups: HashMap<String, HashMap<String, HashMap<String, String>>> = HashMap::new();
        tracing::info!("Auditd monitor started (tailing {})", AUDIT_LOG);

        while let Ok(Some(line)) = lines.next_line().await {
            for evt in parser.handle_line(&line, &mut groups) {
                if tx.send(evt).await.is_err() {
                    let _ = child.kill().await;
                    return;
                }
            }
        }
        let _ = child.kill().await;
    })
}

struct Parser {
    header: Regex,
    field: Regex,
}

impl Parser {
    fn new() -> Self {
        Self {
            header: Regex::new(r"^type=(\S+) msg=audit\(\d+\.\d+:(\d+)\):").unwrap(),
            // key="quoted value" OR key=bareword
            field: Regex::new(r#"(\w+)=(?:"([^"]*)"|(\S+))"#).unwrap(),
        }
    }

    fn parse(&self, line: &str) -> Option<(String, String, HashMap<String, String>)> {
        let h = self.header.captures(line)?;
        let rtype = h[1].to_string();
        let serial = h[2].to_string();
        let rest = &line[h.get(0).unwrap().end()..];
        let mut fields = HashMap::new();
        for c in self.field.captures_iter(rest) {
            let k = c[1].to_string();
            let v = c.get(2).or_else(|| c.get(3)).map(|m| m.as_str()).unwrap_or("");
            fields.insert(k, v.to_string());
        }
        Some((rtype, serial, fields))
    }

    fn handle_line(
        &self,
        line: &str,
        groups: &mut HashMap<String, HashMap<String, HashMap<String, String>>>,
    ) -> Vec<Value> {
        let Some((rtype, serial, fields)) = self.parse(line) else { return vec![] };

        if rtype == "EOE" {
            if let Some(group) = groups.remove(&serial) {
                return process(&group).into_iter().collect();
            }
            return vec![];
        }

        groups.entry(serial).or_default().insert(rtype, fields);

        // ponytail: bound memory; audit records without a clean EOE would leak otherwise.
        if groups.len() > MAX_OPEN_GROUPS {
            let mut keys: Vec<String> = groups.keys().cloned().collect();
            keys.sort();
            for k in keys.into_iter().take(100) {
                groups.remove(&k);
            }
        }
        vec![]
    }
}

fn get<'a>(group: &'a HashMap<String, HashMap<String, String>>, rtype: &str, key: &str) -> &'a str {
    group.get(rtype).and_then(|m| m.get(key)).map(String::as_str).unwrap_or("")
}

fn process(group: &HashMap<String, HashMap<String, String>>) -> Option<Value> {
    let key = get(group, "SYSCALL", "key");
    if !key.starts_with("horus_") {
        return None;
    }
    // auditd records success as "yes"/"no"; default present-but-absent to success.
    if group.get("SYSCALL").and_then(|m| m.get("success")).map(String::as_str).unwrap_or("yes") != "yes" {
        return None;
    }

    let exe = get(group, "SYSCALL", "exe");
    let comm = get(group, "SYSCALL", "comm");
    let uid = get(group, "SYSCALL", "uid");

    match key {
        "horus_exec" => {
            let comm_l = comm.to_lowercase();
            let sev = if BLACKLISTED_CMDS.contains(&comm_l.as_str()) {
                "high"
            } else if SUSPICIOUS_PATHS.iter().any(|p| exe.starts_with(p)) {
                "medium"
            } else {
                return None; // routine exec; ignore
            };
            let argc: usize = get(group, "EXECVE", "argc").parse().unwrap_or(0);
            let args: Vec<String> = (0..argc.min(8))
                .map(|i| get(group, "EXECVE", &format!("a{}", i)).to_string())
                .collect();
            let cmdline: String = args.join(" ").chars().take(300).collect();
            Some(json!({
                "event_type": "new_process",
                "severity": sev,
                "title": format!("Suspicious exec: {}", if comm.is_empty() { exe } else { comm }),
                "payload": {"exe": exe, "comm": comm, "cmdline": cmdline, "uid": uid},
            }))
        }
        "horus_fim" => {
            let path = get(group, "PATH", "name");
            if path.is_empty() {
                return None;
            }
            let sev = if path.starts_with("/etc/") || path.starts_with("/root/") { "high" } else { "medium" };
            Some(json!({
                "event_type": "file_change",
                "severity": sev,
                "title": format!("File modified: {}", path),
                "payload": {"path": path, "exe": exe, "uid": uid},
            }))
        }
        "horus_net" => {
            let port = parse_port(get(group, "SYSCALL", "saddr"))?;
            if !SUSPICIOUS_PORTS.contains(&port) {
                return None; // skip routine connections
            }
            Some(json!({
                "event_type": "new_connection",
                "severity": "high",
                "title": format!("Connection to suspicious port {} from {}", port,
                                 if comm.is_empty() { exe } else { comm }),
                "payload": {"exe": exe, "comm": comm, "uid": uid, "dest_port": port},
            }))
        }
        _ => None,
    }
}

/// Extract the port from an audit hex saddr. AF_INET sockaddr = `0200 PPPP AAAAAAAA …`
/// where PPPP is the big-endian port. (0A00 = AF_INET6, port in the same position.)
fn parse_port(saddr: &str) -> Option<u16> {
    if saddr.len() >= 8 && (saddr.starts_with("0200") || saddr.starts_with("0A00")) {
        u16::from_str_radix(&saddr[4..8], 16).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port_from_saddr() {
        // port 4444 = 0x115C
        assert_eq!(parse_port("0200115C7F000001"), Some(0x115C));
        assert_eq!(parse_port(""), None);
    }

    #[test]
    fn flags_exec_from_tmp() {
        let parser = Parser::new();
        let mut groups = HashMap::new();
        parser.handle_line(
            r#"type=SYSCALL msg=audit(1.2:99): exe="/tmp/evil" comm="evil" uid="1000" key="horus_exec" success="yes""#,
            &mut groups,
        );
        let evts = parser.handle_line("type=EOE msg=audit(1.2:99):", &mut groups);
        assert_eq!(evts.len(), 1);
        assert_eq!(evts[0]["event_type"], "new_process");
        assert_eq!(evts[0]["severity"], "medium");
    }

    #[test]
    fn ignores_non_horus_keys() {
        let parser = Parser::new();
        let mut groups = HashMap::new();
        parser.handle_line(
            r#"type=SYSCALL msg=audit(1.2:7): exe="/usr/bin/ls" key="other" success="yes""#,
            &mut groups,
        );
        let evts = parser.handle_line("type=EOE msg=audit(1.2:7):", &mut groups);
        assert!(evts.is_empty());
    }
}
