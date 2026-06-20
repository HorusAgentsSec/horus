use procfs::net::TcpState;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const SUSPICIOUS_PORTS: &[u16] = &[4444, 5555, 1337, 31337, 6666, 9001];

type ListenerKey = (String, u16);

pub fn spawn(config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut known = snapshot_listeners();
        let interval = Duration::from_secs(config.interval_seconds);
        tracing::info!("Network monitor started ({} initial listeners)", known.len());
        loop {
            tokio::time::sleep(interval).await;
            poll(&mut known, &tx).await;
        }
    })
}

async fn poll(known: &mut HashSet<ListenerKey>, tx: &mpsc::Sender<Value>) {
    let connections = all_tcp();
    let mut current_listeners = HashSet::new();

    for conn in &connections {
        let local: SocketAddr = conn.local_address;
        let remote: SocketAddr = conn.remote_address;

        if conn.state == TcpState::Listen {
            let key = (local.ip().to_string(), local.port());
            current_listeners.insert(key.clone());
            if !known.contains(&key) {
                let name = process_name_for_inode(conn.inode);
                let evt = json!({
                    "event_type": "new_listener",
                    "severity":   "medium",
                    "title":      format!("New listener on port {} ({})", local.port(), name),
                    "payload": {
                        "laddr": { "ip": local.ip().to_string(), "port": local.port() },
                        "pid":   conn.uid,
                        "process_name": name,
                    }
                });
                if tx.send(evt).await.is_err() { return; }
            }
        } else if conn.state == TcpState::Established && SUSPICIOUS_PORTS.contains(&remote.port()) {
            let name = process_name_for_inode(conn.inode);
            let evt = json!({
                "event_type": "new_connection",
                "severity":   "high",
                "title":      format!("Outbound to {}:{} from {}", remote.ip(), remote.port(), name),
                "payload": {
                    "laddr":  { "ip": local.ip().to_string(),  "port": local.port() },
                    "raddr":  { "ip": remote.ip().to_string(), "port": remote.port() },
                    "process_name": name,
                }
            });
            if tx.send(evt).await.is_err() { return; }
        }
    }
    *known = current_listeners;
}

fn snapshot_listeners() -> HashSet<ListenerKey> {
    all_tcp()
        .into_iter()
        .filter(|c| c.state == TcpState::Listen)
        .map(|c| (c.local_address.ip().to_string(), c.local_address.port()))
        .collect()
}

fn all_tcp() -> Vec<procfs::net::TcpNetEntry> {
    let mut v = procfs::net::tcp().unwrap_or_default();
    v.extend(procfs::net::tcp6().unwrap_or_default());
    v
}

// Scan /proc/PID/fd for socket inode → process name
fn process_name_for_inode(inode: u64) -> String {
    (|| -> Option<String> {
        for proc in procfs::process::all_processes().ok()?.flatten() {
            if let Ok(fds) = proc.fd() {
                for fd in fds.flatten() {
                    if let procfs::process::FDTarget::Socket(i) = fd.target {
                        if i == inode {
                            return Some(
                                proc.stat().ok()
                                    .map(|s| s.comm)
                                    .unwrap_or_else(|| proc.pid.to_string()),
                            );
                        }
                    }
                }
            }
        }
        None
    })()
    .unwrap_or_else(|| "<unknown>".to_string())
}
