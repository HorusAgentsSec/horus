use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

mod auditd;
mod journald;

/// Two kernel-fed monitors, zero polling and zero inotify watches:
///   • journald; SSH/sudo/su/user-change + high-priority system messages
///   • auditd  ; exec / file-change / network via the kernel audit subsystem
pub fn spawn_all(config: &Config, tx: mpsc::Sender<Value>) -> Vec<JoinHandle<()>> {
    vec![
        journald::spawn(config.clone(), tx.clone()),
        auditd::spawn(config.clone(), tx),
    ]
}
