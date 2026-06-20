use notify::event::{CreateKind, EventKind, ModifyKind, RemoveKind};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{json, Value};
use std::path::Path;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

const HIGH_SEVERITY: &[&str] = &[
    "/etc/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/boot/", "/lib/", "/usr/lib/",
];
const LOW_SEVERITY:  &[&str] = &["/home/", "/tmp/", "/var/tmp/"];

pub fn spawn(config: Config, tx: mpsc::Sender<Value>) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(e) = run(&config, &tx) {
            tracing::error!("FIM monitor error: {}", e);
        }
    })
}

fn run(config: &Config, tx: &mpsc::Sender<Value>) -> anyhow::Result<()> {
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();
    let mut watcher = RecommendedWatcher::new(notify_tx, NotifyConfig::default())?;

    for path in &config.watch_paths {
        let p = Path::new(path);
        if !p.exists() {
            tracing::warn!("FIM: path does not exist, skipping: {}", path);
            continue;
        }
        match watcher.watch(p, RecursiveMode::Recursive) {
            Ok(_)  => tracing::info!("FIM: watching {}", path),
            Err(e) => tracing::warn!("FIM: cannot watch {}: {}", path, e),
        }
    }
    tracing::info!("FIM monitor started");

    for result in notify_rx {
        match result {
            Ok(event) => {
                for evt in convert(&event, &config.ignore_patterns) {
                    if tx.blocking_send(evt).is_err() {
                        return Ok(()); // channel closed → shutdown
                    }
                }
            }
            Err(e) => tracing::warn!("FIM watcher error: {}", e),
        }
    }
    Ok(())
}

fn convert(event: &Event, ignore_patterns: &[String]) -> Vec<Value> {
    let (action, is_move) = match event.kind {
        EventKind::Create(_) => ("created", false),
        EventKind::Modify(ModifyKind::Name(_)) => ("moved", true),
        EventKind::Modify(_) => ("modified", false),
        EventKind::Remove(_) => ("deleted", false),
        _ => return vec![],
    };

    let paths = &event.paths;
    if paths.is_empty() {
        return vec![];
    }

    let src = paths[0].to_string_lossy();
    if is_ignored(&src, ignore_patterns) {
        return vec![];
    }

    let is_dir = matches!(event.kind, EventKind::Create(CreateKind::Folder) | EventKind::Remove(RemoveKind::Folder));
    let severity = severity(&src);

    let mut payload = json!({ "path": src.as_ref(), "action": action, "is_dir": is_dir });

    if is_move {
        if let Some(dest) = paths.get(1) {
            let dest_str = dest.to_string_lossy();
            payload["dest_path"] = json!(dest_str.as_ref());
        }
    }

    if let Ok(meta) = std::fs::metadata(paths[0].as_path()) {
        payload["size"] = json!(meta.len());
        if let Ok(mtime) = meta.modified().and_then(|t| Ok(t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs_f64())) {
            payload["mtime"] = json!(mtime);
        }
    }

    vec![json!({
        "event_type": "file_change",
        "severity": severity,
        "title": format!("File {}: {}", action, src),
        "payload": payload,
    })]
}

fn severity(path: &str) -> &'static str {
    if HIGH_SEVERITY.iter().any(|p| path.starts_with(p)) { return "high"; }
    if LOW_SEVERITY.iter().any(|p| path.starts_with(p))  { return "low";  }
    "medium"
}

fn is_ignored(path: &str, patterns: &[String]) -> bool {
    let filename = Path::new(path).file_name().and_then(|n| n.to_str()).unwrap_or("");
    patterns.iter().any(|pat| glob_match(pat, filename) || glob_match(pat, path))
}

// Handles patterns like *.log, *.tmp, .git/*
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() { continue; }
        if i == 0 {
            if !text.starts_with(part) { return false; }
            pos = part.len();
        } else if i == parts.len() - 1 {
            return text[pos..].ends_with(part);
        } else if let Some(idx) = text[pos..].find(part) {
            pos += idx + part.len();
        } else {
            return false;
        }
    }
    true
}
