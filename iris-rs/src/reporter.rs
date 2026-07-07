use serde_json::{json, Value};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::Config;

const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 2_000;
/// Hard cap on the offline backlog. Beyond this we drop the OLDEST events: a security agent that
/// can't reach the server must not OOM the host it's protecting. ~5k events is plenty of buffer.
const MAX_QUEUE: usize = 5_000;
/// Belt-and-suspenders: never load a queue file larger than this into memory. Guards against a
/// pathologically large file left by an older buggy build — discard it instead of OOMing on boot.
const MAX_QUEUE_BYTES: u64 = 16 * 1024 * 1024;

pub struct IrisReporter {
    client: reqwest::Client,
    config: Config,
    hostname: String,
    ip: String,
    queue_path: PathBuf,
}

impl IrisReporter {
    pub fn new(config: &Config) -> Self {
        use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(&config.api_key) {
            headers.insert("X-Iris-Key", v);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .user_agent("horus-iris/0.2")
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build HTTP client");

        Self {
            client,
            config: config.clone(),
            hostname: read_hostname(),
            ip: local_ip(),
            queue_path: queue_path(),
        }
    }

    /// POST events to the server, with retries. Pure transport: does NOT touch the local queue,
    /// so callers control queueing. (Folding enqueue into here is what let flush_queue re-enqueue
    /// the backlog onto itself and balloon the queue file.)
    async fn try_post(&self, events: &[Value]) -> bool {
        if events.is_empty() {
            return true;
        }
        let payload = json!({
            "agent_id": self.config.agent_id,
            "hostname": self.hostname,
            "ip": self.ip,
            "events": events,
        });
        let url = format!("{}/api/iris/events", self.config.server_url.trim_end_matches('/'));

        for attempt in 0..MAX_RETRIES {
            match self.client.post(&url).json(&payload).send().await {
                Ok(r) if matches!(r.status().as_u16(), 200 | 201 | 202 | 204) => {
                    tracing::debug!("Sent {} events", events.len());
                    return true;
                }
                Ok(r) => tracing::warn!("Server HTTP {} (attempt {}/{})", r.status(), attempt + 1, MAX_RETRIES),
                Err(e) => tracing::warn!("Request failed: {} (attempt {}/{})", e, attempt + 1, MAX_RETRIES),
            }
            if attempt < MAX_RETRIES - 1 {
                tokio::time::sleep(Duration::from_millis(RETRY_BASE_MS << attempt)).await;
            }
        }
        false
    }

    pub async fn send_events(&self, events: &[Value]) -> bool {
        if events.is_empty() {
            return true;
        }
        if self.try_post(events).await {
            return true;
        }
        self.enqueue_local(events);
        false
    }

    pub async fn flush_queue(&self) -> usize {
        let queued = self.read_queue();
        if queued.is_empty() {
            return 0;
        }
        tracing::info!("Flushing {} queued events", queued.len());
        // Send the backlog directly. On failure leave the file as-is — re-enqueuing it (via
        // send_events) would append the backlog to itself and double the queue every tick.
        if self.try_post(&queued).await {
            self.write_queue(&[]);
            queued.len()
        } else {
            0
        }
    }

    pub async fn test_connection(&self) -> bool {
        let url = format!("{}/api/iris/ping", self.config.server_url.trim_end_matches('/'));
        match self.client.get(&url).send().await {
            Ok(r) if r.status() == 200 => true,
            Ok(r) => { tracing::error!("Server HTTP {} at {}", r.status(), url); false }
            Err(e) => { tracing::error!("Connection failed: {}", e); false }
        }
    }

    fn enqueue_local(&self, events: &[Value]) {
        let mut existing = self.read_queue();
        existing.extend_from_slice(events);
        // Bound the backlog: keep only the newest MAX_QUEUE events, dropping the oldest. An agent
        // that can't reach the server for days must never grow the queue without limit.
        if existing.len() > MAX_QUEUE {
            let overflow = existing.len() - MAX_QUEUE;
            existing.drain(0..overflow);
            tracing::warn!("Queue exceeded {} events; dropped {} oldest", MAX_QUEUE, overflow);
        }
        self.write_queue(&existing);
        tracing::info!("Enqueued {} events locally ({} total)", events.len(), existing.len());
    }

    fn read_queue(&self) -> Vec<Value> {
        if !self.queue_path.exists() {
            return vec![];
        }
        // Guard against a pathologically large queue file (e.g. left by an older build that grew
        // it unbounded): discarding stale telemetry is far better than OOMing the host on boot.
        if let Ok(meta) = std::fs::metadata(&self.queue_path) {
            if meta.len() > MAX_QUEUE_BYTES {
                tracing::error!(
                    "Queue file is {} bytes (> {} cap); discarding to avoid OOM",
                    meta.len(), MAX_QUEUE_BYTES
                );
                self.write_queue(&[]);
                return vec![];
            }
        }
        let text = match std::fs::read_to_string(&self.queue_path) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to read queue file: {}", e);
                return vec![];
            }
        };
        match serde_json::from_str::<Vec<Value>>(&text) {
            Ok(v) => v,
            Err(e) => {
                // A truncated/corrupt queue file used to be discarded silently; log it so the
                // loss of queued telemetry leaves a trace instead of vanishing.
                tracing::error!(
                    "Queue file is corrupt ({}); discarding {} bytes of queued telemetry",
                    e, text.len()
                );
                vec![]
            }
        }
    }

    fn write_queue(&self, events: &[Value]) {
        if let Some(parent) = self.queue_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let text = match serde_json::to_string(events) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to serialize queue: {}", e);
                return;
            }
        };
        // Write to a temp file then rename: rename is atomic on the same filesystem, so a crash
        // mid-write can never leave a half-written queue.json that fails to parse on next boot.
        let tmp = self.queue_path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &text) {
            tracing::error!("Failed to write queue temp file: {}", e);
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &self.queue_path) {
            tracing::error!("Failed to rename queue temp file: {}", e);
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

fn queue_path() -> PathBuf {
    let primary = PathBuf::from("/var/lib/horus/iris/queue.json");
    if std::fs::create_dir_all("/var/lib/horus/iris").is_ok() {
        return primary;
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".horus").join("iris_queue.json")
}

fn read_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| { s.connect("8.8.8.8:80")?; s.local_addr().map(|a| a.ip().to_string()) })
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}
