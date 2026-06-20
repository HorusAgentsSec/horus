use serde_json::{json, Value};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::Config;

const MAX_RETRIES: u32 = 3;
const RETRY_BASE_MS: u64 = 2_000;

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

    pub async fn send_events(&self, events: &[Value]) -> bool {
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
        self.enqueue_local(events);
        false
    }

    pub async fn flush_queue(&self) -> usize {
        let queued = self.read_queue();
        if queued.is_empty() {
            return 0;
        }
        tracing::info!("Flushing {} queued events", queued.len());
        if self.send_events(&queued).await {
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
        self.write_queue(&existing);
        tracing::info!("Enqueued {} events locally ({} total)", events.len(), existing.len());
    }

    fn read_queue(&self) -> Vec<Value> {
        if !self.queue_path.exists() {
            return vec![];
        }
        std::fs::read_to_string(&self.queue_path)
            .ok()
            .and_then(|t| serde_json::from_str::<Vec<Value>>(&t).ok())
            .unwrap_or_default()
    }

    fn write_queue(&self, events: &[Value]) {
        if let Some(parent) = self.queue_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string(events) {
            if let Err(e) = std::fs::write(&self.queue_path, text) {
                tracing::error!("Failed to write queue: {}", e);
            }
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
