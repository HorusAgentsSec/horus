use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::env;
use std::path::PathBuf;

// File/exec/network monitoring is done by the kernel audit subsystem (see auditd monitor),
// configured via /etc/audit/rules.d/horus.rules, not by app-level watch paths. There are
// no watch_paths/ignore_patterns here by design: recursive inotify over /home was the OOM
// cause this architecture removes.

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server_url: String,
    pub api_key: String,
    pub agent_id: String,
    pub interval_seconds: u64,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            api_key: String::new(),
            agent_id: String::new(),
            interval_seconds: 30,
            log_level: "INFO".to_string(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        let missing: Vec<&str> = [
            ("server_url", self.server_url.as_str()),
            ("api_key", self.api_key.as_str()),
            ("agent_id", self.agent_id.as_str()),
        ]
        .iter()
        .filter(|(_, v)| v.is_empty())
        .map(|(k, _)| *k)
        .collect();

        if !missing.is_empty() {
            return Err(anyhow!(
                "Config missing required fields: {}. Edit /etc/horus/iris.yaml.",
                missing.join(", ")
            ));
        }
        Ok(())
    }
}

pub fn load_config(explicit_path: Option<&str>) -> Result<Config> {
    let path = if let Some(p) = explicit_path {
        let p = PathBuf::from(p);
        if !p.exists() {
            return Err(anyhow!("Config file not found: {}", p.display()));
        }
        Some(p)
    } else if let Ok(env_path) = env::var("HORUS_IRIS_CONFIG") {
        let p = PathBuf::from(&env_path);
        if !p.exists() {
            return Err(anyhow!("HORUS_IRIS_CONFIG points to missing file: {}", env_path));
        }
        Some(p)
    } else {
        let candidates = [
            PathBuf::from("/etc/horus/iris.yaml"),
            env::var("HOME")
                .map(|h| PathBuf::from(h).join(".horus").join("iris.yaml"))
                .unwrap_or_default(),
        ];
        candidates.into_iter().find(|p| p.exists())
    };

    let Some(path) = path else {
        tracing::warn!("No config file found — daemon will fail validation unless env vars are set.");
        return Ok(Config::default());
    };

    tracing::info!("Loading config from {}", path.display());
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_yaml::from_str(&text)
        .with_context(|| format!("Failed to parse {}", path.display()))
}
