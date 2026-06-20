use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::Config;

mod auth_log;
mod fim;
mod network;
mod process;

pub fn spawn_all(config: &Config, tx: mpsc::Sender<Value>) -> Vec<JoinHandle<()>> {
    vec![
        fim::spawn(config.clone(), tx.clone()),
        process::spawn(config.clone(), tx.clone()),
        network::spawn(config.clone(), tx.clone()),
        auth_log::spawn(config.clone(), tx),
    ]
}
