use serde_json::Value;
use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

use crate::config::Config;
use crate::monitors;
use crate::reporter::IrisReporter;

const CHANNEL_CAPACITY: usize = 10_000;

pub async fn run(config: Config) -> anyhow::Result<()> {
    tracing::info!(
        agent_id = %config.agent_id,
        server   = %config.server_url,
        interval = config.interval_seconds,
        "Horus Iris starting"
    );

    let (tx, mut rx) = mpsc::channel::<Value>(CHANNEL_CAPACITY);
    let reporter = IrisReporter::new(&config);

    let flushed = reporter.flush_queue().await;
    if flushed > 0 {
        tracing::info!("Flushed {} events from previous run", flushed);
    }

    let handles = monitors::spawn_all(&config, tx.clone());

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint  = signal(SignalKind::interrupt())?;

    let interval = Duration::from_secs(config.interval_seconds);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let events = drain(&mut rx);
                if !events.is_empty() {
                    tracing::debug!("Sending {} events", events.len());
                    reporter.send_events(&events).await;
                }
                let _ = reporter.flush_queue().await;
            }
            _ = sigterm.recv() => { tracing::info!("SIGTERM — shutting down"); break; }
            _ = sigint.recv()  => { tracing::info!("SIGINT — shutting down");  break; }
        }
    }

    for h in handles {
        h.abort();
    }
    drop(tx);
    let final_events = drain(&mut rx);
    if !final_events.is_empty() {
        tracing::info!("Sending {} final events", final_events.len());
        reporter.send_events(&final_events).await;
    }

    tracing::info!("Horus Iris stopped");
    Ok(())
}

fn drain(rx: &mut mpsc::Receiver<Value>) -> Vec<Value> {
    let mut v = Vec::new();
    while let Ok(e) = rx.try_recv() {
        v.push(e);
    }
    v
}
