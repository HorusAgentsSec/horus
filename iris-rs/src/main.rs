use anyhow::Result;
use clap::Parser;

mod config;
mod daemon;
mod monitors;
mod reporter;

#[derive(Parser)]
#[command(name = "horus-iris", about = "Horus Iris security agent daemon")]
struct Cli {
    #[arg(long, value_name = "PATH", help = "Path to iris.yaml config file")]
    config: Option<String>,

    #[arg(long, help = "Show installation instructions")]
    install: bool,

    #[arg(long, help = "Test connectivity and credentials against the Horus server")]
    test_connection: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.install {
        print_install_instructions();
        return Ok(());
    }

    let cfg = config::load_config(cli.config.as_deref())?;
    setup_logging(&cfg.log_level);

    if cli.test_connection {
        let reporter = reporter::IrisReporter::new(&cfg);
        print!("Testing connection to {} … ", cfg.server_url);
        if reporter.test_connection().await {
            println!("[OK]  Server reachable and credentials accepted.");
        } else {
            eprintln!("[FAIL] Could not connect or credentials rejected. Check server_url and api_key.");
            std::process::exit(1);
        }
        return Ok(());
    }

    cfg.validate()?;
    daemon::run(cfg).await
}

fn setup_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_lowercase()));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .init();
}

fn print_install_instructions() {
    println!(r"
╔══════════════════════════════════════════════════════════════╗
║              Horus Iris — Installation Guide                 ║
╚══════════════════════════════════════════════════════════════╝

1. Build and install (requires root):

       sudo bash install.sh

2. Edit the config file:

       sudo nano /etc/horus/iris.yaml

   Set at minimum:
       server_url:  https://your-horus-server
       api_key:     irs_<your-api-key>
       agent_id:    <uuid-from-horus-ui>

3. Enable and start the service:

       sudo systemctl enable --now horus-iris

4. Check status:

       sudo systemctl status horus-iris
       sudo journalctl -u horus-iris -f

For more information: https://docs.horus.security/iris
");
}
