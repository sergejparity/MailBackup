use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let mut port: Option<u16> = None;
    let mut config_path: Option<PathBuf> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" | "-p" => {
                if let Some(val) = args.next() {
                    match val.parse::<u16>() {
                        Ok(p) => port = Some(p),
                        Err(_) => eprintln!("Invalid port number: {}", val),
                    }
                }
            }
            "--config" | "-c" => {
                if let Some(val) = args.next() {
                    config_path = Some(PathBuf::from(val));
                }
            }
            "--help" | "-h" => {
                println!("MailBackup Studio Headless Server");
                println!();
                println!("Usage: mailbackup-server [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -p, --port <PORT>        Override HTTP/REST API web port (default: 8765)");
                println!("  -c, --config <PATH>      Path to config.yaml configuration file");
                println!("  -h, --help               Display this help message");
                return Ok(());
            }
            other => {
                eprintln!("Unknown argument: {}", other);
            }
        }
    }

    mailbackup_server::start_server_with_options(port, config_path).await
}
