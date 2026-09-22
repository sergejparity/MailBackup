use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use console::{style, Emoji};
use dialoguer::{Input, Password, Select};
use indicatif::{ProgressBar, ProgressStyle};
use mailbackup_core::config::{AccountConfig, AppConfig, AuthType, FolderFilter, ProviderType};
use mailbackup_core::db::Database;
use mailbackup_core::imap::ImapSyncEngine;
use mailbackup_core::keyring::CredentialStore;
use mailbackup_core::mbox::MboxExporter;
use mailbackup_core::retention::RetentionManager;
use mailbackup_core::scheduler::BackupScheduler;
use mailbackup_core::storage::StorageEngine;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

static MAIL_EMOJI: Emoji<'_, '_> = Emoji("📬 ", "");
static CHECK_EMOJI: Emoji<'_, '_> = Emoji("✅ ", "");
static WARN_EMOJI: Emoji<'_, '_> = Emoji("⚠️  ", "");
static SYNC_EMOJI: Emoji<'_, '_> = Emoji("🔄 ", "");

#[derive(Parser)]
#[command(name = "mailbackup", author, version, about = "Resilient & Incremental Email Backup Utility in Rust", long_about = None)]
struct Cli {
    #[arg(short, long, global = true, help = "Path to custom configuration file")]
    config: Option<PathBuf>,

    #[arg(short, long, global = true, action = clap::ArgAction::Count, help = "Verbosity level (-v, -vv)")]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand, about = "Manage email accounts and credentials")]
    Account(AccountCommands),

    #[command(about = "Run incremental email backup")]
    Sync(SyncArgs),

    #[command(about = "Search backed-up emails using full-text search")]
    Search(SearchArgs),

    #[command(about = "Export raw .eml emails to an RFC 4155 .mbox archive")]
    ExportMbox(ExportMboxArgs),

    #[command(about = "Run the unattended background scheduler daemon")]
    Daemon,

    #[command(about = "Start the embedded Web UI and REST API server")]
    Serve(ServeArgs),
}

#[derive(Subcommand)]
enum AccountCommands {
    #[command(about = "Add a new email account (interactive or with flags)")]
    Add(AddAccountArgs),

    #[command(about = "List configured accounts")]
    List,

    #[command(about = "Test IMAP connection and credentials for an account")]
    Test {
        #[arg(help = "Account ID or email address")]
        account: String,
    },

    #[command(about = "Remove an account configuration and stored credentials")]
    Remove {
        #[arg(help = "Account ID or email address")]
        account: String,
    },
}

#[derive(Args)]
struct AddAccountArgs {
    #[arg(long)]
    id: Option<String>,
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    email: Option<String>,
    #[arg(long, value_parser = ["generic", "gmail", "outlook", "icloud", "yahoo"])]
    provider: Option<String>,
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long)]
    password: Option<String>,
    #[arg(long)]
    schedule: Option<String>,
    #[arg(long)]
    retention_days: Option<u32>,
}

#[derive(Args)]
struct SyncArgs {
    #[arg(short, long, help = "Specific account ID to sync (defaults to all enabled accounts)")]
    account: Option<String>,
    #[arg(short, long, help = "Specific folder to sync")]
    folder: Option<String>,
}

#[derive(Args)]
struct SearchArgs {
    #[arg(help = "Search query (subject, sender, body, attachment name)")]
    query: String,
    #[arg(short, long, default_value = "20", help = "Maximum search results to display")]
    limit: u32,
}

#[derive(Args)]
struct ExportMboxArgs {
    #[arg(short, long, help = "Account ID to export")]
    account: String,
    #[arg(short, long, help = "Optional folder name to export (default: all folders)")]
    folder: Option<String>,
    #[arg(short, long, help = "Output .mbox file path")]
    output: PathBuf,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(short, long, default_value = "8765", help = "Port to listen on")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let filter = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)))
        .with_target(false)
        .try_init();

    let mut config = AppConfig::load_or_create(cli.config.as_deref())?;
    let db = Database::open(&config.db_path)?;
    let storage = StorageEngine::new(&config.data_dir);
    let credentials = Arc::new(CredentialStore::new());

    match cli.command {
        Commands::Account(AccountCommands::Add(args)) => {
            handle_account_add(&mut config, cli.config.as_deref(), &credentials, args)?;
        }
        Commands::Account(AccountCommands::List) => {
            handle_account_list(&config, &db)?;
        }
        Commands::Account(AccountCommands::Test { account }) => {
            handle_account_test(&config, &credentials, &account).await?;
        }
        Commands::Account(AccountCommands::Remove { account }) => {
            handle_account_remove(&mut config, cli.config.as_deref(), &credentials, &account)?;
        }
        Commands::Sync(args) => {
            handle_sync(&config, &db, &storage, &credentials, args).await?;
        }
        Commands::Search(args) => {
            handle_search(&db, args)?;
        }
        Commands::ExportMbox(args) => {
            handle_export_mbox(&config, &db, &storage, args)?;
        }
        Commands::Daemon => {
            handle_daemon(config, db, storage, credentials).await?;
        }
        Commands::Serve(args) => {
            println!("{} Starting MailBackup Studio on http://127.0.0.1:{}", MAIL_EMOJI, args.port);
            let current_exe = std::env::current_exe()?;
            let server_exe = current_exe.parent().unwrap().join("mailbackup-server");
            if server_exe.exists() {
                let mut child = std::process::Command::new(server_exe).spawn()?;
                child.wait()?;
            } else {
                println!("To launch the standalone web server: cargo run -p mailbackup-server");
            }
        }
    }

    Ok(())
}

fn handle_account_add(
    config: &mut AppConfig,
    config_path: Option<&std::path::Path>,
    credentials: &CredentialStore,
    args: AddAccountArgs,
) -> Result<()> {
    println!("\n{} {}", MAIL_EMOJI, style("Add Email Account").bold());

    let provider_choice = if let Some(p) = args.provider {
        match p.to_lowercase().as_str() {
            "gmail" => ProviderType::Gmail,
            "outlook" => ProviderType::Outlook,
            "icloud" => ProviderType::ICloud,
            "yahoo" => ProviderType::Yahoo,
            _ => ProviderType::GenericImap,
        }
    } else {
        let providers = &["Gmail (Google Workspace)", "Outlook / Office 365", "iCloud", "Yahoo", "Generic IMAP"];
        let selection = Select::new()
            .with_prompt("Select your email provider")
            .items(providers)
            .default(0)
            .interact()?;
        match selection {
            0 => ProviderType::Gmail,
            1 => ProviderType::Outlook,
            2 => ProviderType::ICloud,
            3 => ProviderType::Yahoo,
            _ => ProviderType::GenericImap,
        }
    };

    let (def_server, def_port, def_tls) = provider_choice.default_server();

    let email = match args.email {
        Some(e) => e,
        None => Input::new().with_prompt("Email address").interact_text()?,
    };

    let name = match args.name {
        Some(n) => n,
        None => Input::new().with_prompt("Account display name").default(email.clone()).interact_text()?,
    };

    let id = match args.id {
        Some(i) => i,
        None => StorageEngine::sanitize_slug(&email),
    };

    let imap_server = match args.server {
        Some(s) => s,
        None => Input::new().with_prompt("IMAP Server").default(def_server.to_string()).interact_text()?,
    };

    let imap_port = match args.port {
        Some(p) => p,
        None => Input::new().with_prompt("IMAP Port").default(def_port).interact_text()?,
    };

    let username = match args.username {
        Some(u) => u,
        None => Input::new().with_prompt("IMAP Username").default(email.clone()).interact_text()?,
    };

    let password = match args.password {
        Some(p) => p,
        None => Password::new().with_prompt("Password / App Password").interact()?,
    };

    let retention_days = match args.retention_days {
        Some(d) => Some(d),
        None => {
            let days_str: String = Input::new()
                .with_prompt("Retention in days (0 or enter for keep forever)")
                .default("0".to_string())
                .interact_text()?;
            let parsed: u32 = days_str.parse().unwrap_or(0);
            if parsed > 0 { Some(parsed) } else { None }
        }
    };

    let schedule = args.schedule.or_else(|| Some("0 0 * * *".to_string()));

    // Store password securely
    credentials.set_password(&id, &password)?;

    let account = AccountConfig {
        id: id.clone(),
        name,
        email,
        provider: provider_choice,
        imap_server,
        imap_port,
        use_tls: def_tls,
        auth_type: AuthType::Password,
        username,
        schedule,
        retention_days,
        folder_filter: FolderFilter::default(),
        gmail_smart_labels: true,
        enabled: true,
    };

    config.accounts.retain(|a| a.id != id);
    config.accounts.push(account);

    let save_path = config_path.unwrap_or_else(|| mailbackup_core::config::default_config_path().leak());
    config.save(save_path)?;

    println!("\n{} Account '{}' configured successfully and credentials saved securely!", CHECK_EMOJI, id);
    Ok(())
}

fn handle_account_list(config: &AppConfig, db: &Database) -> Result<()> {
    println!("\n{} {}", MAIL_EMOJI, style("Configured Email Accounts").bold());

    if config.accounts.is_empty() {
        println!("No accounts configured. Use {} to add one.", style("mailbackup account add").cyan());
        return Ok(());
    }

    let stats = db.get_storage_stats()?;
    println!(
        "Total: {} accounts, {} folders, {} messages ({:.2} MB)\n",
        stats.total_accounts,
        stats.total_folders,
        stats.total_messages,
        (stats.total_bytes as f64) / (1024.0 * 1024.0)
    );

    for acc in &config.accounts {
        let status = if acc.enabled { style("ACTIVE").green() } else { style("DISABLED").dim() };
        println!("• {} [{}]", style(&acc.id).bold().cyan(), status);
        println!("  Name:      {}", acc.name);
        println!("  Email:     {}", acc.email);
        println!("  Server:    {}:{}", acc.imap_server, acc.imap_port);
        println!("  Schedule:  {}", acc.schedule.as_deref().unwrap_or("Default"));
        println!(
            "  Retention: {}",
            acc.retention_days.map(|d| format!("{} days", d)).unwrap_or_else(|| "Keep forever".to_string())
        );

        if let Ok(folders) = db.get_folders(&acc.id) {
            let total_msgs: u32 = folders.iter().map(|f| f.message_count).sum();
            println!("  Backup:    {} folders synced, {} messages stored locally", folders.len(), total_msgs);
        }
        println!();
    }
    Ok(())
}

async fn handle_account_test(
    config: &AppConfig,
    credentials: &CredentialStore,
    account_id: &str,
) -> Result<()> {
    let acc = config
        .get_account(account_id)
        .context(format!("Account '{}' not found", account_id))?;

    let password = credentials.get_password(&acc.id)?;
    println!("Connecting to {} ({}:{})...", acc.email, acc.imap_server, acc.imap_port);

    let mut session = ImapSyncEngine::connect(acc, &password).await?;
    {
        use futures_util::StreamExt;
        let mut mailboxes = session.list(None, Some("*")).await.map_err(|e| {
            mailbackup_core::Error::Imap(e.to_string())
        })?;

        println!("\n{} Connection and authentication successful! Available folders:", CHECK_EMOJI);
        while let Some(mb_res) = mailboxes.next().await {
            if let Ok(mb) = mb_res {
                println!("  📁 {}", mb.name());
            }
        }
    }
    let _ = session.logout().await;
    Ok(())
}

fn handle_account_remove(
    config: &mut AppConfig,
    config_path: Option<&std::path::Path>,
    credentials: &CredentialStore,
    account_id: &str,
) -> Result<()> {
    if config.get_account(account_id).is_none() {
        bail!("Account '{}' not found", account_id);
    }

    config.accounts.retain(|a| a.id != account_id && a.email != account_id);
    let _ = credentials.delete_password(account_id);

    let save_path = config_path.unwrap_or_else(|| mailbackup_core::config::default_config_path().leak());
    config.save(save_path)?;

    println!("{} Removed account '{}' from configuration and credentials store.", CHECK_EMOJI, account_id);
    Ok(())
}

async fn handle_sync(
    config: &AppConfig,
    db: &Database,
    storage: &StorageEngine,
    credentials: &CredentialStore,
    args: SyncArgs,
) -> Result<()> {
    let accounts_to_sync: Vec<&AccountConfig> = if let Some(ref target) = args.account {
        let acc = config.get_account(target).context(format!("Account '{}' not found", target))?;
        vec![acc]
    } else {
        config.accounts.iter().filter(|a| a.enabled).collect()
    };

    if accounts_to_sync.is_empty() {
        println!("{} No enabled accounts to sync.", WARN_EMOJI);
        return Ok(());
    }

    println!("\n{} {}", SYNC_EMOJI, style("Starting Email Backup").bold());

    for acc in accounts_to_sync {
        println!("\nSyncing account: {} ({})", style(&acc.id).bold().cyan(), acc.email);
        let password = match credentials.get_password(&acc.id) {
            Ok(p) => p,
            Err(e) => {
                println!("{} Skipping {}: Cannot retrieve password ({})", WARN_EMOJI, acc.id, e);
                continue;
            }
        };

        // Record account in DB
        db.upsert_account(&acc.id, &acc.name, &acc.email, &format!("{:?}", acc.provider))?;

        mailbackup_core::event_log::log_event(
            "SYNC_STARTED",
            &format!("CLI sync started for account '{}' ({})", acc.name, acc.email),
        );

        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );

        let sync_engine = ImapSyncEngine::new(db.clone(), storage.clone());
        let pb_clone = pb.clone();
        let progress_cb = move |p: &mailbackup_core::imap::SyncProgress| {
            pb_clone.set_message(format!(
                "Folder: {} | Synced {}/{} msgs ({:.1} MB)",
                p.current_folder,
                p.processed_messages,
                p.total_messages,
                (p.downloaded_bytes as f64) / (1024.0 * 1024.0)
            ));
        };

        match sync_engine.sync_account(acc, &password, Some(progress_cb)).await {
            Ok(progress) => {
                let mb = (progress.downloaded_bytes as f64) / (1024.0 * 1024.0);
                mailbackup_core::event_log::log_event(
                    "SYNC_SUCCESS",
                    &format!(
                        "Account '{}' CLI sync completed: {} message(s), {:.2} MB downloaded",
                        acc.name, progress.processed_messages, mb
                    ),
                );
                pb.finish_with_message(format!(
                    "{} Done! Synced {} new messages ({:.2} MB)",
                    CHECK_EMOJI,
                    progress.processed_messages,
                    mb
                ));
            }
            Err(e) => {
                let err_msg = e.to_string();
                mailbackup_core::event_log::log_event(
                    "SYNC_ERROR",
                    &format!("Account '{}' CLI sync error: {}", acc.name, err_msg),
                );
                pb.abandon_with_message(format!("{} Sync failed: {}", style("ERROR").red(), err_msg));
            }
        }

        // Apply retention policy
        let retention = RetentionManager::new(db, storage);
        if let Ok(report) = retention.enforce_retention(&acc.id, acc.retention_days) {
            if report.pruned_count > 0 {
                let mb = (report.reclaimed_bytes as f64) / (1024.0 * 1024.0);
                mailbackup_core::event_log::log_event(
                    "RETENTION_CLEANUP",
                    &format!(
                        "Retention cleanup for account '{}': pruned {} message(s), {:.2} MB reclaimed",
                        acc.name, report.pruned_count, mb
                    ),
                );
                println!(
                    "{} Retention policy: pruned {} expired messages ({:.2} MB reclaimed)",
                    CHECK_EMOJI,
                    report.pruned_count,
                    mb
                );
            }
        }
    }

    println!("\n{} Backup run finished!", CHECK_EMOJI);
    Ok(())
}

fn handle_search(db: &Database, args: SearchArgs) -> Result<()> {
    println!("\n{} Search: \"{}\"", MAIL_EMOJI, style(&args.query).bold());

    let results = db.search_fts(&args.query, args.limit)?;
    if results.is_empty() {
        println!("No matching emails found.");
        return Ok(());
    }

    println!("Found {} matching email(s):\n", results.len());
    for (idx, item) in results.iter().enumerate() {
        let date_str = item.date.map(|d| d.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Unknown date".to_string());
        println!("{}. [{}] {}", idx + 1, style(&date_str).dim(), style(&item.subject).bold());
        println!("   From:   {}", item.from_addr);
        println!("   Folder: {} (Account: {})", item.folder_name, item.account_id);
        println!("   Match:  {}", item.snippet.replace("<b>", "\x1b[1;33m").replace("</b>", "\x1b[0m"));
        println!("   File:   {}", item.relative_path);
        println!();
    }

    Ok(())
}

fn handle_export_mbox(
    config: &AppConfig,
    db: &Database,
    storage: &StorageEngine,
    args: ExportMboxArgs,
) -> Result<()> {
    let acc = config.get_account(&args.account).context(format!("Account '{}' not found", args.account))?;
    let folders = db.get_folders(&acc.id)?;

    let target_folders: Vec<_> = if let Some(ref f_name) = args.folder {
        folders.into_iter().filter(|f| f.remote_name == *f_name || f.local_slug == *f_name).collect()
    } else {
        folders
    };

    if target_folders.is_empty() {
        bail!("No matching folders found to export for account '{}'", acc.id);
    }

    let mut all_paths = Vec::new();
    for f in &target_folders {
        let msgs = db.get_messages_for_folder(&f.id)?;
        for m in msgs {
            all_paths.push(m.relative_path);
        }
    }

    println!("Found {} messages across {} folder(s) to export.", all_paths.len(), target_folders.len());
    let exporter = MboxExporter::new(storage);
    let count = exporter.export_to_mbox(&all_paths, &args.output)?;

    println!("{} Successfully exported {} emails to {}", CHECK_EMOJI, count, args.output.display());
    Ok(())
}

async fn handle_daemon(
    config: AppConfig,
    db: Database,
    storage: StorageEngine,
    credentials: Arc<CredentialStore>,
) -> Result<()> {
    println!("\n{} {}", SYNC_EMOJI, style("MailBackup Daemon Started").bold().green());
    println!("Running background scheduled backups. Press Ctrl+C to terminate.");

    let config_arc = Arc::new(config);
    let mut scheduler = BackupScheduler::new(config_arc, db, storage, credentials).await?;
    scheduler.start().await?;

    tokio::signal::ctrl_c().await?;
    println!("\nReceived shutdown signal. Exiting gracefully...");
    Ok(())
}
