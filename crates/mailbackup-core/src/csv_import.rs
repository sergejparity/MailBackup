use serde::{Deserialize, Serialize};
use crate::config::{AccountConfig, AuthType, FolderFilter, ProviderType};
use crate::storage::StorageEngine;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidImportAccount {
    pub id: String,
    pub name: String,
    pub email: String,
    pub provider: ProviderType,
    pub imap_server: String,
    pub imap_port: u16,
    pub use_tls: bool,
    pub auth_type: AuthType,
    pub username: String,
    pub password: String,
    pub schedule: Option<String>,
    pub retention_days: Option<u32>,
}

impl ValidImportAccount {
    pub fn to_account_config(&self) -> AccountConfig {
        AccountConfig {
            id: self.id.clone(),
            name: self.name.clone(),
            email: self.email.clone(),
            provider: self.provider.clone(),
            imap_server: self.imap_server.clone(),
            imap_port: self.imap_port,
            use_tls: self.use_tls,
            auth_type: self.auth_type.clone(),
            username: self.username.clone(),
            schedule: self.schedule.clone(),
            retention_days: self.retention_days,
            folder_filter: FolderFilter::default(),
            gmail_smart_labels: true,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvRowError {
    pub line: usize,
    pub raw_content: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CsvImportReport {
    pub valid_accounts: Vec<ValidImportAccount>,
    pub errors: Vec<CsvRowError>,
    pub total_rows: usize,
}

/// Auto-detect delimiter based on the first non-empty line
pub fn detect_delimiter(content: &str) -> u8 {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let commas = trimmed.chars().filter(|&c| c == ',').count();
        let semicolons = trimmed.chars().filter(|&c| c == ';').count();
        let tabs = trimmed.chars().filter(|&c| c == '\t').count();

        if semicolons > commas && semicolons > tabs {
            return b';';
        }
        if tabs > commas && tabs > semicolons {
            return b'\t';
        }
        return b',';
    }
    b','
}

/// Detects provider and default IMAP server / port from domain if omitted
pub fn detect_provider_and_server(
    email: &str,
    custom_server: Option<&str>,
    custom_port: Option<u16>,
) -> (ProviderType, String, u16) {
    let domain = email
        .split('@')
        .nth(1)
        .unwrap_or("")
        .to_lowercase();

    let server_specified = custom_server
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    if let Some(srv) = server_specified {
        let port = custom_port.unwrap_or(993);
        let srv_lower = srv.to_lowercase();
        let provider = if srv_lower.contains("gmail") {
            ProviderType::Gmail
        } else if srv_lower.contains("outlook") || srv_lower.contains("office365") {
            ProviderType::Outlook
        } else if srv_lower.contains("yahoo") {
            ProviderType::Yahoo
        } else if srv_lower.contains("icloud") || srv_lower.contains("mail.me.com") {
            ProviderType::ICloud
        } else {
            ProviderType::GenericImap
        };
        return (provider, srv.to_string(), port);
    }

    match domain.as_str() {
        "gmail.com" | "googlemail.com" => (
            ProviderType::Gmail,
            "imap.gmail.com".to_string(),
            custom_port.unwrap_or(993),
        ),
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" | "office365.com" => (
            ProviderType::Outlook,
            "outlook.office365.com".to_string(),
            custom_port.unwrap_or(993),
        ),
        "yahoo.com" | "ymail.com" | "myyahoo.com" => (
            ProviderType::Yahoo,
            "imap.mail.yahoo.com".to_string(),
            custom_port.unwrap_or(993),
        ),
        "icloud.com" | "me.com" | "mac.com" => (
            ProviderType::ICloud,
            "imap.mail.me.com".to_string(),
            custom_port.unwrap_or(993),
        ),
        _ => {
            let fallback = if !domain.is_empty() {
                format!("mail.{}", domain)
            } else {
                "localhost".to_string()
            };
            (
                ProviderType::GenericImap,
                fallback,
                custom_port.unwrap_or(993),
            )
        }
    }
}

/// Parses CSV text and returns a structured report of valid accounts and errors
pub fn parse_accounts_csv(content: &str) -> CsvImportReport {
    let mut report = CsvImportReport::default();
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return report;
    }

    let delimiter = detect_delimiter(content);
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(delimiter)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(content.as_bytes());

    let mut records: Vec<(usize, csv::StringRecord)> = Vec::new();
    let mut line_num = 1;

    for result in rdr.records() {
        match result {
            Ok(rec) => {
                if !rec.is_empty() && rec.iter().any(|field| !field.trim().is_empty()) {
                    records.push((line_num, rec));
                }
            }
            Err(e) => {
                report.errors.push(CsvRowError {
                    line: line_num,
                    raw_content: String::new(),
                    error: format!("CSV parsing error: {}", e),
                });
            }
        }
        line_num += 1;
    }

    if records.is_empty() {
        return report;
    }

    // Check if first row is a header row
    let (_first_line, first_row) = &records[0];
    let is_header = first_row.iter().any(|f| {
        let l = f.to_lowercase();
        l == "email" || l == "mail" || l == "address" || l == "e-mail"
    });

    let mut email_idx = None;
    let mut pass_idx = None;
    let mut name_idx = None;
    let mut server_idx = None;
    let mut port_idx = None;
    let mut user_idx = None;
    let mut retention_idx = None;
    let mut schedule_idx = None;

    let data_start = if is_header {
        for (i, col) in first_row.iter().enumerate() {
            let col_clean = col.trim().to_lowercase().replace(['_', '-', ' '], "");
            match col_clean.as_str() {
                "email" | "mail" | "address" | "emailaddress" => email_idx = Some(i),
                "password" | "pass" | "pwd" | "apppassword" | "secret" => pass_idx = Some(i),
                "name" | "displayname" | "fullname" | "accountname" => name_idx = Some(i),
                "server" | "host" | "imap" | "imapserver" | "hostname" => server_idx = Some(i),
                "port" | "imapport" => port_idx = Some(i),
                "username" | "user" | "login" => user_idx = Some(i),
                "retention" | "retentiondays" => retention_idx = Some(i),
                "schedule" | "cron" => schedule_idx = Some(i),
                _ => {}
            }
        }
        1
    } else {
        // Fallback column index mapping: email, password, name, server, port, username
        email_idx = Some(0);
        pass_idx = Some(1);
        name_idx = Some(2);
        server_idx = Some(3);
        port_idx = Some(4);
        user_idx = Some(5);
        0
    };

    let total_data_rows = records.len() - data_start;
    report.total_rows = total_data_rows;

    for (row_num, row) in records.into_iter().skip(data_start) {
        let raw_str = row.iter().collect::<Vec<_>>().join(if delimiter == b';' { ";" } else { "," });

        // Skip comment lines starting with #
        if let Some(first_field) = row.get(0) {
            if first_field.trim_start().starts_with('#') {
                continue;
            }
        }

        let email = email_idx.and_then(|idx| row.get(idx)).unwrap_or("").trim().to_string();
        let password = pass_idx.and_then(|idx| row.get(idx)).unwrap_or("").trim().to_string();

        if email.is_empty() {
            report.errors.push(CsvRowError {
                line: row_num,
                raw_content: raw_str,
                error: "Missing required 'email' address".to_string(),
            });
            continue;
        }

        if !email.contains('@') || email.split('@').nth(1).unwrap_or("").trim().is_empty() {
            report.errors.push(CsvRowError {
                line: row_num,
                raw_content: raw_str,
                error: format!("Invalid email format: '{}'", email),
            });
            continue;
        }

        if password.is_empty() {
            report.errors.push(CsvRowError {
                line: row_num,
                raw_content: raw_str,
                error: format!("Missing password for account '{}'", email),
            });
            continue;
        }

        let custom_name = name_idx.and_then(|idx| row.get(idx)).map(|s| s.trim()).filter(|s| !s.is_empty());
        let name = match custom_name {
            Some(n) => n.to_string(),
            None => {
                let local = email.split('@').next().unwrap_or("User");
                if let Some(first_char) = local.chars().next() {
                    let mut capitalized = first_char.to_uppercase().to_string();
                    capitalized.push_str(&local[first_char.len_utf8()..]);
                    capitalized
                } else {
                    local.to_string()
                }
            }
        };

        let custom_server = server_idx.and_then(|idx| row.get(idx)).map(|s| s.trim());
        let custom_port = port_idx.and_then(|idx| row.get(idx)).and_then(|p| p.trim().parse::<u16>().ok());

        let (provider, imap_server, imap_port) = detect_provider_and_server(&email, custom_server, custom_port);

        let username = user_idx
            .and_then(|idx| row.get(idx))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| email.clone());

        let retention_days = retention_idx
            .and_then(|idx| row.get(idx))
            .and_then(|r| r.trim().parse::<u32>().ok());

        let schedule = schedule_idx
            .and_then(|idx| row.get(idx))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let id = StorageEngine::sanitize_slug(&email);

        report.valid_accounts.push(ValidImportAccount {
            id,
            name,
            email,
            provider,
            imap_server,
            imap_port,
            use_tls: true,
            auth_type: AuthType::Password,
            username,
            password,
            schedule,
            retention_days,
        });
    }

    report
}

/// Generates a starter CSV template with comments and popular provider examples
pub fn generate_csv_template() -> String {
    "email,password,name,server,port,username\n\
user@example.com,AppPassword123,Work Email,mail.example.com,993,user@example.com\n\
john.doe@gmail.com,abcd-efgh-ijkl-mnop,Personal Gmail,,,john.doe@gmail.com\n\
alice@company.com,SecretPass2026,Alice Smith,outlook.office365.com,993,alice@company.com\n"
        .to_string()
}
