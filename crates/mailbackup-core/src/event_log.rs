use crate::config::default_base_dir;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub details: String,
}

pub fn log_dir() -> PathBuf {
    default_base_dir().join("logs")
}

pub fn log_file_path() -> PathBuf {
    log_dir().join("events.log")
}

/// Appends a new event entry to the persistent events.log file
pub fn log_event(event_type: &str, details: &str) {
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let now = Utc::now();
    let formatted_line = format!(
        "[{}] [{}] {}\n",
        now.to_rfc3339(),
        event_type.to_uppercase(),
        details
    );

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(formatted_line.as_bytes());
    }
}

/// Parses recent log entries from events.log (newest first)
pub fn get_recent_logs(limit: usize) -> Result<Vec<LogEntry>> {
    let path = log_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines().flatten() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format: [2026-09-22T03:00:00Z] [EVENT_TYPE] Details...
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(ts_end) = rest.find(']') {
                let ts_str = &rest[..ts_end];
                let after_ts = rest[ts_end + 1..].trim_start();
                if let Some(after_bracket) = after_ts.strip_prefix('[') {
                    if let Some(type_end) = after_bracket.find(']') {
                        let event_type = after_bracket[..type_end].to_string();
                        let details = after_bracket[type_end + 1..].trim().to_string();

                        let timestamp = DateTime::parse_from_rfc3339(ts_str)
                            .map(|dt| dt.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now());

                        entries.push(LogEntry {
                            timestamp,
                            event_type,
                            details,
                        });
                    }
                }
            }
        }
    }

    // Return newest first, capped by limit
    entries.reverse();
    if entries.len() > limit {
        entries.truncate(limit);
    }

    Ok(entries)
}

/// Reads full raw log content
pub fn get_raw_log() -> Result<String> {
    let path = log_file_path();
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(std::fs::read_to_string(&path)?)
}

/// Clears the events.log file
pub fn clear_log() -> Result<()> {
    let path = log_file_path();
    if path.exists() {
        std::fs::write(&path, "")?;
    }
    log_event("LOGS_CLEARED", "Event logs cleared by user");
    Ok(())
}
