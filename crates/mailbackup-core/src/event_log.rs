use crate::config::default_base_dir;
use crate::error::{Error, Result};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFileInfo {
    pub name: String,
    pub size_bytes: u64,
    pub modified: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogRotationReport {
    pub rotated: bool,
    pub rotated_filename: Option<String>,
    pub pruned_files: Vec<String>,
    pub reclaimed_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LogPruneReport {
    pub pruned_files: Vec<String>,
    pub reclaimed_bytes: u64,
}

pub fn log_dir() -> PathBuf {
    default_base_dir().join("logs")
}

pub fn log_file_path() -> PathBuf {
    log_dir().join("events.log")
}

/// Helper to detect the date of log entries in a file or fall back to modification time
fn detect_log_file_date(path: &Path) -> Option<NaiveDate> {
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                if let Some(end) = trimmed.find(']') {
                    let ts_str = &trimmed[1..end];
                    if let Ok(dt) = DateTime::parse_from_rfc3339(ts_str) {
                        return Some(dt.date_naive());
                    }
                }
            }
        }
    }
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(mtime) = meta.modified() {
            let dt: DateTime<Utc> = mtime.into();
            return Some(dt.date_naive());
        }
    }
    None
}

/// Extracts a YYYY-MM-DD date from a filename like events-2026-09-28.log
fn extract_date_from_filename(name: &str) -> Option<NaiveDate> {
    let bytes = name.as_bytes();
    if bytes.len() < 10 {
        return None;
    }
    for i in 0..=bytes.len() - 10 {
        let slice = &name[i..i + 10];
        if slice.chars().nth(4) == Some('-') && slice.chars().nth(7) == Some('-') {
            if let Ok(d) = NaiveDate::parse_from_str(slice, "%Y-%m-%d") {
                return Some(d);
            }
        }
    }
    None
}

/// Rotates active events.log into events-YYYY-MM-DD.log
pub fn rotate_active_log() -> Result<Option<String>> {
    let active_path = log_file_path();
    if !active_path.exists() {
        return Ok(None);
    }
    let metadata = fs::metadata(&active_path)?;
    if metadata.len() == 0 {
        return Ok(None);
    }

    let dir = log_dir();
    fs::create_dir_all(&dir)?;

    let today = Utc::now().date_naive();
    let log_date = detect_log_file_date(&active_path).unwrap_or(today);
    let base_name = format!("events-{}.log", log_date.format("%Y-%m-%d"));
    let mut candidate_path = dir.join(&base_name);
    let mut final_name = base_name.clone();

    // If destination exists, choose suffix (events-YYYY-MM-DD.1.log, etc.)
    if candidate_path.exists() {
        let mut idx = 1;
        loop {
            let suffixed = format!("events-{}.{}.log", log_date.format("%Y-%m-%d"), idx);
            let p = dir.join(&suffixed);
            if !p.exists() || idx > 999 {
                candidate_path = p;
                final_name = suffixed;
                break;
            }
            idx += 1;
        }
    }

    if fs::rename(&active_path, &candidate_path).is_err() {
        // Fallback: copy and truncate
        fs::copy(&active_path, &candidate_path)?;
        let _ = fs::write(&active_path, "");
    }

    Ok(Some(final_name))
}

/// Prunes rotated log files exceeding the retention days policy
pub fn prune_logs(retention_days: Option<u32>) -> Result<LogPruneReport> {
    let mut report = LogPruneReport::default();
    let days = match retention_days {
        Some(d) if d > 0 => d,
        _ => return Ok(report), // 0 or None = retain forever
    };

    let dir = log_dir();
    if !dir.exists() {
        return Ok(report);
    }

    let cutoff_date = Utc::now().date_naive() - Duration::days(days as i64);

    let entries = fs::read_dir(&dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();

        // Never prune active log files
        if file_name == "events.log" || file_name == "service.log" || file_name == "service_err.log" {
            continue;
        }

        // Only prune rotated log files
        let is_rotated_log = (file_name.starts_with("events-")
            || file_name.starts_with("service-")
            || file_name.starts_with("service_err-")
            || file_name.starts_with("mailbackup-"))
            && (file_name.ends_with(".log") || file_name.contains(".log."));

        if !is_rotated_log {
            continue;
        }

        // Extract date from filename or fall back to file modification time
        let file_date = extract_date_from_filename(&file_name).or_else(|| {
            entry.metadata().ok().and_then(|m| m.modified().ok()).map(|mtime| {
                let dt: DateTime<Utc> = mtime.into();
                dt.date_naive()
            })
        });

        if let Some(date) = file_date {
            if date < cutoff_date {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                if fs::remove_file(&path).is_ok() {
                    report.pruned_files.push(file_name);
                    report.reclaimed_bytes += size;
                }
            }
        }
    }

    Ok(report)
}

/// Rotates active log and executes retention pruning in one operation
pub fn rotate_and_prune_logs(retention_days: Option<u32>) -> Result<LogRotationReport> {
    let rotated_filename = rotate_active_log()?;
    let prune_report = prune_logs(retention_days)?;
    Ok(LogRotationReport {
        rotated: rotated_filename.is_some(),
        rotated_filename,
        pruned_files: prune_report.pruned_files,
        reclaimed_bytes: prune_report.reclaimed_bytes,
    })
}

/// Checks whether events.log contains logs from a previous day, and rotates if so
pub fn check_and_rotate_daily() {
    let active_path = log_file_path();
    if !active_path.exists() {
        return;
    }
    if let Ok(meta) = fs::metadata(&active_path) {
        if meta.len() == 0 {
            return;
        }
    } else {
        return;
    }

    let today = Utc::now().date_naive();
    if let Some(log_date) = detect_log_file_date(&active_path) {
        if log_date < today {
            let _ = rotate_active_log();
            let retention_days = crate::config::AppConfig::load_or_create(None)
                .ok()
                .and_then(|cfg| cfg.settings.log_retention_days)
                .unwrap_or(30);
            let _ = prune_logs(Some(retention_days));
        }
    }
}

/// Appends a new event entry to the persistent events.log file
pub fn log_event(event_type: &str, details: &str) {
    // Automatically rotate previous day's log if date has changed
    check_and_rotate_daily();

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

/// Lists all log files in the log directory (active first, then rotated by modified date)
pub fn list_log_files() -> Result<Vec<LogFileInfo>> {
    let dir = log_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    let entries = fs::read_dir(&dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".log") && !name.contains(".log.") {
            continue;
        }

        let meta = entry.metadata().ok();
        let size_bytes = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let modified = meta.and_then(|m| m.modified().ok()).map(|mtime| {
            let dt: DateTime<Utc> = mtime.into();
            dt
        });

        let is_active = name == "events.log";
        result.push(LogFileInfo {
            name,
            size_bytes,
            modified,
            is_active,
        });
    }

    // Sort: active first, then newest modified first
    result.sort_by(|a, b| {
        if a.is_active != b.is_active {
            b.is_active.cmp(&a.is_active)
        } else {
            b.modified.cmp(&a.modified)
        }
    });

    Ok(result)
}

/// Safely reads the specified log file from log_dir()
pub fn get_log_file_content(filename: &str) -> Result<String> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err(Error::Other("Invalid log filename path".to_string()));
    }
    let path = log_dir().join(filename);
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(fs::read_to_string(&path)?)
}

/// Parses entries from a given log file
pub fn parse_log_entries_from_file(path: &Path) -> Vec<LogEntry> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(file) = File::open(path) else {
        return Vec::new();
    };
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
    entries
}

/// Parses recent log entries from events.log (newest first).
/// If events.log has fewer than limit entries, backfills with recent rotated daily logs.
pub fn get_recent_logs(limit: usize) -> Result<Vec<LogEntry>> {
    let mut entries = parse_log_entries_from_file(&log_file_path());

    // Backfill from rotated logs if current active file has fewer entries than requested limit
    if entries.len() < limit {
        if let Ok(files) = list_log_files() {
            for file_info in files {
                if file_info.is_active {
                    continue;
                }
                let rotated_path = log_dir().join(&file_info.name);
                let rotated_entries = parse_log_entries_from_file(&rotated_path);
                entries.splice(0..0, rotated_entries);
                if entries.len() >= limit {
                    break;
                }
            }
        }
    }

    // Return newest first, sorted by timestamp
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    if entries.len() > limit {
        entries.truncate(limit);
    }

    Ok(entries)
}

/// Reads full raw log content of active log file
pub fn get_raw_log() -> Result<String> {
    let path = log_file_path();
    if !path.exists() {
        return Ok(String::new());
    }
    Ok(std::fs::read_to_string(&path)?)
}

/// Clears the active events.log file
pub fn clear_log() -> Result<()> {
    let path = log_file_path();
    if path.exists() {
        std::fs::write(&path, "")?;
    }
    log_event("LOGS_CLEARED", "Event logs cleared by user");
    Ok(())
}
