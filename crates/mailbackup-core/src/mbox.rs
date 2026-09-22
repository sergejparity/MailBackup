use crate::error::Result;
use crate::storage::StorageEngine;
use chrono::{DateTime, Utc};
use mail_parser::MessageParser;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use tracing::info;

pub struct MboxExporter<'a> {
    storage: &'a StorageEngine,
}

impl<'a> MboxExporter<'a> {
    pub fn new(storage: &'a StorageEngine) -> Self {
        Self { storage }
    }

    /// Streams a list of relative .eml paths to an RFC 4155 mbox writer
    pub fn export_to_writer<W: Write>(
        &self,
        eml_relative_paths: &[String],
        mut writer: W,
    ) -> Result<usize> {
        let mut count = 0;

        for rel_path in eml_relative_paths {
            let eml_bytes = match self.storage.read_eml(rel_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::warn!("Skipping {}: {}", rel_path, e);
                    continue;
                }
            };

            // Parse headers to extract from address and date for mbox envelope
            let (from_addr, date_str) = if let Some(parsed) = MessageParser::default().parse(&eml_bytes) {
                let from = parsed
                    .from()
                    .and_then(|f| match f {
                        mail_parser::Address::List(list) => list.first().and_then(|a| a.address.as_deref()),
                        mail_parser::Address::Group(groups) => groups.first().and_then(|g| g.addresses.first()).and_then(|a| a.address.as_deref()),
                    })
                    .unwrap_or("MAILER-DAEMON")
                    .to_string();

                let date = parsed
                    .date()
                    .and_then(|d| DateTime::from_timestamp(d.to_timestamp(), 0))
                    .unwrap_or_else(Utc::now);

                // mbox date format: "Fri Jan 01 00:00:00 2021"
                let formatted_date = date.format("%a %b %e %H:%M:%S %Y").to_string();
                (from, formatted_date)
            } else {
                ("MAILER-DAEMON".to_string(), Utc::now().format("%a %b %e %H:%M:%S %Y").to_string())
            };

            // Write envelope "From " separator
            writeln!(writer, "From {} {}", from_addr, date_str)?;

            // Stream body and escape lines starting with "From " (mboxrd style)
            let content_str = String::from_utf8_lossy(&eml_bytes);
            for line in content_str.lines() {
                if line.starts_with("From ") || line.starts_with(">From ") {
                    write!(writer, ">")?;
                }
                writeln!(writer, "{}", line)?;
            }

            // Mbox requires a trailing newline between messages
            writeln!(writer)?;
            count += 1;
        }

        writer.flush()?;
        Ok(count)
    }

    /// Exports a list of relative .eml paths to an RFC 4155 mbox file
    pub fn export_to_mbox(
        &self,
        eml_relative_paths: &[String],
        output_path: impl AsRef<Path>,
    ) -> Result<usize> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = File::create(output_path)?;
        let writer = BufWriter::new(file);
        let count = self.export_to_writer(eml_relative_paths, writer)?;
        info!("Exported {} messages to mbox: {}", count, output_path.display());
        Ok(count)
    }
}
