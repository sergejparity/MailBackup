use crate::error::{Error, Result};
use std::path::PathBuf;

#[allow(dead_code)]
const APP_NAME: &str = "MailBackup Studio";
const APP_IDENTIFIER: &str = "com.mailbackup.studio";

pub fn is_autostart_supported() -> bool {
    cfg!(target_os = "macos") || cfg!(target_os = "windows") || cfg!(target_os = "linux")
}

pub fn get_executable_path() -> Result<PathBuf> {
    std::env::current_exe().map_err(|e| Error::Config(format!("Failed to get current executable path: {}", e)))
}

#[cfg(target_os = "macos")]
fn get_plist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join("Library").join("LaunchAgents").join(format!("{}.plist", APP_IDENTIFIER)))
}

#[cfg(target_os = "linux")]
fn get_desktop_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".config").join("autostart").join(format!("{}.desktop", APP_IDENTIFIER)))
}

/// Sets or removes autostart registration for the current application
pub fn set_autostart(enabled: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let plist_path = match get_plist_path() {
            Some(p) => p,
            None => return Err(Error::Config("Could not determine user home directory".into())),
        };

        if enabled {
            let exe_path = get_executable_path()?;
            if let Some(parent) = plist_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let plist_content = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#,
                APP_IDENTIFIER,
                exe_path.display()
            );

            std::fs::write(&plist_path, plist_content)?;
        } else if plist_path.exists() {
            let _ = std::fs::remove_file(&plist_path);
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        if enabled {
            let exe_path = get_executable_path()?;
            let val = format!("\"{}\"", exe_path.display());
            let status = Command::new("reg")
                .args(["add", run_key, "/v", "MailBackupStudio", "/t", "REG_SZ", "/d", &val, "/f"])
                .status()
                .map_err(|e| Error::Config(format!("Failed to execute reg add: {}", e)))?;

            if !status.success() {
                return Err(Error::Config("reg add command failed".into()));
            }
        } else {
            let _ = Command::new("reg")
                .args(["delete", run_key, "/v", "MailBackupStudio", "/f"])
                .status();
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let desktop_path = match get_desktop_path() {
            Some(p) => p,
            None => return Err(Error::Config("Could not determine user home directory".into())),
        };

        if enabled {
            let exe_path = get_executable_path()?;
            if let Some(parent) = desktop_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let desktop_content = format!(
                r#"[Desktop Entry]
Type=Application
Version=1.0
Name={}
Comment=MailBackup Studio Email Backup Utility
Exec="{}"
StartupNotify=false
Terminal=false
"#,
                APP_NAME,
                exe_path.display()
            );

            std::fs::write(&desktop_path, desktop_content)?;
        } else if desktop_path.exists() {
            let _ = std::fs::remove_file(&desktop_path);
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = enabled;
        Ok(())
    }
}

/// Checks whether autostart is currently registered in the OS
pub fn is_autostart_registered() -> bool {
    #[cfg(target_os = "macos")]
    {
        get_plist_path().map(|p| p.exists()).unwrap_or(false)
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let run_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
        Command::new("reg")
            .args(["query", run_key, "/v", "MailBackupStudio"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        get_desktop_path().map(|p| p.exists()).unwrap_or(false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false
    }
}
