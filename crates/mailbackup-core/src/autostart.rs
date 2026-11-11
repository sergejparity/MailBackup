use crate::error::{Error, Result};
use std::path::PathBuf;

#[allow(dead_code)]
const APP_NAME: &str = "MailBackup Studio";
#[allow(dead_code)]
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

/// The LaunchAgent that starts `exe` at login (macOS). The path is XML-escaped.
pub fn launch_agent_plist(exe: &std::path::Path) -> String {
    format!(
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
        crate::service::xml_escape(&exe.to_string_lossy())
    )
}

/// The autostart entry that starts `exe` at login (Linux, XDG).
pub fn desktop_entry(exe: &std::path::Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName={}\nComment=MailBackup Studio Email Backup Utility\nExec={}\nStartupNotify=false\nTerminal=false\n",
        APP_NAME,
        desktop_exec_quote(&exe.to_string_lossy())
    )
}

/// One `Exec=` argument, quoted per the Desktop Entry specification: inside
/// double quotes `"`, `` ` ``, `$` and `\` take a backslash, `%` is written
/// `%%`, and since the value is also a string value, every backslash is
/// doubled once more. Line breaks can't be represented and become spaces.
pub fn desktop_exec_quote(arg: &str) -> String {
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for c in arg.chars() {
        match c {
            '"' | '`' | '$' | '\\' => {
                quoted.push('\\');
                quoted.push(c);
            }
            '%' => quoted.push_str("%%"),
            '\n' | '\r' => quoted.push(' '),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted.replace('\\', "\\\\")
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

            let plist_content = launch_agent_plist(&exe_path);

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
            let status = Command::new(crate::service::trusted_program("reg")?)
                .args(["add", run_key, "/v", "MailBackupStudio", "/t", "REG_SZ", "/d", &val, "/f"])
                .status()
                .map_err(|e| Error::Config(format!("Failed to execute reg add: {}", e)))?;

            if !status.success() {
                return Err(Error::Config("reg add command failed".into()));
            }
        } else {
            let _ = Command::new(crate::service::trusted_program("reg")?)
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

            let desktop_content = desktop_entry(&exe_path);

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
        let Ok(reg) = crate::service::trusted_program("reg") else { return false };
        Command::new(reg)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The Desktop Entry spec's own unescaping, written independently:
    /// string-level `\\` -> `\`, then inside quotes `\x` -> `x`, then `%%` -> `%`.
    fn desktop_unquote(exec: &str) -> String {
        let mut string_level = String::new();
        let mut chars = exec.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                string_level.push(chars.next().unwrap());
            } else {
                string_level.push(c);
            }
        }
        let inner = string_level.strip_prefix('"').and_then(|s| s.strip_suffix('"')).expect("quoted");
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                out.push(chars.next().unwrap());
            } else {
                out.push(c);
            }
        }
        out.replace("%%", "%")
    }

    #[test]
    fn exec_paths_with_special_characters_survive_quoting() {
        for path in [
            "/opt/MailBackup Studio/mailbackup-gui",
            "/home/a&b/100%/mail\\backup",
            "/tmp/$HOME/`id`/\"quoted\"",
        ] {
            let exec = desktop_exec_quote(path);
            assert_eq!(desktop_unquote(&exec), path, "{}", exec);
        }
        assert!(desktop_entry(Path::new("/a b/x")).contains("Exec=\"/a b/x\"\n"));
    }

    #[test]
    fn the_launch_agent_escapes_the_path() {
        let plist = launch_agent_plist(Path::new("/Applications/A&B <x>.app/run"));
        assert!(plist.contains("<string>/Applications/A&amp;B &lt;x&gt;.app/run</string>"), "{}", plist);
    }
}
