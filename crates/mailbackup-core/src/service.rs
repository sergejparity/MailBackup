use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_IDENTIFIER: &str = "com.mailbackup.service";
pub const SERVICE_TASK_NAME: &str = "MailBackupService";
pub const SYSTEMD_SERVICE_NAME: &str = "mailbackup.service";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub service_type: String,
    pub details: Option<String>,
    pub manual_install_cmd: String,
    pub manual_uninstall_cmd: String,
}

/// Locates the `mailbackup-server` executable relative to the current binary,
/// in PATH, or returns current executable as fallback.
pub fn find_server_executable() -> PathBuf {
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mailbackup-gui"));
    let parent = current_exe.parent();

    #[cfg(windows)]
    let server_bin_name = "mailbackup-server.exe";
    #[cfg(not(windows))]
    let server_bin_name = "mailbackup-server";

    // 1. Check same directory as current binary (e.g. target/debug or installation folder)
    if let Some(dir) = parent {
        let candidate = dir.join(server_bin_name);
        if candidate.exists() {
            return candidate;
        }
    }

    // 2. If current binary is already mailbackup-server
    if let Some(file_name) = current_exe.file_name() {
        if file_name.to_string_lossy().starts_with("mailbackup-server") {
            return current_exe;
        }
    }

    // 3. Check /usr/local/bin or standard paths
    #[cfg(unix)]
    {
        let usr_local = PathBuf::from("/usr/local/bin").join(server_bin_name);
        if usr_local.exists() {
            return usr_local;
        }
    }

    // Fallback to current executable
    current_exe
}

#[cfg(target_os = "macos")]
fn get_launchdaemon_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons").join(format!("{}.plist", SERVICE_IDENTIFIER))
}

#[cfg(target_os = "linux")]
fn get_systemd_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system").join(SYSTEMD_SERVICE_NAME)
}

/// Returns the manual installation shell command for display in the UI or CLI
pub fn get_manual_install_command(server_exe: &Path, config_path: &Path) -> String {
    #[cfg(target_os = "macos")]
    {
        let plist_path = get_launchdaemon_path();
        format!(
            "sudo bash -c 'cat << \"EOF\" > {}\n{}\nEOF\nchown root:wheel {}\nchmod 644 {}\nlaunchctl load -w {}'",
            plist_path.display(),
            generate_macos_plist(server_exe, config_path),
            plist_path.display(),
            plist_path.display(),
            plist_path.display()
        )
    }

    #[cfg(target_os = "windows")]
    {
        format!(
            "schtasks /Create /TN \"{}\" /TR \"\\\"{}\\\" --config \\\"{}\\\"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F\nschtasks /Run /TN \"{}\"",
            SERVICE_TASK_NAME,
            server_exe.display(),
            config_path.display(),
            SERVICE_TASK_NAME
        )
    }

    #[cfg(target_os = "linux")]
    {
        let service_path = get_systemd_path();
        format!(
            "sudo bash -c 'cat << \"EOF\" > {}\n{}\nEOF\nsystemctl daemon-reload\nsystemctl enable --now {}'",
            service_path.display(),
            generate_linux_systemd(server_exe, config_path),
            SYSTEMD_SERVICE_NAME
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        format!("{} --config {}", server_exe.display(), config_path.display())
    }
}

/// Returns the manual uninstallation shell command
pub fn get_manual_uninstall_command() -> String {
    #[cfg(target_os = "macos")]
    {
        let plist_path = get_launchdaemon_path();
        format!(
            "sudo launchctl unload -w {} && sudo rm -f {}",
            plist_path.display(),
            plist_path.display()
        )
    }

    #[cfg(target_os = "windows")]
    {
        format!(
            "schtasks /End /TN \"{}\" & schtasks /Delete /TN \"{}\" /F",
            SERVICE_TASK_NAME, SERVICE_TASK_NAME
        )
    }

    #[cfg(target_os = "linux")]
    {
        let service_path = get_systemd_path();
        format!(
            "sudo systemctl disable --now {} && sudo rm -f {} && sudo systemctl daemon-reload",
            SYSTEMD_SERVICE_NAME,
            service_path.display()
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "echo Unsupported".to_string()
    }
}

pub fn get_service_status() -> ServiceStatus {
    let server_exe = find_server_executable();
    let config_path = crate::config::default_config_path();
    let manual_install_cmd = get_manual_install_command(&server_exe, &config_path);
    let manual_uninstall_cmd = get_manual_uninstall_command();

    #[cfg(target_os = "macos")]
    {
        let plist_path = get_launchdaemon_path();
        let installed = plist_path.exists();
        let mut running = false;
        let mut details = None;

        if installed {
            let output = Command::new("launchctl")
                .args(["list", SERVICE_IDENTIFIER])
                .output();
            if let Ok(out) = output {
                running = out.status.success();
                if running {
                    details = Some("Service registered and running via macOS launchd LaunchDaemon".to_string());
                } else {
                    details = Some("LaunchDaemon plist exists but service is not currently running".to_string());
                }
            }
        } else {
            details = Some("LaunchDaemon not installed. Run at boot without user login is disabled.".to_string());
        }

        ServiceStatus {
            installed,
            running,
            service_type: "macOS LaunchDaemon".to_string(),
            details,
            manual_install_cmd,
            manual_uninstall_cmd,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let mut installed = false;
        let mut running = false;
        let mut details = None;

        let output = Command::new("schtasks")
            .args(["/Query", "/TN", SERVICE_TASK_NAME])
            .output();

        if let Ok(out) = output {
            installed = out.status.success();
            if installed {
                let stdout = String::from_utf8_lossy(&out.stdout);
                running = stdout.contains("Running");
                details = Some(if running {
                    "Startup background task is active under SYSTEM account".to_string()
                } else {
                    "Startup background task is registered (Idle/Scheduled)".to_string()
                });
            }
        }

        if !installed {
            details = Some("Windows service background task is not registered".to_string());
        }

        ServiceStatus {
            installed,
            running,
            service_type: "Windows Startup Task (SYSTEM)".to_string(),
            details,
            manual_install_cmd,
            manual_uninstall_cmd,
        }
    }

    #[cfg(target_os = "linux")]
    {
        let service_path = get_systemd_path();
        let installed = service_path.exists();
        let mut running = false;
        let mut details = None;

        if installed {
            let output = Command::new("systemctl")
                .args(["is-active", SYSTEMD_SERVICE_NAME])
                .output();
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                running = stdout == "active";
                details = Some(format!("systemd status: {}", stdout));
            }
        } else {
            details = Some("systemd service file does not exist".to_string());
        }

        ServiceStatus {
            installed,
            running,
            service_type: "Linux systemd Service".to_string(),
            details,
            manual_install_cmd,
            manual_uninstall_cmd,
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        ServiceStatus {
            installed: false,
            running: false,
            service_type: "Unsupported".to_string(),
            details: Some("System services are not supported on this OS".to_string()),
            manual_install_cmd,
            manual_uninstall_cmd,
        }
    }
}

pub fn generate_macos_plist(server_exe: &Path, config_path: &Path) -> String {
    let log_dir = crate::config::default_base_dir().join("logs");
    let out_log = log_dir.join("service.log");
    let err_log = log_dir.join("service_err.log");

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
        <string>--config</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
"#,
        SERVICE_IDENTIFIER,
        server_exe.display(),
        config_path.display(),
        out_log.display(),
        err_log.display()
    )
}

pub fn generate_linux_systemd(server_exe: &Path, config_path: &Path) -> String {
    let log_dir = crate::config::default_base_dir().join("logs");
    let out_log = log_dir.join("service.log");
    let err_log = log_dir.join("service_err.log");

    format!(
        r#"[Unit]
Description=MailBackup Studio Headless Service
After=network.target

[Service]
Type=simple
ExecStart="{}" --config "{}"
Restart=always
RestartSec=10
StandardOutput=append:{}
StandardError=append:{}

[Install]
WantedBy=multi-user.target
"#,
        server_exe.display(),
        config_path.display(),
        out_log.display(),
        err_log.display()
    )
}

/// Sets or removes system service registration.
/// When non-root, attempts standard OS authorization elevation or returns error with instructions.
pub fn set_service_enabled(enabled: bool) -> Result<()> {
    let server_exe = find_server_executable();
    let config_path = crate::config::default_config_path();

    // Ensure logs directory exists
    let log_dir = crate::config::default_base_dir().join("logs");
    let _ = std::fs::create_dir_all(&log_dir);

    #[cfg(target_os = "macos")]
    {
        let plist_path = get_launchdaemon_path();

        if enabled {
            let plist_content = generate_macos_plist(&server_exe, &config_path);
            let tmp_plist = std::env::temp_dir().join("mailbackup_service.plist");
            std::fs::write(&tmp_plist, plist_content)?;

            // Try direct write (if running as root)
            let direct_write = (|| -> std::io::Result<()> {
                std::fs::copy(&tmp_plist, &plist_path)?;
                let status = Command::new("launchctl")
                    .args(["load", "-w", &plist_path.to_string_lossy()])
                    .status()?;
                if status.success() {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "launchctl load failed",
                    ))
                }
            })();

            if direct_write.is_err() {
                // Elevate via osascript
                let script = format!(
                    "do shell script \"cp '{}' '{}' && chown root:wheel '{}' && chmod 644 '{}' && launchctl load -w '{}'\" with administrator privileges",
                    tmp_plist.display(),
                    plist_path.display(),
                    plist_path.display(),
                    plist_path.display(),
                    plist_path.display()
                );

                let status = Command::new("osascript")
                    .args(["-e", &script])
                    .status()
                    .map_err(|e| Error::Config(format!("Failed to run elevation script: {}", e)))?;

                let _ = std::fs::remove_file(&tmp_plist);

                if !status.success() {
                    return Err(Error::Config(
                        "Administrator authorization was cancelled or failed to register LaunchDaemon".into(),
                    ));
                }
            } else {
                let _ = std::fs::remove_file(&tmp_plist);
            }
        } else if plist_path.exists() {
            // Direct unload if root
            let direct_remove = (|| -> std::io::Result<()> {
                let _ = Command::new("launchctl")
                    .args(["unload", "-w", &plist_path.to_string_lossy()])
                    .status();
                std::fs::remove_file(&plist_path)
            })();

            if direct_remove.is_err() {
                // Elevate via osascript
                let script = format!(
                    "do shell script \"launchctl unload -w '{}' && rm -f '{}'\" with administrator privileges",
                    plist_path.display(),
                    plist_path.display()
                );

                let status = Command::new("osascript")
                    .args(["-e", &script])
                    .status()
                    .map_err(|e| Error::Config(format!("Failed to run elevation script: {}", e)))?;

                if !status.success() {
                    return Err(Error::Config(
                        "Administrator authorization was cancelled or failed to remove LaunchDaemon".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        if enabled {
            // Attempt to create scheduled task
            let tr_arg = format!("\"{}\" --config \"{}\"", server_exe.display(), config_path.display());
            let status = Command::new("schtasks")
                .args([
                    "/Create",
                    "/TN",
                    SERVICE_TASK_NAME,
                    "/TR",
                    &tr_arg,
                    "/SC",
                    "ONSTART",
                    "/RU",
                    "SYSTEM",
                    "/RL",
                    "HIGHEST",
                    "/F",
                ])
                .status();

            let success = status.map(|s| s.success()).unwrap_or(false);
            if !success {
                // Attempt elevation via PowerShell Start-Process
                let ps_cmd = format!(
                    "Start-Process schtasks -ArgumentList '/Create /TN \"{}\" /TR \"\\\"{}\\\" --config \\\"{}\\\"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F' -Verb RunAs -Wait",
                    SERVICE_TASK_NAME,
                    server_exe.display(),
                    config_path.display()
                );

                let ps_status = Command::new("powershell")
                    .args(["-Command", &ps_cmd])
                    .status()
                    .map_err(|e| Error::Config(format!("Failed to invoke elevated PowerShell: {}", e)))?;

                if !ps_status.success() {
                    return Err(Error::Config("Administrator authorization failed to create Windows startup task".into()));
                }
            }

            // Trigger immediate run
            let _ = Command::new("schtasks").args(["/Run", "/TN", SERVICE_TASK_NAME]).status();
        } else {
            let _ = Command::new("schtasks").args(["/End", "/TN", SERVICE_TASK_NAME]).status();
            let status = Command::new("schtasks").args(["/Delete", "/TN", SERVICE_TASK_NAME, "/F"]).status();
            let success = status.map(|s| s.success()).unwrap_or(false);

            if !success {
                let ps_cmd = format!(
                    "Start-Process schtasks -ArgumentList '/Delete /TN \"{}\" /F' -Verb RunAs -Wait",
                    SERVICE_TASK_NAME
                );
                let _ = Command::new("powershell").args(["-Command", &ps_cmd]).status();
            }
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let service_path = get_systemd_path();

        if enabled {
            let content = generate_linux_systemd(&server_exe, &config_path);
            let tmp_path = std::env::temp_dir().join(SYSTEMD_SERVICE_NAME);
            std::fs::write(&tmp_path, content)?;

            let direct = (|| -> std::io::Result<()> {
                std::fs::copy(&tmp_path, &service_path)?;
                Command::new("systemctl").arg("daemon-reload").status()?;
                Command::new("systemctl").args(["enable", "--now", SYSTEMD_SERVICE_NAME]).status()?;
                Ok(())
            })();

            if direct.is_err() {
                // Elevate via pkexec
                let cmd = format!(
                    "cp '{}' '{}' && systemctl daemon-reload && systemctl enable --now {}",
                    tmp_path.display(),
                    service_path.display(),
                    SYSTEMD_SERVICE_NAME
                );
                let status = Command::new("pkexec")
                    .args(["sh", "-c", &cmd])
                    .status()
                    .map_err(|e| Error::Config(format!("Elevation via pkexec failed: {}", e)))?;

                let _ = std::fs::remove_file(&tmp_path);

                if !status.success() {
                    return Err(Error::Config("Administrator authorization failed to install systemd service".into()));
                }
            } else {
                let _ = std::fs::remove_file(&tmp_path);
            }
        } else if service_path.exists() {
            let direct = (|| -> std::io::Result<()> {
                let _ = Command::new("systemctl").args(["disable", "--now", SYSTEMD_SERVICE_NAME]).status();
                let _ = std::fs::remove_file(&service_path);
                let _ = Command::new("systemctl").arg("daemon-reload").status();
                Ok(())
            })();

            if direct.is_err() {
                let cmd = format!(
                    "systemctl disable --now {} && rm -f '{}' && systemctl daemon-reload",
                    SYSTEMD_SERVICE_NAME,
                    service_path.display()
                );
                let _ = Command::new("pkexec").args(["sh", "-c", &cmd]).status();
            }
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = enabled;
        Err(Error::Config("System service registration not supported on this operating system".into()))
    }
}
