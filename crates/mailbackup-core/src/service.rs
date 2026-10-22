//! Background service registration.
//!
//! The service starts at boot but runs as the user who installs it, never as
//! root/SYSTEM: a systemd unit with `User=`, a LaunchDaemon with `UserName`, or a
//! Windows boot task with the user's account and S4U logon. Installing still needs
//! administrator rights because the definitions live in system folders. To keep
//! that step safe, definitions are staged in a private folder under the user's
//! MailBackup directory (never a shared temp folder), every elevated command is a
//! separate argument vector or a constant script that receives paths through the
//! environment, and every command's exit status is checked.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SERVICE_IDENTIFIER: &str = "com.mailbackup.service";
pub const SERVICE_TASK_NAME: &str = "MailBackupService";
pub const SYSTEMD_SERVICE_NAME: &str = "mailbackup.service";

pub const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/mailbackup.service";
pub const LAUNCHD_PLIST_PATH: &str = "/Library/LaunchDaemons/com.mailbackup.service.plist";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub service_type: String,
    pub details: Option<String>,
    pub manual_install_cmd: String,
    pub manual_uninstall_cmd: String,
    /// Account the installed service runs as (`None` = root/SYSTEM or unknown).
    #[serde(default)]
    pub runs_as: Option<String>,
    /// An installed service still runs with administrator rights (installed by an
    /// older version) and should be turned off and on again.
    #[serde(default)]
    pub needs_reinstall: bool,
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

// ---------------------------------------------------------------------------
// User identity
// ---------------------------------------------------------------------------

/// True for account names that are safe to embed in a unit file, plist or task
/// XML. On Windows a `DOMAIN\user` form is accepted.
pub fn is_valid_user_name(name: &str) -> bool {
    let part_ok = |p: &str| {
        !p.is_empty()
            && p.len() <= 256
            && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ' '))
            && !p.starts_with('-')
            && p.trim() == p
    };
    match name.split_once('\\') {
        Some((domain, user)) if cfg!(windows) => part_ok(domain) && part_ok(user) && !user.contains('\\'),
        Some(_) => false,
        // Spaces are only valid in Windows account names
        None => part_ok(name) && (cfg!(windows) || !name.contains(' ')),
    }
}

/// The account the service will run as: the user running MailBackup.
pub fn current_user() -> Result<String> {
    #[cfg(windows)]
    let name = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) if !d.is_empty() => format!("{}\\{}", d, u),
        (_, Ok(u)) => u,
        _ => command_output("whoami", &[])?,
    };
    #[cfg(not(windows))]
    let name = match std::env::var("USER").or_else(|_| std::env::var("LOGNAME")) {
        Ok(u) if !u.is_empty() => u,
        _ => command_output("whoami", &[])?,
    };

    if !is_valid_user_name(&name) {
        return Err(Error::Config(format!("Unsupported account name for the background service: {:?}", name)));
    }
    if name == "root" || name.eq_ignore_ascii_case("SYSTEM") || name.to_ascii_uppercase().ends_with("\\SYSTEM") {
        return Err(Error::Config(
            "Run MailBackup as your normal user to install the background service; it must not run as root/SYSTEM.".into(),
        ));
    }
    Ok(name)
}

fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| Error::Config(format!("Failed to run {}: {}", program, e)))?;
    if !out.status.success() {
        return Err(Error::Config(format!("{} exited with {}", program, out.status)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// ---------------------------------------------------------------------------
// Definition generators (pure, compiled on every OS so they can be tested)
// ---------------------------------------------------------------------------

/// Quotes one `ExecStart=` argument per systemd's rules.
pub fn systemd_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Escapes a value for `Key=value` lines that take a plain path (specifiers only).
fn systemd_plain(value: &str) -> String {
    value.replace('%', "%%").replace(['\n', '\r'], " ")
}

pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn service_log_paths() -> (PathBuf, PathBuf) {
    let log_dir = crate::config::default_base_dir().join("logs");
    (log_dir.join("service.log"), log_dir.join("service_err.log"))
}

/// systemd system unit that runs the server as `user`.
pub fn generate_linux_systemd(server_exe: &Path, config_path: &Path, user: &str) -> String {
    let (out_log, err_log) = service_log_paths();
    format!(
        r#"[Unit]
Description=MailBackup Studio Headless Service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User={}
ExecStart={} --service --config {}
Restart=always
RestartSec=10
StandardOutput=append:{}
StandardError=append:{}

[Install]
WantedBy=multi-user.target
"#,
        systemd_plain(user),
        systemd_quote(&server_exe.to_string_lossy()),
        systemd_quote(&config_path.to_string_lossy()),
        systemd_plain(&out_log.to_string_lossy()),
        systemd_plain(&err_log.to_string_lossy()),
    )
}

/// LaunchDaemon (starts at boot) that runs the server as `user`.
pub fn generate_macos_plist(server_exe: &Path, config_path: &Path, user: &str) -> String {
    let (out_log, err_log) = service_log_paths();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>UserName</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--service</string>
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
        xml_escape(user),
        xml_escape(&server_exe.to_string_lossy()),
        xml_escape(&config_path.to_string_lossy()),
        xml_escape(&out_log.to_string_lossy()),
        xml_escape(&err_log.to_string_lossy()),
    )
}

/// Task Scheduler definition: starts at boot as `user` with S4U logon (no stored
/// password), least privilege, restarted on failure.
pub fn generate_windows_task_xml(server_exe: &Path, config_path: &Path, user: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>MailBackup Studio background service</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{}</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>--service --config {}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        xml_escape(user),
        xml_escape(&server_exe.to_string_lossy()),
        xml_escape(&format!("\"{}\"", config_path.to_string_lossy())),
    )
}

/// Account named by `User=` in a systemd unit (`None` = runs as root).
pub fn unit_runs_as(unit: &str) -> Option<String> {
    unit.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("User="))
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty() && u != "root" && u != "0")
}

/// Account named by `UserName` in a launchd plist (`None` = runs as root).
pub fn plist_runs_as(plist: &str) -> Option<String> {
    let after = plist.split("<key>UserName</key>").nth(1)?;
    let start = after.find("<string>")? + "<string>".len();
    let end = after[start..].find("</string>")?;
    let user = after[start..start + end].trim().to_string();
    (!user.is_empty() && user != "root").then_some(user)
}

/// Account named by `<UserId>` in a task definition (`None` = SYSTEM).
pub fn task_runs_as(xml: &str) -> Option<String> {
    let start = xml.find("<UserId>")? + "<UserId>".len();
    let end = xml[start..].find("</UserId>")?;
    let user = xml[start..start + end].trim().to_string();
    let upper = user.to_ascii_uppercase();
    let system = user.is_empty() || upper == "S-1-5-18" || upper == "SYSTEM" || upper.ends_with("\\SYSTEM");
    (!system).then_some(user)
}

// ---------------------------------------------------------------------------
// Install environment
// ---------------------------------------------------------------------------

/// Everything the install/uninstall flow touches. Production code uses
/// [`ServiceEnv::detect`]; tests substitute paths and programs.
#[derive(Debug, Clone)]
pub struct ServiceEnv {
    pub server_exe: PathBuf,
    pub config_path: PathBuf,
    pub user: String,
    /// Private folder (0700) where definitions are staged before installing.
    pub staging_dir: PathBuf,
    /// Where the definition is installed (systemd unit / LaunchDaemon plist).
    pub definition_path: PathBuf,
    pub pkexec: PathBuf,
    pub systemctl: PathBuf,
    pub install: PathBuf,
    pub rm: PathBuf,
}

impl ServiceEnv {
    pub fn detect() -> Result<Self> {
        Ok(Self {
            server_exe: find_server_executable(),
            config_path: crate::config::default_config_path(),
            user: current_user()?,
            staging_dir: crate::config::default_base_dir().join("staging"),
            definition_path: PathBuf::from(if cfg!(target_os = "macos") { LAUNCHD_PLIST_PATH } else { SYSTEMD_UNIT_PATH }),
            pkexec: find_program("pkexec"),
            systemctl: find_program("systemctl"),
            install: find_program("install"),
            rm: find_program("rm"),
        })
    }
}

/// Absolute path of `name` from PATH (pkexec resets PATH, so root commands get
/// absolute paths); falls back to the bare name.
fn find_program(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

/// A definition written to the private staging folder; removed on drop.
struct StagedFile(PathBuf);

impl StagedFile {
    fn write(staging_dir: &Path, extension: &str, content: &[u8]) -> Result<Self> {
        create_private_dir(staging_dir)?;
        let path = staging_dir.join(format!("{}.{}", uuid::Uuid::new_v4().simple(), extension));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Readable by root's install step; the folder itself is private.
            options.mode(0o644);
        }
        let mut file = options.open(&path)?;
        std::io::Write::write_all(&mut file, content)?;
        Ok(Self(path))
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Runs a command and turns a launch failure or a non-zero exit into an error.
fn run_checked(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| Error::Config(format!("{}: could not run {:?}: {}", what, cmd.get_program(), e)))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Config(format!("{} failed ({}). Authorization may have been cancelled.", what, status)))
    }
}

// ---------------------------------------------------------------------------
// Manual commands (shown in the UI for users who prefer to install by hand)
// ---------------------------------------------------------------------------

/// Returns the manual installation shell command for display in the UI or CLI
pub fn get_manual_install_command(server_exe: &Path, config_path: &Path) -> String {
    let user = current_user().unwrap_or_else(|_| "<your-user>".to_string());

    #[cfg(target_os = "macos")]
    {
        format!(
            "sudo tee {path} > /dev/null << 'EOF'\n{}EOF\nsudo chown root:wheel {path} && sudo chmod 644 {path}\nsudo launchctl bootstrap system {path}",
            generate_macos_plist(server_exe, config_path, &user),
            path = LAUNCHD_PLIST_PATH,
        )
    }

    #[cfg(target_os = "windows")]
    {
        format!(
            "Save the following as mailbackup-task.xml, then run in an administrator prompt:\nschtasks /Create /TN \"{}\" /XML mailbackup-task.xml /F\n\n{}",
            SERVICE_TASK_NAME,
            generate_windows_task_xml(server_exe, config_path, &user)
        )
    }

    #[cfg(target_os = "linux")]
    {
        format!(
            "sudo tee {} > /dev/null << 'EOF'\n{}EOF\nsudo systemctl enable {}\nsudo systemctl restart {}",
            SYSTEMD_UNIT_PATH,
            generate_linux_systemd(server_exe, config_path, &user),
            SYSTEMD_SERVICE_NAME,
            SYSTEMD_SERVICE_NAME
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        let _ = user;
        format!("{} --service --config {}", server_exe.display(), config_path.display())
    }
}

/// Returns the manual uninstallation shell command
pub fn get_manual_uninstall_command() -> String {
    #[cfg(target_os = "macos")]
    {
        format!(
            "sudo launchctl bootout system/{} ; sudo rm -f {}",
            SERVICE_IDENTIFIER, LAUNCHD_PLIST_PATH
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
        format!(
            "sudo systemctl disable --now {} && sudo rm -f {} && sudo systemctl daemon-reload",
            SYSTEMD_SERVICE_NAME, SYSTEMD_UNIT_PATH
        )
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        "echo Unsupported".to_string()
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

pub fn get_service_status() -> ServiceStatus {
    let server_exe = find_server_executable();
    let config_path = crate::config::default_config_path();
    let manual_install_cmd = get_manual_install_command(&server_exe, &config_path);
    let manual_uninstall_cmd = get_manual_uninstall_command();

    #[cfg(target_os = "linux")]
    {
        let mut status = linux_status(Path::new(SYSTEMD_UNIT_PATH), Path::new("systemctl"));
        status.manual_install_cmd = manual_install_cmd;
        status.manual_uninstall_cmd = manual_uninstall_cmd;
        status
    }

    #[cfg(target_os = "macos")]
    {
        let content = std::fs::read_to_string(LAUNCHD_PLIST_PATH).ok();
        let installed = content.is_some();
        let runs_as = content.as_deref().and_then(plist_runs_as);
        let running = installed
            && Command::new("launchctl")
                .args(["print", &format!("system/{}", SERVICE_IDENTIFIER)])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        let needs_reinstall = installed && runs_as.is_none();
        ServiceStatus {
            installed,
            running,
            service_type: "macOS LaunchDaemon (starts at boot)".to_string(),
            details: Some(status_details(installed, running, &runs_as, needs_reinstall)),
            manual_install_cmd,
            manual_uninstall_cmd,
            runs_as,
            needs_reinstall,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let xml = Command::new("schtasks")
            .args(["/Query", "/TN", SERVICE_TASK_NAME, "/XML"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| decode_task_query(&o.stdout));
        let installed = xml.is_some();
        let runs_as = xml.as_deref().and_then(task_runs_as);
        let running = installed
            && Command::new("schtasks")
                .args(["/Query", "/TN", SERVICE_TASK_NAME, "/FO", "CSV", "/NH"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("Running"))
                .unwrap_or(false);
        let needs_reinstall = installed && runs_as.is_none();
        ServiceStatus {
            installed,
            running,
            service_type: "Windows boot task (runs as you)".to_string(),
            details: Some(status_details(installed, running, &runs_as, needs_reinstall)),
            manual_install_cmd,
            manual_uninstall_cmd,
            runs_as,
            needs_reinstall,
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
            runs_as: None,
            needs_reinstall: false,
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos", target_os = "windows")), allow(dead_code))]
fn status_details(installed: bool, running: bool, runs_as: &Option<String>, needs_reinstall: bool) -> String {
    if !installed {
        return "Background service is not installed.".to_string();
    }
    if needs_reinstall {
        return "The background service runs with administrator rights (installed by an older version). \
                Turn it off and on again to run it as your user."
            .to_string();
    }
    let who = runs_as.as_deref().unwrap_or("?");
    if running {
        format!("Running as {}; starts at boot.", who)
    } else {
        format!("Installed (runs as {}, starts at boot) but not running right now.", who)
    }
}

/// Linux status for a unit at `unit_path`; the paths are parameters so tests can
/// point them at a temp folder and a fake `systemctl`.
#[cfg(target_os = "linux")]
pub fn linux_status(unit_path: &Path, systemctl: &Path) -> ServiceStatus {
    let content = std::fs::read_to_string(unit_path).ok();
    let installed = content.is_some();
    let runs_as = content.as_deref().and_then(unit_runs_as);
    let running = installed
        && Command::new(systemctl)
            .args(["is-active", SYSTEMD_SERVICE_NAME])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);
    let needs_reinstall = installed && runs_as.is_none();
    ServiceStatus {
        installed,
        running,
        service_type: "Linux systemd service (starts at boot)".to_string(),
        details: Some(status_details(installed, running, &runs_as, needs_reinstall)),
        manual_install_cmd: String::new(),
        manual_uninstall_cmd: String::new(),
        runs_as,
        needs_reinstall,
    }
}

#[cfg(target_os = "windows")]
fn decode_task_query(bytes: &[u8]) -> String {
    // schtasks /XML prints UTF-16LE (with BOM) on most systems
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

/// Installs (or removes) the background service. Installing replaces any older
/// definition, including one that ran as root/SYSTEM.
pub fn set_service_enabled(enabled: bool) -> Result<()> {
    let env = ServiceEnv::detect()?;
    let log_dir = crate::config::default_base_dir().join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    set_service_enabled_in(&env, enabled)
}

#[cfg(target_os = "linux")]
pub fn set_service_enabled_in(env: &ServiceEnv, enabled: bool) -> Result<()> {
    let unit = env.definition_path.to_string_lossy().to_string();
    if enabled {
        let content = generate_linux_systemd(&env.server_exe, &env.config_path, &env.user);
        let staged = StagedFile::write(&env.staging_dir, "service", content.as_bytes())?;
        let staged_path = staged.0.to_string_lossy().to_string();

        run_checked(
            Command::new(&env.pkexec)
                .arg(&env.install)
                .args(["-m", "0644", "-o", "root", "-g", "root", &staged_path, &unit]),
            "Installing the service definition",
        )?;
        drop(staged);

        // The new file must be the one in place (runs as the user, not root)
        let installed = std::fs::read_to_string(&env.definition_path)
            .map_err(|e| Error::Config(format!("Service definition missing after install: {}", e)))?;
        if unit_runs_as(&installed).as_deref() != Some(env.user.as_str()) {
            return Err(Error::Config("The installed service definition doesn't run as your user.".into()));
        }

        // `enable` reloads systemd; `restart` starts it, or replaces an old root instance
        run_checked(
            Command::new(&env.pkexec).arg(&env.systemctl).args(["enable", SYSTEMD_SERVICE_NAME]),
            "Enabling the service",
        )?;
        run_checked(
            Command::new(&env.pkexec).arg(&env.systemctl).args(["restart", SYSTEMD_SERVICE_NAME]),
            "Starting the service",
        )?;
    } else if env.definition_path.exists() {
        run_checked(
            Command::new(&env.pkexec)
                .arg(&env.systemctl)
                .args(["disable", "--now", SYSTEMD_SERVICE_NAME]),
            "Stopping and disabling the service",
        )?;
        run_checked(
            Command::new(&env.pkexec).arg(&env.rm).args(["-f", &unit]),
            "Removing the service definition",
        )?;
        if env.definition_path.exists() {
            return Err(Error::Config(format!("{} is still present after removal.", unit)));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn set_service_enabled_in(env: &ServiceEnv, enabled: bool) -> Result<()> {
    // Constant scripts: the only variable (the staged file) arrives via the
    // environment and is shell-quoted by AppleScript's `quoted form of`.
    const INSTALL_SCRIPT: &str = r#"set staged to system attribute "MB_STAGED_PLIST"
do shell script "/usr/bin/install -m 644 -o root -g wheel " & quoted form of staged & " /Library/LaunchDaemons/com.mailbackup.service.plist && (/bin/launchctl bootout system/com.mailbackup.service 2>/dev/null; true) && /bin/launchctl bootstrap system /Library/LaunchDaemons/com.mailbackup.service.plist" with administrator privileges"#;
    const UNINSTALL_SCRIPT: &str = r#"do shell script "(/bin/launchctl bootout system/com.mailbackup.service 2>/dev/null; true) && /bin/rm -f /Library/LaunchDaemons/com.mailbackup.service.plist" with administrator privileges"#;

    if enabled {
        let content = generate_macos_plist(&env.server_exe, &env.config_path, &env.user);
        let staged = StagedFile::write(&env.staging_dir, "plist", content.as_bytes())?;
        run_checked(
            Command::new("osascript").args(["-e", INSTALL_SCRIPT]).env("MB_STAGED_PLIST", &staged.0),
            "Installing the LaunchDaemon",
        )?;
        drop(staged);
        let installed = std::fs::read_to_string(LAUNCHD_PLIST_PATH)
            .map_err(|e| Error::Config(format!("LaunchDaemon missing after install: {}", e)))?;
        if plist_runs_as(&installed).as_deref() != Some(env.user.as_str()) {
            return Err(Error::Config("The installed LaunchDaemon doesn't run as your user.".into()));
        }
    } else if Path::new(LAUNCHD_PLIST_PATH).exists() {
        run_checked(Command::new("osascript").args(["-e", UNINSTALL_SCRIPT]), "Removing the LaunchDaemon")?;
        if Path::new(LAUNCHD_PLIST_PATH).exists() {
            return Err(Error::Config(format!("{} is still present after removal.", LAUNCHD_PLIST_PATH)));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_service_enabled_in(env: &ServiceEnv, enabled: bool) -> Result<()> {
    // Constant commands: the staged XML path is read from the environment.
    const CREATE_PS: &str = "$p = Start-Process -FilePath schtasks.exe -ArgumentList @('/Create','/TN','MailBackupService','/XML',('\"' + $env:MB_TASK_XML + '\"'),'/F') -Verb RunAs -Wait -PassThru; exit $p.ExitCode";
    const DELETE_PS: &str = "$p = Start-Process -FilePath schtasks.exe -ArgumentList @('/Delete','/TN','MailBackupService','/F') -Verb RunAs -Wait -PassThru; exit $p.ExitCode";

    let task_exists = || {
        Command::new("schtasks")
            .args(["/Query", "/TN", SERVICE_TASK_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    if enabled {
        let xml = generate_windows_task_xml(&env.server_exe, &env.config_path, &env.user);
        // Task Scheduler expects UTF-16 with a BOM for an encoding="UTF-16" document
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
        let staged = StagedFile::write(&env.staging_dir, "xml", &bytes)?;
        run_checked(
            Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", CREATE_PS])
                .env("MB_TASK_XML", &staged.0),
            "Registering the background task",
        )?;
        drop(staged);
        let status = get_service_status();
        if !status.installed || status.runs_as.is_none() {
            return Err(Error::Config("The background task wasn't registered to run as your user.".into()));
        }
        // Start it now as well; if this fails it still starts at the next boot
        let _ = Command::new("schtasks").args(["/Run", "/TN", SERVICE_TASK_NAME]).status();
    } else if task_exists() {
        let _ = Command::new("schtasks").args(["/End", "/TN", SERVICE_TASK_NAME]).status();
        let deleted = Command::new("schtasks")
            .args(["/Delete", "/TN", SERVICE_TASK_NAME, "/F"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !deleted {
            run_checked(
                Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", DELETE_PS]),
                "Removing the background task",
            )?;
        }
        if task_exists() {
            return Err(Error::Config("The background task is still registered after removal.".into()));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn set_service_enabled_in(_env: &ServiceEnv, _enabled: bool) -> Result<()> {
    Err(Error::Config("System service registration not supported on this operating system".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_quoting() {
        assert_eq!(systemd_quote("/opt/Mail Backup/server"), "\"/opt/Mail Backup/server\"");
        assert_eq!(systemd_quote(r#"a"b\c%d"#), r#""a\"b\\c%%d""#);
        assert_eq!(systemd_quote("x\ny"), "\"x y\"");
    }

    #[test]
    fn linux_unit_runs_as_user() {
        let unit = generate_linux_systemd(Path::new("/opt/mb/server"), Path::new("/home/a/.mailbackup/config.yaml"), "alice");
        assert!(unit.contains("\nUser=alice\n"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("ExecStart=\"/opt/mb/server\" --service --config \"/home/a/.mailbackup/config.yaml\""));
        assert_eq!(unit_runs_as(&unit).as_deref(), Some("alice"));

        let legacy = "[Service]\nExecStart=/opt/mb/server --service\n";
        assert_eq!(unit_runs_as(legacy), None);
        assert_eq!(unit_runs_as("[Service]\nUser=root\n"), None);
    }

    #[test]
    fn plist_runs_as_user_and_is_escaped() {
        let plist = generate_macos_plist(Path::new("/Apps/A&B/server"), Path::new("/Users/a/<c>.yaml"), "alice");
        assert!(plist.contains("<key>UserName</key>\n    <string>alice</string>"));
        assert!(plist.contains("/Apps/A&amp;B/server"));
        assert!(plist.contains("/Users/a/&lt;c&gt;.yaml"));
        assert_eq!(plist_runs_as(&plist).as_deref(), Some("alice"));
        assert_eq!(plist_runs_as("<dict><key>Label</key><string>x</string></dict>"), None);
    }

    #[test]
    fn task_xml_uses_s4u_and_user() {
        let xml = generate_windows_task_xml(Path::new(r"C:\Program Files\MB\server.exe"), Path::new(r"C:\Users\a\cfg.yaml"), r"PC\alice");
        assert!(xml.contains("<UserId>PC\\alice</UserId>"));
        assert!(xml.contains("<LogonType>S4U</LogonType>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<BootTrigger>"));
        assert!(xml.contains("&quot;C:\\Users\\a\\cfg.yaml&quot;"));
        assert_eq!(task_runs_as(&xml).as_deref(), Some(r"PC\alice"));
        assert_eq!(task_runs_as("<UserId>S-1-5-18</UserId>"), None);
        assert_eq!(task_runs_as("<UserId>NT AUTHORITY\\SYSTEM</UserId>"), None);
    }

    #[test]
    fn user_name_validation() {
        assert!(is_valid_user_name("alice"));
        assert!(is_valid_user_name("a.b_c-d@corp"));
        for bad in ["", "-x", "a\nUser=root", "a</string>", "a\"b", "a;b", " alice"] {
            assert!(!is_valid_user_name(bad), "{bad:?}");
        }
        if !cfg!(windows) {
            assert!(!is_valid_user_name("a b"));
            assert!(!is_valid_user_name(r"PC\alice"));
        }
    }
}
