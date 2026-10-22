//! Install/uninstall flow of the Linux background service, run against fake
//! `pkexec`, `install`, `systemctl`, `rm` and `chown` programs that record their
//! argument vectors and can be told to fail at a given step.
#![cfg(target_os = "linux")]

use mailbackup_core::service::{
    linux_status, ownership_candidates, set_service_enabled_in, trusted_program, ServiceEnv,
};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Which fake command exits non-zero (or misbehaves).
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    Install,
    /// `install` succeeds but leaves a definition that runs as root
    InstallLegacyContent,
    SystemctlEnable,
    SystemctlRestart,
    SystemctlDisable,
    Rm,
    /// `rm` exits 0 without removing anything
    RmNoop,
    Chown,
}

struct Fixture {
    dir: TempDir,
    env: ServiceEnv,
    log: PathBuf,
    user: String,
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{}", body)).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn current_user() -> String {
    let out = std::process::Command::new(trusted_program("id").unwrap()).arg("-un").output().unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// Service installed for an account that owns every fixture file, so no
/// ownership repair is needed: the account running the tests, or `nobody` (with
/// the files handed to it) when the tests run as root, which can't be a service
/// account.
fn fixture(fault: Fault) -> Fixture {
    let me = current_user();
    if me != "root" {
        return fixture_as(fault, &me);
    }
    let f = fixture_as(fault, "nobody");
    let status = std::process::Command::new(trusted_program("chown").unwrap())
        .args(["-R", "nobody"])
        .arg(f.dir.path().join("home"))
        .status()
        .unwrap();
    assert!(status.success());
    f
}

/// Service installed for `user`. With another account (e.g. `nobody`) the
/// fixture's files count as left behind by someone else and need repair.
fn fixture_as(fault: Fault, user: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(dir.path().join("etc")).unwrap();
    let log = dir.path().join("calls.log");
    let log_s = log.display().to_string();

    script(&bin.join("pkexec"), &format!("echo \"pkexec $*\" >> '{log_s}'\nexec \"$@\"\n"));

    let install_body = match fault {
        Fault::Install => "exit 1\n".to_string(),
        Fault::InstallLegacyContent => {
            "for a; do last=$a; done\nprintf '[Service]\\nExecStart=/x --service\\n' > \"$last\"\n".to_string()
        }
        _ => "for a; do prev=$last; last=$a; done\ncp \"$prev\" \"$last\"\n".to_string(),
    };
    script(&bin.join("install"), &format!("echo \"install $*\" >> '{log_s}'\n{install_body}"));

    let failing = match fault {
        Fault::SystemctlEnable => "enable",
        Fault::SystemctlRestart => "restart",
        Fault::SystemctlDisable => "disable",
        _ => "__none__",
    };
    script(
        &bin.join("systemctl"),
        &format!(
            "echo \"systemctl $*\" >> '{log_s}'\n[ \"$1\" = \"{failing}\" ] && exit 1\n[ \"$1\" = is-active ] && echo active\nexit 0\n"
        ),
    );

    let rm_body = match fault {
        Fault::Rm => "exit 1\n",
        Fault::RmNoop => "exit 0\n",
        _ => "exec /bin/rm \"$@\"\n",
    };
    script(&bin.join("rm"), &format!("echo \"rm $*\" >> '{log_s}'\n{rm_body}"));

    let chown_body = if fault == Fault::Chown { "exit 1\n" } else { "exit 0\n" };
    script(&bin.join("chown"), &format!("echo \"chown $*\" >> '{log_s}'\n{chown_body}"));

    // A realistic MailBackup folder: config, credentials, catalog, archive
    let base = dir.path().join("home/.mailbackup");
    let data = base.join("data");
    std::fs::create_dir_all(data.join("acc/inbox/2026/10")).unwrap();
    std::fs::write(data.join("acc/inbox/2026/10/1_abc.eml"), "Subject: x").unwrap();
    std::fs::write(base.join("mailbackup.db"), "db").unwrap();
    std::fs::write(base.join(".credentials_store.json"), "{}").unwrap();
    std::fs::write(base.join(".credentials_key"), "k").unwrap();
    let config = base.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "data_dir: {}\ndb_path: {}\nsettings: {{}}\naccounts: []\n",
            data.display(),
            base.join("mailbackup.db").display()
        ),
    )
    .unwrap();

    let env = ServiceEnv {
        server_exe: PathBuf::from("/opt/mailbackup/mailbackup-server"),
        config_path: config,
        user: Ok(user.to_string()),
        staging_dir: base.join("staging"),
        definition_path: dir.path().join("etc/mailbackup.service"),
        pkexec: bin.join("pkexec"),
        systemctl: bin.join("systemctl"),
        install: bin.join("install"),
        rm: bin.join("rm"),
        chown: bin.join("chown"),
        id: trusted_program("id").unwrap(),
    };
    Fixture { dir, env, log, user: user.to_string() }
}

fn calls(f: &Fixture) -> Vec<String> {
    std::fs::read_to_string(&f.log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

/// A real account other than the one running the tests (and not root), so the
/// fixture's files count as left behind by someone else.
fn other_account() -> &'static str {
    if current_user() == "nobody" {
        "daemon"
    } else {
        "nobody"
    }
}

fn install_user_unit(f: &Fixture) {
    std::fs::write(&f.env.definition_path, format!("[Service]\nUser={}\n", f.user)).unwrap();
}

fn install_legacy_root_unit(f: &Fixture) {
    std::fs::write(&f.env.definition_path, "[Service]\nExecStart=/opt/x --service\n").unwrap();
}

#[test]
fn enable_installs_user_unit_with_checked_commands() {
    let f = fixture(Fault::None);
    set_service_enabled_in(&f.env, true).unwrap();

    let unit = std::fs::read_to_string(&f.env.definition_path).unwrap();
    assert!(unit.contains(&format!("\nUser={}\n", f.user)), "{unit}");

    let c = calls(&f);
    let unit_path = f.env.definition_path.display().to_string();
    assert!(c[0].starts_with(&format!("pkexec {} -m 0644 -o root -g root ", f.env.install.display())), "{c:?}");
    assert!(c[0].ends_with(&unit_path), "{c:?}");
    // The staged file lived in the private staging folder and is gone
    let staged = c[0].split_whitespace().nth(8).unwrap().to_string();
    assert_eq!(Path::new(&staged).parent(), Some(f.env.staging_dir.as_path()), "{staged}");
    assert!(!Path::new(&staged).exists(), "staged file must be removed");
    let mode = std::fs::metadata(&f.env.staging_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    let pkexec_calls: Vec<&String> = c.iter().filter(|l| l.starts_with("pkexec ")).collect();
    assert_eq!(pkexec_calls.len(), 3, "{c:?}");
    assert!(pkexec_calls[1].ends_with("systemctl enable mailbackup.service"));
    assert!(pkexec_calls[2].ends_with("systemctl restart mailbackup.service"));
    // Every elevated call runs a program directly, never a shell
    for call in &pkexec_calls {
        let program = call.split_whitespace().nth(1).unwrap();
        assert!(!program.ends_with("/sh") && program != "sh" && !program.ends_with("bash"), "{call}");
    }
}

#[test]
fn enable_reports_each_failing_step() {
    for (fault, expected, must_not_run) in [
        (Fault::Install, "Installing the service definition", "systemctl"),
        (Fault::InstallLegacyContent, "doesn't run as your user", "systemctl"),
        (Fault::SystemctlEnable, "Enabling the service", "systemctl restart"),
        (Fault::SystemctlRestart, "Starting the service", "__nothing__"),
    ] {
        let f = fixture(fault);
        let err = set_service_enabled_in(&f.env, true).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
        assert!(!calls(&f).iter().any(|l| l.starts_with(must_not_run)), "{:?}", calls(&f));
        // No staged files are left behind on failure either
        let staged = std::fs::read_dir(&f.env.staging_dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(staged, 0);
    }
}

#[test]
fn disable_removes_unit_with_checked_commands() {
    let f = fixture(Fault::None);
    install_user_unit(&f);
    set_service_enabled_in(&f.env, false).unwrap();
    assert!(!f.env.definition_path.exists());

    let c = calls(&f);
    assert!(c.iter().any(|l| l.ends_with("systemctl disable --now mailbackup.service")), "{c:?}");
    assert!(c.iter().any(|l| l == &format!("pkexec {} -f {}", f.env.rm.display(), f.env.definition_path.display())), "{c:?}");
}

#[test]
fn disable_reports_each_failing_step() {
    for (fault, expected) in [
        (Fault::SystemctlDisable, "Stopping and disabling the service"),
        (Fault::Rm, "Removing the service definition"),
        (Fault::RmNoop, "still present after removal"),
    ] {
        let f = fixture(fault);
        install_user_unit(&f);
        let err = set_service_enabled_in(&f.env, false).unwrap_err().to_string();
        assert!(err.contains(expected), "{err}");
        if fault == Fault::SystemctlDisable {
            assert!(!calls(&f).iter().any(|l| l.starts_with("rm ")), "rm must not run after a failed disable");
        }
    }
}

#[test]
fn disable_without_unit_is_a_no_op() {
    let f = fixture(Fault::None);
    set_service_enabled_in(&f.env, false).unwrap();
    assert!(calls(&f).is_empty());
}

#[test]
fn removal_works_without_a_service_user() {
    // e.g. the old root service serving the UI couldn't determine an account
    let mut f = fixture(Fault::None);
    f.env.user = Err("can't tell which user".to_string());
    install_user_unit(&f);
    set_service_enabled_in(&f.env, false).unwrap();
    assert!(!f.env.definition_path.exists());

    // ...while installing reports why it can't proceed, before running anything
    let err = set_service_enabled_in(&f.env, true).unwrap_err().to_string();
    assert!(err.contains("can't tell which user"), "{err}");
    assert!(!calls(&f).iter().any(|l| l.starts_with("pkexec") && l.contains("install")));
}

#[test]
fn status_flags_root_units_for_reinstall() {
    let f = fixture(Fault::None);

    let missing = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(!missing.installed && !missing.needs_reinstall);

    install_legacy_root_unit(&f);
    let legacy = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(legacy.installed && legacy.needs_reinstall && legacy.runs_as.is_none());
    assert!(legacy.details.unwrap().contains("administrator rights"));

    install_user_unit(&f);
    let current = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(current.installed && current.running && !current.needs_reinstall);
    assert_eq!(current.runs_as.as_deref(), Some(f.user.as_str()));
}

// --- Ownership repair after an old root service -------------------------------

fn chown_call(f: &Fixture) -> Option<String> {
    calls(f).into_iter().find(|l| l.starts_with(&format!("pkexec {}", f.env.chown.display())))
}

#[test]
fn files_already_owned_by_the_user_are_left_alone() {
    let f = fixture(Fault::None);
    install_legacy_root_unit(&f);
    set_service_enabled_in(&f.env, true).unwrap();
    assert_eq!(chown_call(&f), None, "{:?}", calls(&f));
}

#[test]
fn foreign_owned_files_are_given_to_the_service_user_before_start() {
    let f = fixture_as(Fault::None, other_account());
    install_legacy_root_unit(&f);
    set_service_enabled_in(&f.env, true).unwrap();

    let call = chown_call(&f).unwrap_or_else(|| panic!("{:?}", calls(&f)));
    let args: Vec<&str> = call.split_whitespace().skip(2).collect();
    assert_eq!(&args[..3], ["-R", "-h", f.user.as_str()]);
    let base = f.dir.path().join("home/.mailbackup");
    let targets: Vec<PathBuf> = args[3..].iter().map(PathBuf::from).collect();
    for expected in [
        base.join("config.yaml"),
        base.join(".credentials_store.json"),
        base.join(".credentials_key"),
        base.join("mailbackup.db"),
        base.join("data"),
    ] {
        assert!(targets.contains(&expected), "missing {} in {call}", expected.display());
    }
    // Only MailBackup's own files and archive: never the folders around them
    for not_expected in [base.clone(), f.dir.path().join("home"), f.dir.path().to_path_buf()] {
        assert!(!targets.contains(&not_expected), "{} in {call}", not_expected.display());
    }
    // Missing files (WAL/SHM, logs) aren't passed
    assert!(targets.iter().all(|t| t.exists()), "{call}");

    let c = calls(&f);
    let chown_at = c.iter().position(|l| l == &call).unwrap();
    let restart_at = c.iter().position(|l| l.ends_with("systemctl restart mailbackup.service")).unwrap();
    assert!(chown_at < restart_at, "ownership must be fixed before the service starts: {c:?}");
}

#[test]
fn off_then_on_still_repairs_ownership() {
    // The documented migration: turn the old service off (removing its
    // definition), then on again
    let f = fixture_as(Fault::None, other_account());
    install_legacy_root_unit(&f);
    set_service_enabled_in(&f.env, false).unwrap();
    assert!(!f.env.definition_path.exists());
    set_service_enabled_in(&f.env, true).unwrap();
    assert!(chown_call(&f).is_some(), "{:?}", calls(&f));
}

#[test]
fn failed_ownership_fix_stops_the_migration() {
    let f = fixture_as(Fault::Chown, other_account());
    install_legacy_root_unit(&f);
    let err = set_service_enabled_in(&f.env, true).unwrap_err().to_string();
    assert!(err.contains("ownership"), "{err}");
    assert!(!calls(&f).iter().any(|l| l.contains("systemctl")), "{:?}", calls(&f));
}

#[test]
fn ownership_repair_never_targets_system_folders() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    // Custom catalog in /var/lib and a data folder pointing at a system folder
    std::fs::write(
        &config,
        "data_dir: /var/lib\ndb_path: /var/lib/mailbackup-test.db\nsettings: {}\naccounts: []\n",
    )
    .unwrap();
    let candidates = ownership_candidates(&config);
    for forbidden in ["/var/lib", "/var", "/", "/etc"] {
        assert!(!candidates.contains(&PathBuf::from(forbidden)), "{forbidden} in {candidates:?}");
    }
    assert!(candidates.contains(&PathBuf::from("/var/lib/mailbackup-test.db")));
    assert!(candidates.contains(&PathBuf::from("/var/lib/mailbackup-test.db-wal")));
    assert!(!candidates.contains(&dir.path().to_path_buf()), "the config's folder itself is never included");
}

#[test]
fn privileged_process_installs_for_the_config_owner() {
    use std::os::unix::fs::MetadataExt;
    // Needs root to hand a file to another account; skipped otherwise
    if std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(1) != 0 {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.yaml");
    std::fs::write(&config, "x").unwrap();
    let status = std::process::Command::new("/bin/chown").args(["nobody", config.to_str().unwrap()]).status().unwrap();
    assert!(status.success());

    // The old root service: USER=root, but the config belongs to `nobody`
    std::env::set_var("USER", "root");
    assert_eq!(mailbackup_core::service::service_user(&config).unwrap(), "nobody");

    // A config that only root owns gives no safe account to install for
    let root_only = dir.path().join("root.yaml");
    std::fs::write(&root_only, "x").unwrap();
    assert!(mailbackup_core::service::service_user(&root_only).is_err());
}
