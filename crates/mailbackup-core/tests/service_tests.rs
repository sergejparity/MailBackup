//! Install/uninstall flow of the Linux background service, run against fake
//! `pkexec`, `install`, `systemctl` and `rm` programs that record their argument
//! vectors and can be told to fail at a given step.
#![cfg(target_os = "linux")]

use mailbackup_core::service::{linux_status, set_service_enabled_in, ServiceEnv};
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
    _dir: TempDir,
    env: ServiceEnv,
    log: PathBuf,
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{}", body)).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn fixture(fault: Fault) -> Fixture {
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
    let data = dir.path().join("home/.mailbackup");
    let archive = dir.path().join("archive");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&archive).unwrap();

    let env = ServiceEnv {
        server_exe: PathBuf::from("/opt/mailbackup/mailbackup-server"),
        config_path: PathBuf::from("/home/alice/.mailbackup/config.yaml"),
        user: "alice".to_string(),
        staging_dir: dir.path().join("home/.mailbackup/staging"),
        definition_path: dir.path().join("etc/mailbackup.service"),
        pkexec: bin.join("pkexec"),
        systemctl: bin.join("systemctl"),
        install: bin.join("install"),
        rm: bin.join("rm"),
        chown: bin.join("chown"),
        owned_dirs: vec![data, archive, dir.path().join("missing-folder")],
    };
    Fixture { _dir: dir, env, log }
}

fn calls(f: &Fixture) -> Vec<String> {
    std::fs::read_to_string(&f.log)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn install_fixture_unit(f: &Fixture) {
    std::fs::write(&f.env.definition_path, "[Service]\nUser=alice\n").unwrap();
}

#[test]
fn enable_installs_user_unit_with_checked_commands() {
    let f = fixture(Fault::None);
    set_service_enabled_in(&f.env, true).unwrap();

    let unit = std::fs::read_to_string(&f.env.definition_path).unwrap();
    assert!(unit.contains("\nUser=alice\n"), "{unit}");

    let c = calls(&f);
    let unit_path = f.env.definition_path.display().to_string();
    assert!(c[0].starts_with(&format!("pkexec {} -m 0644 -o root -g root ", f.env.install.display())), "{c:?}");
    assert!(c[0].ends_with(&unit_path), "{c:?}");
    // The staged file lived in the private staging folder, never in a temp dir
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
        let leftovers = std::fs::read_dir(&f.env.staging_dir).map(|d| d.count()).unwrap_or(0);
        assert_eq!(leftovers, 0);
    }
}

#[test]
fn disable_removes_unit_with_checked_commands() {
    let f = fixture(Fault::None);
    install_fixture_unit(&f);
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
        install_fixture_unit(&f);
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
fn status_flags_root_units_for_reinstall() {
    let f = fixture(Fault::None);

    let missing = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(!missing.installed && !missing.needs_reinstall);

    std::fs::write(&f.env.definition_path, "[Service]\nExecStart=/opt/x --service\n").unwrap();
    let legacy = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(legacy.installed && legacy.needs_reinstall && legacy.runs_as.is_none());
    assert!(legacy.details.unwrap().contains("administrator rights"));

    install_fixture_unit(&f);
    let current = linux_status(&f.env.definition_path, &f.env.systemctl);
    assert!(current.installed && current.running && !current.needs_reinstall);
    assert_eq!(current.runs_as.as_deref(), Some("alice"));
}

fn install_legacy_root_unit(f: &Fixture) {
    std::fs::write(&f.env.definition_path, "[Service]\nExecStart=/opt/x --service\n").unwrap();
}

#[test]
fn fresh_install_does_not_touch_ownership() {
    let f = fixture(Fault::None);
    set_service_enabled_in(&f.env, true).unwrap();
    assert!(!calls(&f).iter().any(|l| l.contains("chown")), "{:?}", calls(&f));
}

#[test]
fn migrating_from_root_gives_files_back_to_the_user() {
    let f = fixture(Fault::None);
    install_legacy_root_unit(&f);
    set_service_enabled_in(&f.env, true).unwrap();

    let c = calls(&f);
    let expected = format!(
        "pkexec {} -R -h alice {} {}",
        f.env.chown.display(),
        f.env.owned_dirs[0].display(),
        f.env.owned_dirs[1].display()
    );
    let chown_at = c.iter().position(|l| l == &expected).unwrap_or_else(|| panic!("{c:?}"));
    // Ownership is fixed before the service is started as the user
    let restart_at = c.iter().position(|l| l.ends_with("systemctl restart mailbackup.service")).unwrap();
    assert!(chown_at < restart_at, "{c:?}");
    assert!(std::fs::read_to_string(&f.env.definition_path).unwrap().contains("User=alice"));
}

#[test]
fn failed_ownership_fix_stops_the_migration() {
    let f = fixture(Fault::Chown);
    install_legacy_root_unit(&f);
    let err = set_service_enabled_in(&f.env, true).unwrap_err().to_string();
    assert!(err.contains("ownership"), "{err}");
    assert!(!calls(&f).iter().any(|l| l.contains("systemctl")), "{:?}", calls(&f));
}
