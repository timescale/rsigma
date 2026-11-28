//! Config discovery: `config path` lists every location it searched,
//! including the per-platform system directory; the `.rsigmarc` walk stops
//! at `$HOME`; and on Unix a discovered file that other accounts may write
//! is skipped with a warning.

use crate::common;

use std::path::Path;

use common::rsigma;

/// Run `config path --output-format json` in `cwd` with a private home and
/// user config directory, returning the parsed envelope.
fn config_path_json(cwd: &Path, home: &Path) -> serde_json::Value {
    let output = rsigma()
        .args(["config", "path", "--output-format", "json"])
        .current_dir(cwd)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .output()
        .unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn searched<'a>(envelope: &'a serde_json::Value, layer: &str) -> &'a serde_json::Value {
    envelope["searched"]
        .as_array()
        .unwrap()
        .iter()
        .find(|location| location["layer"] == layer)
        .unwrap_or_else(|| panic!("no {layer} location in {envelope}"))
}

#[test]
fn config_path_lists_the_system_location() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let envelope = config_path_json(cwd.path(), home.path());
    let system = searched(&envelope, "system");
    let path = Path::new(system["path"].as_str().unwrap());
    assert!(path.is_absolute(), "{}", path.display());
    assert!(path.ends_with("rsigma/config.yaml"), "{}", path.display());
    #[cfg(unix)]
    assert_eq!(path, Path::new("/etc/rsigma/config.yaml"));
    #[cfg(windows)]
    {
        let program_data = std::env::var_os("ProgramData").expect("ProgramData is set");
        let expected = Path::new(&program_data).join("rsigma").join("config.yaml");
        assert!(
            path.as_os_str().eq_ignore_ascii_case(expected.as_os_str()),
            "{} vs {}",
            path.display(),
            expected.display()
        );
    }

    let user = searched(&envelope, "user");
    assert_eq!(
        Path::new(user["path"].as_str().unwrap()),
        home.path()
            .join(".config")
            .join("rsigma")
            .join("config.yaml")
    );
    assert_eq!(user["status"], "missing");
}

#[test]
fn config_path_text_mode_names_the_searched_locations() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let output = rsigma()
        .args(["config", "path"])
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("Searched"), "{stdout}");
    assert!(
        stderr.contains("Searched (low to high precedence):"),
        "{stderr}"
    );
    let system = stderr
        .lines()
        .find(|line| line.trim_start().starts_with("system"))
        .unwrap_or_else(|| panic!("{stderr}"));
    #[cfg(unix)]
    assert!(system.contains("/etc/rsigma/config.yaml"), "{system}");
    #[cfg(windows)]
    assert!(system.contains(r"\rsigma\config.yaml"), "{system}");
}

#[test]
fn the_rsigmarc_walk_stops_at_home() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let cwd = home.join("repo/rules");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::write(root.path().join(".rsigmarc"), "version: 1\n").unwrap();

    // Windows reads the home directory from the profile known folder, not HOME.
    #[cfg(unix)]
    {
        let envelope = config_path_json(&cwd, &home);
        assert_eq!(searched(&envelope, "project_rc")["status"], "missing");
    }

    let elsewhere = tempfile::tempdir().unwrap();
    let envelope = config_path_json(&cwd, elsewhere.path());
    let rc = searched(&envelope, "project_rc");
    assert_eq!(rc["status"], "loaded", "{envelope}");
    assert_eq!(
        std::fs::canonicalize(rc["path"].as_str().unwrap()).unwrap(),
        std::fs::canonicalize(root.path().join(".rsigmarc")).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn a_project_file_other_users_may_write_is_skipped() {
    use std::os::unix::fs::PermissionsExt;

    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let config = project.path().join("rsigma.yaml");
    std::fs::write(&config, "eval:\n  rules: ./from-project\n").unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();

    let output = rsigma()
        .args(["config", "validate", "--format", "json"])
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let skipped = envelope["skipped_files"].as_array().unwrap();
    assert_eq!(skipped.len(), 1, "{envelope}");
    assert_eq!(skipped[0]["file"], "./rsigma.yaml");
    assert_eq!(skipped[0]["reason"], "the file is writable by all users");
    assert!(envelope["sources"].as_array().unwrap().is_empty());

    let output = rsigma()
        .args(["config", "show", "--for", "eval"])
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("from-project"), "{stdout}");
    assert!(
        stderr.contains("warning: skipping config ./rsigma.yaml: the file is writable by all users; pass it with --config to read it anyway"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn a_user_config_in_a_world_writable_directory_is_skipped() {
    use std::os::unix::fs::PermissionsExt;

    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".config/rsigma");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.yaml"), "version: 1\n").unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

    let envelope = config_path_json(cwd.path(), home.path());
    let user = searched(&envelope, "user");
    assert_eq!(user["status"], "skipped", "{envelope}");
    let reason = user["reason"].as_str().unwrap();
    assert!(reason.starts_with("its directory "), "{reason}");
    assert!(reason.ends_with("is writable by all users"), "{reason}");

    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let envelope = config_path_json(cwd.path(), home.path());
    assert_eq!(searched(&envelope, "user")["status"], "loaded");
}

#[test]
fn an_explicit_config_is_read_even_when_discovery_would_skip_it() {
    let project = tempfile::tempdir().unwrap();
    let config = project.path().join("rsigma.yaml");
    std::fs::write(&config, "version: 1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    rsigma()
        .args(["config", "validate", "-c"])
        .arg(&config)
        .assert()
        .success();
}
