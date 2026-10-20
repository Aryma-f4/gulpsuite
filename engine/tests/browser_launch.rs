use gulpsuite::browser::{BrowserInstall, LaunchConfig};
use gulpsuite::platform_paths::data_dir_for;
use std::path::{Path, PathBuf};

#[test]
fn profiles_follow_platform_data_directories_not_working_directory() {
    assert_eq!(
        data_dir_for("macos", Some("/Users/person"), None).unwrap(),
        PathBuf::from("/Users/person/Library/Application Support/Gulpsuite")
    );
    assert_eq!(
        data_dir_for("linux", Some("/home/person"), None).unwrap(),
        PathBuf::from("/home/person/.local/share/gulpsuite")
    );
    assert_eq!(
        data_dir_for("linux", None, Some("/data/private")).unwrap(),
        PathBuf::from("/data/private/gulpsuite")
    );
    assert_eq!(
        data_dir_for("windows", None, Some("C:/Users/person/AppData/Local")).unwrap(),
        PathBuf::from("C:/Users/person/AppData/Local/Gulpsuite")
    );
    assert!(data_dir_for("windows", Some("/home"), None).is_err());
    assert!(data_dir_for("linux", None, Some("relative")).is_err());
    assert!(data_dir_for("windows", None, Some("C:relative")).is_err());
    assert!(data_dir_for("windows", None, Some("/relative-to-drive")).is_err());
}

fn config() -> LaunchConfig {
    LaunchConfig {
        proxy_port: 18765,
        ca_spki: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        profile_dir: std::env::temp_dir().join("private/profile with spaces"),
        target: "https://example.test/a?q=1".into(),
    }
}

#[test]
fn browser_arguments_route_loopback_and_only_trust_the_proxy_pin() {
    let args = config().arguments().unwrap();
    let args: Vec<_> = args
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&"--proxy-server=http://127.0.0.1:18765".into()));
    assert!(args.contains(&"--proxy-bypass-list=<-loopback>".into()));
    assert!(args.contains(&"--disable-quic".into()));
    assert!(args.contains(
        &"--ignore-certificate-errors-spki-list=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            .into()
    ));
    assert!(args.contains(&format!("--user-data-dir={}", config().profile_dir.display())));
    assert_eq!(args.last().unwrap(), "https://example.test/a?q=1");
    assert!(!args
        .iter()
        .any(|s| s == "--ignore-certificate-errors" || s == "--no-sandbox"));
}

#[test]
fn invalid_launch_targets_and_pins_are_refused() {
    for target in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "--no-sandbox",
        "https://user:secret@example.test/",
    ] {
        let mut input = config();
        input.target = target.into();
        assert!(input.arguments().is_err(), "accepted {target}");
    }
    let mut input = config();
    input.proxy_port = 0;
    assert!(input.arguments().is_err());
    input.proxy_port = 8080;
    input.ca_spki = "invalid,pin".into();
    assert!(input.arguments().is_err());
    input = config();
    input.target = "about:blank".into();
    assert!(input.arguments().is_ok());
}

#[test]
fn resources_are_resolved_from_each_installed_executable_layout() {
    for (platform, app, resources) in [
        (
            "macos-arm64",
            "/Applications/Gulp Test.app/Contents/MacOS/Gulpsuite",
            "/Applications/Gulp Test.app/Contents/Resources",
        ),
        (
            "macos-x64",
            "/Applications/Gulp Test.app/Contents/MacOS/Gulpsuite",
            "/Applications/Gulp Test.app/Contents/Resources",
        ),
        (
            "windows-x64",
            "/Program Files/Gulpsuite/gulpsuite.exe",
            "/Program Files/Gulpsuite/resources",
        ),
        (
            "linux-x64",
            "/opt/gulpsuite/gulpsuite",
            "/opt/gulpsuite/resources",
        ),
    ] {
        assert_eq!(
            BrowserInstall::resource_dir(Path::new(app), platform).unwrap(),
            PathBuf::from(resources)
        );
    }
    assert!(BrowserInstall::from_app_executable(Path::new("/not/installed/gulpsuite")).is_err());
}

#[test]
fn session_ca_pin_has_exact_sha256_size_and_changes_with_authority() {
    use base64::Engine;
    let a = gulpsuite::tls::Authority::generate().unwrap();
    let b = gulpsuite::tls::Authority::generate().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(a.spki_pin())
        .unwrap();
    assert_eq!(decoded.len(), 32);
    assert_ne!(a.spki_pin(), b.spki_pin());
}

#[cfg(unix)]
#[test]
fn owned_browser_shutdown_does_not_kill_an_unrelated_process() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("gulp-owned-browser-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir_all(&root).unwrap();
    let executable = root.join("fake-browser");
    let pid_file = root.join("owned.pid");
    std::fs::write(&executable, format!("#!/bin/sh\necho $$ > '{}'\nexec sleep 60\n", pid_file.display())).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut unrelated = std::process::Command::new("sleep").arg("60").spawn().unwrap();
    let install = BrowserInstall { executable, revision: "fixture".into() };
    let mut input = config(); input.profile_dir = root.join("profile");
    let session = install.launch(input).unwrap();
    let pid: i32 = std::fs::read_to_string(pid_file).unwrap().trim().parse().unwrap();
    drop(session);
    assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "owned browser was not reaped");
    assert!(unrelated.try_wait().unwrap().is_none(), "unrelated process was terminated");
    unrelated.kill().unwrap(); unrelated.wait().unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn spawn_errors_do_not_report_browser_success() {
    let install = BrowserInstall { executable: PathBuf::from("/nonexistent/gulpsuite-chromium"), revision: "fixture".into() };
    let mut input = config(); input.profile_dir = std::env::temp_dir().join(format!("gulp-missing-browser-{}", std::process::id()));
    assert!(install.launch(input.clone()).is_err());
    let _ = std::fs::remove_dir(input.profile_dir);
}

#[test]
fn standalone_gulpsuite_binary_discovers_staged_chromium_when_present() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let manifest = root.join(".build/browser-stage/resources/chromium-manifest.json");
    if manifest.is_file() {
        let install = BrowserInstall::from_app_executable(&root.join("gulpsuite")).expect("staged browser");
        assert!(install.executable.is_file());
    }
}
