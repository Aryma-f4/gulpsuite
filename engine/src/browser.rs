//! Bundled Chromium, owned by this app session, with no global browser settings changes.
use base64::Engine;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub fn platform() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "macos-x64"
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "windows-x64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x64"
    } else {
        "unsupported"
    }
}

#[derive(Clone, Debug)]
pub struct LaunchConfig {
    pub proxy_port: u16,
    pub ca_spki: String,
    pub profile_dir: PathBuf,
    pub target: String,
}

impl LaunchConfig {
    pub fn arguments(&self) -> Result<Vec<OsString>, String> {
        if self.proxy_port == 0
            || base64::engine::general_purpose::STANDARD
                .decode(&self.ca_spki)
                .map(|pin| pin.len() != 32)
                .unwrap_or(true)
        {
            return Err("invalid browser proxy port or session CA pin".into());
        }
        if !self.profile_dir.is_absolute() {
            return Err("browser profile must be absolute".into());
        }
        if self.target != "about:blank" {
            let target = url::Url::parse(&self.target).map_err(|e| e.to_string())?;
            if !matches!(target.scheme(), "http" | "https")
                || target.host_str().is_none()
                || !target.username().is_empty()
                || target.password().is_some()
            {
                return Err(
                    "browser target must be HTTP/HTTPS without embedded credentials".into(),
                );
            }
        }
        let mut profile: OsString = "--user-data-dir=".into();
        profile.push(&self.profile_dir);
        Ok(vec![
            profile,
            format!("--proxy-server=http://127.0.0.1:{}", self.proxy_port).into(),
            "--proxy-bypass-list=<-loopback>".into(),
            "--disable-quic".into(),
            format!("--ignore-certificate-errors-spki-list={}", self.ca_spki).into(),
            "--no-first-run".into(),
            "--no-default-browser-check".into(),
            "--disable-background-networking".into(),
            "--disable-sync".into(),
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(),
            self.target.clone().into(),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct BrowserInstall {
    pub executable: PathBuf,
    pub revision: String,
}

impl BrowserInstall {
    pub fn resource_dir(app: &Path, platform: &str) -> Result<PathBuf, String> {
        let parent = app
            .parent()
            .ok_or("application executable has no directory")?;
        Ok(if platform.starts_with("macos-") {
            parent
                .parent()
                .ok_or("application bundle has no Contents directory")?
                .join("Resources")
        } else if matches!(platform, "windows-x64" | "linux-x64") {
            parent.join("resources")
        } else {
            return Err("unsupported bundled browser platform".into());
        })
    }

    pub fn from_app_executable(app: &Path) -> Result<Self, String> {
        let is_gulpsuite_bin = app.is_file()
            && app
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| {
                    let lower = s.to_ascii_lowercase();
                    lower == "gulpsuite" || lower.starts_with("gulpsuite-setup")
                });
        let mut resources = Self::resource_dir(app, platform())?;
        if !resources.join("chromium-manifest.json").is_file() && is_gulpsuite_bin {
            let mut ancestor = app.parent();
            for _ in 0..4 {
                let Some(dir) = ancestor else { break };
                let staged = dir.join(".build/browser-stage/resources");
                if staged.join("chromium-manifest.json").is_file() {
                    resources = staged;
                    break;
                }
                ancestor = dir.parent();
            }
        }
        if !resources.join("chromium-manifest.json").is_file() && is_gulpsuite_bin {
            if let Some(sys_browser) = Self::find_system_chromium_browser() {
                return Ok(Self {
                    executable: sys_browser,
                    revision: "system-chromium".into(),
                });
            }
        }
        let raw = std::fs::read(resources.join("chromium-manifest.json"))
            .map_err(|_| "Bundled Chromium is missing. Install the complete Gulpsuite package, not the standalone binary.".to_string())?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if manifest["platform"].as_str() != Some(platform()) {
            return Err("bundled Chromium architecture mismatch".into());
        }
        let relative = match platform() {
            "macos-arm64" | "macos-x64" => "Chromium.app/Contents/MacOS/Chromium",
            "windows-x64" => "chrome.exe",
            "linux-x64" => "chrome",
            _ => return Err("unsupported browser platform".into()),
        };
        if manifest["executable"].as_str() != Some(relative) {
            return Err("invalid bundled browser executable".into());
        }
        let executable = resources.join("chromium").join(relative);
        if !executable.is_file() {
            if is_gulpsuite_bin {
                if let Some(sys_browser) = Self::find_system_chromium_browser() {
                    return Ok(Self {
                        executable: sys_browser,
                        revision: "system-chromium".into(),
                    });
                }
            }
            return Err(format!(
                "bundled Chromium executable is missing: {}",
                executable.display()
            ));
        }
        Ok(Self {
            executable,
            revision: manifest["revision"]
                .as_str()
                .ok_or("browser revision missing")?
                .into(),
        })
    }

    /// Discovers an installed Chromium-based browser (Chromium, Google Chrome, Brave, Microsoft Edge)
    /// when the standalone binary is run without a staged `resources/chromium` bundle.
    pub fn find_system_chromium_browser() -> Option<PathBuf> {
        if let Ok(custom) = std::env::var("GULPSUITE_BROWSER_PATH") {
            let p = PathBuf::from(custom);
            if p.is_file() {
                return Some(p);
            }
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if cfg!(target_os = "macos") {
            if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
                candidates.push(home.join(
                    "Applications/Gulpsuite.app/Contents/Resources/chromium/Chromium.app/Contents/MacOS/Chromium",
                ));
                candidates.push(home.join("Applications/Chromium.app/Contents/MacOS/Chromium"));
                candidates.push(
                    home.join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                );
                candidates.push(
                    home.join("Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
                );
            }
            candidates.extend([
                PathBuf::from(
                    "/Applications/Gulpsuite.app/Contents/Resources/chromium/Chromium.app/Contents/MacOS/Chromium",
                ),
                PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
                PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                PathBuf::from("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
                PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
            ]);
        } else if cfg!(target_os = "windows") {
            for env_key in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
                if let Some(base) = std::env::var_os(env_key).map(PathBuf::from) {
                    candidates.push(base.join("Google/Chrome/Application/chrome.exe"));
                    candidates.push(base.join("Chromium/Application/chrome.exe"));
                    candidates.push(base.join("BraveSoftware/Brave-Browser/Application/brave.exe"));
                    candidates.push(base.join("Microsoft/Edge/Application/msedge.exe"));
                    candidates.push(base.join("Programs/Gulpsuite/resources/chromium/chrome.exe"));
                }
            }
            candidates.extend([
                PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"),
                PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
                PathBuf::from(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"),
                PathBuf::from(r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"),
            ]);
        } else {
            candidates.extend([
                PathBuf::from("/usr/bin/chromium"),
                PathBuf::from("/usr/bin/chromium-browser"),
                PathBuf::from("/usr/bin/google-chrome"),
                PathBuf::from("/usr/bin/google-chrome-stable"),
                PathBuf::from("/usr/bin/brave-browser"),
                PathBuf::from("/usr/bin/microsoft-edge"),
                PathBuf::from("/snap/bin/chromium"),
            ]);
        }
        candidates.into_iter().find(|p| p.is_file())
    }

    pub fn command(&self, config: &LaunchConfig) -> Result<Command, String> {
        let mut command = Command::new(&self.executable);
        command
            .args(config.arguments()?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        Ok(command)
    }

    pub fn launch(&self, config: LaunchConfig) -> Result<BrowserSession, String> {
        config.arguments()?;
        std::fs::create_dir_all(&config.profile_dir).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&config.profile_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let mut command = self.command(&config)?;
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x4);
        } // CREATE_SUSPENDED, assign job before resume
        let mut child = command
            .spawn()
            .map_err(|e| format!("Cannot launch bundled Chromium: {e}"))?;
        #[cfg(windows)]
        let job = match windows_job::Job::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        // Catch immediate loader/permission errors, without waiting for full browser startup.
        std::thread::sleep(std::time::Duration::from_millis(150));
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("Chromium exited during startup ({status}). Check sandbox and system library support."));
        }
        Ok(BrowserSession {
            child,
            install: self.clone(),
            config,
            #[cfg(windows)]
            job,
        })
    }
}

pub struct BrowserSession {
    child: Child,
    install: BrowserInstall,
    pub config: LaunchConfig,
    #[cfg(windows)]
    job: windows_job::Job,
}

impl BrowserSession {
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn open_window(&mut self, target: String) -> Result<(), String> {
        if !self.is_running() {
            return Err("integrated browser has closed; open it again".into());
        }
        let mut config = self.config.clone();
        config.target = target;
        // Chromium forwards to the profile's existing process, then exits. Reap that helper.
        let mut child = self
            .install
            .command(&config)?
            .arg("--new-window")
            .spawn()
            .map_err(|e| e.to_string())?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        Ok(())
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGTERM);
        }
        #[cfg(windows)]
        self.job.terminate();
        for _ in 0..20 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        #[cfg(unix)]
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn new_profile_dir() -> Result<PathBuf, String> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    Ok(crate::platform_paths::data_dir()?
        .join("BrowserProfiles")
        .join(format!("session-{}-{nonce}", std::process::id())))
}

#[cfg(windows)]
mod windows_job {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::*,
        System::{Diagnostics::ToolHelp::*, JobObjects::*, Threading::*},
    };
    pub struct Job(HANDLE);
    unsafe impl Send for Job {}
    impl Job {
        pub fn attach(child: &std::process::Child) -> Result<Self, String> {
            unsafe {
                let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if handle.is_null() {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let job = Self(handle);
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    &limits as *const _ as _,
                    std::mem::size_of_val(&limits) as u32,
                ) == 0
                    || AssignProcessToJobObject(handle, child.as_raw_handle() as _) == 0
                {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                let mut entry: THREADENTRY32 = std::mem::zeroed();
                entry.dwSize = std::mem::size_of_val(&entry) as u32;
                let mut found = Thread32First(snapshot, &mut entry) != 0;
                let mut resumed = false;
                while found {
                    if entry.th32OwnerProcessID == child.id() {
                        let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                        if !thread.is_null() {
                            resumed = ResumeThread(thread) != u32::MAX;
                            CloseHandle(thread);
                        }
                        break;
                    }
                    found = Thread32Next(snapshot, &mut entry) != 0;
                }
                CloseHandle(snapshot);
                if !resumed {
                    return Err("Cannot resume Chromium inside its owned job".into());
                }
                Ok(job)
            }
        }
        pub fn terminate(&self) {
            unsafe {
                TerminateJobObject(self.0, 0);
            }
        }
    }
    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
