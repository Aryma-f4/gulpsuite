//! Cross-platform in-app auto-updater backed by GitHub Releases.
//!
//! Queries `https://api.github.com/repos/<owner>/<repo>/releases/latest` (or a custom update
//! endpoint URL), compares semantic versions against `CARGO_PKG_VERSION`, selects the native
//! installer asset for the host OS/CPU (`macos-arm64`, `macos-x64`, `windows-x64`, `linux-x64`),
//! streams the download with live byte progress, requires a matching `.sha256` digest,
//! and launches the platform installer.

use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const DEFAULT_REPO: &str = "Aryma-f4/gulpsuite";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

impl ReleaseInfo {
    pub fn clean_version(&self) -> String {
        self.tag_name
            .trim()
            .trim_start_matches(['v', 'V'])
            .to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateCheckOutcome {
    UpToDate {
        current_version: String,
        latest_version: String,
    },
    UpdateAvailable {
        current_version: String,
        release: ReleaseInfo,
        installer_asset: Option<ReleaseAsset>,
        sha256_asset: Option<ReleaseAsset>,
    },
}

#[derive(Clone, Debug)]
pub enum UpdateEvent {
    Checked(Result<UpdateCheckOutcome, String>),
    DownloadProgress {
        downloaded_bytes: u64,
        total_bytes: u64,
    },
    Downloaded {
        path: PathBuf,
        sha256_verified: bool,
    },
    InstallLaunched(String),
    Error(String),
}

/// Parses a `major.minor.patch` semantic version string, ignoring leading `v`/`V` and pre-release suffixes.
pub fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let clean = version
        .trim()
        .trim_start_matches(['v', 'V'])
        .split(['-', '+'])
        .next()?;
    let mut parts = clean.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor, patch))
}

/// Returns `true` if `candidate` is strictly newer than `current`.
pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    match (parse_semver(current), parse_semver(candidate)) {
        (Some(cur), Some(cand)) => cand > cur,
        _ => false,
    }
}

/// Returns the canonical platform identifier for the current OS and CPU architecture.
pub fn current_platform_tag() -> &'static str {
    platform_tag(std::env::consts::OS, std::env::consts::ARCH)
}

fn platform_tag(os: &str, arch: &str) -> &'static str {
    match (os, arch) {
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("windows", "x86_64") => "windows-x64",
        ("linux", "x86_64") => "linux-x64",
        _ => "unsupported",
    }
}

fn safe_asset_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Selects a supported native installer; never substitutes another OS/architecture or an archive.
pub fn select_installer_asset(assets: &[ReleaseAsset], platform: &str) -> Option<ReleaseAsset> {
    let preferences: &[&str] = match platform {
        "macos-arm64" => &["-macos-arm64-setup.pkg", "-macos-arm64.dmg"],
        "macos-x64" => &["-macos-x64-setup.pkg", "-macos-x64.dmg"],
        "windows-x64" => &["-windows-x64-setup.exe"],
        "linux-x64" if std::env::var_os("APPIMAGE").is_some() => &[
            "-x86_64.appimage",
            "-linux-x64-setup.run",
            "_amd64.deb",
            "-x86_64.pkg.tar.gz",
        ],
        "linux-x64" => &[
            "-linux-x64-setup.run",
            "-x86_64.appimage",
            "_amd64.deb",
            "-x86_64.pkg.tar.gz",
        ],
        _ => return None,
    };
    preferences.iter().find_map(|suffix| {
        assets
            .iter()
            .find(|a| safe_asset_name(&a.name) && a.name.to_ascii_lowercase().ends_with(suffix))
            .cloned()
    })
}

/// Finds the `.sha256` companion asset for `installer_name`, if published on the release.
pub fn select_sha256_asset(assets: &[ReleaseAsset], installer_name: &str) -> Option<ReleaseAsset> {
    let expected = format!("{installer_name}.sha256");
    assets.iter().find(|a| a.name == expected).cloned()
}

/// Computes the lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for b in digest.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Resolves a repository slug (`owner/repo`) or explicit URL into the GitHub Releases API URL.
pub fn release_api_url(repo_or_url: &str) -> String {
    let trimmed = repo_or_url.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        let slug = if trimmed.is_empty() {
            DEFAULT_REPO
        } else {
            trimmed.trim_matches('/')
        };
        format!("https://api.github.com/repos/{slug}/releases/latest")
    }
}

/// Performs an HTTP/HTTPS `GET` request (following up to 8 redirects, with a `curl -fsSL`
/// fallback if the direct socket/TLS client encounters a proxy or custom CA) and returns the body.
pub async fn http_get_bytes(
    initial_url: &str,
    progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
) -> Result<Vec<u8>, String> {
    use std::time::Duration;
    let url = url::Url::parse(initial_url).map_err(|e| format!("Invalid update URL: {e}"))?;
    let redirect_protocols = match url.scheme() {
        "https" => "=https",
        "http" => "=http,https",
        _ => return Err("Update URLs must use HTTP or HTTPS".into()),
    };
    let direct_err = match tokio::time::timeout(
        Duration::from_secs(180),
        http_get_bytes_direct(initial_url, progress),
    )
    .await
    {
        Ok(Ok(bytes)) => return Ok(bytes),
        Ok(Err(err)) => err,
        Err(_) => "Update request timed out".to_string(),
    };
    let url = url.to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("curl")
            .args([
                "-q",
                "-fsSL",
                "--max-time",
                "180",
                "--max-redirs",
                "8",
                "--proto",
                "=http,https",
                "--proto-redir",
                redirect_protocols,
                "-A",
                &format!("Gulpsuite/{CURRENT_VERSION}"),
                "--",
                &url,
            ])
            .output()
    })
    .await;
    if let Ok(Ok(output)) = output {
        if output.status.success() {
            if let Some(cb) = progress {
                let len = output.stdout.len() as u64;
                cb(len, len);
            }
            return Ok(output.stdout);
        }
    }
    Err(direct_err)
}

async fn http_get_bytes_direct(
    initial_url: &str,
    progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
) -> Result<Vec<u8>, String> {
    let mut current_url = initial_url.to_string();
    for _redirect in 0..=8 {
        let parsed = url::Url::parse(&current_url)
            .map_err(|e| format!("Invalid update URL '{current_url}': {e}"))?;
        let scheme = parsed.scheme();
        let host = parsed
            .host_str()
            .ok_or_else(|| format!("Update URL missing host: {current_url}"))?
            .to_string();
        let is_https = match scheme {
            "https" => true,
            "http" => false,
            other => return Err(format!("Unsupported URL scheme: {other}")),
        };
        let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });
        let mut path_and_query = parsed.path().to_string();
        if path_and_query.is_empty() {
            path_and_query.push('/');
        }
        if let Some(q) = parsed.query() {
            path_and_query.push('?');
            path_and_query.push_str(q);
        }

        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let req_bytes = format!(
            "GET {path_and_query} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             User-Agent: Gulpsuite/{CURRENT_VERSION}\r\n\
             Accept: application/vnd.github+json, application/octet-stream, */*\r\n\
             Connection: close\r\n\r\n"
        );

        let tcp = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| format!("Timed out connecting to {host}:{port}"))?
        .map_err(|e| format!("Failed to connect to {host}:{port}: {e}"))?;

        let (status, headers, body) = if is_https {
            let tls_cfg = crate::tls::client_config_arc(&[])?;
            let connector = tokio_rustls::TlsConnector::from(tls_cfg);
            let server_name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|e| format!("Invalid TLS server name '{host}': {e}"))?;
            let mut stream = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| format!("TLS handshake with {host} failed: {e}"))?;
            stream
                .write_all(req_bytes.as_bytes())
                .await
                .map_err(|e| format!("Failed sending request to {host}: {e}"))?;
            read_http_response(&mut stream, progress).await?
        } else {
            let mut stream = tcp;
            stream
                .write_all(req_bytes.as_bytes())
                .await
                .map_err(|e| format!("Failed sending request to {host}: {e}"))?;
            read_http_response(&mut stream, progress).await?
        };

        if matches!(status, 301 | 302 | 303 | 307 | 308) {
            let loc = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .ok_or_else(|| format!("Redirect HTTP {status} missing Location header"))?;
            current_url = if loc.starts_with("http://") || loc.starts_with("https://") {
                loc
            } else {
                parsed
                    .join(&loc)
                    .map(|u| u.to_string())
                    .map_err(|e| format!("Invalid redirect Location '{loc}': {e}"))?
            };
            if is_https && !current_url.starts_with("https://") {
                return Err("Refusing insecure redirect from HTTPS update server".into());
            }
            continue;
        }

        if status != 200 {
            return Err(format!(
                "Update server returned HTTP {status} for {current_url}"
            ));
        }
        return Ok(body);
    }
    Err("Too many HTTP redirects while fetching update".into())
}

async fn read_http_response<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let mut raw_head = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    while !raw_head.ends_with(b"\r\n\r\n") {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| format!("Error reading response headers: {e}"))?;
        if n == 0 {
            break;
        }
        raw_head.push(byte[0]);
        if raw_head.len() > 64 * 1024 {
            return Err("Response headers exceeded 64 KiB".into());
        }
    }

    if !raw_head.ends_with(b"\r\n\r\n") {
        return Err("Incomplete HTTP response headers".into());
    }
    let head_str = String::from_utf8_lossy(&raw_head);
    let mut lines = head_str.lines();
    let status_line = lines.next().ok_or("Empty HTTP response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("Malformed HTTP status line: {status_line}"))?;

    let mut headers = Vec::new();
    let mut content_length: Option<u64> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                let length = val.parse().map_err(|_| "Invalid HTTP Content-Length")?;
                if content_length.is_some_and(|previous| previous != length) {
                    return Err("Conflicting HTTP Content-Length values".into());
                }
                content_length = Some(length);
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((key, val));
        }
    }

    if status != 200 {
        return Ok((status, headers, Vec::new()));
    }
    if chunked && content_length.is_some() {
        return Err("Ambiguous HTTP response framing".into());
    }
    if content_length == Some(0) {
        return Ok((status, headers, Vec::new()));
    }

    let total = content_length.unwrap_or(0);
    let mut body = Vec::with_capacity((total as usize).min(64 * 1024 * 1024));
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("Error reading response body: {e}"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
        if let Some(cb) = progress {
            cb(body.len() as u64, total);
        }
        if let Some(len) = content_length {
            if body.len() as u64 >= len {
                body.truncate(len as usize);
                break;
            }
        }
    }

    if content_length.is_some_and(|length| length != body.len() as u64) {
        return Err("Update transfer ended before the declared Content-Length".into());
    }
    let final_body = if chunked {
        decode_chunked(&body)?
    } else {
        body
    };
    Ok((status, headers, final_body))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("Truncated HTTP chunk header")?;
        let line =
            std::str::from_utf8(&input[..line_end]).map_err(|_| "Invalid HTTP chunk header")?;
        let hex = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16).map_err(|_| "Invalid HTTP chunk size")?;
        input = &input[line_end + 2..];
        if size == 0 {
            if input == b"\r\n" || input.ends_with(b"\r\n\r\n") {
                return Ok(out);
            }
            return Err("Truncated HTTP chunk trailer".into());
        }
        let end = size.checked_add(2).ok_or("HTTP chunk size overflow")?;
        if input.get(size..end) != Some(b"\r\n") {
            return Err("Truncated or malformed HTTP chunk".into());
        }
        out.extend_from_slice(&input[..size]);
        input = &input[end..];
    }
}

/// Checks GitHub Releases (or a custom release JSON URL) for a newer version than `current_version`.
pub async fn check_latest_release(
    repo_or_url: &str,
    current_version: &str,
) -> Result<UpdateCheckOutcome, String> {
    let url = release_api_url(repo_or_url);
    let bytes = http_get_bytes(&url, None).await?;
    let release: ReleaseInfo = serde_json::from_slice(&bytes)
        .map_err(|e| format!("Failed to parse release metadata JSON: {e}"))?;
    let latest_version = release.clean_version();
    if is_newer_version(current_version, &latest_version) {
        let platform = current_platform_tag();
        let installer_asset = select_installer_asset(&release.assets, platform);
        let sha256_asset = installer_asset
            .as_ref()
            .and_then(|inst| select_sha256_asset(&release.assets, &inst.name));
        Ok(UpdateCheckOutcome::UpdateAvailable {
            current_version: current_version.to_string(),
            release,
            installer_asset,
            sha256_asset,
        })
    } else {
        Ok(UpdateCheckOutcome::UpToDate {
            current_version: current_version.to_string(),
            latest_version,
        })
    }
}

/// Requires the platform installer's checksum before staging a complete, verified download.
pub async fn download_and_verify_release(
    release: &ReleaseInfo,
    platform: &str,
    dest_dir: &Path,
    progress: &(dyn Fn(u64, u64) + Send + Sync),
) -> Result<(PathBuf, bool), String> {
    let asset = select_installer_asset(&release.assets, platform).ok_or_else(|| {
        format!(
            "Release {} does not contain an installer for platform '{platform}'",
            release.tag_name
        )
    })?;
    let sha_asset = select_sha256_asset(&release.assets, &asset.name).ok_or_else(|| {
        format!(
            "Checksum for {} is not published yet; try again later",
            asset.name
        )
    })?;
    let sha_bytes = http_get_bytes(&sha_asset.browser_download_url, None).await?;
    let expected = checksum_token(&sha_bytes)?;
    let bytes = http_get_bytes(&asset.browser_download_url, Some(progress)).await?;
    if bytes.is_empty() || (asset.size != 0 && bytes.len() as u64 != asset.size) {
        return Err(format!("Installer size mismatch for {}", asset.name));
    }
    let actual = sha256_hex(&bytes);
    if !expected.eq_ignore_ascii_case(&actual) {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected}, got {actual}",
            asset.name
        ));
    }

    let dest_dir = dest_dir.to_path_buf();
    let out_path =
        tokio::task::spawn_blocking(move || stage_installer(&dest_dir, &asset.name, &bytes))
            .await
            .map_err(|e| format!("Installer staging interrupted: {e}"))??;
    Ok((out_path, true))
}

fn checksum_token(bytes: &[u8]) -> Result<&str, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Invalid SHA-256 asset encoding")?;
    let token = text.split_whitespace().next().unwrap_or("");
    if token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(token)
    } else {
        Err("Invalid or empty SHA-256 asset".into())
    }
}

fn stage_installer(parent: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    std::fs::create_dir_all(parent).map_err(|e| format!("Cannot create update directory: {e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let dir = parent.join(format!(
        "update-{}-{}-{id}",
        std::process::id(),
        now.as_nanos()
    ));
    let builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        let mut builder = builder;
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
        builder
    };
    builder
        .create(&dir)
        .map_err(|e| format!("Cannot stage installer: {e}"))?;
    let path = dir.join(name);
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)?;
        file.write_all(bytes)?;
        #[cfg(unix)]
        if name.to_ascii_lowercase().ends_with(".appimage") {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }
        file.sync_all()
    })();
    if let Err(err) = result {
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
        return Err(format!("Failed staging installer: {err}"));
    }
    Ok(path)
}

/// Atomically replaces `target_exe` with `new_bin` by renaming the running binary to `.old`,
/// copying `new_bin` into place, setting executable permissions, and removing `.old`.
pub fn replace_executable_at(target_exe: &Path, new_bin: &Path) -> Result<(), String> {
    if !new_bin.is_file() {
        return Err(format!("New binary does not exist: {}", new_bin.display()));
    }
    let backup = target_exe.with_extension("old-update");
    let _ = std::fs::remove_file(&backup);
    if target_exe.exists() {
        std::fs::rename(target_exe, &backup).map_err(|e| {
            format!(
                "Cannot move existing executable {} for in-place update: {e}",
                target_exe.display()
            )
        })?;
    }
    if let Err(e) = std::fs::copy(new_bin, target_exe) {
        let _ = std::fs::rename(&backup, target_exe);
        return Err(format!(
            "Failed copying updated binary to {}: {e}",
            target_exe.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(target_exe, std::fs::Permissions::from_mode(0o755));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(target_exe)
            .status();
    }
    let _ = std::fs::remove_file(&backup);
    Ok(())
}

/// Replaces the currently running executable (`std::env::current_exe()`) with `new_bin`.
pub fn replace_current_executable(new_bin: &Path) -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|e| format!("Cannot resolve current executable path: {e}"))?;
    replace_executable_at(&current, new_bin)?;
    Ok(current)
}

/// Spawns a fresh instance of the currently installed Gulpsuite executable and exits the current process.
pub fn relaunch_current_executable() -> Result<(), String> {
    let exe = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .ok_or_else(|| "Cannot determine executable path to relaunch".to_string())?;
    std::process::Command::new(&exe)
        .spawn()
        .map_err(|e| format!("Failed to relaunch {}: {e}", exe.display()))?;
    std::process::exit(0);
}

/// Launches the downloaded native installer (`-setup.pkg` / `.dmg` on macOS, `-setup.exe` on Windows,
/// `-setup.run` / `.AppImage` / `.deb` on Linux). Replaces an existing portable AppImage atomically.
pub fn launch_installer(installer_path: &Path) -> Result<String, String> {
    if !installer_path.is_file() {
        return Err(format!(
            "Downloaded installer does not exist: {}",
            installer_path.display()
        ));
    }
    let name = installer_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    #[cfg(target_os = "macos")]
    {
        if !name.ends_with(".pkg") && !name.ends_with(".dmg") {
            return Err(format!("Unsupported macOS installer: {name}"));
        }
        let status = std::process::Command::new("open")
            .arg(installer_path)
            .status()
            .map_err(|e| format!("Failed to open macOS installer {name}: {e}"))?;
        if !status.success() {
            return Err(format!("macOS could not open installer {name}: {status}"));
        }
        return Ok(format!(
            "Opened macOS installer: {}",
            installer_path.display()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        if !name.ends_with("-windows-x64-setup.exe") {
            return Err(format!("Unsupported Windows installer: {name}"));
        }
        let mut cmd = std::process::Command::new(installer_path);
        if name.contains("setup") {
            cmd.arg("--install").arg("--yes");
        }
        cmd.spawn()
            .map_err(|e| format!("Failed to launch Windows setup {}: {e}", name))?;
        return Ok(format!(
            "Launched Windows setup installer: {}",
            installer_path.display()
        ));
    }

    #[cfg(target_os = "linux")]
    {
        if name.ends_with(".appimage") {
            if let Some(current) = std::env::var_os("APPIMAGE") {
                let current = PathBuf::from(current)
                    .canonicalize()
                    .map_err(|e| format!("Cannot locate installed AppImage: {e}"))?;
                replace_portable_appimage(&current, installer_path)?;
                return Ok(format!(
                    "Updated {}. Click 'Relaunch Gulpsuite' to restart.",
                    current.display()
                ));
            }
            std::process::Command::new(installer_path)
                .arg("--appimage-extract-and-run")
                .spawn()
                .map_err(|e| format!("Failed to launch updated AppImage {}: {e}", name))?;
            return Ok(format!(
                "Started the downloaded AppImage (existing installation unchanged): {}",
                installer_path.display()
            ));
        }
        if name.ends_with(".run") {
            std::process::Command::new("sh")
                .arg(installer_path)
                .arg("--yes")
                .spawn()
                .map_err(|e| format!("Failed to run Linux setup {}: {e}", name))?;
            return Ok(format!(
                "Started Linux self-extracting installer: {}",
                installer_path.display()
            ));
        }
        if !name.ends_with(".deb") && !name.ends_with(".pkg.tar.gz") {
            return Err(format!("Unsupported Linux installer: {name}"));
        }
        std::process::Command::new("xdg-open")
            .arg(installer_path)
            .spawn()
            .map_err(|e| format!("Failed to open Linux package {}: {e}", name))?;
        Ok(format!(
            "Opened Linux installer package: {}",
            installer_path.display()
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    Err(format!(
        "Installer launch is not supported on this platform: {name}"
    ))
}

#[cfg(any(target_os = "linux", test))]
fn replace_portable_appimage(current: &Path, installer: &Path) -> Result<(), String> {
    if !current.is_file() {
        return Err("Installed AppImage is not a regular file".into());
    }
    let parent = current.parent().ok_or("Cannot locate AppImage directory")?;
    let bytes =
        std::fs::read(installer).map_err(|e| format!("Cannot read verified AppImage: {e}"))?;
    let staged = stage_installer(parent, "replacement.AppImage", &bytes)?;
    let result = std::fs::rename(&staged, current);
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    if let Some(dir) = staged.parent() {
        let _ = std::fs::remove_dir(dir);
    }
    result.map_err(|e| {
        format!(
            "Could not replace {}; the existing AppImage is unchanged: {e}",
            current.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_comparison_handles_v_prefixes_and_prereleases() {
        assert_eq!(parse_semver("v0.0.1"), Some((0, 0, 1)));
        assert_eq!(parse_semver("0.2.10-rc1"), Some((0, 2, 10)));
        assert!(is_newer_version("0.0.1", "v0.0.2"));
        assert!(is_newer_version("v0.0.1", "0.1.0"));
        assert!(is_newer_version("0.0.1", "1.0.0"));
        assert!(!is_newer_version("0.0.1", "v0.0.1"));
        assert!(!is_newer_version("0.2.0", "v0.0.1"));
    }

    #[test]
    fn platform_asset_selector_picks_native_installers_first() {
        let assets = vec![
            ReleaseAsset {
                name: "Gulpsuite-0.0.2-macos-arm64.dmg".into(),
                browser_download_url: "https://example.test/mac.dmg".into(),
                size: 100,
            },
            ReleaseAsset {
                name: "Gulpsuite-0.0.2-macos-arm64-setup.pkg".into(),
                browser_download_url: "https://example.test/mac.pkg".into(),
                size: 100,
            },
            ReleaseAsset {
                name: "Gulpsuite-0.0.2-macos-arm64-setup.pkg.sha256".into(),
                browser_download_url: "https://example.test/mac.pkg.sha256".into(),
                size: 64,
            },
            ReleaseAsset {
                name: "Gulpsuite-0.0.2-windows-x64-setup.exe".into(),
                browser_download_url: "https://example.test/win-setup.exe".into(),
                size: 100,
            },
            ReleaseAsset {
                name: "Gulpsuite-0.0.2-linux-x64-setup.run".into(),
                browser_download_url: "https://example.test/linux-setup.run".into(),
                size: 100,
            },
        ];

        let mac = select_installer_asset(&assets, "macos-arm64").unwrap();
        assert_eq!(mac.name, "Gulpsuite-0.0.2-macos-arm64-setup.pkg");
        let sha = select_sha256_asset(&assets, &mac.name).unwrap();
        assert_eq!(sha.name, "Gulpsuite-0.0.2-macos-arm64-setup.pkg.sha256");

        let win = select_installer_asset(&assets, "windows-x64").unwrap();
        assert_eq!(win.name, "Gulpsuite-0.0.2-windows-x64-setup.exe");

        let lin = select_installer_asset(&assets, "linux-x64").unwrap();
        assert_eq!(lin.name, "Gulpsuite-0.0.2-linux-x64-setup.run");
    }

    #[tokio::test]
    async fn updater_checks_and_downloads_verified_installer_from_local_release_server() {
        let payload = b"fake-installer-binary-payload-v0.0.2";
        let digest = sha256_hex(payload);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base_url = format!("http://127.0.0.1:{port}");

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut req = Vec::new();
                let mut b = [0u8; 1];
                while !req.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut b).await.unwrap() == 0 {
                        break;
                    }
                    req.push(b[0]);
                }
                let req_line = String::from_utf8_lossy(&req);
                let path = req_line.split_whitespace().nth(1).unwrap_or("/");
                if path == "/releases/latest" {
                    let body = serde_json::json!({
                        "tag_name": "v0.0.2",
                        "name": "Gulpsuite v0.0.2",
                        "body": "Automated update test release",
                        "html_url": format!("http://127.0.0.1:{port}/release/v0.0.2"),
                        "assets": [
                            {
                                "name": "Gulpsuite-0.0.2-linux-x64-setup.run",
                                "browser_download_url": format!("http://127.0.0.1:{port}/download/Gulpsuite-0.0.2-linux-x64-setup.run"),
                                "size": payload.len()
                            },
                            {
                                "name": "Gulpsuite-0.0.2-linux-x64-setup.run.sha256",
                                "browser_download_url": format!("http://127.0.0.1:{port}/download/Gulpsuite-0.0.2-linux-x64-setup.run.sha256"),
                                "size": 96
                            }
                        ]
                    })
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(resp.as_bytes()).await.unwrap();
                } else if path.ends_with(".sha256") {
                    let sha_body = format!("{digest}  Gulpsuite-0.0.2-linux-x64-setup.run\n");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        sha_body.len(),
                        sha_body
                    );
                    stream.write_all(resp.as_bytes()).await.unwrap();
                } else {
                    let mut resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                        payload.len()
                    )
                    .into_bytes();
                    resp.extend_from_slice(payload);
                    stream.write_all(&resp).await.unwrap();
                }
            }
        });

        let api_url = format!("{base_url}/releases/latest");
        let outcome = check_latest_release(&api_url, "0.0.1").await.unwrap();
        let UpdateCheckOutcome::UpdateAvailable { release, .. } = outcome else {
            panic!("Expected UpdateAvailable");
        };
        assert_eq!(release.clean_version(), "0.0.2");

        let tmp = std::env::temp_dir().join(format!("gulpsuite-update-test-{port}"));
        let _ = std::fs::remove_dir_all(&tmp);
        let (downloaded_path, verified) =
            download_and_verify_release(&release, "linux-x64", &tmp, &|_, _| {})
                .await
                .unwrap();
        assert!(verified, "SHA-256 companion digest must be verified");
        assert_eq!(std::fs::read(&downloaded_path).unwrap(), payload);

        let target_exe = tmp.join("gulpsuite-running-bin");
        std::fs::write(&target_exe, b"old-binary-v0.0.1").unwrap();
        replace_executable_at(&target_exe, &downloaded_path).unwrap();
        assert_eq!(std::fs::read(&target_exe).unwrap(), payload);
        assert!(!target_exe.with_extension("old-update").exists());

        let _ = std::fs::remove_dir_all(&tmp);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn updater_rejects_truncated_http_bodies() {
        for fixture in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"[..],
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: xyz\r\n\r\nabc"[..],
        ] {
            assert!(read_http_response(&mut &fixture[..], None).await.is_err());
        }
    }

    #[test]
    fn updater_does_not_select_unlaunchable_or_cross_platform_assets() {
        let assets: Vec<_> = [
            "Gulpsuite-windows-arm64-setup.exe",
            "Gulpsuite-windows-x64.zip",
            "Gulpsuite-macos-arm64.tar.gz",
            "../Gulpsuite-linux-x64-setup.run",
        ]
        .into_iter()
        .map(|name| ReleaseAsset {
            name: name.into(),
            browser_download_url: "https://example.test/update".into(),
            size: 1,
        })
        .collect();
        for platform in ["windows-x64", "macos-arm64", "linux-x64", "linux-arm64"] {
            assert!(
                select_installer_asset(&assets, platform).is_none(),
                "{platform}"
            );
        }
    }

    #[test]
    fn updater_validates_platform_and_checksum_metadata() {
        assert_eq!(platform_tag("macos", "x86_64"), "macos-x64");
        assert_eq!(platform_tag("macos", "aarch64"), "macos-arm64");
        assert_eq!(platform_tag("linux", "x86_64"), "linux-x64");
        assert_eq!(platform_tag("windows", "x86_64"), "windows-x64");
        assert_eq!(platform_tag("windows", "aarch64"), "unsupported");
        assert_eq!(platform_tag("linux", "aarch64"), "unsupported");
        assert!(checksum_token(b"").is_err());
        assert!(checksum_token(&[b'z'; 64]).is_err());
        assert!(
            checksum_token(format!("{}  Gulpsuite.AppImage\n", "AB".repeat(32)).as_bytes()).is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn updater_replaces_portable_appimage_only_after_staging() {
        let current = stage_installer(&std::env::temp_dir(), "Gulpsuite.AppImage", b"old").unwrap();
        let dir = current.parent().unwrap();
        let installer = dir.join("Download.AppImage");
        assert!(replace_portable_appimage(&current, &installer).is_err());
        assert_eq!(std::fs::read(&current).unwrap(), b"old");
        std::fs::write(&installer, b"new").unwrap();
        replace_portable_appimage(&current, &installer).unwrap();
        assert_eq!(std::fs::read(&current).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
