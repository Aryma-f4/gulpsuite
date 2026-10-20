//! Cross-platform in-app auto-updater backed by GitHub Releases.
//!
//! Queries `https://api.github.com/repos/<owner>/<repo>/releases/latest` (or a custom update
//! endpoint URL), compares semantic versions against `CARGO_PKG_VERSION`, selects the native
//! installer asset for the host OS/CPU (`macos-arm64`, `macos-x64`, `windows-x64`, `linux-x64`),
//! streams the download with live byte progress, verifies its `.sha256` digest when present,
//! and launches the platform installer.

use std::path::{Path, PathBuf};
use std::sync::Arc;
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
        self.tag_name.trim().trim_start_matches(['v', 'V']).to_string()
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-arm64"
    }
    #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
    {
        "macos-x64"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-x64"
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        "linux-x64"
    }
}

/// Selects the best matching native installer asset for `platform`.
pub fn select_installer_asset(assets: &[ReleaseAsset], platform: &str) -> Option<ReleaseAsset> {
    let preferences: &[&str] = match platform {
        "macos-arm64" => &[
            "macos-arm64-setup.pkg",
            "macos-arm64.dmg",
            "macos-arm64.tar.gz",
        ],
        "macos-x64" => &[
            "macos-x64-setup.pkg",
            "macos-x64.dmg",
            "macos-x64.tar.gz",
        ],
        "windows-x64" => &["windows-x64-setup.exe", "windows-x64.zip", ".exe"],
        "linux-x64" => &[
            "linux-x64-setup.run",
            "_amd64.deb",
            "linux-x64.tar.gz",
        ],
        _ => &[],
    };

    for suffix in preferences {
        if let Some(found) = assets.iter().find(|a| {
            !a.name.ends_with(".sha256")
                && !a.name.ends_with(".json")
                && a.name.to_ascii_lowercase().ends_with(suffix)
        }) {
            return Some(found.clone());
        }
    }
    assets
        .iter()
        .find(|a| {
            !a.name.ends_with(".sha256")
                && !a.name.ends_with(".json")
                && a.name.contains(platform)
        })
        .cloned()
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

/// Performs an HTTP/HTTPS `GET` request (following up to 5 redirects) and returns the response body.
pub async fn http_get_bytes(
    initial_url: &str,
    progress: Option<&(dyn Fn(u64, u64) + Send + Sync)>,
) -> Result<Vec<u8>, String> {
    let mut current_url = initial_url.to_string();
    for _redirect in 0..=5 {
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

        let req_bytes = format!(
            "GET {path_and_query} HTTP/1.1\r\n\
             Host: {host}\r\n\
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
            let tls_cfg = crate::tls::client_config_with(&[])?;
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
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
            continue;
        }

        if !(200..=299).contains(&status) {
            return Err(format!("Update server returned HTTP {status} for {current_url}"));
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
                content_length = val.parse().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
            headers.push((key, val));
        }
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

    let final_body = if chunked {
        decode_chunked(&body)
    } else {
        body
    };
    Ok((status, headers, final_body))
}

fn decode_chunked(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < input.len() {
        let Some(rel_end) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&input[pos..pos + rel_end]);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let Ok(chunk_size) = usize::from_str_radix(size_hex, 16) else {
            break;
        };
        pos += rel_end + 2;
        if chunk_size == 0 || pos + chunk_size > input.len() {
            break;
        }
        out.extend_from_slice(&input[pos..pos + chunk_size]);
        pos += chunk_size + 2;
    }
    out
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

/// Downloads the platform installer for `release`, verifies its `.sha256` companion asset when
/// present, and writes the verified installer into `dest_dir`.
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
    std::fs::create_dir_all(dest_dir)
        .map_err(|e| format!("Cannot create update directory {}: {e}", dest_dir.display()))?;

    let bytes = http_get_bytes(&asset.browser_download_url, Some(progress)).await?;

    let mut sha256_verified = false;
    if let Some(sha_asset) = select_sha256_asset(&release.assets, &asset.name) {
        let sha_bytes = http_get_bytes(&sha_asset.browser_download_url, None).await?;
        let sha_text = String::from_utf8_lossy(&sha_bytes);
        let expected = sha_text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let actual = sha256_hex(&bytes);
        if !expected.is_empty() && expected != actual {
            return Err(format!(
                "SHA-256 mismatch for {}: expected {expected}, got {actual}",
                asset.name
            ));
        }
        sha256_verified = !expected.is_empty();
    }

    let out_path = dest_dir.join(&asset.name);
    std::fs::write(&out_path, &bytes)
        .map_err(|e| format!("Failed writing installer to {}: {e}", out_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if out_path.extension().and_then(|e| e.to_str()) == Some("run") {
            let _ = std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755));
        }
    }
    Ok((out_path, sha256_verified))
}

/// Launches the downloaded native installer (`-setup.pkg` / `.dmg` on macOS, `-setup.exe` on Windows,
/// `-setup.run` / `.deb` on Linux).
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
        std::process::Command::new("open")
            .arg(installer_path)
            .spawn()
            .map_err(|e| format!("Failed to open macOS installer {}: {e}", name))?;
        return Ok(format!(
            "Launched macOS installer: {}",
            installer_path.display()
        ));
    }

    #[cfg(target_os = "windows")]
    {
        std::process::Command::new(installer_path)
            .spawn()
            .map_err(|e| format!("Failed to launch Windows setup {}: {e}", name))?;
        return Ok(format!(
            "Launched Windows setup wizard: {}",
            installer_path.display()
        ));
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
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
        std::process::Command::new("xdg-open")
            .arg(installer_path)
            .spawn()
            .map_err(|e| format!("Failed to open Linux package {}: {e}", name))?;
        Ok(format!(
            "Opened Linux installer package: {}",
            installer_path.display()
        ))
    }
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
        let _ = std::fs::remove_dir_all(&tmp);
        server.await.unwrap();
    }
}
