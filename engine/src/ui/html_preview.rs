//! Isolated, non-interactive HTML screenshots using the application's bundled Chromium.
use eframe::egui::{self, Ui};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Pixels {
    pub rgba: Vec<u8>,
    pub width: usize,
    pub height: usize,
}

pub fn html_body(raw: &str) -> Option<String> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .filter(|(head, _)| head.starts_with("HTTP/"))
        .unwrap_or(("", raw));
    let mut body = body.trim_start_matches('\u{feff}').to_owned();
    // History may already have decoded the wire framing. Only dechunk a complete valid stream.
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        let mut rest = body.as_bytes();
        let mut decoded = Vec::new();
        let chunks = (|| -> Option<Vec<u8>> {
            loop {
                let end = rest.windows(2).position(|s| s == b"\r\n")?;
                let n = usize::from_str_radix(
                    std::str::from_utf8(&rest[..end])
                        .ok()?
                        .split(';')
                        .next()?
                        .trim(),
                    16,
                )
                .ok()?;
                rest = &rest[end + 2..];
                if n == 0 {
                    return Some(decoded);
                }
                let chunk = rest.get(..n)?;
                decoded.extend_from_slice(chunk);
                if rest.get(n..n + 2)? != b"\r\n" {
                    return None;
                }
                rest = &rest[n + 2..];
            }
        })();
        if let Some(chunks) = chunks {
            body = String::from_utf8_lossy(&chunks).into_owned();
        }
    }
    let typed_html = head
        .lines()
        .filter_map(|l| l.split_once(':'))
        .any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type")
                && (v.to_ascii_lowercase().contains("html")
                    || v.to_ascii_lowercase().contains("svg"))
        });
    (typed_html || body.trim_start().starts_with('<')).then_some(body)
}

/// Real CSS/inline-JavaScript/data-image rendering. No target cookies or network access.
pub fn render(executable: &Path, html: &str) -> Result<Pixels, String> {
    render_with_options(executable, html, false, None)
}

pub fn render_with_options(
    executable: &Path,
    html: &str,
    external: bool,
    base_url: Option<&str>,
) -> Result<Pixels, String> {
    let dir = std::env::temp_dir().join(format!(
        "gulpsuite-preview-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
    }
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    // Defense in depth: CSP blocks connections, remote resources, frames and form submission;
    // a dead proxy also blocks navigation/redirects that a captured document might request.
    let sources = if external { " http: https:" } else { "" };
    let base_policy = if external { "http: https:" } else { "'none'" };
    let policy = format!("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'{sources}; style-src 'unsafe-inline' data:{sources}; img-src data:{sources}; font-src data:{sources}; connect-src 'none'; frame-src 'self'; object-src 'none'; base-uri {base_policy}; form-action 'none'\">");
    let mut html = html.to_owned();
    if external {
        if let Some(base) = base_url
            .and_then(|base| url::Url::parse(base).ok())
            .filter(|u| matches!(u.scheme(), "http" | "https"))
        {
            let tag = format!(
                "<base href=\"{}\">",
                base.as_str().replace('&', "&amp;").replace('"', "&quot;")
            );
            if let Some(start) = html
                .to_ascii_lowercase()
                .find("<head")
                .and_then(|i| html[i..].find('>').map(|n| i + n + 1))
            {
                html.insert_str(start, &tag);
            } else {
                html = format!("{tag}{html}");
            }
        }
    }
    let escaped = html
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;");
    // Opaque sandbox origin keeps captured scripts out of local files and the wrapper.
    let document = format!("<!doctype html><head>{policy}<style>html,body{{margin:0;width:100%;height:100%}}iframe{{width:100%;height:100%;border:0;display:block}}</style></head><body><iframe sandbox=\"allow-scripts\" srcdoc=\"{escaped}\"></iframe></body>");
    let path = dir.join("page.html");
    let png_path = dir.join("preview.png");
    std::fs::write(&path, document).map_err(|e| e.to_string())?;
    let file_url = url::Url::from_file_path(&path).map_err(|_| "Invalid preview file URL")?;
    // Own the offline proxy endpoint so no unrelated local service can forward traffic.
    let offline_proxy = if external { None } else { Some(std::net::TcpListener::bind(("127.0.0.1",0)).map_err(|e|e.to_string())?) };
    let mut command = std::process::Command::new(executable);
    if let Some(proxy) = &offline_proxy {
        command.arg(format!("--proxy-server=http://{}",proxy.local_addr().map_err(|e|e.to_string())?))
            .arg("--proxy-bypass-list=<-loopback>");
    }
    let mut child = command
        .args([
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-component-update",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--window-size=960,720",
            "--hide-scrollbars",
            "--virtual-time-budget=1000",
        ])
        .arg(format!("--user-data-dir={}", dir.join("profile").display()))
        .arg(format!("--screenshot={}", png_path.display()))
        .arg(file_url.as_str())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => return Err(format!("Chromium preview exited {status}")),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.to_string());
            }
            _ => {}
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Chromium preview timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let file = std::fs::File::open(png_path).map_err(|e| e.to_string())?;
    let mut decoder = png::Decoder::new(std::io::BufReader::new(file));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let mut bytes = vec![0; reader.output_buffer_size().ok_or("Invalid image size")?];
    let info = reader.next_frame(&mut bytes).map_err(|e| e.to_string())?;
    let mut rgba = Vec::new();
    match info.color_type {
        png::ColorType::Rgba => rgba.extend_from_slice(&bytes[..info.buffer_size()]),
        png::ColorType::Rgb => {
            for p in bytes[..info.buffer_size()].chunks_exact(3) {
                rgba.extend_from_slice(&[p[0], p[1], p[2], 255]);
            }
        }
        _ => return Err("Unexpected Chromium screenshot format".into()),
    }
    Ok(Pixels {
        rgba,
        width: info.width as usize,
        height: info.height as usize,
    })
}

#[derive(Clone)]
enum State {
    Pending,
    Pixels(Pixels),
    Texture(egui::TextureHandle),
    Failed(String),
}
type Cache = Arc<Mutex<std::collections::HashMap<u64, Arc<Mutex<State>>>>>;
static WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn draw(ui: &mut Ui, id: &str, height: f32, raw: &str) -> egui::Response {
    draw_with_base_url(ui, id, height, raw, None)
}

pub fn draw_with_base_url(
    ui: &mut Ui,
    id: &str,
    height: f32,
    raw: &str,
    base_url: Option<&str>,
) -> egui::Response {
    use std::hash::{Hash, Hasher};
    let Some(html) = html_body(raw) else {
        return ui
            .vertical(|ui| {
                ui.label("HTML preview: this response is not HTML. Use Raw to inspect its body.");
            })
            .response;
    };
    // Approval is per captured response/origin, never inherited by another tab/document.
    let mut document = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut document);
    base_url.hash(&mut document);
    let setting_id = ui.make_persistent_id((id, "external-preview", document.finish()));
    let mut external = ui
        .ctx()
        .data_mut(|d| d.get_temp::<bool>(setting_id).unwrap_or(false));
    ui.checkbox(
        &mut external,
        "Load external HTTP(S) resources (sends network requests)",
    );
    ui.ctx().data_mut(|d| d.insert_temp(setting_id, external));
    let base_url = base_url.map(str::to_owned);
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    html.hash(&mut hash);
    external.hash(&mut hash);
    base_url.hash(&mut hash);
    let hash = hash.finish();
    let ctx = ui.ctx().clone();
    let cache: Cache = ctx.data_mut(|d| {
        d.get_temp_mut_or_default::<Cache>(egui::Id::new("html-preview-cache"))
            .clone()
    });
    let slot = {
        let mut cache = cache.lock().unwrap();
        cache
            .entry(hash)
            .or_insert_with(|| {
                let slot = Arc::new(Mutex::new(State::Pending));
                let worker = slot.clone();
                let ctx = ctx.clone();
                if WORKERS
                    .fetch_update(
                        std::sync::atomic::Ordering::SeqCst,
                        std::sync::atomic::Ordering::SeqCst,
                        |n| (n < 2).then_some(n + 1),
                    )
                    .is_err()
                {
                    *slot.lock().unwrap() = State::Failed("Preview busy; retry in a moment".into());
                } else {
                    std::thread::spawn(move || {
                        struct Worker;
                        impl Drop for Worker {
                            fn drop(&mut self) {
                                WORKERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                        let _worker = Worker;
                        let executable = std::env::var_os("GULPSUITE_TEST_CHROMIUM")
                            .map(std::path::PathBuf::from)
                            .or_else(|| {
                                std::env::current_exe().ok().and_then(|p| {
                                    crate::browser::BrowserInstall::from_app_executable(&p)
                                        .ok()
                                        .map(|i| i.executable)
                                })
                            });
                        *worker.lock().unwrap() = match executable
                            .ok_or_else(|| {
                                "Bundled Chromium not found. Run the installed Gulpsuite app."
                                    .to_string()
                            })
                            .and_then(|exe| {
                                render_with_options(&exe, &html, external, base_url.as_deref())
                            }) {
                            Ok(p) => State::Pixels(p),
                            Err(e) => State::Failed(e),
                        };
                        ctx.request_repaint();
                    });
                }
                slot
            })
            .clone()
    };
    let mut state = slot.lock().unwrap();
    if let State::Pixels(p) = &*state {
        let image = egui::ColorImage::from_rgba_unmultiplied([p.width, p.height], &p.rgba);
        *state = State::Texture(ctx.load_texture(
            format!("html-preview-{hash}"),
            image,
            egui::TextureOptions::LINEAR,
        ));
    }
    let response=ui.vertical(|ui| {
        ui.label("Chromium HTML preview — visual snapshot; inline CSS/JavaScript and embedded images supported.");
        ui.small(if external { "External resources enabled: remote sites receive requests. No session cookies are shared. Forms and parent navigation remain blocked." } else { "Isolated preview: external resources and network requests are blocked. No session cookies are shared." });
        match &*state {
            State::Texture(texture)=> {egui::ScrollArea::both().id_salt((id,"render-scroll")).max_height(height.max(80.)).show(ui,|ui| {ui.add(egui::Image::new((texture.id(),texture.size_vec2())).alt_text("Rendered HTTP response"));});},
            State::Failed(error)=> {ui.label(format!("Preview failed: {error}")); if ui.button("Retry preview").clicked(){cache.lock().unwrap().remove(&hash);}},
            _=>{ui.label("Rendering HTML preview…");},
        }
    }).response;
    drop(state);
    let mut cache = cache.lock().unwrap();
    while cache.len() > 4 {
        if let Some(key) = cache.keys().copied().find(|k| *k != hash) {
            cache.remove(&key);
        } else {
            break;
        }
    }
    response
}
