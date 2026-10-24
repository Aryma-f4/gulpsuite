//! Discover: content discovery over the captured host list.
//!
//! Burp's Discover walks a starting point and reports what it finds. This does the same from the
//! proxy history: it takes hosts already seen, requests a bounded set of well-known paths against
//! them through the proxy, and lists what answered.

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::ui::app::App;

/// Paths probed per host. Kept small and fixed so a scan cannot fan out without bound.
pub const PATHS: &[&str] = &[
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/admin",
    "/.env",
];

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    heading(ui, &theme, "Create your own Repeater feature");
    muted(
        ui,
        &theme,
        "Create powerful custom actions to extract, analyze, and transform data with Bambda scripts.",
    );
    ui.horizontal(|ui| {
        if crate::ui::app::primary_button(ui, &theme, "Try it out").clicked() {
            app.tool = crate::ui::app::EXTENSIONS;
            app.view = 0;
            app.status = "Opened Bambda custom actions editor".into();
        }
    });
    ui.separator();
    heading(ui, &theme, "Content discovery");

    ui.horizontal(|ui| {
        label(ui, &theme, "Paths");
        ui.text_edit_singleline(&mut app.panels.discover_paths);
    });
    ui.horizontal(|ui| {
        let running = app.panels.discover_running;
        if ui.add_enabled(!running, eframe::egui::Button::new(if running { "Discovering…" } else { "Start" })).clicked() {
            start(app);
        }
        if ui.button("Clear results").clicked() {
            app.panels.discover_results.clear();
            app.status = "Discover results cleared".into();
        }
    });

    ui.add_space(4.0);
    if app.panels.discover_running {
        ui.horizontal(|ui| {
            super::scanner::paint_burp_spinner(
                ui,
                eframe::egui::Vec2::new(16.0, 16.0),
                eframe::egui::Color32::from_rgb(0x5B, 0x4F, 0xFF),
            );
            muted(ui, &theme, &format!("Probing… {}", app.panels.discover_progress));
        });
    } else {
        muted(ui, &theme, "Gulp crawls a starting URL; this build probes a fixed path list against hosts already in the proxy history.");
    }

    ui.add_space(6.0);
    label(ui, &theme, "Results");
    if app.panels.discover_results.is_empty() {
        muted(ui, &theme, "No results yet.");
        return;
    }
    let chosen: Vec<(String, u16)> = app.panels.discover_results.clone();
    eframe::egui::ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
        for (url, status) in chosen.iter() {
            ui.horizontal(|ui| {
                ui.label(eframe::egui::RichText::new(format!("{status}  {url}")).monospace());
                if ui.small_button("To Repeater").clicked() {
                    if let Ok(parsed) = crate::http_target::HttpTarget::parse(url) {
                        let path = url::Url::parse(url)
                            .ok()
                            .map(|u| u.path().to_string())
                            .filter(|p| !p.is_empty())
                            .unwrap_or_else(|| "/".into());
                        let req = format!(
                            "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                            parsed.authority()
                        );
                        app.panels.repeater.open(url, &req);
                        app.tool = crate::ui::app::REPEATER;
                        app.view = 0;
                        app.status = format!("Sent {url} to Repeater");
                    }
                }
            });
        }
    });
}

/// Kicks off a run against the hosts in proxy history.
fn start(app: &mut App) {
    let paths = crate::discover::paths_from(&app.panels.discover_paths);
    // `host` is recorded as host:port, which is what the probe needs; `target` is only a path.
    let mut hosts = crate::discover::hosts_from(app.log.iter().map(|tx| {
        if tx.secure {
            format!("https://{}", tx.host)
        } else {
            format!("http://{}", tx.host)
        }
    }));
    if hosts.is_empty() {
        let mut fallback_seeds = Vec::new();
        for cand in [
            app.panels.scanner.seed.trim(),
            app.panels.repeater.active().host.trim(),
        ] {
            if cand.starts_with("http://") || cand.starts_with("https://") {
                fallback_seeds.push(cand.to_string());
            }
        }
        for rule in app.panels.target_panel.scope.split([',', '\n']) {
            let trimmed = rule.trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                fallback_seeds.push(trimmed.to_string());
            }
        }
        hosts = crate::discover::hosts_from(fallback_seeds.into_iter());
    }
    if hosts.is_empty() || paths.is_empty() {
        app.status = "Discover needs history to work from and at least one path".into();
        return;
    }
    let urls = crate::discover::plan(&hosts, &paths);
    if urls.is_empty() {
        app.status = "Discover has nothing to probe".into();
        return;
    }
    app.panels.discover_running = true;
    app.panels.discover_progress = String::new();
    app.status = format!("Discover probing {} url(s)", urls.len());
    app.workspace_adapter
        .begin_discover(&mut app.workspace, urls.len());

    let proxy = app.proxy.clone();
    let runtime = app.runtime_handle();
    let (tx, rx) = std::sync::mpsc::channel::<crate::discover::Update>();
    app.discover_updates = Some(rx);
    std::thread::spawn(move || {
        runtime.block_on(async move {
            let report = |update: crate::discover::Update| {
                let _ = tx.send(update);
            };
            crate::discover::probe(proxy, urls, &report).await;
        });
    });
}

/// The default probe list, as a single editable string.
pub fn default_paths() -> String {
    PATHS.join("\n")
}
