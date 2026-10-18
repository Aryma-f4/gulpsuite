//! Scanner: crawl a target, then inject payloads at what the crawl finds.

use std::sync::Arc;

use eframe::egui::Ui;

use super::{heading, muted};
use crate::ui::app::App;

#[derive(Clone)]
pub struct ScannerPanel {
    pub seed: String,
    pub host: String,
    pub max_depth: usize,
    pub max_pages: usize,
    pub active_checks: bool,
    pub running: bool,
    pub progress: String,
    /// Findings from the finished scan.
    pub findings: Vec<crate::scanner::Finding>,
    pub pages: Vec<(String, u16)>,
    pub only_high: bool,
}

impl Default for ScannerPanel {
    fn default() -> Self {
        ScannerPanel {
            seed: "http://127.0.0.1:8080/".into(),
            host: "127.0.0.1:8080".into(),
            max_depth: 2,
            max_pages: 50,
            active_checks: true,
            running: false,
            progress: String::new(),
            findings: Vec::new(),
            pages: Vec::new(),
            only_high: false,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Scanner");

    ui.horizontal(|ui| {
        ui.label("Seed URL");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.scanner.seed)
                .desired_width(300.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        if ui
            .add_enabled(
                !app.panels.scanner.running,
                eframe::egui::Button::new("Start scan"),
            )
            .clicked()
        {
            start(app);
        }
        if ui
            .add_enabled(
                app.panels.scanner.running,
                eframe::egui::Button::new("Cancel"),
            )
            .clicked()
        {
            app.panels.scanner.running = false;
            app.panels.scanner.progress = "Cancelled".into();
        }
    });

    ui.horizontal(|ui| {
        ui.label("Depth");
        let mut depth = app.panels.scanner.max_depth.to_string();
        if ui.add(eframe::egui::TextEdit::singleline(&mut depth).desired_width(40.0)).changed() {
            if let Ok(n) = depth.trim().parse::<usize>() {
                app.panels.scanner.max_depth = n.min(10);
            }
        }
        ui.label("Pages");
        let mut pages = app.panels.scanner.max_pages.to_string();
        if ui.add(eframe::egui::TextEdit::singleline(&mut pages).desired_width(56.0)).changed() {
            if let Ok(n) = pages.trim().parse::<usize>() {
                app.panels.scanner.max_pages = n.clamp(1, 5_000);
            }
        }
        ui.checkbox(&mut app.panels.scanner.active_checks, "Active checks");
        ui.checkbox(&mut app.panels.scanner.only_high, "High and medium only");
        if ui.button("Clear").clicked() {
            app.panels.scanner.findings.clear();
            app.panels.scanner.pages.clear();
        }
    });

    let counts = counts(&app.panels.scanner.findings, app.panels.scanner.only_high);
    ui.horizontal(|ui| {
        ui.label(format!("{} page(s)", app.panels.scanner.pages.len()));
        for severity in [
            crate::scanner::Severity::High,
            crate::scanner::Severity::Medium,
            crate::scanner::Severity::Low,
            crate::scanner::Severity::Info,
        ] {
            ui.label(
                eframe::egui::RichText::new(format!(
                    "{} {}",
                    severity.as_str(),
                    counts.iter().find(|(s, _)| *s == severity).map(|(_, n)| *n).unwrap_or(0)
                ))
                .color(severity_colour(&theme, severity)),
            );
        }
    });

    if app.panels.scanner.running || !app.panels.scanner.progress.is_empty() {
        muted(ui, &theme, &app.panels.scanner.progress);
    }
    ui.add_space(4.0);

    if app.panels.scanner.findings.is_empty() {
        muted(ui, &theme, "No issues yet. Point the scanner at a target and start a scan.");
        return;
    }

    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        eframe::egui::Grid::new("scanner-findings")
            .num_columns(4)
            .striped(true)
            .show(ui, |ui| {
                for name in ["Severity", "Issue", "Parameter", "Evidence"] {
                    ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                }
                ui.end_row();
                for finding in app.panels.scanner.findings.clone() {
                    if app.panels.scanner.only_high
                        && matches!(finding.severity, crate::scanner::Severity::Low | crate::scanner::Severity::Info)
                    {
                        continue;
                    }
                    ui.label(
                        eframe::egui::RichText::new(finding.severity.as_str())
                            .color(severity_colour(&theme, finding.severity)),
                    );
                    ui.label(eframe::egui::RichText::new(&finding.name).color(theme.color("ui.text.body")));
                    ui.label(
                        eframe::egui::RichText::new(finding.parameter.clone().unwrap_or_default())
                            .color(theme.color("icon.link")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(format!(
                            "{} — {}",
                            finding.url,
                            truncate(&finding.evidence, 60)
                        ))
                        .color(theme.color("ui.icon.default")),
                    );
                    ui.end_row();
                }
            });
    });
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let head: String = text.chars().take(limit).collect();
    format!("{head}…")
}

fn counts(findings: &[crate::scanner::Finding], only_high: bool) -> Vec<(crate::scanner::Severity, usize)> {
    use crate::scanner::Severity;
    let severities = [Severity::High, Severity::Medium, Severity::Low, Severity::Info];
    severities
        .iter()
        .map(|severity| {
            (
                *severity,
                findings
                    .iter()
                    .filter(|f| f.severity == *severity)
                    .filter(|_| !only_high || matches!(severity, Severity::High | Severity::Medium))
                    .count(),
            )
        })
        .collect()
}

fn severity_colour(theme: &crate::ui::theme::Theme, severity: crate::scanner::Severity) -> eframe::egui::Color32 {
    use crate::scanner::Severity;
    match severity {
        Severity::High => theme.color("ui.issue.high"),
        Severity::Medium => theme.color("ui.issue.medium"),
        Severity::Low => theme.color("ui.issue.low"),
        Severity::Info => theme.color("ui.icon.information"),
    }
}

pub(crate) fn start(app: &mut App) {
    let seed = app.panels.scanner.seed.trim().to_string();
    if seed.is_empty() {
        app.status = "Scanner needs a seed URL".into();
        return;
    }
    let Some(host) = crate::scanner::split(&seed).map(|(h, _)| h) else {
        app.status = "Seed URL must be absolute, e.g. http://host/".into();
        return;
    };
    app.panels.scanner.host = host.clone();
    app.panels.scanner.findings.clear();
    app.panels.scanner.pages.clear();
    app.panels.scanner.running = true;
    app.panels.scanner.progress = "Crawling…".into();
    app.status = format!("Scanning {seed}");

    // The Target panel's include/exclude fields own the scope; the seed host is only the fallback
    // when the operator has not written anything down yet.
    let include = app.panels.target_panel.scope.trim().to_string();
    let exclude = app.panels.target_panel.scope_exclude.trim().to_string();
    let scope = if include.is_empty() {
        crate::scanner::Scope::for_host(&host)
    } else {
        crate::scanner::Scope::from_spec(
            &include,
            &exclude,
            app.panels.scanner.max_depth,
            app.panels.scanner.max_pages,
        )
    };
    let run_active = app.panels.scanner.active_checks;
    let proxy: Arc<crate::proxy::Proxy> = app.proxy.clone();
    let runtime = app.runtime_handle();

    // The scan is long-running, so it owns its own thread and reports back over the event channel.
    let (tx, rx) = std::sync::mpsc::channel::<ScanUpdate>();
    app.scanner_updates = Some(rx);

    std::thread::spawn(move || {
        runtime.block_on(async move {
            let noop = |_| {};
            let coverage =
                crate::scanner::crawler::crawl(&seed, &scope, &proxy, &noop).await;

            let mut findings = coverage.findings.clone();
            let mut pages = coverage.pages.clone();

            if run_active {
                let _ = tx.send(ScanUpdate::Progress(format!(
                    "Passive: {} issue(s); injecting payloads…",
                    findings.len()
                )));
                let checks = crate::scanner::active::all_checks();
                let mut probes = 0usize;

                for (url, status) in coverage.pages.iter().take(40) {
                    if *status < 200 || *status >= 400 {
                        continue;
                    }
                    // Re-fetch the page so its forms are known; the crawl does not retain bodies.
                    let Some((host, port, tls, raw)) =
                        crate::scanner::active::InjectionPoint::query(url, "x").request("x")
                    else {
                        continue;
                    };
                    let Ok((_, body_text)) =
                        proxy.one_shot_secure(&host, port, &raw, tls, 8_000).await
                    else {
                        continue;
                    };
                    let body = crate::scanner::http::parse_response(&body_text).body;

                    for point in crate::scanner::crawler::injection_points(url, &body)
                        .into_iter()
                        .take(6)
                    {
                        for check in &checks {
                            for payload in check.payloads {
                                let Some((h, p, tls, request)) = point.request(payload) else { continue };
                                let Ok((_, text)) =
                                    proxy.one_shot_secure(&h, p, &request, tls, 8_000).await
                                else {
                                    continue;
                                };
                                probes += 1;
                                let response = crate::scanner::http::parse_response(&text);
                                if let Some(finding) = crate::scanner::active::evaluate(
                                    check,
                                    url,
                                    &point.name,
                                    payload,
                                    &response,
                                ) {
                                    // Do not report the same issue at the same site twice.
                                    let duplicate = findings.iter().any(|existing| {
                                        existing.name == finding.name
                                            && existing.url == finding.url
                                            && existing.parameter == finding.parameter
                                    });
                                    if !duplicate {
                                        findings.push(finding);
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = tx.send(ScanUpdate::Progress(format!("{probes} probe(s) sent")));
            }

            pages.dedup();
            findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            let _ = tx.send(ScanUpdate::Done { findings, pages });
        });
    });
}

/// What a running scan reports back to the UI.
pub enum ScanUpdate {
    Progress(String),
    Done {
        findings: Vec<crate::scanner::Finding>,
        pages: Vec<(String, u16)>,
    },
}