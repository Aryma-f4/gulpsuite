//! Intruder: payload position markers, grid enumeration, and the attack itself.

use eframe::egui::Ui;

use crate::logic;
use crate::proxy::MatchRules;
use crate::ui::app::App;
use crate::ui::panels::muted;

#[derive(Clone, Default)]
pub struct Result {
    pub status: u16,
    pub length: usize,
    pub matched: bool,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct IntruderPanel {
    pub template: String,
    pub payloads: String,
    pub results: Vec<Result>,
    pub running: bool,
    pub matches: usize,
    pub threads: usize,
    pub host: String,
    pub status_codes: String,
    pub negative_status: String,
    pub negative_regex: String,
    pub match_length: bool,
    /// Burp updates the Host header to follow the target by default; turning it off lets the
    /// attack send an arbitrary Host header to a fixed target.
    pub update_host: bool,
    /// Payload sets, in Burp's model: each holds a type and the text that defines it.
    pub payload_sets: Vec<PayloadSet>,
    /// Sources for the generated payloads, one per line.
    pub generation_sources: String,
    /// Files that make up the resource pool, and how many requests share one of each.
    pub resources: Vec<String>,
    pub resources_per_request: usize,
}

/// One Intruder payload set: the type that produced it and the values themselves.
#[derive(Clone)]
pub struct PayloadSet {
    pub kind: String,
    pub values: String,
}

impl Default for IntruderPanel {
    fn default() -> Self {
        IntruderPanel {
            template: "GET /search?q=§x§ HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            payloads: "a\nb\nc".into(),
            results: Vec::new(),
            running: false,
            matches: 0,
            threads: 4,
            host: "example.com".into(),
            status_codes: String::new(),
            negative_status: String::new(),
            negative_regex: String::new(),
            match_length: false,
            update_host: true,
            payload_sets: vec![PayloadSet { kind: "Simple list".into(), values: "a\nb\nc".into() }],
            generation_sources: String::new(),
            resources: Vec::new(),
            resources_per_request: 1,
        }
    }
}

impl IntruderPanel {
    /// Records one result from the proxy's event stream.
    pub fn record(&mut self, index: usize, status: u16, length: usize, matched: bool, error: Option<String>) {
        if self.results.len() <= index {
            self.results.resize(index + 1, Result::default());
        }
        self.results[index] = Result { status, length, matched, error };
    }
}

/// The payload kinds Burp offers for a payload set.
const PAYLOAD_KINDS: [&str; 4] =
    ["Simple list", "Numbers", "Dates & times", "Custom modification"];

/// Positions: the base request, where the payload markers decide insertion points.
fn positions(app: &mut App, ui: &mut Ui) {
    ui.add(
        eframe::egui::TextEdit::multiline(&mut app.panels.intruder.template)
            .font(eframe::egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .desired_rows(6),
    );
    let markers = logic::markers(&app.panels.intruder.template);
    let positions = markers.iter().map(|m| m.positions.len()).sum::<usize>();
    muted(
        ui,
        &app.theme.clone(),
        &format!("{positions} marker position(s) across {} cluster(s)", markers.len()),
    );
}

/// Payloads: the sets the attack draws from, each with the type that produced it.
fn payloads(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let mut remove = None;
    eframe::egui::Grid::new("intruder-payloads")
        .num_columns(3)
        .striped(true)
        .show(ui, |ui| {
            for name in ["Payload set", "Payload type", ""] {
                ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
            }
            ui.end_row();
            for (index, set) in app.panels.intruder.payload_sets.iter_mut().enumerate() {
                ui.label(format!("{}", index + 1));
                eframe::egui::ComboBox::from_id_salt(("intruder-kind", index))
                    .selected_text(set.kind.clone())
                    .show_ui(ui, |ui| {
                        for kind in PAYLOAD_KINDS {
                            ui.selectable_value(&mut set.kind, kind.to_string(), kind);
                        }
                    });
                if ui.button("Remove").clicked() {
                    remove = Some(index);
                }
                ui.end_row();
                ui.label("");
                ui.add(
                    eframe::egui::TextEdit::multiline(&mut set.values)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3),
                );
                ui.end_row();
            }
        });
    if let Some(index) = remove {
        app.panels.intruder.payload_sets.remove(index);
    }
    if ui.button("Add payload set").clicked() {
        app.panels.intruder.payload_sets.push(PayloadSet {
            kind: PAYLOAD_KINDS[0].into(),
            values: String::new(),
        });
    }
    // The attack enumerates the first set, which keeps the marker expansion in one place.
    app.panels.intruder.payloads = app
        .panels
        .intruder
        .payload_sets
        .first()
        .map(|set| set.values.clone())
        .unwrap_or_default();
}

/// Options: how many requests run at once and which responses count as interesting.
fn options(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Number of threads");
        let mut threads = app.panels.intruder.threads.to_string();
        if ui
            .add(eframe::egui::TextEdit::singleline(&mut threads).desired_width(60.0))
            .changed()
        {
            if let Ok(n) = threads.trim().parse::<usize>() {
                app.panels.intruder.threads = n.clamp(1, 64);
            }
        }
    });
    ui.horizontal(|ui| {
        ui.label("Filter status");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.status_codes)
                .desired_width(120.0),
        );
        ui.label("Exclude status");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.negative_status)
                .desired_width(120.0),
        );
        ui.checkbox(&mut app.panels.intruder.match_length, "Match length");
    });
    ui.horizontal(|ui| {
        ui.label("Exclude pattern");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.negative_regex)
                .desired_width(260.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
    });
}

/// Payload generation: where a large set of payloads is collected from.
fn payload_generation(app: &mut App, ui: &mut Ui) {
    muted(
        ui,
        &app.theme.clone(),
        "List the sources to generate payloads from, one per line.",
    );
    ui.add(
        eframe::egui::TextEdit::multiline(&mut app.panels.intruder.generation_sources)
            .font(eframe::egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .desired_rows(4),
    );
    let count = app
        .panels
        .intruder
        .generation_sources
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    muted(ui, &app.theme.clone(), &format!("{count} source(s)"));
}

/// Resource pool: files the attack cycles through, and how many requests share one of each.
fn resource_pool(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal(|ui| {
        ui.label("Resources per request");
        let mut per = app.panels.intruder.resources_per_request.to_string();
        if ui
            .add(eframe::egui::TextEdit::singleline(&mut per).desired_width(60.0))
            .changed()
        {
            if let Ok(n) = per.trim().parse::<usize>() {
                app.panels.intruder.resources_per_request = n.clamp(1, 1000);
            }
        }
    });
    let mut remove = None;
    eframe::egui::Grid::new("intruder-resources")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            for name in ["Path", ""] {
                ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
            }
            ui.end_row();
            for (index, path) in app.panels.intruder.resources.iter_mut().enumerate() {
                ui.add(
                    eframe::egui::TextEdit::singleline(path)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(320.0),
                );
                if ui.button("Remove").clicked() {
                    remove = Some(index);
                }
                ui.end_row();
            }
        });
    if let Some(index) = remove {
        app.panels.intruder.resources.remove(index);
    }
    if ui.button("Add file").clicked() {
        app.panels.intruder.resources.push(String::new());
    }
}

/// Burp's Intruder attack editor is a row of side panels — Positions, Payloads, Options,
/// Payload generation, Resource pool — with the results table below them.
pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    ui.horizontal(|ui| {
        ui.label("Target host");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.host)
                .desired_width(180.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        ui.checkbox(&mut app.panels.intruder.update_host, "Update Host header to match target");
        if ui
            .add_enabled(!app.panels.intruder.running, eframe::egui::Button::new("Start attack"))
            .clicked()
        {
            start(app);
        }
        if ui
            .add_enabled(app.panels.intruder.running, eframe::egui::Button::new("Clear"))
            .clicked()
        {
            app.panels.intruder.results.clear();
            app.panels.intruder.matches = 0;
        }
    });

    match app.view {
        1 => payloads(app, ui),
        2 => options(app, ui),
        3 => payload_generation(app, ui),
        4 => resource_pool(app, ui),
        _ => positions(app, ui),
    }

    let template = app.panels.intruder.template.clone();
    let payloads = app.panels.intruder.payloads.clone();
    eframe::egui::ScrollArea::vertical()
        .max_height(180.0)
        .show(ui, |ui| {
            eframe::egui::Grid::new("intruder-results")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["#", "Status", "Length", ""] {
                        ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                    }
                    ui.end_row();
                    let preview: Vec<String> =
                        payloads.lines().map(str::to_string).collect();
                    let requests = logic::enumerate(&template, &preview, 2000);
                    for (index, row) in app.panels.intruder.results.iter().enumerate() {
                        let colour = if row.matched {
                            theme.color("ui.icon.success")
                        } else {
                            theme.color("ui.text.body")
                        };
                        ui.label(eframe::egui::RichText::new(index.to_string()).color(theme.color("ui.icon.default")));
                        ui.label(eframe::egui::RichText::new(row.status.to_string()).color(colour));
                        ui.label(eframe::egui::RichText::new(row.length.to_string()).color(colour));
                        ui.label(eframe::egui::RichText::new(
                            row.error.clone().unwrap_or_else(|| {
                                if row.matched { "match".into() } else { String::new() }
                            }),
                        ).color(theme.color("ui.icon.error")));
                        ui.end_row();
                    }
                    if app.panels.intruder.results.is_empty() {
                        ui.label(eframe::egui::RichText::new(format!(
                            "{} request(s) would be sent",
                            requests.len()
                        )).color(theme.color("ui.icon.default")));
                        ui.end_row();
                    }
                });
        });
}

fn numbers(text: &str) -> Vec<u16> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
}

pub(crate) fn start(app: &mut App) {
    let host = app.panels.intruder.host.trim().to_string();
    let (hostname, port) = match host.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (host.clone(), 80),
        },
        None => (host.clone(), 80),
    };
    if hostname.is_empty() {
        app.status = "Intruder needs a host".into();
        return;
    }
    let payloads: Vec<String> = app
        .panels
        .intruder
        .payloads
        .lines()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if payloads.is_empty() {
        app.status = "No payloads supplied".into();
        return;
    }
    let requests = logic::enumerate(&app.panels.intruder.template, &payloads, 50_000);
    if requests.is_empty() {
        app.status = "No § markers found, so nothing would be sent".into();
        return;
    }
    let rules = MatchRules::new(
        numbers(&app.panels.intruder.status_codes),
        numbers(&app.panels.intruder.negative_status),
        Some(app.panels.intruder.negative_regex.clone()),
        app.panels.intruder.match_length,
    );
    let threads = app.panels.intruder.threads;
    app.panels.intruder.results.clear();
    app.panels.intruder.matches = 0;
    app.panels.intruder.running = true;
    app.status = format!("Sending {} requests…", requests.len());

    let proxy = app.proxy.clone();
    let runtime = app.runtime_handle();
    std::thread::spawn(move || {
        runtime.block_on(proxy.attack(hostname, port, requests, threads, rules));
    });
}
