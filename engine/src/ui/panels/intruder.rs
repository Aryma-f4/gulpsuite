//! Intruder: payload position markers, grid enumeration, and the attack itself.

use eframe::egui::Ui;

use crate::logic;
use crate::proxy::MatchRules;
use crate::ui::app::App;

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

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    
    ui.horizontal(|ui| {
        ui.label("Target host");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.host)
                .desired_width(180.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        ui.label("Threads");
        let mut threads = app.panels.intruder.threads.to_string();
        if ui.add(eframe::egui::TextEdit::singleline(&mut threads).desired_width(48.0)).changed() {
            if let Ok(n) = threads.trim().parse::<usize>() {
                app.panels.intruder.threads = n.clamp(1, 64);
            }
        }
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

    ui.horizontal(|ui| {
        ui.label("Payloads");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.payloads)
                .desired_width(360.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
    });

    ui.add(
        eframe::egui::TextEdit::multiline(&mut app.panels.intruder.template)
            .font(eframe::egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .desired_rows(5),
    );

    let markers = logic::markers(&app.panels.intruder.template);
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} marker position(s) across {} cluster(s)",
            markers.iter().map(|m| m.positions.len()).sum::<usize>(),
            markers.len()
        ));
    });

    ui.horizontal(|ui| {
        ui.label("Filter status");
        ui.add(eframe::egui::TextEdit::singleline(&mut app.panels.intruder.status_codes).desired_width(90.0));
        ui.label("Exclude status");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.intruder.negative_status)
                .desired_width(90.0),
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
