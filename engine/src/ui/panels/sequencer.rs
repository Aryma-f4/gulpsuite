//! Sequencer: character entropy of a token.

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::logic;
use crate::ui::app::App;

#[derive(Default, Clone)]
pub struct SequencerPanel {
    pub text: String,
    pub token: String,
    /// Samples collected for the Automaton view.
    pub automaton: Vec<String>,
}

/// Burp's Automaton view: run the statistical suite across a whole set of samples and detect the
/// character set they came from.
fn automaton(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Sequencer — Automaton");

    ui.horizontal_wrapped(|ui| {
        if ui.button("Add current text").clicked() {
            app.panels.sequencer
                .automaton
                .push(app.panels.sequencer.text.clone());
        }
        if ui.button("Add from Repeater response").clicked() {
            let (_, body) = crate::analysis::split_message(&app.panels.repeater.active().response);
            if !body.trim().is_empty() {
                app.panels.sequencer.automaton.push(body.to_string());
            }
        }
        if ui.button("Add from Logger history").clicked() {
            let bodies: Vec<String> = app
                .log
                .iter()
                .rev()
                .take(50)
                .map(|tx| crate::analysis::split_message(&tx.response).1.to_string())
                .filter(|body| !body.trim().is_empty())
                .collect();
            let added = bodies.len();
            app.panels.sequencer.automaton.extend(bodies);
            app.status = format!("Added {added} response(s) to the Automaton");
        }
        ui.separator();
        if ui.button("Clear").clicked() {
            app.panels.sequencer.automaton.clear();
        }
        muted(
            ui,
            &theme,
            &format!("{} sample(s)", app.panels.sequencer.automaton.len()),
        );
    });

    ui.add_space(4.0);

    let samples: Vec<Vec<u8>> = app
        .panels
        .sequencer
        .automaton
        .iter()
        .map(|s| s.trim().as_bytes().to_vec())
        .filter(|s| !s.is_empty())
        .collect();

    if samples.len() < 2 {
        muted(
            ui,
            &theme,
            "Add at least two samples. Gulp compares a set: a single token tells you nothing.",
        );
        return;
    }

    let verdicts = crate::automaton::analyse(&samples);
    let (charset, family) = crate::automaton::detect_charset(&samples);

    eframe::egui::Grid::new("automaton-grid")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            for name in ["Test", "Outcome", "Observed", "Confidence"] {
                ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
            }
            ui.end_row();
            for verdict in &verdicts {
                let colour = match verdict.outcome {
                    crate::automaton::Outcome::Pass => theme.color("ui.icon.success"),
                    crate::automaton::Outcome::Interest => theme.color("ui.icon.warning"),
                    crate::automaton::Outcome::Fail => theme.color("ui.icon.error"),
                };
                ui.label(eframe::egui::RichText::new(verdict.test).color(theme.color("ui.text.body")));
                ui.label(eframe::egui::RichText::new(verdict.outcome.label()).color(colour));
                ui.label(
                    eframe::egui::RichText::new(format!("{:.3}", verdict.observed))
                        .monospace()
                        .color(theme.color("ui.icon.default")),
                );
                ui.label(
                    eframe::egui::RichText::new(format!("{:.1}%", verdict.p_value * 100.0))
                        .monospace()
                        .color(theme.color("ui.icon.default")),
                );
                ui.end_row();
            }
        });

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        label(ui, &theme, "Detected set");
        ui.label(
            eframe::egui::RichText::new(family)
                .strong()
                .color(theme.color("ui.text.body")),
        );
    });
    if !charset.is_empty() {
        eframe::egui::ScrollArea::vertical()
            .max_height(90.0)
            .show(ui, |ui| {
                ui.label(
                    eframe::egui::RichText::new(&charset)
                        .monospace()
                        .color(theme.color("ui.icon.default")),
                );
            });
    }

    ui.add_space(4.0);
    let groups = crate::automaton::by_length(&samples);
    let summary: Vec<String> = groups
        .iter()
        .map(|(len, count)| format!("{len}b: {count}"))
        .collect();
    muted(ui, &theme, &format!("Lengths — {}", summary.join(", ")));
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    if app.view == 1 {
        automaton(app, ui);
        return;
    }
    if app.view == 2 {
        heading(ui, &theme, "Token handling");
        muted(
            ui,
            &theme,
            "Configure how each token is prepared before character-level and bit-level FIPS 140-2 statistical tests run.",
        );
        ui.add_space(6.0);
        ui.label("• Character-level analysis: counts distinct symbols, frequency distribution, and Shannon bits per character.");
        ui.label("• Bit-level FIPS 140-2 suite (Manual load tab): Monobit, Poker, Runs, and Long run tests over sample sets.");
        ui.add_space(6.0);
        muted(
            ui,
            &theme,
            &format!(
                "Current sample pool: {} sample(s) loaded",
                app.panels.sequencer.automaton.len()
            ),
        );
        return;
    }
    heading(ui, &theme, "Select live capture request");
    muted(
        ui,
        &theme,
        "Send requests here from other tools to configure a live capture. Select the request to \
         use, configure the other options below, then click \"Start live capture\".",
    );
    ui.add_space(6.0);

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(86.0);
            if ui
                .add_sized([80.0, 24.0], eframe::egui::Button::new("Remove"))
                .clicked()
            {
                app.panels.sequencer.text.clear();
            }
            if ui
                .add_sized([80.0, 24.0], eframe::egui::Button::new("Clear"))
                .clicked()
            {
                app.panels.sequencer.text.clear();
                app.panels.sequencer.automaton.clear();
            }
            if ui
                .add_sized([80.0, 24.0], eframe::egui::Button::new("+ Repeater"))
                .on_hover_text("Load active Repeater response")
                .clicked()
            {
                app.panels.sequencer.text = app.panels.repeater.active().response.clone();
            }
        });
        ui.add_space(6.0);
        eframe::egui::Frame::new()
            .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
            .show(ui, |ui| {
                ui.set_min_width(460.0);
                ui.set_min_height(110.0);
                eframe::egui::ScrollArea::vertical()
                    .id_salt("seq-live-requests")
                    .max_height(130.0)
                    .show(ui, |ui| {
                        eframe::egui::Grid::new("seq-live-grid")
                            .num_columns(3)
                            .striped(true)
                            .show(ui, |ui| {
                                for h in ["# ▲", "Host", "Request"] {
                                    ui.label(
                                        eframe::egui::RichText::new(h)
                                            .strong()
                                            .color(theme.color("ui.text.body")),
                                    );
                                }
                                ui.end_row();
                                let recent: Vec<_> = app
                                    .log
                                    .iter()
                                    .enumerate()
                                    .rev()
                                    .take(25)
                                    .map(|(i, tx)| {
                                        (
                                            i,
                                            tx.host_url(),
                                            format!("{} {}", tx.method, tx.path_and_query()),
                                            tx.target.clone(),
                                            tx.request.clone(),
                                            tx.response.clone(),
                                        )
                                    })
                                    .collect();
                                for (i, host_url, req_line, target, req, resp) in recent {
                                    let short_host = if host_url.chars().count() > 28 {
                                        let mut s: String = host_url.chars().take(27).collect();
                                        s.push('…');
                                        s
                                    } else {
                                        host_url.clone()
                                    };
                                    let short_req = if req_line.chars().count() > 42 {
                                        let mut s: String = req_line.chars().take(41).collect();
                                        s.push('…');
                                        s
                                    } else {
                                        req_line.clone()
                                    };
                                    let is_sel =
                                        app.panels.sequencer.text == resp && !resp.is_empty();
                                    let r1 = ui.selectable_label(is_sel, format!("{}", i + 1));
                                    let r2 = ui
                                        .selectable_label(is_sel, short_host)
                                        .on_hover_text(&host_url);
                                    let r3 = ui
                                        .selectable_label(
                                            is_sel,
                                            eframe::egui::RichText::new(short_req).monospace(),
                                        )
                                        .on_hover_text(&req_line);
                                    if r1.clicked() || r2.clicked() || r3.clicked() {
                                        app.panels.sequencer.text = resp.clone();
                                    }
                                    super::attach_message_context_menu(
                                        app, &r3, &target, &req, &resp,
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            });
    });

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        let b1 = ui.button("Start live capture");
        let b2 = ui.button("Analyze");
        if b1.clicked() || b2.clicked() {
            analyze(app);
        }
    });
    ui.add_space(6.0);
    ui.separator();
    ui.add_space(4.0);

    heading(ui, &theme, "Token location within response");
    muted(
        ui,
        &theme,
        "Select the location in the response where the token appears.",
    );
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        ui.label("Cookie / Form field / Custom location:");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.sequencer.token)
                .hint_text("Cookie or parameter name (e.g. session)")
                .desired_width(240.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        if ui.button("Configure").clicked() {
            analyze(app);
        }
        if ui.button("Load from Repeater").clicked() {
            app.panels.sequencer.text = app.panels.repeater.active().response.clone();
        }
    });

    let report = logic::analyse_token(&app.panels.sequencer.text, &app.panels.sequencer.token);
    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        ui.label("Input");
        ui.add(
            eframe::egui::TextEdit::multiline(&mut app.panels.sequencer.text)
                .font(eframe::egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(6),
        );
        ui.add_space(4.0);
        match report {
            None => {
                ui.label(
                    eframe::egui::RichText::new("Token not found in the input.")
                        .color(theme.color("ui.icon.default")),
                );
            }
            Some(report) => {
                ui.horizontal(|ui| {
                    ui.label(format!("length {}", report.length));
                    ui.label(format!("distinct {}", report.distinct));
                    ui.label(format!("entropy {:.4}", report.entropy));
                    ui.label(format!("max {:.4}", report.max_entropy));
                });
                ui.add_space(4.0);
                eframe::egui::Grid::new("seq-chars").num_columns(4).striped(true).show(ui, |ui| {
                    for name in ["Char", "Code", "Count", "Freq"] {
                        ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                    }
                    ui.end_row();
                    for c in &report.chars {
                        ui.label(eframe::egui::RichText::new(c.ch.to_string()).monospace().color(theme.color("ui.text.body")));
                        ui.label(eframe::egui::RichText::new(format!("U+{:04X}", c.code)).monospace().color(theme.color("ui.icon.default")));
                        ui.label(eframe::egui::RichText::new(c.count.to_string()).color(theme.color("ui.icon.default")));
                        ui.label(eframe::egui::RichText::new(format!("{:.4}", c.freq)).color(theme.color("ui.icon.default")));
                        ui.end_row();
                    }
                });
            }
        }
    });
}

pub(crate) fn analyze(app: &mut App) {
    match logic::analyse_token(&app.panels.sequencer.text, &app.panels.sequencer.token) {
        Some(report) => {
            app.status =
                format!("{} characters, entropy {:.4}", report.length, report.entropy);
        }
        None => app.status = "Token not found".into(),
    }
}
