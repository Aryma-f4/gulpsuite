//! Logger: every transaction and every other protocol the listeners see, split the way Burp splits it.

use eframe::egui::Ui;

use super::{heading, muted};
use crate::ui::app::App;

/// One captured DNS exchange.
#[derive(Clone, Debug)]
pub struct DnsEntry {
    pub question: String,
    pub kind: u16,
    pub answers: Vec<String>,
    pub server: String,
}

/// One captured SMTP message.
#[derive(Clone, Debug)]
pub struct SmtpEntry {
    pub direction: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

#[derive(Default, Clone)]
pub struct LoggerPanel {
    pub filter: String,
    pub only_errors: bool,
    /// Ports the DNS and SMTP listeners are bound to, once started.
    pub dns_port: Option<u16>,
    pub smtp_port: Option<u16>,
    /// Set by the view when the operator asks for capture to start.
    pub dns_start: bool,
    pub smtp_start: bool,
    /// Set by the view when the operator asks for capture to stop.
    pub dns_stop: bool,
    pub smtp_stop: bool,
    /// The history row the operator has selected, so its message can be shown below the table.
    pub selected: Option<usize>,
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    match app.view {
        0 => http(app, ui),
        1 => super::websocket::draw(app, ui, "Logger"),
        2 => dns(app, ui),
        _ => email(app, ui),
    }
}

fn http(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    // Burp names the tool in its tab and the sub-tab below it, so a panel heading would repeat
    // it; the sub-tab row already says which log this is.

    ui.horizontal(|ui| {
        ui.label("Filter");
        ui.text_edit_singleline(&mut app.panels.logger.filter);
        ui.checkbox(&mut app.panels.logger.only_errors, "errors only");
    });

    let filter = app.panels.logger.filter.to_lowercase();
    let errors_only = app.panels.logger.only_errors;
    // Rows are indexed from the end, because the table is shown newest first.
    let rows: Vec<(usize, &crate::ui::app::Transaction)> = app
        .log
        .iter()
        .enumerate()
        .rev()
        .take(500)
        .filter(|(_, tx)| !errors_only || tx.status >= 400)
        .filter(|(_, tx)| filter.is_empty() || tx.target.to_lowercase().contains(&filter))
        .collect();

    eframe::egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .show(ui, |ui| {
            eframe::egui::Grid::new("logger-grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["Method", "Target", "Status", "Bytes", "Host"] {
                        ui.label(
                            eframe::egui::RichText::new(name)
                                .strong()
                                .color(theme.color("ui.text.body")),
                        );
                    }
                    ui.end_row();
                    for (index, tx) in rows.iter() {
                        let selected = app.panels.logger.selected == Some(*index);
                        let text = if selected {
                            eframe::egui::RichText::new(&tx.method).color(theme.color("ui.icon.link"))
                        } else {
                            eframe::egui::RichText::new(&tx.method)
                        };
                        if ui.label(text).clicked() {
                            app.panels.logger.selected = Some(*index);
                        }
                        ui.label(&tx.target);
                        ui.label(tx.status.to_string());
                        ui.label(tx.bytes.to_string());
                        ui.label(
                            tx.target
                                .split('/')
                                .next()
                                .unwrap_or_default()
                                .to_string(),
                        );
                        ui.end_row();
                    }
                });
        });

    // The selected row's raw message, highlighted the way Burp shows it.
    let selected = app.panels.logger.selected;
    if let Some(tx) = selected.and_then(|index| app.log.get(index)) {
        ui.add_space(6.0);
        eframe::egui::Grid::new("logger-detail")
            .num_columns(2)
            .striped(false)
            .show(ui, |ui| {
                ui.label(eframe::egui::RichText::new("Request").strong());
                ui.label(eframe::egui::RichText::new("Response").strong());
                ui.end_row();
                ui.add(eframe::egui::Label::new(eframe::egui::RichText::new(&tx.request).monospace()));
                ui.add(eframe::egui::Label::new(eframe::egui::RichText::new(&tx.response).monospace()));
                ui.end_row();
            });
        ui.add_space(4.0);
        crate::ui::highlight::show_message(
            ui,
            &tx.request,
            &theme,
            theme.color("ui.background.2"),
        );
        crate::ui::highlight::show_message(
            ui,
            &tx.response,
            &theme,
            theme.color("ui.background.2"),
        );
    }
}

fn dns(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "DNS");
    ui.horizontal(|ui| {
        if app.panels.logger.dns_port.is_none() {
            if ui.button("Start capture").clicked() {
                app.panels.logger.dns_start = true;
            }
        } else if ui.button("Stop capture").clicked() {
            app.panels.logger.dns_port = None;
            app.panels.logger.dns_stop = true;
        }
        if let Some(port) = app.panels.logger.dns_port {
            ui.label(format!("listening on 127.0.0.1:{port} udp"));
        }
    });

    if app.dns_log.is_empty() {
        muted(ui, &theme, "No DNS queries captured yet.");
        return;
    }
    eframe::egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .max_height(320.0)
        .show(ui, |ui| {
            eframe::egui::Grid::new("dns-grid")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["Question", "Type", "Server"] {
                        ui.label(
                            eframe::egui::RichText::new(name)
                                .strong()
                                .color(theme.color("ui.text.body")),
                        );
                    }
                    ui.end_row();
                    for entry in app.dns_log.iter().rev() {
                        ui.label(eframe::egui::RichText::new(&entry.question).monospace());
                        ui.label(crate::dns::kind_name(entry.kind));
                        ui.label(&entry.server);
                        ui.end_row();
                    }
                });
        });
}

fn email(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "SMTP");
    ui.horizontal(|ui| {
        if app.panels.logger.smtp_port.is_none() {
            if ui.button("Start capture").clicked() {
                app.panels.logger.smtp_start = true;
            }
        } else if ui.button("Stop capture").clicked() {
            app.panels.logger.smtp_port = None;
            app.panels.logger.smtp_stop = true;
        }
        if let Some(port) = app.panels.logger.smtp_port {
            ui.label(format!("listening on 127.0.0.1:{port}"));
        }
    });

    if app.smtp_log.is_empty() {
        muted(ui, &theme, "No messages captured yet.");
        return;
    }
    let mut expanded: Option<usize> = None;
    eframe::egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .max_height(320.0)
        .show(ui, |ui| {
            for (index, message) in app.smtp_log.iter().enumerate().rev() {
                let head = format!("{} — {} → {}", message.subject, message.from, message.to.join(", "));
                if eframe::egui::CollapsingHeader::new(head)
                    .default_open(expanded == Some(index))
                    .show(ui, |ui| {
                        ui.label(eframe::egui::RichText::new(message.body.clone()).monospace());
                    })
                    .header_response.clicked()
                {
                    expanded = Some(index);
                }
            }
        });
}
