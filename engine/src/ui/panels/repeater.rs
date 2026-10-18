//! Repeater: hand-edited requests.

use eframe::egui::Ui;

use super::heading;
use crate::ui::app::App;

#[derive(Clone)]
pub struct RepeaterPanel {
    pub host: String,
    pub raw: String,
    pub response: String,
    pub status: Option<u16>,
    pub sending: bool,
    /// The in-flight request id, if any.
    pending: Option<u64>,
    /// The raw editor is shown only on demand; the coloured view is the default.
    pub editing: bool,
}

impl Default for RepeaterPanel {
    fn default() -> Self {
        RepeaterPanel {
            host: "http://example.com/".into(),
            raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            response: String::new(),
            status: None,
            sending: false,
            pending: None,
            editing: false,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Repeater");

    // Collect anything that came back since the last frame.
    if let Some(id) = app.panels.repeater.pending {
        if let Some((status, body)) = app.take_response(id) {
            app.panels.repeater.status = Some(status);
            app.panels.repeater.response = body;
            app.panels.repeater.sending = false;
            app.panels.repeater.pending = None;
            app.status = format!("Response {status} ({} bytes)", app.panels.repeater.response.len());
        }
    }

    ui.horizontal(|ui| {
        ui.label("Target");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.repeater.host)
                .desired_width(320.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
        if ui
            .add_enabled(
                !app.panels.repeater.sending,
                eframe::egui::Button::new("Send"),
            )
            .clicked()
        {
            send(app);
        }
    });
    ui.add_space(4.0);

    let message_bg = theme.color("ui.editor.message.background");
    let colour = match app.panels.repeater.status {
        Some(200..=399) => theme.color("ui.icon.success"),
        Some(400..=499) => theme.color("ui.icon.warning"),
        Some(_) => theme.color("ui.icon.error"),
        None => theme.color("ui.icon.default"),
    };
    let response = app.panels.repeater.response.clone();
    let request = app.panels.repeater.raw.clone();

    ui.columns(2, |columns| {
        columns[0].horizontal(|ui| {
            ui.label("Request");
            if ui.button(if app.panels.repeater.editing { "View" } else { "Edit" }).clicked() {
                app.panels.repeater.editing = !app.panels.repeater.editing;
            }
        });
        if app.panels.repeater.editing {
            crate::ui::highlight::show_editable(
                &mut columns[0],
                &mut app.panels.repeater.raw,
                &theme,
                message_bg,
            );
        } else {
            crate::ui::highlight::show_message(&mut columns[0], &request, &theme, message_bg);
        }

        columns[1].horizontal(|ui| {
            ui.label("Response");
            let status = match app.panels.repeater.status {
                Some(status) => status.to_string(),
                None if response.is_empty() => "no response yet".into(),
                None => "error".into(),
            };
            ui.label(eframe::egui::RichText::new(status).color(colour));
        });
        crate::ui::highlight::show_message(&mut columns[1], &response, &theme, message_bg);
    });

    ui.add_space(6.0);
    ui.separator();
    analyzers(app, ui, &response);
}

/// Burp's response analyzers. Backed by `http/message/responses/analysis/*` in the shipped API:
/// a keywords analyser, a variations analyser and attribute extraction.
fn analyzers(app: &mut App, ui: &mut Ui, response: &str) {
    let theme = app.theme.clone();
    let (head, body) = crate::analysis::split_message(response);
    let content_type = head
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-type:"))
        .map(|line| line[13..].trim().to_string())
        .unwrap_or_default();

    if body.is_empty() {
        super::muted(ui, &theme, "No response body to analyse.");
        return;
    }

    let markup = crate::analysis::is_markup(&content_type, body);
    let keywords = crate::analysis::keywords(body, 40);
    let attributes = if markup {
        crate::analysis::attributes(body, 40)
    } else {
        Vec::new()
    };
    // Variations compare this response against its siblings from the same host in the history.
    let siblings: Vec<String> = app
        .log
        .iter()
        .rev()
        .filter(|tx| {
            !tx.response.is_empty()
                && tx.target != app.panels.repeater.host
                && app.panels.repeater.host.ends_with(&tx.host)
        })
        .take(20)
        .map(|tx| {
            crate::analysis::split_message(&tx.response)
                .1
                .to_string()
        })
        .collect();
    let variations = crate::analysis::variations(body, &siblings);
    let (unique, partial, shared) = crate::analysis::variation_summary(&variations);

    ui.horizontal_wrapped(|ui| {
        super::label(ui, &theme, &format!("Keywords: {}", keywords.len()));
        super::label(
            ui,
            &theme,
            &format!(
                "Attributes: {}",
                if markup { attributes.len() } else { 0 }
            ),
        );
        super::label(
            ui,
            &theme,
            &format!("Variations: {unique} unique, {partial} partial, {shared} shared"),
        );
        super::muted(
            ui,
            &theme,
            &format!("(compared against {} response(s))", siblings.len()),
        );
    });

    ui.columns(3, |columns| {
        super::label(&mut columns[0], &theme, "Keywords");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[0], |ui| {
                for keyword in &keywords {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(keyword.text.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &keyword.count.to_string());
                    });
                }
            });

        super::label(&mut columns[1], &theme, "Attributes");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[1], |ui| {
                if !markup {
                    super::muted(ui, &theme, "Not a markup response.");
                }
                for attribute in &attributes {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(attribute.name.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &attribute.count.to_string());
                    });
                }
            });

        super::label(&mut columns[2], &theme, "Variations");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[2], |ui| {
                if siblings.is_empty() {
                    super::muted(
                        ui,
                        &theme,
                        "No comparable responses yet. Send a few requests to the same host.",
                    );
                }
                for (index, row) in variations.iter().take(80).enumerate() {
                    let text = match row {
                        crate::analysis::Variation::Unique => "unique".to_string(),
                        crate::analysis::Variation::Shared(n) => format!("in {n}"),
                        crate::analysis::Variation::Partial(n, total) => format!("in {n} of {total}"),
                    };
                    let colour = match row {
                        crate::analysis::Variation::Unique => theme.color("ui.icon.warning"),
                        crate::analysis::Variation::Partial(_, _) => theme.color("ui.icon.information"),
                        crate::analysis::Variation::Shared(_) => theme.color("ui.icon.default"),
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(format!("{index}"))
                                .color(theme.color("ui.icon.disabled")),
                        );
                        ui.label(eframe::egui::RichText::new(text).color(colour));
                    });
                }
            });
    });
}

pub(crate) fn send(app: &mut App) {
    let host = app.panels.repeater.host.trim().to_string();
    // A live Bambda script rewrites the request before it leaves, and a broken one blocks the send
    // rather than quietly sending something the operator did not intend.
    let raw = match app.panels.extender.apply_live(&app.panels.repeater.raw) {
        Ok(raw) => raw,
        Err(why) => {
            app.status = format!("Bambda rejected the request: {why}");
            return;
        }
    };
    let rest = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(&host)
        .to_string();
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(&rest);
    let (hostname, port) = match authority.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), 80),
        },
        None => (authority.to_string(), 80),
    };
    if hostname.is_empty() {
        app.status = "Target is missing a host".into();
        return;
    }
    app.panels.repeater.status = None;
    app.panels.repeater.response = format!("Sending to {hostname}:{port}…");
    let id = app.send_request(hostname, port, raw);
    app.panels.repeater.pending = Some(id);
    app.panels.repeater.sending = true;
    app.status = format!("Sent request #{id}");
}
