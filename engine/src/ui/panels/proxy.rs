//! Proxy: listener control, interception, and the held-request queue.

use eframe::egui::Ui;

use super::{heading, muted};
use crate::ui::app::App;

#[derive(Clone)]
pub struct ProxyPanel {
    pub port: u16,
    /// Index into the log of the row whose detail is open.
    pub selected: Option<usize>,
    /// Which parked request is open in the intercept editor.
    pub held_selected: Option<u64>,
    /// The edited message waiting to be forwarded, with the id of the message it belongs to.
    pub held_edit: Option<(u64, String)>,
}

impl Default for ProxyPanel {
    fn default() -> Self {
        ProxyPanel {
            port: 8080,
            selected: None,
            held_selected: None,
            held_edit: None,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Proxy");

    match app.view {
        0 => intercept(app, ui),
        1 => history(app, ui),
        2 => super::websocket::draw(app, ui, "Proxy"),
        _ => match_and_replace(app, ui),
    }
}

/// Burp's match-and-replace view: the rules that rewrite traffic on its way out.
///
/// The rules use the same Bambda language as the Extensions tab, so one script serves both: here
/// it is a set of live rules, there it is a script being written.
fn match_and_replace(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Proxy — Match and replace");

    let active = app.proxy.has_rules();
    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut app.panels.match_replace_enabled, "Enable rules")
            .changed()
        {
            if app.panels.match_replace_enabled {
                match app.proxy.set_rules(&app.panels.extender.script) {
                    Ok(()) => app.status = "Match and replace rules are live".into(),
                    Err(why) => {
                        app.panels.match_replace_enabled = false;
                        app.status = format!("Rules rejected: {why}");
                    }
                }
            } else {
                app.proxy.clear_rules();
                app.status = "Match and replace rules are off".into();
            }
        }
        if ui.button("Apply now").clicked() {
            match app.proxy.set_rules(&app.panels.extender.script) {
                Ok(()) => app.status = "Match and replace rules reloaded".into(),
                Err(why) => app.status = format!("Rules rejected: {why}"),
            }
        }
        muted(ui, &theme, if active { "rules are live" } else { "no rules active" });
    });

    ui.add_space(6.0);
    let script = app.panels.extender.script.clone();
    match crate::bambda::parse(&script) {
        Ok(statements) => {
            if statements.is_empty() {
                muted(ui, &theme, "No rules. Edit the script in the Extensions tab.");
                return;
            }
            eframe::egui::Grid::new("match-replace-grid")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(eframe::egui::RichText::new("Rule").strong());
                    ui.label(eframe::egui::RichText::new("Effect").strong());
                    ui.end_row();
                    for statement in statements.iter() {
                        ui.label(statement.describe());
                        ui.label(statement.effect());
                        ui.end_row();
                    }
                });
        }
        Err(error) => {
            ui.label(
                eframe::egui::RichText::new(format!("Script error — {error}"))
                    .color(theme.color("ui.issue.high")),
            );
        }
    }
}

/// Burp's Intercept view: listener controls plus the requests parked for a decision.
fn intercept(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Proxy — Intercept");

    ui.horizontal(|ui| {
        let listening = app.listening.is_some();
        if ui.add_enabled(!listening, eframe::egui::Button::new("Start")).clicked() {
            app.start_proxy(app.panels.proxy_panel.port);
        }
        if ui.add_enabled(listening, eframe::egui::Button::new("Stop")).clicked() {
            app.stop_proxy();
        }
        ui.separator();
        ui.label("Port");
        let mut port_text = app.panels.proxy_panel.port.to_string();
        if ui.text_edit_singleline(&mut port_text).changed() {
            if let Ok(port) = port_text.trim().parse::<u16>() {
                app.panels.proxy_panel.port = port;
            }
        }
        ui.checkbox(&mut app.intercepting, "Intercept");
        app.proxy.set_intercept(app.intercepting);
        ui.separator();
        // Burp has a switch for responses as well, so a response can be changed before the client
        // gets to see it.
        let mut responses = app.intercepting_responses;
        if ui.checkbox(&mut responses, "Responses").changed() {
            app.intercepting_responses = responses;
            app.proxy.set_intercept_response(responses);
        }
        // Https is intercepted with a certificate of the proxy's own, so the traffic inside the
        // tunnel can be seen. With it off the tunnel is passed through as it is.
        let mut tls = app.tls_intercepting;
        if ui.checkbox(&mut tls, "TLS").changed() {
            app.tls_intercepting = tls;
            app.proxy.set_tls_interception(tls);
        }
    });

    if app.held.is_empty() {
        muted(ui, &theme, "Nothing held. Traffic passes straight through.");
        return;
    }

    // Burp parks the request and shows it in an editor, so it can be changed before it is let
    // through. The edit lives with the held item, and the row that is being edited is the one
    // that is open.
    ui.add_space(6.0);
    // A selection that points at a message that is gone falls back to the first one that is
    // still held, so the buttons always act on something real.
    let selected = app
        .panels
        .proxy_panel
        .held_selected
        .filter(|id| app.held.iter().any(|item| item.id == *id))
        .unwrap_or(app.held[0].id);
    let current = app
        .held
        .iter()
        .find(|item| item.id == selected)
        .cloned()
        .unwrap_or_else(|| app.held[0].clone());

    let requests = app
        .held
        .iter()
        .filter(|item| item.kind == crate::proxy::HeldKind::Request)
        .count();
    let responses = app.held.len() - requests;
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} request(s), {} response(s) held",
            requests, responses
        ));
        ui.separator();
        for item in app.held.clone() {
            let label = match item.kind {
                crate::proxy::HeldKind::Request => format!("{} {}", item.method, item.target),
                crate::proxy::HeldKind::Response => format!("response {}", item.method),
            };
            if ui
                .selectable_label(item.id == selected, truncate(&label, 34))
                .clicked()
            {
                app.panels.proxy_panel.held_selected = Some(item.id);
                // The edit belongs to the message that is open.
                app.panels.proxy_panel.held_edit = None;
            }
        }
    });

    // The editor holds the message that will be sent.
    let mut edited = app
        .panels
        .proxy_panel
        .held_edit
        .as_ref()
        .filter(|(id, _)| *id == selected)
        .map(|(_, text)| text.clone())
        .unwrap_or_else(|| current.raw.clone());
    let is_response = current.kind == crate::proxy::HeldKind::Response;
    ui.horizontal(|ui| {
        if ui.button(if is_response { "Forward" } else { "Forward" }).clicked() {
            app.forward_edited(selected, &edited);
        }
        if ui.button(if is_response { "Cancel" } else { "Drop" }).clicked() {
            app.release(selected, false);
        }
        if !is_response && ui.button("To Repeater").clicked() {
            app.panels.repeater.open(&current.target, &edited);
            app.tool = 4;
            app.status = format!("Held request #{} sent to Repeater", selected);
        }
        if ui.button("Reset").clicked() {
            app.panels.proxy_panel.held_edit = None;
        }
        if ui.button("Forward all").clicked() {
            app.release_all();
        }
    });
    ui.add_space(4.0);
    eframe::egui::ScrollArea::vertical()
        .max_height(320.0)
        .show(ui, |ui| {
            let response = ui.add(
                eframe::egui::TextEdit::multiline(&mut edited)
                    .font(eframe::egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(12),
            );
            if response.changed() {
                app.panels.proxy_panel.held_edit = Some((selected, edited));
            }
        });
}

/// Shortens a label so a row of held requests still fits.
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// The session cookie jar. Burp keeps this under its session settings rather than a tool tab, so
/// it sits at the end of the HTTP history view.
fn cookie_jar(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.add_space(6.0);
    heading(ui, &theme, "Cookie jar");
    ui.horizontal(|ui| {
        if ui.button("Evict expired").clicked() {
            let removed = app.proxy.cookies().evict_expired();
            app.status = format!("Evicted {removed} expired cookie(s)");
        }
        if ui.button("Clear all").clicked() {
            app.proxy.cookies().clear();
            app.status = "Cookie jar cleared".into();
        }
        ui.separator();
        muted(
            ui,
            &theme,
            &format!("{} cookie(s) stored", app.proxy.cookies().len()),
        );
    });

    let cookies = app.proxy.cookies().all();
    if cookies.is_empty() {
        muted(
            ui,
            &theme,
            "No cookies yet. The proxy stores them from Set-Cookie and replays them on later requests.",
        );
        return;
    }

    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        eframe::egui::Grid::new("cookie-grid")
            .num_columns(6)
            .striped(true)
            .show(ui, |ui| {
                for name in ["Name", "Value", "Domain", "Path", "Flags", "Expires"] {
                    ui.label(
                        eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")),
                    );
                }
                ui.end_row();
                for cookie in &cookies {
                    ui.label(eframe::egui::RichText::new(&cookie.name).color(theme.color("ui.text.body")));
                    ui.label(eframe::egui::RichText::new(&cookie.value).color(theme.color("ui.text.disabled")));
                    ui.label(eframe::egui::RichText::new(&cookie.domain).color(theme.color("ui.icon.default")));
                    ui.label(eframe::egui::RichText::new(&cookie.path).color(theme.color("ui.icon.default")));
                    let mut flags = String::new();
                    if cookie.secure {
                        flags.push_str("Secure ");
                    }
                    if cookie.http_only {
                        flags.push_str("HttpOnly");
                    }
                    ui.label(eframe::egui::RichText::new(if flags.is_empty() { "-" } else { &flags })
                        .color(theme.color("ui.icon.default")));
                    let expires = cookie
                        .expires
                        .map(|at| {
                            let secs = at.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                            format!("{secs}s")
                        })
                        .unwrap_or_else(|| "session".into());
                    ui.label(eframe::egui::RichText::new(expires).color(theme.color("ui.icon.default")));
                    ui.end_row();
                }
            });
    });
}

/// Burp's History view: everything the proxy has forwarded.
fn history(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Proxy — HTTP history");
    if app.log.is_empty() {
        muted(ui, &theme, "Nothing captured yet.");
        cookie_jar(app, ui);
        return;
    }

    if let Some(index) = app.panels.proxy_panel.selected {
        if let Some(tx) = app.log.get(index) {
            ui.horizontal(|ui| {
                ui.label(format!("{}", tx.target));
                if ui.button("To Repeater").clicked() {
                    app.panels.repeater.open(&tx.target, &tx.request);
                    app.tool = 4;
                    app.status = "Request copied to Repeater".into();
                }
                if ui.button("Close").clicked() {
                    app.panels.proxy_panel.selected = None;
                }
            });
            let (request, response) = (tx.request.clone(), tx.response.clone());
            let message_bg = theme.color("ui.editor.message.background");
            ui.columns(2, |columns| {
                columns[0].label("Request");
                crate::ui::highlight::show_message(&mut columns[0], &request, &theme, message_bg);
                columns[1].label("Response");
                crate::ui::highlight::show_message(&mut columns[1], &response, &theme, message_bg);
            });
            ui.add_space(4.0);
        }
    }
    eframe::egui::ScrollArea::vertical()
        .stick_to_bottom(true)
        .show(ui, |ui| {
            eframe::egui::Grid::new("proxy-history")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["Method", "Target", "Status", "Bytes", ""] {
                        ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                    }
                    ui.end_row();
                    let rows = app.log.len();
                    let first = rows.saturating_sub(300);
                    // Only the four tiny display fields are copied. Cloning whole transactions here
                    // would copy both message bodies for every visible row, on every frame.
                    let visible: Vec<(usize, String, String, u16, u64, bool)> = (first..rows)
                        .map(|index| {
                            let tx = &app.log[index];
                            (
                                index,
                                tx.method.clone(),
                                tx.target.clone(),
                                tx.status,
                                tx.bytes,
                                tx.truncated,
                            )
                        })
                        .collect();
                    for (index, method, target, status, bytes, truncated) in visible {
                        let tx_method = method;
                        let selected = app.panels.proxy_panel.selected == Some(index);
                        let method_colour = if selected {
                            theme.color("icon.linkHover")
                        } else {
                            theme.color("icon.link")
                        };
                        // The method cell doubles as the row's click target.
                        let response = ui.label(
                            eframe::egui::RichText::new(&tx_method).color(method_colour),
                        );
                        if response.clicked() {
                            app.panels.proxy_panel.selected = Some(index);
                        }
                        // Burp's right-click menu on a history row (ui/contextmenu/*).
                        if response.secondary_clicked() {
                            app.panels.proxy_panel.selected = Some(index);
                            app.context_menu(&response, index);
                        }
                        ui.label(eframe::egui::RichText::new(&target).color(theme.color("ui.text.body")));
                        ui.label(eframe::egui::RichText::new(status.to_string()).color(theme.color("ui.text.body")));
                        ui.label(eframe::egui::RichText::new(if truncated {
                            format!("{bytes}+")
                        } else {
                            bytes.to_string()
                        }).color(theme.color("ui.icon.default")));
                        if ui.button("To Repeater").clicked() {
                            // The whole request travels, not just the URL: rewriting it by hand is
                            // exactly what the operator does not want to do. Only on click, so the
                            // bodies are copied once here rather than every frame.
                            if let Some(tx) = app.log.get(index) {
                                app.panels.repeater.open(&tx.target, &tx.request);
                            }
                            app.tool = 4;
                            app.status = "Request copied to Repeater".into();
                        }
                        ui.end_row();
                    }
                });
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{HeldInfo, HeldKind};

    /// The text the frame drew, so a test can look for a label or a message.
    fn text_of(output: &eframe::egui::FullOutput) -> Vec<String> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                eframe::egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect()
    }

    /// The intercept view has to show the parked request in an editor, with the buttons that let
    /// it through. It is checked headless, because the window cannot be driven from a test.
    #[test]
    fn the_intercept_view_shows_the_parked_request() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.held.push(HeldInfo {
            id: 7,
            kind: HeldKind::Request,
            method: "GET".into(),
            target: "/held".into(),
            raw: "GET /held HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
        });

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                intercept(&mut app, ui);
            });
        });
        let texts = text_of(&output);

        let all = texts.join("\n");
        assert!(
            all.contains("GET /held HTTP/1.1"),
            "the parked request should be in the editor: {all}"
        );
        for button in ["Forward", "Drop", "To Repeater", "Reset"] {
            assert!(
                all.contains(button),
                "the {button} button should be there: {all}"
            );
        }
    }

    /// A parked response is shown with its own wording.
    #[test]
    fn the_intercept_view_shows_a_parked_response() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.held.push(HeldInfo {
            id: 8,
            kind: HeldKind::Response,
            method: "200".into(),
            target: String::new(),
            raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".into(),
        });

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                intercept(&mut app, ui);
            });
        });
        let texts = text_of(&output);

        let all = texts.join("\n");
        assert!(
            all.contains("HTTP/1.1 200 OK"),
            "the parked response should be in the editor: {all}"
        );
        assert!(
            all.contains("Cancel"),
            "a parked response is cancelled rather than dropped: {all}"
        );
    }
}
