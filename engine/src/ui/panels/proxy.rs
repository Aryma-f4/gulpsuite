//! Proxy: listener control, interception, and the held-request queue.

use eframe::egui::Ui;

use super::{heading, muted};
use crate::ui::app::App;

#[derive(Clone)]
pub struct ProxyPanel {
    pub port: u16,
    /// Index into the log of the row whose detail is open.
    pub selected: Option<usize>,
}

impl Default for ProxyPanel {
    fn default() -> Self {
        ProxyPanel { port: 8080, selected: None }
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
    });

    if !app.held.is_empty() {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Forward all").clicked() {
                app.release_all();
            }
        });
        eframe::egui::ScrollArea::vertical()
            .max_height(170.0)
            .show(ui, |ui| {
                eframe::egui::Grid::new("held-grid").num_columns(3).striped(true).show(ui, |ui| {
                    for name in ["Method", "Target", ""] {
                        ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                    }
                    ui.end_row();
                    for item in app.held.clone() {
                        ui.label(eframe::egui::RichText::new(&item.method).color(theme.color("icon.link")));
                        ui.label(eframe::egui::RichText::new(&item.target).color(theme.color("ui.text.body")));
                        ui.horizontal(|ui| {
                            if ui.button("Forward").clicked() {
                                app.release(item.id, true);
                            }
                            if ui.button("Drop").clicked() {
                                app.release(item.id, false);
                            }
                            if ui.button("To Repeater").clicked() {
                                app.panels.repeater.raw = item.raw.clone();
                                app.panels.repeater.host = item.target.clone();
                                app.panels.repeater.editing = false;
                                app.tool = 4;
                                app.status = format!("Held request #{} sent to Repeater", item.id);
                            }
                        });
                        ui.end_row();
                    }
                });
            });
    }

    if app.held.is_empty() {
        muted(ui, &theme, "No requests held. Traffic passes straight through.");
    }
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
                    app.panels.repeater.raw = tx.request.clone();
                    app.panels.repeater.host = tx.target.clone();
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
                                app.panels.repeater.raw = tx.request.clone();
                                app.panels.repeater.host = tx.target.clone();
                            }
                            app.panels.repeater.editing = false;
                            app.tool = 4;
                            app.status = "Request copied to Repeater".into();
                        }
                        ui.end_row();
                    }
                });
        });
}
