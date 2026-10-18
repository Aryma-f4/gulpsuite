//! The WebSocket message view, shared by the Proxy and Logger tools the way Burp shares the same
//! recorded messages between them.

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::ui::app::App;

/// Human-readable name for a frame opcode.
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        crate::ws::opcode::CONTINUATION => "continuation",
        crate::ws::opcode::TEXT => "text",
        crate::ws::opcode::BINARY => "binary",
        crate::ws::opcode::CLOSE => "close",
        crate::ws::opcode::PING => "ping",
        crate::ws::opcode::PONG => "pong",
        _ => "reserved",
    }
}

/// Records captured WebSocket traffic. `tool` is shown in the heading so the same data reads
/// correctly under either Proxy or Logger.
pub fn draw(app: &mut App, ui: &mut Ui, tool: &str) {
    let theme = app.theme.clone();
    heading(ui, &theme, &format!("{tool} — WebSockets"));

    if app.websockets.is_empty() {
        muted(
            ui,
            &theme,
            "No WebSocket connections captured. The proxy records one when a request upgrades and the \\
             server answers 101.",
        );
        return;
    }

    let mut to_remove: Option<usize> = None;
    ui.horizontal(|ui| {
        label(ui, &theme, "Filter");
        ui.text_edit_singleline(&mut app.panels.ws_filter);
    });

    for (index, connection) in app.websockets.iter().enumerate() {
        let haystack = format!("{} {}", connection.host, connection.id);
        let filter = app.panels.ws_filter.trim();
        if !filter.is_empty() && !haystack.to_lowercase().contains(&filter.to_lowercase()) {
            continue;
        }
        ui.add_space(6.0);
        let state = if connection.open { "open" } else { "closed" };
        let header = eframe::egui::RichText::new(format!(
            "{} {} — {} message{}, {}",
            connection.id,
            connection.host,
            connection.messages.len(),
            if connection.messages.len() == 1 { "" } else { "s" },
            state,
        ))
        .strong();
        eframe::egui::CollapsingHeader::new(header)
            .default_open(index + 1 == app.websockets.len())
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("View handshake").clicked() {
                        app.panels.ws_handshake = Some((connection.id, true));
                    }
                    if ui.button("Copy handshake").clicked() {
                        let text = format!("{}\n{}", connection.request, connection.response);
                        ui.ctx().copy_text(text);
                        app.status = "WebSocket handshake copied".into();
                    }
                    if ui.button("Remove").clicked() {
                        to_remove = Some(index);
                    }
                });

                if app.panels.ws_handshake == Some((connection.id, true)) {
                    ui.add_space(4.0);
                    label(ui, &theme, "Client handshake");
                    crate::ui::highlight::show_message(
                        ui,
                        &connection.request,
                        &theme,
                        theme.color("ui.editor.message.background"),
                    );
                    label(ui, &theme, "Server handshake");
                    crate::ui::highlight::show_message(
                        ui,
                        &connection.response,
                        &theme,
                        theme.color("ui.editor.message.background"),
                    );
                }

                ui.add_space(4.0);
                if connection.messages.is_empty() {
                    muted(ui, &theme, "No frames recorded yet.");
                    return;
                }
                eframe::egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(ui, |ui| {
                        for (frame_index, message) in connection.messages.iter().enumerate() {
                            let direction = if message.to_server { "→ server" } else { "← client" };
                            let is_open = app.panels.ws_selected == Some((connection.id, frame_index as u64));
                            let line = format!(
                                "{direction}  {}  {} bytes",
                                opcode_name(message.opcode),
                                message.bytes,
                            );
                            if ui.selectable_label(is_open, line).clicked() {
                                app.panels.ws_selected = Some((connection.id, frame_index as u64));
                            }
                            if is_open {
                                ui.add_space(2.0);
                                crate::ui::highlight::show_message(
                                    ui,
                                    &message.text,
                                    &theme,
                                    theme.color("ui.editor.message.background"),
                                );
                            }
                        }
                    });
            });
    }

    if let Some(index) = to_remove {
        app.websockets.remove(index);
        if app.panels.ws_selected.map(|(id, _)| id == index as u64).unwrap_or(false) {
            app.panels.ws_selected = None;
        }
    }
}
