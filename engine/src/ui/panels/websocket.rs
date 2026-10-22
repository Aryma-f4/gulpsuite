//! The WebSocket message view, shared by the Proxy and Logger tools.

use eframe::egui::{self, Color32, RichText, Stroke, Ui, Vec2};

use super::{empty_state, label, muted};
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

/// Records captured WebSocket traffic. `tool` names the owning panel for status messages.
pub fn draw(app: &mut App, ui: &mut Ui, tool: &str) {
    let theme = app.theme.clone();

    if app.websockets.is_empty() {
        let (learn, _) = empty_state(
            ui,
            &theme,
            "WebSockets history is empty",
            "The WebSockets history displays all WebSocket messages passed through Gulpsuite. The \
             proxy records a connection when a request upgrades and the server answers 101.",
            true,
            None,
        );
        if learn {
            app.status = format!(
                "{tool} WebSockets: upgrade an HTTP connection (101 Switching Protocols) to capture frames"
            );
        }
        return;
    }

    let border_col = theme.color("ui.border.1");
    let bg0 = theme.color("ui.background.0");
    let bg1 = theme.color("ui.background.1");

    // Top Filter Bar
    egui::Frame::new()
        .fill(bg1)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                label(ui, &theme, "Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.ws_filter)
                        .hint_text("Filter by host, URL, or message payload…")
                        .desired_width(280.0),
                );
                if !app.panels.ws_filter.is_empty() && ui.small_button("Clear").clicked() {
                    app.panels.ws_filter.clear();
                }
                ui.separator();
                let total_frames: usize = app.websockets.iter().map(|c| c.messages.len()).sum();
                muted(
                    ui,
                    &theme,
                    &format!(
                        "{} connection(s) · {} message(s)",
                        app.websockets.len(),
                        total_frames
                    ),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Clear history").clicked() {
                        app.websockets.clear();
                        app.panels.ws_selected = None;
                        app.panels.ws_handshake = None;
                        return;
                    }
                });
            });
        });
    ui.separator();

    if app.websockets.is_empty() {
        return;
    }

    let filter = app.panels.ws_filter.trim().to_lowercase();
    // Build flattened rows: `(conn_idx, conn_id, host, path, open, Option<(frame_idx, to_server, opcode, bytes, preview)>)`
    let mut flat_rows: Vec<(
        usize,
        u64,
        String,
        String,
        bool,
        Option<(usize, bool, u8, usize, String)>,
    )> = Vec::new();

    for (conn_idx, conn) in app.websockets.iter().enumerate() {
        let first_line = conn.request.lines().next().unwrap_or("GET /");
        let req_path = first_line.split_whitespace().nth(1).unwrap_or("/");
        let full_url = if req_path.starts_with("http://") || req_path.starts_with("https://") {
            req_path.to_string()
        } else {
            format!("wss://{}{}", conn.host, req_path)
        };
        if conn.messages.is_empty() {
            let hay = format!("{} {} {}", conn.id, conn.host, full_url).to_lowercase();
            if filter.is_empty() || hay.contains(&filter) {
                flat_rows.push((conn_idx, conn.id, conn.host.clone(), full_url, conn.open, None));
            }
        } else {
            for (f_idx, msg) in conn.messages.iter().enumerate() {
                let hay = format!("{} {} {} {}", conn.id, conn.host, full_url, msg.text).to_lowercase();
                if !filter.is_empty() && !hay.contains(&filter) {
                    continue;
                }
                let preview: String = msg
                    .text
                    .lines()
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(44)
                    .collect();
                flat_rows.push((
                    conn_idx,
                    conn.id,
                    conn.host.clone(),
                    full_url.clone(),
                    conn.open,
                    Some((f_idx, msg.to_server, msg.opcode, msg.bytes, preview)),
                ));
            }
        }
    }

    // Default-select the newest row if nothing is selected
    if app.panels.ws_selected.is_none() {
        if let Some((_, cid, _, _, _, frame_opt)) = flat_rows.last() {
            let f_id = frame_opt.as_ref().map(|(fi, _, _, _, _)| *fi as u64).unwrap_or(0);
            app.panels.ws_selected = Some((*cid, f_id));
        }
    }

    let mut to_remove: Option<usize> = None;
    let table_h = (ui.available_height() * 0.42).clamp(130.0, 280.0);

    egui::Frame::new()
        .fill(bg0)
        .stroke(Stroke::new(1.0_f32, border_col))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("ws-history-master-table")
                .max_height(table_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("ws-history-grid")
                        .num_columns(8)
                        .striped(true)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            for h in [
                                "#",
                                "URL",
                                "Direction",
                                "Opcode",
                                "Length",
                                "Payload preview",
                                "State",
                                "",
                            ] {
                                ui.label(
                                    RichText::new(h)
                                        .size(11.5)
                                        .strong()
                                        .color(theme.color("ui.text.heading")),
                                );
                            }
                            ui.end_row();

                            for (row_num, (conn_idx, conn_id, _host, full_url, is_open, frame_opt)) in
                                flat_rows.iter().enumerate()
                            {
                                let f_idx_u64 = frame_opt
                                    .as_ref()
                                    .map(|(fi, _, _, _, _)| *fi as u64)
                                    .unwrap_or(0);
                                let selected =
                                    app.panels.ws_selected == Some((*conn_id, f_idx_u64));
                                let short_url = if full_url.chars().count() > 38 {
                                    let mut s: String = full_url.chars().take(37).collect();
                                    s.push('…');
                                    s
                                } else {
                                    full_url.clone()
                                };
                                let (dir_lbl, op_lbl, len_lbl, prev_lbl) = match frame_opt {
                                    Some((_, to_srv, op, len, prev)) => (
                                        if *to_srv { "→ To server" } else { "← To client" },
                                        opcode_name(*op),
                                        format!("{len} B"),
                                        prev.as_str(),
                                    ),
                                    None => (
                                        "Handshake",
                                        "101 Upgrade",
                                        "0 B".to_string(),
                                        "(connected — awaiting frames)",
                                    ),
                                };
                                let state_lbl = if *is_open { "open" } else { "closed" };

                                let c1 = ui.selectable_label(selected, (row_num + 1).to_string());
                                let c2 = ui
                                    .selectable_label(selected, short_url)
                                    .on_hover_text(full_url);
                                let c3 = ui.selectable_label(selected, dir_lbl);
                                let c4 = ui.selectable_label(selected, op_lbl);
                                let c5 = ui.selectable_label(selected, len_lbl);
                                let c6 = ui.selectable_label(
                                    selected,
                                    RichText::new(prev_lbl).monospace().size(11.0),
                                );
                                let c7 = ui.selectable_label(selected, state_lbl);
                                if c1.clicked()
                                    || c2.clicked()
                                    || c3.clicked()
                                    || c4.clicked()
                                    || c5.clicked()
                                    || c6.clicked()
                                    || c7.clicked()
                                {
                                    app.panels.ws_selected = Some((*conn_id, f_idx_u64));
                                }
                                if ui
                                    .small_button("×")
                                    .on_hover_text("Remove WebSocket connection")
                                    .clicked()
                                {
                                    to_remove = Some(*conn_idx);
                                }
                                ui.end_row();
                            }
                        });
                });
        });

    if let Some(index) = to_remove {
        if let Some(removed) = app.websockets.get(index) {
            let removed_id = removed.id;
            app.websockets.remove(index);
            if app
                .panels
                .ws_selected
                .is_some_and(|(id, _)| id == removed_id)
            {
                app.panels.ws_selected = None;
            }
        }
        return;
    }

    // Bottom Detail Split Pane: Left = WebSocket Message | Right = Upgrade Handshake (Request & Response)
    let Some((sel_conn_id, sel_frame_idx)) = app.panels.ws_selected else {
        return;
    };
    let Some(conn) = app
        .websockets
        .iter()
        .find(|c| c.id == sel_conn_id)
        .cloned()
    else {
        return;
    };
    let frame_msg = conn.messages.get(sel_frame_idx as usize).cloned();
    let detail_h = (ui.available_height() - 12.0).max(180.0);
    let mut split_ratio = 0.54f32;
    let msg_bg = theme.color("ui.editor.message.background");

    super::vertical_split(
        ui,
        &theme,
        "ws-history-detail-split",
        &mut split_ratio,
        detail_h,
        |pane, ui| {
            if pane == 0 {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("WebSocket Message")
                            .size(13.5)
                            .strong()
                            .color(Color32::from_rgb(0xE0, 0x53, 0x20)),
                    );
                    if let Some(ref fm) = frame_msg {
                        muted(
                            ui,
                            &theme,
                            &format!(
                                "{} · {} · {} bytes",
                                if fm.to_server {
                                    "Client → Server"
                                } else {
                                    "Server → Client"
                                },
                                opcode_name(fm.opcode),
                                fm.bytes
                            ),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Send to Repeater").clicked() {
                                let host_url = format!("https://{}", conn.host);
                                let req_with_ws = format!("{}\r\n{}", conn.request.trim_end(), fm.text);
                                app.panels.repeater.open(&host_url, &req_with_ws);
                                app.tool = crate::ui::app::REPEATER;
                                app.view = 0;
                                app.status = "Sent WebSocket message to Repeater".into();
                            }
                            if ui.small_button("Copy message").clicked() {
                                ui.ctx().copy_text(fm.text.clone());
                                app.status = "Copied WebSocket message payload".into();
                            }
                        });
                    }
                });
                ui.add_space(4.0);
                let payload_text = frame_msg
                    .as_ref()
                    .map(|m| m.text.as_str())
                    .unwrap_or("(No WebSocket data frames captured yet on this connection)");
                crate::ui::highlight::show_message_in(
                    ui,
                    "ws-selected-frame-payload",
                    (detail_h - 36.0).max(120.0),
                    payload_text,
                    &theme,
                    msg_bg,
                );
            } else {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Upgrade Handshake (101 Switching Protocols)")
                            .size(13.5)
                            .strong()
                            .color(Color32::from_rgb(0xE0, 0x53, 0x20)),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("Send to Repeater").clicked() {
                            let host_url = format!("https://{}", conn.host);
                            app.panels.repeater.open(&host_url, &conn.request);
                            app.tool = crate::ui::app::REPEATER;
                            app.view = 0;
                            app.status = "Sent WebSocket upgrade handshake to Repeater".into();
                        }
                        if ui.small_button("Copy handshake").clicked() {
                            ui.ctx()
                                .copy_text(format!("{}\n{}", conn.request, conn.response));
                            app.status = "WebSocket handshake copied".into();
                        }
                    });
                });
                ui.add_space(4.0);
                let half_h = ((detail_h - 52.0) * 0.5).max(60.0);
                label(ui, &theme, "Client Upgrade Request");
                crate::ui::highlight::show_message_in(
                    ui,
                    "ws-handshake-req",
                    half_h,
                    &conn.request,
                    &theme,
                    msg_bg,
                );
                ui.add_space(4.0);
                label(ui, &theme, "Server 101 Response");
                crate::ui::highlight::show_message_in(
                    ui,
                    "ws-handshake-resp",
                    half_h,
                    &conn.response,
                    &theme,
                    msg_bg,
                );
            }
        },
    );
    let _ = Vec2::ZERO;
}
