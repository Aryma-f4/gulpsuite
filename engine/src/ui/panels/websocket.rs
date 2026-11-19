//! WebSocket history and read-only message viewer, shared by Proxy and Logger.

use std::io::Write;
use std::rc::Rc;

use super::{heading, muted};
use crate::ui::app::{App, WsConnection, WsMessage};
use base64::Engine;
use eframe::egui::{self, RichText, Ui};

const HEADERS: [&str; 10] = [
    "#",
    "URL",
    "Direction",
    "Edited",
    "Length",
    "Notes",
    "TLS",
    "Time",
    "Listener port",
    "WebSocket ID",
];
const FRACTIONS: [f32; 10] = [0.05, 0.24, 0.11, 0.06, 0.07, 0.10, 0.04, 0.15, 0.09, 0.09];
const EDITOR_DOC: &str = "https://portswigger.net/burp/documentation/desktop/tools/message-editor";
const HISTORY_DOC: &str =
    "https://portswigger.net/burp/documentation/desktop/tools/proxy/websockets-history";

#[derive(Clone)]
struct View {
    sort: Option<(usize, bool)>,
    filter_on: bool,
    direction: u8,
    notes: bool,
    inspector: bool,
    mode: usize,
    offset: f32,
    split: f32,
    find: String,
    hit: usize,
    save: Option<(String, String)>,
}
impl Default for View {
    fn default() -> Self {
        Self {
            sort: None,
            filter_on: true,
            direction: 0,
            notes: true,
            inspector: false,
            mode: 1,
            offset: -1.0,
            split: 0.77,
            find: String::new(),
            hit: 0,
            save: None,
        }
    }
}

struct Row<'a> {
    number: usize,
    conn: &'a WsConnection,
    url: Rc<str>,
    index: usize,
    frame: Option<&'a WsMessage>,
}
impl Row<'_> {
    fn key(&self) -> (u64, u64) {
        (self.conn.id, self.index as u64)
    }
    fn direction(&self) -> &'static str {
        match self.frame {
            Some(f) if f.to_server => "→ To server",
            Some(_) => "← To client",
            None => "Handshake",
        }
    }
    fn notes(&self) -> &str {
        self.frame.map_or("", |f| f.notes.as_str())
    }
    fn length(&self) -> usize {
        self.frame.map_or(0, |f| f.bytes)
    }
    fn time(&self) -> Option<time::OffsetDateTime> {
        self.frame.and_then(|f| f.received_at)
    }
}

enum Action {
    Repeater,
    Comparer(String),
    Decoder(String),
}

fn menu(
    ui: &mut Ui,
    view: &mut View,
    selected: Option<&str>,
    text: &str,
    action: &mut Option<Action>,
) {
    ui.set_min_width(224.0);
    for label in ["Send to Repeater", "Send to Comparer", "Send to Decoder"] {
        if ui.button(label).clicked() {
            *action = Some(match label {
                "Send to Repeater" => Action::Repeater,
                "Send to Comparer" => Action::Comparer(text.to_string()),
                _ => Action::Decoder(text.to_string()),
            });
            ui.close();
        }
    }
    ui.separator();
    if ui.button("Copy").clicked() {
        ui.ctx().copy_text(text.to_string());
        ui.close();
    }
    if ui.button("Copy prettified").clicked() {
        ui.ctx().copy_text(prettify(text));
        ui.close();
    }
    if let Some(selection) = selected.filter(|_| ui.button("Save selected text to file").clicked())
    {
        view.save = Some((selection.to_string(), String::new()));
        ui.close();
    } else if selected.is_none() {
        ui.add_enabled(false, egui::Button::new("Save selected text to file"));
    }
    ui.add_enabled_ui(selected.is_some(), |ui| {
        ui.menu_button("Convert selection", |ui| {
            let Some(selection) = selected else {
                return;
            };
            if ui.button("Copy as Base64").clicked() {
                ui.ctx()
                    .copy_text(base64::engine::general_purpose::STANDARD.encode(selection));
                ui.close();
            }
            if ui.button("Copy as URL-encoded text").clicked() {
                ui.ctx().copy_text(
                    url::form_urlencoded::byte_serialize(selection.as_bytes()).collect(),
                );
                ui.close();
            }
        });
    });
    ui.separator();
    ui.add_enabled(false, egui::Button::new("Cut"));
    if ui
        .add_enabled(selected.is_some(), egui::Button::new("Copy selection"))
        .clicked()
    {
        if let Some(selection) = selected {
            ui.ctx().copy_text(selection.to_string());
        }
        ui.close();
    }
    ui.add_enabled(false, egui::Button::new("Paste"));
    ui.separator();
    for (label, url) in [
        ("Message editor documentation", EDITOR_DOC),
        ("Proxy history documentation", HISTORY_DOC),
    ] {
        if ui.button(label).clicked() {
            ui.ctx().open_url(egui::OpenUrl::new_tab(url));
            ui.close();
        }
    }
}

fn prettify(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|data| serde_json::to_string_pretty(&data).ok())
        .unwrap_or_else(|| text.to_string())
}

pub fn draw(app: &mut App, ui: &mut Ui, tool: &str) {
    let theme = app.theme.clone();
    if app.websockets.is_empty() {
        let (learn, _) = super::empty_state(
            ui,
            &theme,
            "WebSockets history is empty",
            "This history shows WebSocket messages captured by Gulpsuite.",
            true,
            None,
        );
        if learn {
            ui.ctx().open_url(egui::OpenUrl::new_tab(HISTORY_DOC));
        }
        return;
    }
    let id = ui.make_persistent_id(("ws-history-ui", tool));
    let mut view = ui.data(|d| d.get_temp::<View>(id)).unwrap_or_default();
    egui::Frame::new()
        .fill(theme.color("ui.background.1"))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let setting = if !view.filter_on {
                    "Filter settings: Off"
                } else {
                    [
                        "Filter settings: Showing all items",
                        "Filter settings: To server",
                        "Filter settings: To client",
                    ][view.direction as usize]
                };
                let bar = (ui.available_width() - 365.0).max(118.0);
                let button = ui.add_sized(
                    [bar, 22.0],
                    egui::Label::new(setting)
                        .truncate()
                        .halign(egui::Align::Min)
                        .sense(egui::Sense::click()),
                );
                egui::Popup::menu(&button).show(|ui| {
                    for (value, label) in ["All directions", "To server", "To client"]
                        .into_iter()
                        .enumerate()
                    {
                        if ui
                            .selectable_value(&mut view.direction, value as u8, label)
                            .clicked()
                        {
                            ui.close();
                        }
                    }
                });
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.ws_filter)
                        .hint_text("Search")
                        .desired_width(180.0),
                );
                let filter_label = if view.filter_on {
                    "Filter on"
                } else {
                    "Filter off"
                };
                ui.checkbox(&mut view.filter_on, filter_label);
                if ui
                    .small_button("?")
                    .on_hover_text("WebSockets history documentation")
                    .clicked()
                {
                    ui.ctx().open_url(egui::OpenUrl::new_tab(HISTORY_DOC));
                }
                ui.menu_button("⋮", |ui| {
                    if ui.button("Clear history").clicked() {
                        app.websockets.clear();
                        app.panels.ws_selected = None;
                        view.offset = -1.0;
                        ui.close();
                    }
                });
            });
        });
    let query = if view.filter_on {
        app.panels.ws_filter.trim().to_lowercase()
    } else {
        String::new()
    };
    let mut rows = Vec::new();
    let mut ordinal = 0;
    for conn in &app.websockets {
        let path = conn.request.split_whitespace().nth(1).unwrap_or("/");
        let url: Rc<str> = if path.contains("://") {
            path.into()
        } else if let Some(secure) = conn.secure {
            format!(
                "{}://{}{path}",
                if secure { "https" } else { "http" },
                conn.host
            )
            .into()
        } else {
            format!("{}{path}", conn.host).into()
        };
        let conn_matches = query.is_empty()
            || url.to_lowercase().contains(&query)
            || conn.id.to_string().contains(&query);
        for index in 0..conn.messages.len().max(1) {
            ordinal += 1;
            let frame = conn.messages.get(index);
            let direction_matches = !view.filter_on
                || view.direction == 0
                || frame.is_some_and(|f| f.to_server == (view.direction == 1));
            if direction_matches
                && (conn_matches
                    || frame.is_some_and(|f| {
                        f.text.to_lowercase().contains(&query)
                            || f.notes.to_lowercase().contains(&query)
                    }))
            {
                rows.push(Row {
                    number: frame
                        .map_or(ordinal, |f| if f.number == 0 { ordinal } else { f.number }),
                    conn,
                    url: url.clone(),
                    index,
                    frame,
                });
            }
        }
    }
    if !rows.iter().any(|r| Some(r.key()) == app.panels.ws_selected) {
        app.panels.ws_selected = rows.last().map(Row::key);
    }
    if let Some((col, ascending)) = view.sort {
        rows.sort_by(|a, b| {
            let order = match col {
                1 => a.url.cmp(&b.url),
                2 => a.direction().cmp(b.direction()),
                4 => a.length().cmp(&b.length()),
                5 => a.notes().cmp(b.notes()),
                6 => a.conn.secure.cmp(&b.conn.secure),
                7 => a.time().cmp(&b.time()),
                8 => a.conn.listener_port.cmp(&b.conn.listener_port),
                9 => a.conn.id.cmp(&b.conn.id),
                _ => a.number.cmp(&b.number),
            };
            (if ascending { order } else { order.reverse() }).then(a.number.cmp(&b.number))
        });
    } else {
        rows.sort_by_key(|row| row.number);
    }
    let focus = id.with("table-focus");
    let focused = ui.memory_mut(|m| {
        m.set_focus_lock_filter(
            focus,
            egui::EventFilter {
                vertical_arrows: true,
                ..Default::default()
            },
        );
        m.has_focus(focus)
    });
    let delta = if focused {
        ui.input_mut(|i| {
            let down = i.count_and_consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown);
            let up = i.count_and_consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp);
            down as isize - up as isize
        })
    } else {
        0
    };
    if delta != 0 {
        if let Some(i) = rows
            .iter()
            .position(|r| Some(r.key()) == app.panels.ws_selected)
        {
            app.panels.ws_selected =
                Some(rows[i.saturating_add_signed(delta).min(rows.len() - 1)].key());
        }
    }

    let width = (ui.available_width() - 15.0).max(0.0);
    let widths = FRACTIONS.map(|fraction| width * fraction);
    let mut request_focus = false;
    egui::Frame::new()
        .fill(theme.color("ui.background.2"))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (col, title) in HEADERS.into_iter().enumerate() {
                    let header = match view.sort {
                        Some((n, true)) if n == col => format!("{title} ▲"),
                        Some((n, false)) if n == col => format!("{title} ▼"),
                        _ => title.to_string(),
                    };
                    if col == 3 {
                        ui.add_sized(
                            [widths[col], 24.0],
                            egui::Label::new(header).truncate().halign(egui::Align::Min),
                        );
                        continue;
                    }
                    if ui
                        .add_sized(
                            [widths[col], 24.0],
                            egui::Label::new(header)
                                .truncate()
                                .halign(egui::Align::Min)
                                .sense(egui::Sense::click()),
                        )
                        .clicked()
                    {
                        view.sort = match view.sort {
                            Some((n, true)) if n == col => Some((col, false)),
                            Some((n, false)) if n == col => None,
                            _ => Some((col, true)),
                        };
                        request_focus = true;
                    }
                }
            });
        });
    let mut action = None;
    let table_height = (ui.available_height() * 0.34).clamp(92.0, 360.0);
    const ROW_H: f32 = 19.0;
    let stride = ROW_H + ui.spacing().item_spacing.y;
    let mut table = egui::ScrollArea::vertical()
        .id_salt(id.with("rows"))
        .max_height(table_height)
        .auto_shrink([false, false]);
    if delta != 0 || request_focus || view.offset < 0.0 {
        if let Some(index) = rows
            .iter()
            .position(|r| Some(r.key()) == app.panels.ws_selected)
        {
            let top = index as f32 * stride;
            table = table.vertical_scroll_offset(
                view.offset
                    .max(0.0)
                    .clamp((top + stride - table_height).max(0.0), top),
            );
        }
    }
    let table = table.show_rows(ui, ROW_H, rows.len(), |ui, visible| {
        for index in visible {
            let row = &rows[index];
            let selected = Some(row.key()) == app.panels.ws_selected;
            let time = row.time().map_or_else(String::new, |t| {
                format!(
                    "{:02}:{:02}:{:02} {:02} {} {:04} UTC",
                    t.hour(),
                    t.minute(),
                    t.second(),
                    t.day(),
                    &t.month().to_string()[..3],
                    t.year()
                )
            });
            let labels = [
                row.number.to_string(),
                row.url.to_string(),
                row.direction().into(),
                String::new(),
                format!("{} B", row.length()),
                row.notes().into(),
                row.conn
                    .secure
                    .map_or("", |tls| if tls { "✓" } else { "—" })
                    .into(),
                time,
                row.conn
                    .listener_port
                    .map_or_else(String::new, |p| p.to_string()),
                row.conn.id.to_string(),
            ];
            let fill = if selected {
                ui.visuals().selection.bg_fill
            } else if index % 2 == 0 {
                theme.color("ui.background.0")
            } else {
                theme.color("ui.background.1")
            };
            let mut clicked = false;
            let line = ui
                .push_id(row.key(), |ui| {
                    egui::Frame::new()
                        .fill(fill)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.0;
                                for (col, label) in labels.into_iter().enumerate() {
                                    let mut cell = ui.add_sized(
                                        [widths[col], ROW_H],
                                        egui::Label::new(label)
                                            .halign(egui::Align::Min)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    );
                                    if col == 1 {
                                        cell = cell.on_hover_text(row.url.as_ref());
                                    }
                                    clicked |= cell.clicked() || cell.secondary_clicked();
                                }
                            });
                        })
                        .response
                })
                .inner;
            if clicked {
                app.panels.ws_selected = Some(row.key());
                request_focus = true;
            }
            super::show_persistent_context_menu(&line, |ui| {
                menu(
                    ui,
                    &mut view,
                    None,
                    row.frame
                        .map_or(row.conn.request.as_str(), |f| f.text.as_str()),
                    &mut action,
                )
            });
        }
        if rows.is_empty() {
            muted(ui, &theme, "No messages match the filter.");
        }
    });
    view.offset = table.state.offset.y;
    let focus_widget = ui.interact(
        table.inner_rect,
        focus,
        egui::Sense::focusable_noninteractive(),
    );
    focus_widget.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Other, true, "WebSocket messages")
    });
    if request_focus {
        focus_widget.request_focus();
        ui.ctx().request_repaint();
    }
    drop(rows);
    ui.separator();

    if let Some((conn_id, index)) = app.panels.ws_selected {
        if let Some(conn) = app.websockets.iter_mut().find(|conn| conn.id == conn_id) {
            let mut ratio = view.split;
            let height = ui.available_height();
            super::vertical_split(
                ui,
                &theme,
                "ws-proxy-detail",
                &mut ratio,
                height,
                |pane, ui| {
                    if pane == 0 {
                        ui.horizontal(|ui| {
                            heading(ui, &theme, "Message");
                            if ui.small_button("Send to Repeater").clicked() {
                                action = Some(Action::Repeater);
                            }
                        });
                        let frame = conn.messages.get(index as usize);
                        let text = frame.map_or(conn.request.as_str(), |f| f.text.as_str());
                        let full = frame.is_none_or(|f| {
                            f.opcode == crate::ws::opcode::TEXT && f.bytes == f.text.len()
                        });
                        message(
                            ui,
                            &theme,
                            id.with((
                                conn_id,
                                frame.map_or(index as usize, |f| f.number.max(index as usize)),
                            )),
                            &mut view,
                            text,
                            full,
                            &mut action,
                        );
                    } else {
                        ui.horizontal(|ui| {
                            if ui.selectable_label(view.notes, "Notes panel").clicked() {
                                view.notes = !view.notes;
                                view.inspector = false;
                            }
                            if ui.selectable_label(view.inspector, "Inspector").clicked() {
                                view.inspector = !view.inspector;
                                view.notes = false;
                            }
                        });
                        ui.separator();
                        if view.inspector {
                            ui.label(format!("WebSocket ID: {conn_id}"));
                            ui.collapsing("Upgrade request", |ui| {
                                ui.monospace(&conn.request);
                            });
                            ui.collapsing("Upgrade response", |ui| {
                                ui.monospace(&conn.response);
                            });
                        } else if view.notes {
                            heading(ui, &theme, "Notes");
                            if let Some(frame) = conn.messages.get_mut(index as usize) {
                                ui.add(
                                    egui::TextEdit::multiline(&mut frame.notes)
                                        .char_limit(2048)
                                        .desired_width(f32::INFINITY)
                                        .desired_rows(7)
                                        .hint_text("Add notes for this message"),
                                );
                            } else {
                                muted(ui, &theme, "No captured message selected.");
                            }
                        }
                    }
                },
            );
            view.split = ratio;
            if matches!(action, Some(Action::Repeater)) {
                let frame = conn.messages.get(index as usize).map(|_| index as usize);
                app.panels.repeater.open_websocket_capture(conn, frame);
                app.tool = crate::ui::app::REPEATER;
                app.view = 0;
            }
        }
    }
    match action {
        Some(Action::Comparer(text)) => {
            let comparer = &mut app.panels.comparer;
            if comparer.left.is_empty() {
                comparer.left = text;
            } else {
                comparer.right = text;
            }
            app.tool = crate::ui::app::COMPARER;
            app.view = 0;
        }
        Some(Action::Decoder(text)) => {
            app.panels.decoder.input = text;
            app.tool = crate::ui::app::DECODER;
            app.view = 0;
        }
        _ => {}
    }
    if let Some((content, path)) = &mut view.save {
        let mut close = false;
        egui::Window::new("Save selected text to file")
            .id(id.with("save"))
            .collapsible(false)
            .show(ui.ctx(), |ui| {
                ui.add(
                    egui::TextEdit::singleline(path)
                        .hint_text("Absolute path to a new file")
                        .desired_width(300.0),
                );
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            std::path::Path::new(path.as_str()).is_absolute(),
                            egui::Button::new("Save"),
                        )
                        .clicked()
                    {
                        match std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(path.as_str())
                            .and_then(|mut f| f.write_all(content.as_bytes()))
                        {
                            Ok(()) => {
                                app.status = "Saved selected WebSocket text".into();
                                close = true;
                            }
                            Err(err) => {
                                ui.label(err.to_string());
                                app.status = format!("Save failed: {err}");
                            }
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if close {
            view.save = None;
        }
    }
    ui.data_mut(|data| data.insert_temp(id, view));
}

fn message(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    id: egui::Id,
    view: &mut View,
    text: &str,
    full: bool,
    action: &mut Option<Action>,
) {
    ui.horizontal(|ui| {
        for (mode, label) in ["Pretty", "Raw", "Hex"].into_iter().enumerate() {
            if ui
                .add_enabled(
                    full || mode != 2,
                    egui::Button::selectable(view.mode == mode, label),
                )
                .clicked()
            {
                view.mode = mode;
            }
        }
    });
    if !full {
        muted(ui, theme, "Only a capture preview is available.");
    }
    ui.separator();
    let display = match view.mode {
        0 if full => prettify(text),
        2 if full => super::format_gulp_hex_dump(text),
        _ => text.to_string(),
    };
    let editor_h = (ui.available_height() - 37.0).max(40.0);
    let editor = egui::ScrollArea::both()
        .id_salt(id.with("scroll"))
        .max_height(editor_h)
        .min_scrolled_height(editor_h)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                let mut gutter = String::new();
                for i in 1..=display.split('\n').count() {
                    if i > 1 {
                        gutter.push('\n');
                    }
                    gutter.push_str(&i.to_string());
                }
                ui.add(egui::Label::new(RichText::new(gutter).monospace().weak()).extend());
                egui::TextEdit::multiline(&mut display.as_str())
                    .font(egui::TextStyle::Monospace)
                    .id(id.with("editor"))
                    .desired_width(f32::INFINITY)
                    .desired_rows(1)
                    .margin(egui::Margin::ZERO)
                    .frame(false)
                    .show(ui)
            })
            .inner
        });
    let selected = editor
        .inner
        .cursor_range
        .or_else(|| editor.inner.state.cursor.char_range())
        .filter(|r| !r.is_empty())
        .map(|r| {
            let range = r.as_sorted_char_range();
            display
                .chars()
                .skip(range.start)
                .take(range.len())
                .collect::<String>()
        });
    let trigger = ui.interact(editor.inner_rect, id.with("menu"), egui::Sense::hover());
    super::show_persistent_context_menu(&trigger, |ui| {
        menu(ui, view, selected.as_deref(), text, action)
    });
    let hits: Vec<_> = if view.find.is_empty() {
        Vec::new()
    } else {
        display
            .match_indices(&view.find)
            .map(|(i, s)| (i, s.len()))
            .collect()
    };
    ui.horizontal(|ui| {
        for (button, next) in [("←", false), ("→", true)] {
            if ui
                .add_enabled(!hits.is_empty(), egui::Button::new(button))
                .clicked()
            {
                view.hit = if next {
                    (view.hit + 1) % hits.len()
                } else {
                    (view.hit + hits.len() - 1) % hits.len()
                };
                let (at, len) = hits[view.hit];
                let start = display[..at].chars().count();
                let end = start + display[at..at + len].chars().count();
                let mut state = editor.inner.state.clone();
                state
                    .cursor
                    .set_char_range(Some(egui::text::CCursorRange::two(
                        egui::text::CCursor::new(start),
                        egui::text::CCursor::new(end),
                    )));
                state.store(ui.ctx(), editor.inner.response.id);
                editor.inner.response.request_focus();
            }
        }
        if ui
            .add(
                egui::TextEdit::singleline(&mut view.find)
                    .hint_text("Search")
                    .desired_width((ui.available_width() - 95.0).max(42.0)),
            )
            .changed()
        {
            view.hit = hits.len().saturating_sub(1);
        }
        muted(ui, theme, &format!("{} matches", hits.len()));
    });
}
