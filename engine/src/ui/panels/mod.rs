//! The tool panels. Each tool owns its own state; the shell only routes.

mod collaborator;
mod comparer;
pub(crate) mod dashboard;
pub(crate) mod decoder;
mod extender;
pub mod discover;
pub mod organizer;
pub(crate) mod intruder;
pub mod logger;
pub(crate) mod proxy;
pub(crate) mod repeater;
pub mod scanner;
pub mod replayer;
pub(crate) mod sequencer;
mod websocket;
pub mod target;

use std::sync::Arc;

use eframe::egui::Ui;

use crate::proxy::Proxy;
use crate::ui::app::{self, App};
use crate::ui::theme::Theme;

pub use dashboard::DashboardState;

/// Per-tool state.
#[derive(Clone)]
pub struct Panels {
    pub theme: Theme,
    pub proxy: Arc<Proxy>,
    pub proxy_panel: proxy::ProxyPanel,
    pub intruder: intruder::IntruderPanel,
    pub repeater: repeater::RepeaterPanel,
    pub sequencer: sequencer::SequencerPanel,
    pub decoder: decoder::DecoderPanel,
    pub comparer: comparer::ComparerPanel,
    pub logger: logger::LoggerPanel,
    pub extender: extender::ExtenderPanel,
    pub organizer: organizer::OrganizerPanel,
    pub target_panel: target::TargetPanel,
    pub scanner: scanner::ScannerPanel,
    pub replayer: replayer::ReplayerPanel,
    /// Path to a saved Bambda script.
    pub extender_path: String,
    /// Where a saved project lives.
    pub project_path: String,
    /// WebSocket view state.
    pub ws_filter: String,
    pub ws_selected: Option<(u64, u64)>,
    pub ws_handshake: Option<(u64, bool)>,
    /// Collaborator state.
    pub collaborator_local: bool,
    pub collaborator_port: Option<u16>,
    /// The port the collaborator's resolver listens on, when it runs.
    pub collaborator_dns_port: Option<u16>,
    pub collaborator_token: String,
    pub collaborator_stop: bool,
    pub collaborator_hits: Vec<crate::collaborator::Hit>,
    /// Discover state.
    /// Whether the match-and-replace rules are live on the proxy.
    pub match_replace_enabled: bool,
    /// Where saved extension scripts live, and the name for the next one.
    pub extender_folder: String,
    pub extender_new_name: String,
    pub discover_paths: String,
    pub discover_results: Vec<(String, u16)>,
    /// True while a discovery run is in flight, so the view can disable Start.
    pub discover_running: bool,
    /// Progress from the running discovery, e.g. "3/12 a.test".
    pub discover_progress: String,
}

impl Default for Panels {
    fn default() -> Self {
        Panels {
            theme: Theme::load(true),
            proxy: Arc::new(Proxy::new().0),
            proxy_panel: proxy::ProxyPanel::default(),
            intruder: intruder::IntruderPanel::default(),
            repeater: repeater::RepeaterPanel::default(),
            sequencer: sequencer::SequencerPanel::default(),
            decoder: decoder::DecoderPanel::default(),
            comparer: comparer::ComparerPanel::default(),
            extender: extender::ExtenderPanel::default(),
            organizer: organizer::OrganizerPanel::default(),
            target_panel: target::TargetPanel::default(),
            scanner: scanner::ScannerPanel::default(),
            replayer: replayer::ReplayerPanel::default(),
            extender_path: String::new(),
            project_path: String::new(),
            ws_filter: String::new(),
            ws_selected: None,
            ws_handshake: None,
            collaborator_local: true,
            collaborator_port: None,
            collaborator_dns_port: None,
            collaborator_token: crate::collaborator::new_token(),
            collaborator_stop: false,
            collaborator_hits: Vec::new(),
            logger: logger::LoggerPanel::default(),
            match_replace_enabled: false,
            extender_folder: default_extension_folder(),
            extender_new_name: String::new(),
            discover_paths: discover::default_paths(),
            discover_results: Vec::new(),
            discover_running: false,
            discover_progress: String::new(),
        }
    }
}

/// Draws the currently selected tool.
/// The default folder for saved scripts: `~/.gulpsuite/extensions` when the home directory is
/// known, otherwise the working directory.
pub fn default_extension_folder() -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.is_empty() => format!("{home}/.gulpsuite/extensions"),
        _ => ".gulpsuite/extensions".to_string(),
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    // Named indices, so reordering `TOOLS` cannot silently point a panel at the wrong tool.
    match app.tool {
        app::SUITE => dashboard::draw(app, ui),
        app::TARGET => target::draw(app, ui),
        app::PROXY => proxy::draw(app, ui),
        app::COLLABORATOR => collaborator::draw(app, ui),
        app::INTRUDER => intruder::draw(app, ui),
        app::REPEATER => repeater::draw(app, ui),
        app::LOGGER => logger::draw(app, ui),
        app::SEQUENCER => sequencer::draw(app, ui),
        app::DECODER => decoder::draw(app, ui),
        app::COMPARER => comparer::draw(app, ui),
        app::EXTENSIONS => extender::draw(app, ui),
        app::ORGANIZER => organizer::draw(app, ui),
        app::DISCOVER => discover::draw(app, ui),
        _ => {}
    }
}

/// A heading with Burp's title colour.
pub fn heading(ui: &mut Ui, theme: &Theme, text: &str) {
    crate::ui::app::bold_text(ui, text, 15.0, theme.color("ui.text.body"));
}

pub fn label(ui: &mut Ui, theme: &Theme, text: &str) {
    ui.label(
        eframe::egui::RichText::new(text).size(12.0).color(theme.color("ui.text.body")),
    );
}

pub fn muted(ui: &mut Ui, theme: &Theme, text: &str) {
    ui.label(
        eframe::egui::RichText::new(text).size(12.0).color(theme.color("ui.icon.default")),
    );
}

/// Burp's isometric three-tile illustration shown above centered empty states.
pub fn empty_illustration(ui: &mut Ui, colour: eframe::egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(
        eframe::egui::Vec2::new(140.0, 84.0),
        eframe::egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    for (dx, dy, angle) in [(-28.0, 4.0, -0.3_f32), (0.0, -14.0, 0.0), (28.0, 12.0, 0.3)] {
        let center = rect.center() + eframe::egui::Vec2::new(dx, dy);
        let (sin, cos) = angle.sin_cos();
        let corner = |x: f32, y: f32| {
            center + eframe::egui::Vec2::new(x * cos - y * sin, x * sin + y * cos)
        };
        painter.add(eframe::egui::Shape::convex_polygon(
            vec![
                corner(-18.0, -11.0),
                corner(18.0, -11.0),
                corner(18.0, 11.0),
                corner(-18.0, 11.0),
            ],
            colour,
            eframe::egui::Stroke::NONE,
        ));
        painter.line_segment(
            [corner(-19.0, 0.0), corner(19.0, 0.0)],
            eframe::egui::Stroke::new(2.0, eframe::egui::Color32::WHITE),
        );
    }
}

/// Centered Burp-style empty state: isometric icon, 20px bold headline, description,
/// and optional `Learn more` + primary action buttons. Returns `(learn_more_clicked, primary_clicked)`.
pub fn empty_state(
    ui: &mut Ui,
    theme: &Theme,
    title: &str,
    description: &str,
    learn_more: bool,
    primary_action: Option<&str>,
) -> (bool, bool) {
    let mut learned = false;
    let mut acted = false;
    ui.add_space((ui.available_height() * 0.22).clamp(48.0, 160.0));
    ui.vertical_centered(|ui| {
        empty_illustration(ui, theme.color("palette.secondary.core"));
        ui.add_space(18.0);
        crate::ui::app::bold_text(ui, title, 20.0, theme.color("ui.text.header"));
        ui.add_space(12.0);
        ui.scope(|ui| {
            ui.set_max_width(460.0);
            ui.with_layout(
                eframe::egui::Layout::top_down(eframe::egui::Align::Center),
                |ui| {
                    ui.label(
                        eframe::egui::RichText::new(description)
                            .size(12.0)
                            .color(theme.color("ui.text.body")),
                    );
                },
            );
        });
        if learn_more || primary_action.is_some() {
            ui.add_space(18.0);
            let width = match (learn_more, primary_action.is_some()) {
                (true, true) => 230.0,
                _ => 110.0,
            };
            ui.allocate_ui(eframe::egui::Vec2::new(width, 28.0), |ui| {
                ui.horizontal(|ui| {
                    if learn_more && crate::ui::app::burp_button(ui, "Learn more").clicked() {
                        learned = true;
                    }
                    if let Some(label) = primary_action {
                        if crate::ui::app::primary_button(ui, theme, label).clicked() {
                            acted = true;
                        }
                    }
                });
            });
        }
    });
    (learned, acted)
}

/// A full-width draggable horizontal splitter bar that resizes `height` between `min_h` and `max_h`.
/// Double-clicking resets `height` to `default_h`.
pub fn horizontal_resize_handle(
    ui: &mut Ui,
    theme: &Theme,
    _id: &str,
    height: &mut f32,
    min_h: f32,
    max_h: f32,
    default_h: f32,
) {
    let width = ui.available_width().max(40.0);
    let (rect, response) = ui.allocate_exact_size(
        eframe::egui::Vec2::new(width, 8.0),
        eframe::egui::Sense::click_and_drag(),
    );
    if response.hovered() || response.dragged() {
        ui.ctx().set_cursor_icon(eframe::egui::CursorIcon::ResizeVertical);
    }
    if response.dragged() {
        *height = (*height + response.drag_delta().y).clamp(min_h, max_h.max(min_h));
    }
    if response.double_clicked() {
        *height = default_h.clamp(min_h, max_h.max(min_h));
    }
    let painter = ui.painter_at(rect);
    let line_col = if response.hovered() || response.dragged() {
        theme.color("ui.icon.link")
    } else {
        theme.color("ui.border.1")
    };
    let y = rect.center().y;
    painter.line_segment(
        [eframe::egui::pos2(rect.min.x, y), eframe::egui::pos2(rect.max.x, y)],
        eframe::egui::Stroke::new(1.0, line_col),
    );
    for dx in [-8.0_f32, 0.0, 8.0] {
        painter.circle_filled(
            eframe::egui::pos2(rect.center().x + dx, y),
            1.6,
            line_col,
        );
    }
}

/// Side-by-side two-pane split with a draggable vertical divider.
/// Calls `pane(0, ui)` for the left pane and `pane(1, ui)` for the right pane.
/// Dragging adjusts `ratio` (`0.18..=0.82`); double-clicking resets to `0.5`.
pub fn vertical_split(
    ui: &mut Ui,
    theme: &Theme,
    _id: &str,
    ratio: &mut f32,
    height: f32,
    mut pane: impl FnMut(usize, &mut Ui),
) {
    let total_width = ui.available_width().max(200.0);
    let handle_w = 10.0;
    *ratio = ratio.clamp(0.18, 0.82);
    let left_w = ((total_width - handle_w) * *ratio).max(80.0);
    let right_w = (total_width - handle_w - left_w).max(80.0);

    ui.horizontal_top(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.allocate_ui_with_layout(
            eframe::egui::Vec2::new(left_w, height),
            eframe::egui::Layout::top_down(eframe::egui::Align::Min),
            |ui| {
                ui.set_min_width(left_w);
                ui.set_max_width(left_w);
                pane(0, ui);
            },
        );

        let (rect, response) = ui.allocate_exact_size(
            eframe::egui::Vec2::new(handle_w, height.max(120.0)),
            eframe::egui::Sense::click_and_drag(),
        );
        let response = response.interact(eframe::egui::Sense::click_and_drag());
        if response.hovered() || response.dragged() {
            ui.ctx()
                .set_cursor_icon(eframe::egui::CursorIcon::ResizeHorizontal);
        }
        if response.dragged() && total_width > handle_w {
            *ratio = (*ratio + response.drag_delta().x / (total_width - handle_w)).clamp(0.18, 0.82);
        }
        if response.double_clicked() {
            *ratio = 0.5;
        }
        let painter = ui.painter_at(rect);
        let line_col = if response.hovered() || response.dragged() {
            theme.color("ui.icon.link")
        } else {
            theme.color("ui.border.1")
        };
        let x = rect.center().x;
        painter.line_segment(
            [eframe::egui::pos2(x, rect.min.y), eframe::egui::pos2(x, rect.max.y)],
            eframe::egui::Stroke::new(1.0_f32, line_col),
        );
        for dy in [-8.0_f32, 0.0, 8.0] {
            painter.circle_filled(
                eframe::egui::pos2(x, rect.center().y + dy),
                1.6,
                line_col,
            );
        }

        ui.allocate_ui_with_layout(
            eframe::egui::Vec2::new(right_w, height),
            eframe::egui::Layout::top_down(eframe::egui::Align::Min),
            |ui| {
                ui.set_min_width(right_w);
                ui.set_max_width(right_w);
                pane(1, ui);
            },
        );
    });
}

thread_local! {
    static LAST_MESSAGE_SELECTION: std::cell::RefCell<Option<(String, std::ops::Range<usize>, String)>> =
        const { std::cell::RefCell::new(None) };
    static PENDING_EDITOR_CURSOR: std::cell::RefCell<Option<(String, std::ops::Range<usize>)>> =
        const { std::cell::RefCell::new(None) };
}

/// Returns the most recent non-empty character selection `(char_range, selected_text)` for `id_salt`.
pub fn latest_selection_for(id_salt: &str) -> Option<(std::ops::Range<usize>, String)> {
    LAST_MESSAGE_SELECTION.with(|cell| {
        cell.borrow()
            .as_ref()
            .filter(|(id, range, txt)| id == id_salt && range.start < range.end && !txt.is_empty())
            .map(|(_, range, txt)| (range.clone(), txt.clone()))
    })
}

/// Returns the most recent non-empty selection `(id_salt, char_range, selected_text)` across any pane.
pub fn latest_selection_full() -> Option<(String, std::ops::Range<usize>, String)> {
    LAST_MESSAGE_SELECTION.with(|cell| {
        cell.borrow()
            .as_ref()
            .filter(|(_, range, txt)| range.start < range.end && !txt.is_empty())
            .cloned()
    })
}

/// Returns the most recent non-empty selected ("blocked") text across any HTTP message pane.
pub fn latest_selected_text() -> Option<String> {
    latest_selection_full().map(|(_, _, txt)| txt)
}

pub fn take_pending_editor_cursor(id_salt: &str) -> Option<std::ops::Range<usize>> {
    PENDING_EDITOR_CURSOR.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if borrow.as_ref().is_some_and(|(id, _)| id == id_salt) {
            borrow.take().map(|(_, r)| r)
        } else {
            None
        }
    })
}

pub fn set_pending_editor_cursor(id_salt: &str, range: std::ops::Range<usize>) {
    PENDING_EDITOR_CURSOR.with(|cell| {
        *cell.borrow_mut() = Some((id_salt.to_string(), range));
    });
}

pub fn record_message_selection(id_salt: &str, range: std::ops::Range<usize>, full_text: &str) {
    if range.start >= range.end {
        return;
    }
    let start_b = full_text
        .char_indices()
        .nth(range.start)
        .map(|(i, _)| i)
        .unwrap_or(full_text.len());
    let end_b = full_text
        .char_indices()
        .nth(range.end)
        .map(|(i, _)| i)
        .unwrap_or(full_text.len());
    if start_b < end_b && end_b <= full_text.len() {
        let slice = full_text[start_b..end_b].to_string();
        LAST_MESSAGE_SELECTION.with(|cell| {
            *cell.borrow_mut() = Some((id_salt.to_string(), range, slice));
        });
    }
}

/// Replaces `range` (or `expected_selected` if char offsets shifted) inside `target` with `replacement`,
/// returning the updated character range covering `replacement`.
pub fn replace_selection_in_text(
    target: &mut String,
    range: &std::ops::Range<usize>,
    expected_selected: &str,
    replacement: &str,
) -> Option<std::ops::Range<usize>> {
    let start_b = target
        .char_indices()
        .nth(range.start)
        .map(|(i, _)| i)
        .unwrap_or(target.len());
    let end_b = target
        .char_indices()
        .nth(range.end)
        .map(|(i, _)| i)
        .unwrap_or(target.len());
    if start_b < end_b && end_b <= target.len() && &target[start_b..end_b] == expected_selected {
        target.replace_range(start_b..end_b, replacement);
        let new_end = range.start + replacement.chars().count();
        return Some(range.start..new_end);
    }
    if !expected_selected.is_empty() {
        if let Some(byte_pos) = target.find(expected_selected) {
            let char_start = target[..byte_pos].chars().count();
            target.replace_range(byte_pos..byte_pos + expected_selected.len(), replacement);
            let char_end = char_start + replacement.chars().count();
            return Some(char_start..char_end);
        }
    }
    None
}

/// Runs `op_name` (`Base64 encode`, `Base64 decode`, `URL encode`, `URL decode`, `HTML encode`,
/// `HTML decode`, `Hex encode`, `Hex decode`) on the active blocked selection, replaces it IN-PLACE
/// when the selection belongs to an editable buffer (`Repeater`, `Intruder`, `Proxy -> Intercept`, `Decoder`),
/// updates the active selection to cover the converted text, and copies the result to the clipboard.
pub fn apply_convert_selection(
    app: &mut App,
    ctx: &eframe::egui::Context,
    op_name: &str,
    fallback_req: &str,
    fallback_resp: &str,
) {
    let Some(op) = crate::logic::find_op(op_name) else {
        return;
    };
    if let Some((source_id, range, selected_txt)) = latest_selection_full() {
        let converted = (op.run)(&selected_txt)
            .or_else(|_| (op.run)(selected_txt.trim()))
            .unwrap_or_default();
        if converted.is_empty() && !selected_txt.is_empty() {
            app.status = format!("{op_name} failed on selected text");
            return;
        }
        ctx.copy_text(converted.clone());

        let mut replaced_in_editor = None;
        if source_id.starts_with("repeater-req") || app.tool == app::REPEATER {
            let raw = &mut app.panels.repeater.active_mut().raw;
            if let Some(new_r) = replace_selection_in_text(raw, &range, &selected_txt, &converted) {
                replaced_in_editor = Some(("repeater-req-edit", new_r));
            }
        } else if source_id.starts_with("intruder-") || app.tool == app::INTRUDER {
            let tmpl = &mut app.panels.intruder.template;
            if let Some(new_r) = replace_selection_in_text(tmpl, &range, &selected_txt, &converted)
            {
                replaced_in_editor = Some(("intruder-positions-edit", new_r));
            }
        } else if source_id.starts_with("proxy-intercept")
            || (app.tool == app::PROXY && app.view == 0)
        {
            if let Some(sel_idx) = app.panels.proxy_panel.held_selected {
                if app
                    .panels
                    .proxy_panel
                    .held_edit
                    .as_ref()
                    .is_none_or(|(idx, _)| *idx != sel_idx)
                {
                    let seed = if !fallback_req.is_empty() {
                        fallback_req.to_string()
                    } else {
                        fallback_resp.to_string()
                    };
                    if !seed.is_empty() {
                        app.panels.proxy_panel.held_edit = Some((sel_idx, seed));
                    }
                }
            }
            if let Some((_, ref mut buf)) = app.panels.proxy_panel.held_edit {
                if let Some(new_r) =
                    replace_selection_in_text(buf, &range, &selected_txt, &converted)
                {
                    replaced_in_editor = Some(("proxy-intercept-editor", new_r));
                }
            }
        } else if source_id.starts_with("decoder-") || app.tool == app::DECODER {
            let inp = &mut app.panels.decoder.input;
            if let Some(new_r) = replace_selection_in_text(inp, &range, &selected_txt, &converted) {
                app.panels.decoder.output = converted.clone();
                replaced_in_editor = Some(("decoder-input", new_r));
            }
        }

        if let Some((editor_id, new_range)) = replaced_in_editor {
            LAST_MESSAGE_SELECTION.with(|cell| {
                *cell.borrow_mut() =
                    Some((editor_id.to_string(), new_range.clone(), converted.clone()));
            });
            set_pending_editor_cursor(editor_id, new_range);
            app.status = format!("Applied {op_name} to selection in-place (and copied)");
        } else {
            let new_end = range.start + converted.chars().count();
            LAST_MESSAGE_SELECTION.with(|cell| {
                *cell.borrow_mut() = Some((source_id, range.start..new_end, converted.clone()));
            });
            app.panels.decoder.input = selected_txt;
            app.panels.decoder.output = converted;
            app.status = format!("Applied {op_name} to selection and copied to clipboard");
        }
    } else {
        let fallback = if !fallback_req.trim().is_empty() {
            fallback_req
        } else {
            fallback_resp
        };
        if let Ok(out) = (op.run)(fallback) {
            ctx.copy_text(out.clone());
            app.panels.decoder.output = out;
            app.status = format!("Applied {op_name} and copied to clipboard");
        }
    }
}

/// Opens a persistent right-click context menu whenever the pointer is secondary-clicked
/// anywhere inside `trigger.rect` (including selectable labels, text editors, gutters, and blank space),
/// and keeps it open across subsequent frames until dismissed or an action calls `ui.close()`.
pub fn show_persistent_context_menu(
    trigger: &eframe::egui::Response,
    add_contents: impl FnOnce(&mut eframe::egui::Ui),
) {
    let secondary_in_rect = trigger.secondary_clicked()
        || trigger.ctx.input(|i| {
            (i.pointer
                .button_clicked(eframe::egui::PointerButton::Secondary)
                || i.pointer
                    .button_released(eframe::egui::PointerButton::Secondary))
                && i.pointer
                    .interact_pos()
                    .is_some_and(|pos| trigger.rect.contains(pos))
        });
    eframe::egui::Popup::context_menu(trigger)
        .close_behavior(eframe::egui::PopupCloseBehavior::CloseOnClick)
        .open_memory(if secondary_in_rect {
            Some(eframe::egui::SetOpenCommand::Bool(true))
        } else {
            None
        })
        .show(add_contents);
}

/// Attaches Burp Suite Pro v2026.3.3's universal right-click context menu
/// (`quick-start-pro-send-to-repeater.png`, `getting-started-logger-tab-3-context-menu.png`, `context-menu.html`)
/// to any HTTP message or row widget.
pub fn attach_message_context_menu(
    app: &mut App,
    trigger: &eframe::egui::Response,
    url: &str,
    raw_request: &str,
    raw_response: &str,
) {
    show_persistent_context_menu(trigger, |ui| {
        ui.set_min_width(235.0);
        let url = url.to_string();
        let req = raw_request.to_string();
        let resp = raw_response.to_string();
        let has_req = !req.trim().is_empty();
        let has_resp = !resp.trim().is_empty();
        let host_origin = url
            .split_once("://")
            .map(|(s, r)| format!("{}://{}/", s, r.split('/').next().unwrap_or(r)))
            .unwrap_or_else(|| url.clone());

        if !url.is_empty() {
            let short_u: String = url.chars().take(48).collect();
            ui.label(eframe::egui::RichText::new(short_u).strong());
            ui.separator();
            if ui.button("Add to scope").clicked() {
                if !app.panels.target_panel.scope.contains(&host_origin) {
                    if !app.panels.target_panel.scope.trim().is_empty() {
                        app.panels.target_panel.scope.push_str(", ");
                    }
                    app.panels.target_panel.scope.push_str(&host_origin);
                }
                app.status = format!("Added {host_origin} to Target scope");
                ui.close();
            }
            if ui.button("Exclude from scope").clicked() {
                if !app.panels.target_panel.scope_exclude.contains(&host_origin) {
                    if !app.panels.target_panel.scope_exclude.trim().is_empty() {
                        app.panels.target_panel.scope_exclude.push_str(", ");
                    }
                    app.panels.target_panel.scope_exclude.push_str(&host_origin);
                }
                app.status = format!("Excluded {host_origin} from Target scope");
                ui.close();
            }
            ui.separator();
        }

        // Scan section (`Scan`, `Do passive scan`, `Do active scan`)
        if !url.is_empty() && ui.button("Scan").clicked() {
            app.panels.scanner.seed = url.clone();
            app.panels.scanner.urls_to_scan = url.clone();
            app.panels.scanner.show_launcher = true;
            app.panels.scanner.launcher_tab = 0;
            app.status = format!("Opened scan launcher for {url}");
            ui.close();
        }
        if has_resp && ui.button("Do passive scan").clicked() {
            app.passive_scan_transaction(&url, &resp);
            ui.close();
        }
        if !url.is_empty() && ui.button("Do active scan").clicked() {
            app.scan_url(&url, true);
            ui.close();
        }
        ui.separator();

        // Send to... tools (`Send to Intruder`, `Send to Repeater`, `Send to Sequencer`, `Send to Comparer`, `Send to Decoder`, `Send to Organizer`)
        if has_req && ui.button("Send to Intruder").clicked() {
            app.send_to_intruder(&url, &req);
            ui.close();
        }
        if has_req && ui.button("Send to Repeater").clicked() {
            app.panels.repeater.open(&url, &req);
            app.tool = app::REPEATER;
            app.view = 0;
            app.status = "Sent to Repeater".into();
            ui.close();
        }
        if has_resp && ui.button("Send to Sequencer").clicked() {
            app.panels.sequencer.text = resp.clone();
            app.tool = app::SEQUENCER;
            app.view = 0;
            app.status = "Sent response to Sequencer".into();
            ui.close();
        }
        if has_req && ui.button("Send to Comparer (request)").clicked() {
            if app.panels.comparer.left.trim().is_empty() {
                app.panels.comparer.left = req.clone();
            } else {
                app.panels.comparer.right = req.clone();
            }
            app.tool = app::COMPARER;
            app.view = 0;
            app.status = "Sent request to Comparer".into();
            ui.close();
        }
        if has_resp && ui.button("Send to Comparer (response)").clicked() {
            if app.panels.comparer.left.trim().is_empty() {
                app.panels.comparer.left = resp.clone();
            } else {
                app.panels.comparer.right = resp.clone();
            }
            app.tool = app::COMPARER;
            app.view = 0;
            app.status = "Sent response to Comparer".into();
            ui.close();
        }
        if (has_req || has_resp) && ui.button("Send to Decoder").clicked() {
            app.panels.decoder.input = if has_req { req.clone() } else { resp.clone() };
            app.tool = app::DECODER;
            app.view = 0;
            app.status = "Sent to Decoder".into();
            ui.close();
        }
        if (has_req || has_resp) && ui.button("Send to Organizer").clicked() {
            let next = app.organizer.len() + 1;
            organizer::retain(
                app,
                organizer::OrganizerItem {
                    host: url.clone(),
                    name: format!("item-{next}"),
                    notes: String::new(),
                    request: req.clone(),
                    response: resp.clone(),
                },
            );
            app.status = "Saved to Organizer".into();
            ui.close();
        }
        ui.separator();

        // Extensions, Engagement tools & Request in browser
        ui.menu_button("Extensions", |ui| {
            if ui.button("Open in Bambda editor").clicked() {
                app.tool = app::EXTENSIONS;
                app.view = 0;
                ui.close();
            }
        });
        ui.menu_button("Engagement tools", |ui| {
            if has_req && ui.button("Generate CSRF PoC").clicked() {
                app.open_csrf_poc(&url, &req);
                ui.close();
            }
            if ui.button("Discover content").clicked() {
                app.tool = app::DISCOVER;
                app.view = 0;
                ui.close();
            }
            if ui.button("Search").clicked() {
                app.show_search = true;
                ui.close();
            }
        });
        if !url.is_empty() && ui.button("Request in browser").clicked() {
            app.open_browser();
            ui.close();
        }
        ui.separator();

        // Request manipulation & Copy helpers
        let selected_snippet = latest_selected_text();
        if let Some(sel_txt) = &selected_snippet {
            if ui.button("Copy selection").clicked() {
                ui.ctx().copy_text(sel_txt.clone());
                app.status = format!("Copied {} selected character(s)", sel_txt.chars().count());
                ui.close();
            }
            if ui.button("Base64 encode selection").clicked() {
                apply_convert_selection(app, ui.ctx(), "Base64 encode", &req, &resp);
                ui.close();
            }
            if ui.button("Base64 decode selection").clicked() {
                apply_convert_selection(app, ui.ctx(), "Base64 decode", &req, &resp);
                ui.close();
            }
            if ui.button("URL encode selection").clicked() {
                apply_convert_selection(app, ui.ctx(), "URL encode", &req, &resp);
                ui.close();
            }
            if ui.button("URL decode selection").clicked() {
                apply_convert_selection(app, ui.ctx(), "URL decode", &req, &resp);
                ui.close();
            }
            if ui.button("Send selection to Decoder").clicked() {
                app.panels.decoder.input = sel_txt.clone();
                app.tool = app::DECODER;
                app.view = 0;
                app.status = "Sent selected text to Decoder".into();
                ui.close();
            }
            if ui.button("Send selection to Comparer").clicked() {
                if app.panels.comparer.left.trim().is_empty() {
                    app.panels.comparer.left = sel_txt.clone();
                } else {
                    app.panels.comparer.right = sel_txt.clone();
                }
                app.tool = app::COMPARER;
                app.view = 0;
                app.status = "Sent selected text to Comparer".into();
                ui.close();
            }
            ui.separator();
        }
        if has_req && ui.button("Change request method (GET ↔ POST)").clicked() {
            let toggled = crate::ui::app::Transaction::toggle_request_method(&req);
            app.panels.repeater.open(&url, &toggled);
            app.tool = app::REPEATER;
            app.view = 0;
            app.status = "Converted request method and opened in Repeater".into();
            ui.close();
        }
        ui.menu_button("Convert selection", |ui| {
            for op_name in [
                "URL encode",
                "URL decode",
                "Base64 encode",
                "Base64 decode",
                "HTML encode",
                "HTML decode",
                "Hex encode",
                "Hex decode",
            ] {
                if ui.button(op_name).clicked() {
                    apply_convert_selection(app, ui.ctx(), op_name, &req, &resp);
                    ui.close();
                }
            }
        });
        if ui.button("Insert Collaborator payload").clicked() {
            let payload = format!(
                "{}.{}",
                app.panels.collaborator_token,
                crate::collaborator::DOMAIN
            );
            ui.ctx().copy_text(payload.clone());
            app.status = format!("Copied Collaborator payload {payload}");
            ui.close();
        }
        if !url.is_empty() && ui.button("Copy URL").clicked() {
            ui.ctx().copy_text(url.clone());
            app.status = "URL copied".into();
            ui.close();
        }
        if has_req && ui.button("Copy as curl command").clicked() {
            let curl = crate::ui::app::Transaction::to_curl_command(&url, &req);
            ui.ctx().copy_text(curl);
            app.status = "Copied as curl command".into();
            ui.close();
        }
        if has_resp && ui.button("Copy links").clicked() {
            let links = crate::scanner::crawler::links(&resp, &url);
            ui.ctx().copy_text(links.join("\n"));
            app.status = format!("Copied {} link(s) to clipboard", links.len());
            ui.close();
        }
        if has_req && ui.button("Copy request").clicked() {
            ui.ctx().copy_text(req);
            app.status = "Request copied".into();
            ui.close();
        }
        if has_resp && ui.button("Copy response").clicked() {
            ui.ctx().copy_text(resp);
            app.status = "Response copied".into();
            ui.close();
        }
        ui.separator();

        if !url.is_empty() && ui.button("Record an issue › Create an issue").clicked() {
            app.panels.scanner.manual_issue_service = url.clone();
            app.panels.scanner.show_manual_issue_modal = true;
            ui.close();
        }
        if ui.button("Report issues…").clicked() {
            app.panels.scanner.report_host_filter.clear();
            app.panels.scanner.show_report_wizard = true;
            ui.close();
        }
    });
}

fn auto_decode_value(val: &str) -> String {
    let mut cur = val.to_string();
    for _ in 0..3 {
        let Some(op) = crate::logic::magic_decode(&cur).and_then(crate::logic::find_op) else {
            break;
        };
        let Ok(next) = (op.run)(&cur) else { break };
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Burp's Inspector accordion: parses and displays Request attributes, Query parameters,
/// Body parameters, Request cookies, Request headers, and Response headers with automatic decoding.
pub fn draw_inspector(
    ui: &mut Ui,
    theme: &Theme,
    id: &str,
    raw_request: &str,
    raw_response: &str,
) {
    let (req_head, req_body) = crate::analysis::split_message(raw_request);
    let (resp_head, _) = crate::analysis::split_message(raw_response);
    let mut req_lines = req_head.lines();
    let first_line = req_lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("-");
    let uri = parts.next().unwrap_or("/");
    let proto = parts.next().unwrap_or("HTTP/1.1");
    let (path, query_str) = uri.split_once('?').unwrap_or((uri, ""));

    let query_params: Vec<(String, String)> = query_str
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (k.to_string(), v.to_string())
        })
        .collect();

    let body_params: Vec<(String, String)> = if req_body.contains('=') && !req_body.trim_start().starts_with('{') {
        req_body
            .trim()
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (k.to_string(), v.to_string())
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut req_headers = Vec::new();
    let mut req_cookies = Vec::new();
    for line in req_lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_trim = k.trim().to_string();
            let v_trim = v.trim().to_string();
            if k_trim.eq_ignore_ascii_case("cookie") {
                for pair in v_trim.split(';') {
                    let pair = pair.trim();
                    if !pair.is_empty() {
                        let (ck, cv) = pair.split_once('=').unwrap_or((pair, ""));
                        req_cookies.push((ck.trim().to_string(), cv.trim().to_string()));
                    }
                }
            }
            req_headers.push((k_trim, v_trim));
        }
    }

    let resp_headers: Vec<(String, String)> = resp_head
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    eframe::egui::CollapsingHeader::new(
        eframe::egui::RichText::new(format!(
            "Inspector — {} query, {} body, {} cookies, {} req headers, {} resp headers",
            query_params.len(),
            body_params.len(),
            req_cookies.len(),
            req_headers.len(),
            resp_headers.len()
        ))
        .strong()
        .color(theme.color("ui.text.body")),
    )
    .id_salt((id, "inspector-root"))
    .default_open(false)
    .show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(eframe::egui::RichText::new("Request attributes:").strong());
            ui.monospace(format!("Method={method}  Path={path}  Protocol={proto}"));
        });
        if !query_params.is_empty() {
            ui.label(
                eframe::egui::RichText::new(format!("Query parameters ({})", query_params.len()))
                    .strong(),
            );
            eframe::egui::Grid::new((id, "insp-query"))
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    for h in ["Name", "Value", "Decoded"] {
                        ui.label(eframe::egui::RichText::new(h).strong());
                    }
                    ui.end_row();
                    for (k, v) in &query_params {
                        ui.monospace(k);
                        ui.monospace(v);
                        ui.monospace(auto_decode_value(v));
                        ui.end_row();
                    }
                });
        }
        if !body_params.is_empty() {
            ui.label(
                eframe::egui::RichText::new(format!("Body parameters ({})", body_params.len()))
                    .strong(),
            );
            eframe::egui::Grid::new((id, "insp-body"))
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    for h in ["Name", "Value", "Decoded"] {
                        ui.label(eframe::egui::RichText::new(h).strong());
                    }
                    ui.end_row();
                    for (k, v) in &body_params {
                        ui.monospace(k);
                        ui.monospace(v);
                        ui.monospace(auto_decode_value(v));
                        ui.end_row();
                    }
                });
        }
        if !req_cookies.is_empty() {
            ui.label(
                eframe::egui::RichText::new(format!("Request cookies ({})", req_cookies.len()))
                    .strong(),
            );
            eframe::egui::Grid::new((id, "insp-cookies"))
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    for h in ["Name", "Value", "Decoded"] {
                        ui.label(eframe::egui::RichText::new(h).strong());
                    }
                    ui.end_row();
                    for (k, v) in &req_cookies {
                        ui.monospace(k);
                        ui.monospace(v);
                        ui.monospace(auto_decode_value(v));
                        ui.end_row();
                    }
                });
        }
        if !req_headers.is_empty() {
            ui.label(
                eframe::egui::RichText::new(format!("Request headers ({})", req_headers.len()))
                    .strong(),
            );
            eframe::egui::Grid::new((id, "insp-req-hdr"))
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (k, v) in &req_headers {
                        ui.monospace(k);
                        ui.monospace(v);
                        ui.end_row();
                    }
                });
        }
        if !resp_headers.is_empty() {
            ui.label(
                eframe::egui::RichText::new(format!("Response headers ({})", resp_headers.len()))
                    .strong(),
            );
            eframe::egui::Grid::new((id, "insp-resp-hdr"))
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (k, v) in &resp_headers {
                        ui.monospace(k);
                        ui.monospace(v);
                        ui.end_row();
                    }
                });
        }
    });
}

/// Exact Burp Suite Pro v2026.3.3 Site Map tree icons (`resources/Media/svg/site-map-*.svg`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SiteMapIcon {
    /// `site-map-secure.svg`: Gold padlock (`https://`)
    SecureHost,
    /// `site-map-insecure.svg`: Open padlock (`http://`)
    InsecureHost,
    /// `site-map-folder-open.svg`: Yellow folder
    FolderOpen,
    /// `site-map-dyn-page.svg`: Gold cog/gear for dynamic/parameterized endpoints
    DynPage,
    /// `site-map-request-with-query.svg`: White document with `?`
    QueryPage,
    /// `site-map-default.svg`: White document with folded top-right corner
    DefaultPage,
}

/// Paints a 16x16 Burp Site Map node icon with an optional bottom-right status/severity indicator dot
/// (matching `Pro-QSG-5-site-map.png` and `site-map-populated.png`).
pub fn paint_sitemap_node_icon(
    ui: &mut Ui,
    icon: SiteMapIcon,
    dot_color: Option<eframe::egui::Color32>,
) {
    use eframe::egui::{Color32, Pos2, Rect, Sense, Shape, Stroke, StrokeKind, Vec2, pos2};
    let (rect, _) = ui.allocate_exact_size(Vec2::new(16.0, 16.0), Sense::hover());
    let painter = ui.painter_at(rect);
    let u = rect.width() / 16.0;
    let p = |x: f32, y: f32| -> Pos2 { pos2(rect.min.x + x * u, rect.min.y + y * u) };
    let dark_outline = Color32::from_rgb(0x6E, 0x5B, 0x2B);

    match icon {
        SiteMapIcon::SecureHost | SiteMapIcon::InsecureHost => {
            // Shackle
            let shackle_stroke = Stroke::new(1.5 * u, Color32::from_rgb(0x70, 0x72, 0x76));
            if icon == SiteMapIcon::SecureHost {
                painter.add(Shape::line(
                    vec![p(5.2, 7.2), p(5.2, 4.0), p(8.0, 2.2), p(10.8, 4.0), p(10.8, 7.2)],
                    shackle_stroke,
                ));
            } else {
                painter.add(Shape::line(
                    vec![p(5.2, 7.2), p(5.2, 4.0), p(8.0, 2.2), p(11.4, 3.6)],
                    shackle_stroke,
                ));
            }
            // Gold body (`#F5C242`)
            let body = Rect::from_min_max(p(3.0, 7.0), p(13.0, 14.5));
            painter.rect_filled(body, 1.5 * u, Color32::from_rgb(0xF5, 0xC2, 0x42));
            painter.rect_stroke(body, 1.5 * u, Stroke::new(1.0 * u, dark_outline), StrokeKind::Inside);
            painter.circle_filled(p(8.0, 10.6), 1.0 * u, dark_outline);
        }
        SiteMapIcon::FolderOpen => {
            // Yellow folder (`#F5C242` with `#8A6D29` border)
            painter.add(Shape::convex_polygon(
                vec![p(1.5, 3.5), p(6.2, 3.5), p(7.6, 5.2), p(14.0, 5.2), p(14.0, 13.5), p(1.5, 13.5)],
                Color32::from_rgb(0xF5, 0xC2, 0x42),
                Stroke::new(1.0 * u, dark_outline),
            ));
            painter.line_segment([p(1.5, 6.8), p(14.2, 6.8)], Stroke::new(1.0 * u, dark_outline));
        }
        SiteMapIcon::DynPage => {
            // Gold gear (`#D8A42A`)
            let gold = Color32::from_rgb(0xD8, 0xA4, 0x2A);
            painter.circle_filled(p(8.0, 8.0), 4.6 * u, gold);
            painter.circle_stroke(p(8.0, 8.0), 4.8 * u, Stroke::new(1.0 * u, dark_outline));
            for i in 0..8 {
                let a = (i as f32) * std::f32::consts::FRAC_PI_4;
                let (s, c) = a.sin_cos();
                painter.line_segment(
                    [p(8.0 + c * 4.5, 8.0 + s * 4.5), p(8.0 + c * 6.4, 8.0 + s * 6.4)],
                    Stroke::new(1.6 * u, dark_outline),
                );
            }
            painter.circle_filled(p(8.0, 8.0), 1.8 * u, Color32::WHITE);
        }
        SiteMapIcon::QueryPage | SiteMapIcon::DefaultPage => {
            // Document page with folded top-right corner
            let doc_stroke = Stroke::new(1.1 * u, Color32::from_rgb(0x7A, 0x72, 0x58));
            painter.add(Shape::convex_polygon(
                vec![p(3.0, 1.8), p(10.0, 1.8), p(13.0, 4.8), p(13.0, 14.2), p(3.0, 14.2)],
                Color32::from_rgb(0xFA, 0xFA, 0xF8),
                doc_stroke,
            ));
            painter.add(Shape::line(vec![p(9.8, 1.8), p(9.8, 5.0), p(13.0, 5.0)], doc_stroke));
            if icon == SiteMapIcon::QueryPage {
                painter.text(
                    p(8.0, 9.5),
                    eframe::egui::Align2::CENTER_CENTER,
                    "?",
                    eframe::egui::FontId::proportional(9.5 * u),
                    Color32::from_rgb(0x6E, 0x5B, 0x2B),
                );
            }
        }
    }

    if let Some(dot) = dot_color {
        painter.circle_filled(p(12.8, 12.6), 3.1 * u, Color32::WHITE);
        painter.circle_filled(p(12.8, 12.6), 2.5 * u, dot);
    }
}

fn format_burp_hex_dump(text: &str) -> String {
    let mut out = String::new();
    for (row, chunk) in text.as_bytes().chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", row * 16));
        for i in 0..16 {
            if let Some(b) = chunk.get(i) {
                out.push_str(&format!("{b:02x} "));
            } else {
                out.push_str("   ");
            }
        }
        out.push(' ');
        for &b in chunk {
            out.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}

fn format_non_printable(text: &str) -> String {
    text.replace("\r\n", "\\r\\n\n")
        .replace('\t', "\\t")
}

/// Renders Burp Suite Pro v2026.3.3's Message Editor header & formatter tab bar
/// (`Pro-QSG-5-site-map.png`, `quick-start-pro-proxy-history.png`, `quick-start-pro-intercepted-request.png`):
/// Bold `Request` / `Response` title on top, followed by `Pretty | Raw | Hex` (and optional `Render`)
/// tabs with a 3px solid orange (`#FF6633`) underline under the active tab, plus the right-aligned
/// `eye-crossed-out`, `line-wrap` (`#1858A8` blue pill when active), `\n`, and `≡` icons.
pub fn burp_message_formatter_bar(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    heading_text: &str,
    mode: &mut usize,
    show_render: bool,
    wrap: &mut bool,
    show_non_printable: &mut bool,
) {
    use eframe::egui::{Align2, Color32, FontId, Rect, Sense, Shape, Stroke, Vec2, pos2};
    ui.push_id(id_salt, |ui| {
        if !heading_text.is_empty() {
            ui.label(
                eframe::egui::RichText::new(heading_text)
                    .size(14.5)
                    .strong()
                    .color(theme.color("ui.text.header")),
            );
        }
        let bar_w = ui.available_width().max(160.0);
        let bar_h = 26.0;
        let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, bar_h), Sense::hover());
        let painter = ui.painter_at(bar_rect);
        painter.rect_filled(bar_rect, 0.0, theme.color("ui.background.0"));
        painter.line_segment(
            [bar_rect.left_bottom(), bar_rect.right_bottom()],
            Stroke::new(1.0, theme.color("ui.border.1")),
        );

        let tabs: &[&str] = if show_render {
            &["Pretty", "Raw", "Hex", "Render"]
        } else {
            &["Pretty", "Raw", "Hex"]
        };
        let accent = theme.color("ui.icon.accent"); // `#FF6633`
        let mut x = bar_rect.min.x + 4.0;
        for (idx, &tab_name) in tabs.iter().enumerate() {
            let tab_w = 52.0;
            let tab_rect = Rect::from_min_size(pos2(x, bar_rect.min.y), Vec2::new(tab_w, bar_h));
            let resp = ui.interact(tab_rect, ui.id().with(("fmt-tab", idx)), Sense::click());
            resp.widget_info(|| {
                eframe::egui::WidgetInfo::labeled(eframe::egui::WidgetType::Button, true, tab_name)
            });
            if resp.clicked() {
                *mode = idx;
            }
            let active = *mode == idx;
            let text_col = if active {
                theme.color("ui.text.header")
            } else {
                theme.color("ui.icon.default")
            };
            painter.text(
                tab_rect.center(),
                Align2::CENTER_CENTER,
                tab_name,
                FontId::proportional(12.0),
                text_col,
            );
            if active {
                let underline = Rect::from_min_max(
                    pos2(tab_rect.min.x + 4.0, tab_rect.max.y - 3.0),
                    pos2(tab_rect.max.x - 4.0, tab_rect.max.y),
                );
                painter.rect_filled(underline, 0.0, accent);
            }
            x += tab_w + 4.0;
        }

        // Right-aligned icons: `eye-crossed-out`, `line-wrap` (blue pill), `\n`, `≡`
        let mut rx = bar_rect.max.x - 24.0;
        // 1. `≡` menu icon
        let menu_rect = Rect::from_min_size(pos2(rx, bar_rect.min.y + 4.0), Vec2::new(18.0, 18.0));
        let ic_col = theme.color("ui.icon.default");
        for dy in [5.0, 9.0, 13.0] {
            painter.line_segment(
                [
                    pos2(menu_rect.min.x + 3.0, menu_rect.min.y + dy),
                    pos2(menu_rect.max.x - 3.0, menu_rect.min.y + dy),
                ],
                Stroke::new(1.4, ic_col),
            );
        }
        rx -= 24.0;

        // 2. `\n` non-printable characters toggle (`non-printable-characters.svg`)
        let np_rect = Rect::from_min_size(pos2(rx, bar_rect.min.y + 4.0), Vec2::new(20.0, 18.0));
        let np_resp = ui.interact(np_rect, ui.id().with("fmt-np"), Sense::click());
        if np_resp.on_hover_text("Show non-printable characters (\\r\\n)").clicked() {
            *show_non_printable = !*show_non_printable;
        }
        if *show_non_printable {
            painter.rect_filled(np_rect, 3.0, Color32::from_rgb(0x18, 0x58, 0xA8));
        }
        painter.text(
            np_rect.center(),
            Align2::CENTER_CENTER,
            "\\n",
            FontId::monospace(10.5),
            if *show_non_printable { Color32::WHITE } else { ic_col },
        );
        rx -= 24.0;

        // 3. `line-wrap.svg` toggle (solid blue `#1858A8` rounded square when active, matching `Pro-QSG-5-site-map.png`)
        let wrap_rect = Rect::from_min_size(pos2(rx, bar_rect.min.y + 4.0), Vec2::new(18.0, 18.0));
        let wrap_resp = ui.interact(wrap_rect, ui.id().with("fmt-wrap"), Sense::click());
        if wrap_resp.on_hover_text("Toggle line wrapping").clicked() {
            *wrap = !*wrap;
        }
        if *wrap {
            painter.rect_filled(wrap_rect, 3.0, Color32::from_rgb(0x18, 0x58, 0xA8));
        }
        let w_col = if *wrap { Color32::WHITE } else { ic_col };
        painter.line_segment(
            [pos2(wrap_rect.min.x + 3.0, wrap_rect.min.y + 5.0), pos2(wrap_rect.max.x - 3.0, wrap_rect.min.y + 5.0)],
            Stroke::new(1.4, w_col),
        );
        painter.add(Shape::line(
            vec![
                pos2(wrap_rect.min.x + 3.0, wrap_rect.min.y + 9.5),
                pos2(wrap_rect.max.x - 3.5, wrap_rect.min.y + 9.5),
                pos2(wrap_rect.max.x - 3.5, wrap_rect.min.y + 13.5),
                pos2(wrap_rect.min.x + 8.5, wrap_rect.min.y + 13.5),
            ],
            Stroke::new(1.4, w_col),
        ));
        painter.line_segment(
            [pos2(wrap_rect.min.x + 3.0, wrap_rect.min.y + 13.5), pos2(wrap_rect.min.x + 6.0, wrap_rect.min.y + 13.5)],
            Stroke::new(1.4, w_col),
        );
        rx -= 24.0;

        // 4. `eye-crossed-out.svg` icon (shown on Request formatter bar in `quick-start-pro-proxy-history.png`)
        if !show_render {
            let eye_rect = Rect::from_min_size(pos2(rx, bar_rect.min.y + 4.0), Vec2::new(18.0, 18.0));
            painter.circle_stroke(eye_rect.center(), 4.5, Stroke::new(1.3, ic_col));
            painter.line_segment(
                [pos2(eye_rect.min.x + 3.0, eye_rect.min.y + 3.0), pos2(eye_rect.max.x - 3.0, eye_rect.max.y - 3.0)],
                Stroke::new(1.3, ic_col),
            );
        }
    });
}

/// Read-only message view with wrapping enabled by default.
pub fn burp_numbered_message_view(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    height: f32,
    raw_message: &str,
    mode: usize,
    show_non_printable: bool,
) -> eframe::egui::Response {
    burp_numbered_message_view_wrapped(
        ui,
        theme,
        id_salt,
        height,
        raw_message,
        mode,
        show_non_printable,
        true,
    )
}

/// A single scroll viewport keeps wrapped message lines and their gutter aligned.
/// Disables `ScrollArea` drag-to-scroll (`drag: false`) so mouse dragging selects ("blocks") text.
pub fn burp_numbered_message_view_wrapped(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    height: f32,
    raw_message: &str,
    mode: usize,
    show_non_printable: bool,
    wrap: bool,
) -> eframe::egui::Response {
    use eframe::egui::{self, FontId, Label, Sense, TextWrapMode, Vec2};
    let no_drag_scroll = egui::containers::scroll_area::ScrollSource {
        scroll_bar: true,
        drag: false,
        mouse_wheel: true,
    };
    if mode == 3 {
        let outer = egui::Frame::new()
            .fill(theme.color("ui.editor.message.background"))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.label("HTML preview — text only; CSS, JavaScript, images and external resources are not rendered.");
                egui::ScrollArea::both()
                    .id_salt((id_salt, "html-preview"))
                    .scroll_source(no_drag_scroll)
                    .max_height(height.max(60.0))
                    .show(ui, |ui| {
                        ui.add(Label::new(html_text_preview(raw_message)).selectable(true))
                    })
                    .inner
            });
        let mut resp = outer.inner;
        resp.rect = outer.response.rect;
        return resp;
    }
    let display_text = message_display_text(raw_message, mode, show_non_printable);
    let width = (ui.available_width() - 48.0).max(40.0);
    let mut job = if mode == 0 {
        crate::ui::highlight::layout(&display_text, theme)
    } else {
        egui::text::LayoutJob::simple(
            display_text,
            FontId::monospace(12.0),
            theme.color("ui.text.body"),
            f32::INFINITY,
        )
    };
    job.wrap.max_width = if wrap && mode != 2 {
        width
    } else {
        f32::INFINITY
    };
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    let outer = egui::Frame::new()
        .fill(theme.color("ui.editor.message.background"))
        .stroke(egui::Stroke::new(1.0_f32, theme.color("ui.border.1")))
        .show(ui, |ui| {
            let content = egui::ScrollArea::both()
                .id_salt((id_salt, "numbered-view-scroll"))
                .scroll_source(no_drag_scroll)
                .max_height(height.max(60.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let (gutter, _) = ui.allocate_exact_size(
                            Vec2::new(38.0, galley.size().y.max(height.max(60.0))),
                            Sense::hover(),
                        );
                        ui.painter()
                            .rect_filled(gutter, 0.0, theme.color("ui.background.2"));
                        let mut line = 1;
                        let mut new_line = true;
                        for row in &galley.rows {
                            if new_line {
                                ui.painter().text(
                                    gutter.left_top() + egui::vec2(30.0, row.pos.y),
                                    egui::Align2::RIGHT_TOP,
                                    line.to_string(),
                                    FontId::monospace(12.0),
                                    theme.color("ui.icon.default"),
                                );
                                line += 1;
                            }
                            new_line = row.ends_with_newline;
                        }
                        ui.add(
                            Label::new(galley)
                                .wrap_mode(TextWrapMode::Extend)
                                .selectable(true)
                                .sense(Sense::click()),
                        )
                    })
                })
                .inner;
            let mut response = content.inner;
            response.rect = content.response.rect;
            response
        });
    let mut response = outer.inner;
    response.rect = outer.response.rect;
    response
}

fn message_display_text(raw: &str, mode: usize, non_printable: bool) -> String {
    if mode == 1 && !non_printable {
        return raw.to_string();
    }
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    mode.hash(&mut hasher);
    non_printable.hash(&mut hasher);
    raw.hash(&mut hasher);
    let key = hasher.finish();

    thread_local! {
        static DISPLAY_CACHE: std::cell::RefCell<std::collections::VecDeque<(u64, String)>> =
            std::cell::RefCell::new(std::collections::VecDeque::with_capacity(16));
    }

    if let Some(cached) = DISPLAY_CACHE.with(|cache| {
        cache
            .borrow()
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, s)| s.clone())
    }) {
        return cached;
    }

    let display = if mode == 2 {
        format_burp_hex_dump(raw)
    } else if mode == 0 {
        // Formatting is display-only; never rewrite a captured or editable message.
        let boundary = raw
            .find("\r\n\r\n")
            .map(|i| (i, 4))
            .or_else(|| raw.find("\n\n").map(|i| (i, 2)));
        if let Some((at, separator)) = boundary {
            let (head, body) = (&raw[..at], &raw[at + separator..]);
            let trimmed = body.trim_start();
            if trimmed.starts_with('{') || trimmed.starts_with('[') {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                    format!(
                        "{head}\n\n{}",
                        serde_json::to_string_pretty(&value).unwrap_or_else(|_| body.to_string())
                    )
                } else {
                    raw.to_string()
                }
            } else {
                raw.to_string()
            }
        } else {
            raw.to_string()
        }
    } else {
        raw.to_string()
    };
    let out = if non_printable && mode != 2 {
        format_non_printable(&display)
    } else {
        display
    };
    DISPLAY_CACHE.with(|cache| {
        let mut guard = cache.borrow_mut();
        if guard.len() >= 16 {
            guard.pop_front();
        }
        guard.push_back((key, out.clone()));
    });
    out
}

fn html_text_preview(raw: &str) -> String {
    let body = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .map_or(raw, |(_, body)| body);
    if !body.trim_start().starts_with('<') {
        return "HTML preview is unavailable for this non-HTML response.".into();
    }
    // No markup is executed and no URLs are fetched. This deliberately renders only text.
    use std::sync::LazyLock;
    static ACTIVE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?is)<(script|style)\b[^>]*>.*?</(?:script|style)\s*>").unwrap()
    });
    static BREAKS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?is)<\s*(?:br\b[^>]*|/?(?:p|div|h[1-6]|li|tr)\b[^>]*)>").unwrap()
    });
    static TAGS: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?s)<[^>]*>").unwrap());
    let without_active = ACTIVE.replace_all(body, "");
    let lines = BREAKS.replace_all(&without_active, "\n");
    let text = TAGS.replace_all(&lines, "");
    let decoded = crate::logic::find_op("HTML decode")
        .and_then(|op| (op.run)(&text).ok())
        .unwrap_or_else(|| text.into_owned());
    decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Editable message; only the layout changes when wrapping is toggled.
pub fn burp_numbered_message_editor(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    height: f32,
    text: &mut String,
    mode: usize,
) -> (eframe::egui::Response, bool) {
    burp_numbered_message_editor_wrapped(ui, theme, id_salt, height, text, mode, true)
}

pub fn burp_numbered_message_editor_wrapped(
    ui: &mut Ui,
    theme: &Theme,
    id_salt: &str,
    height: f32,
    text: &mut String,
    mode: usize,
    wrap: bool,
) -> (eframe::egui::Response, bool) {
    use eframe::egui::{self, FontId};
    if mode >= 2 {
        return (
            burp_numbered_message_view_wrapped(ui, theme, id_salt, height, text, mode, false, wrap),
            false,
        );
    }
    let no_drag_scroll = egui::containers::scroll_area::ScrollSource {
        scroll_bar: true,
        drag: false,
        mouse_wheel: true,
    };
    let rows = ((height / 15.0) as usize).clamp(6, 55);
    let edit_id = ui.make_persistent_id((id_salt, "numbered-edit-body"));
    let prev_range = egui::text_edit::TextEditState::load(ui.ctx(), edit_id)
        .and_then(|s| s.cursor.char_range())
        .filter(|r| r.primary != r.secondary);
    let right_mouse_event = ui.input(|i| {
        i.pointer.button_pressed(egui::PointerButton::Secondary)
            || i.pointer.button_down(egui::PointerButton::Secondary)
            || i.pointer.button_released(egui::PointerButton::Secondary)
    });

    let mut changed = false;
    let outer = egui::Frame::new()
        .fill(theme.color("ui.editor.message.background"))
        .stroke(egui::Stroke::new(1.0_f32, theme.color("ui.border.1")))
        .show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt((id_salt, "numbered-edit-scroll"))
                .scroll_source(no_drag_scroll)
                .max_height(height.max(80.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        let (mut gutter, _) = ui.allocate_exact_size(
                            egui::vec2(38.0, height.max(80.0)),
                            egui::Sense::hover(),
                        );
                        let mut layouter = |ui: &Ui, buf: &dyn egui::TextBuffer, width: f32| {
                            let mut job = if mode == 0 {
                                crate::ui::highlight::layout(buf.as_str(), theme)
                            } else {
                                egui::text::LayoutJob::simple(
                                    buf.as_str().into(),
                                    FontId::monospace(12.0),
                                    theme.color("ui.text.body"),
                                    width,
                                )
                            };
                            job.wrap.max_width = if wrap { width.max(40.0) } else { f32::INFINITY };
                            ui.fonts_mut(|fonts| fonts.layout_job(job))
                        };
                        let mut output = egui::TextEdit::multiline(text)
                            .id(edit_id)
                            .font(FontId::monospace(12.0))
                            .desired_width(f32::INFINITY)
                            .desired_rows(rows)
                            .frame(false)
                            .layouter(&mut layouter)
                            .show(ui);

                        if let Some(pending) = take_pending_editor_cursor(id_salt) {
                            let ccr = egui::text::CCursorRange::two(
                                egui::text::CCursor::new(pending.start),
                                egui::text::CCursor::new(pending.end),
                            );
                            output.state.cursor.set_char_range(Some(ccr));
                            output.state.store(ui.ctx(), edit_id);
                            output.cursor_range = Some(ccr);
                        } else if right_mouse_event {
                            if let Some(saved) = prev_range {
                                output.state.cursor.set_char_range(Some(saved));
                                output.state.store(ui.ctx(), edit_id);
                                output.cursor_range = Some(saved);
                            }
                        }
                        if let Some(cr) = output.cursor_range {
                            let sorted = cr.as_sorted_char_range();
                            if sorted.start < sorted.end {
                                record_message_selection(id_salt, sorted, text);
                            }
                        }

                        gutter.max.y = gutter.top() + output.galley.size().y.max(height.max(80.0));
                        ui.painter()
                            .rect_filled(gutter, 0.0, theme.color("ui.background.2"));
                        let mut line = 1;
                        let mut new_line = true;
                        for row in &output.galley.rows {
                            if new_line {
                                ui.painter().text(
                                    egui::pos2(
                                        gutter.right() - 8.0,
                                        output.galley_pos.y + row.pos.y,
                                    ),
                                    egui::Align2::RIGHT_TOP,
                                    line.to_string(),
                                    FontId::monospace(12.0),
                                    theme.color("ui.icon.default"),
                                );
                                line += 1;
                            }
                            new_line = row.ends_with_newline;
                        }
                        changed = output.response.changed();
                        output.response
                    })
                    .inner
                })
                .inner
        });
    let mut response = outer.inner;
    response.rect = outer.response.rect;
    (response, changed)
}
