//! Organizer: saved request/response collections.
//!
//! Retention is bounded exactly like the proxy history. An organizer is a long-lived store, so an
//! unbounded one would be the slowest way to run this machine out of memory.

use eframe::egui::Ui;

use crate::ui::app::{clip, App, ORGANIZER_BODY_LIMIT, ORGANIZER_CAPACITY};
use crate::ui::panels::{empty_state, heading, muted};
use crate::ui::theme::Theme;

/// One saved item. Notes are the operator's own text; messages come from live traffic.
#[derive(Clone, Default)]
pub struct OrganizerItem {
    pub host: String,
    pub name: String,
    pub notes: String,
    pub request: String,
    pub response: String,
}

impl OrganizerItem {
    pub fn summary(&self) -> String {
        let first = self.request.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            "empty request".into()
        } else {
            first.chars().take(80).collect()
        }
    }
}

/// Per-panel state.
#[derive(Clone, Default)]
pub struct OrganizerPanel {
    /// Index of the item shown in the detail pane.
    pub selected: Option<usize>,
    /// Case-insensitive filter over saved items.
    pub search: String,
    pub req_fmt_mode: usize,
    pub resp_fmt_mode: usize,
    pub req_wrap: bool,
    pub resp_wrap: bool,
    pub req_np: bool,
    pub resp_np: bool,
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme: Theme = app.theme.clone();
    let mut remove = None;

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(240.0);
            ui.horizontal(|ui| {
                super::scanner::paint_launcher_icon(
                    ui,
                    eframe::egui::Vec2::new(16.0, 16.0),
                    theme.color("ui.icon.default"),
                    super::scanner::LauncherIcon::Folder,
                );
                heading(ui, &theme, "Collections");
                ui.with_layout(
                    eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                    |ui| {
                        if ui
                            .small_button("+ New")
                            .on_hover_text("Save Repeater request to Inbox")
                            .clicked()
                        {
                            let (host, name) = (
                                app.panels.repeater.active().host.clone(),
                                app.panels.repeater.active().raw.clone(),
                            );
                            if name.trim().is_empty() {
                                app.status = "Nothing to save: the Repeater request is empty".into();
                            } else {
                                let next = app.organizer.len() + 1;
                                retain(
                                    app,
                                    OrganizerItem {
                                        host,
                                        name: format!("item-{next}"),
                                        request: name,
                                        response: app.panels.repeater.active().response.clone(),
                                        notes: String::new(),
                                    },
                                );
                                app.status = "Saved to Organizer".into();
                            }
                        }
                    },
                );
            });
            ui.add_space(4.0);
            if ui.button("Save Repeater request").clicked() {
                let (host, name) = (
                    app.panels.repeater.active().host.clone(),
                    app.panels.repeater.active().raw.clone(),
                );
                if name.trim().is_empty() {
                    app.status = "Nothing to save: the Repeater request is empty".into();
                } else {
                    let next = app.organizer.len() + 1;
                    retain(
                        app,
                        OrganizerItem {
                            host,
                            name: format!("item-{next}"),
                            request: name,
                            response: app.panels.repeater.active().response.clone(),
                            notes: String::new(),
                        },
                    );
                    app.status = "Saved to Organizer".into();
                }
            }
            ui.add_space(4.0);
            ui.add(
                eframe::egui::TextEdit::singleline(&mut app.panels.organizer.search)
                    .hint_text("Search")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(4.0);
            let _ = ui.selectable_label(
                true,
                eframe::egui::RichText::new(format!(
                    "Inbox ({} / max {})",
                    app.organizer.len(),
                    ORGANIZER_CAPACITY
                ))
                .color(theme.color("ui.text.body")),
            );
            if !app.organizer.is_empty() && ui.button("Clear").clicked() {
                let count = app.organizer.len();
                app.organizer.clear();
                app.status = format!("Cleared {count} organizer items");
            }
        });

        ui.separator();

        ui.vertical(|ui| {
            if app.organizer.is_empty() {
                let (learn, _) = empty_state(
                    ui,
                    &theme,
                    "Organizer inbox is empty",
                    "To get started, send a message to Organizer from anywhere in Gulp.",
                    true,
                    None,
                );
                if learn {
                    app.status =
                        "Organizer: right-click a Proxy history row or save from Repeater to store items".into();
                }
                return;
            }

            let selected = app
                .panels
                .organizer
                .selected
                .filter(|&i| i < app.organizer.len())
                .or(Some(0));
            app.panels.organizer.selected = selected;
            let needle = app.panels.organizer.search.trim().to_lowercase();

            // 1. Top Bordered Master Table (`# | Name | Host | Request | Response bytes | Notes | Actions`)
            eframe::egui::Frame::new()
                .fill(theme.color("ui.background.1"))
                .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                .inner_margin(eframe::egui::Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    eframe::egui::ScrollArea::vertical()
                        .id_salt("organizer-master-table-scroll")
                        .max_height(180.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            eframe::egui::Grid::new("organizer-master-grid")
                                .num_columns(7)
                                .striped(true)
                                .min_col_width(48.0)
                                .spacing([14.0, 4.0])
                                .show(ui, |ui| {
                                    for hdr in [
                                        "#",
                                        "Name",
                                        "Host",
                                        "Request",
                                        "Resp bytes",
                                        "Notes",
                                        "Actions",
                                    ] {
                                        ui.label(
                                            eframe::egui::RichText::new(hdr)
                                                .strong()
                                                .color(theme.color("ui.text.heading")),
                                        );
                                    }
                                    ui.end_row();

                                    for index in 0..app.organizer.len() {
                                        let summary = app.organizer[index].summary();
                                        let name = app.organizer[index].name.clone();
                                        let host = app.organizer[index].host.clone();
                                        let notes_preview: String = app.organizer[index]
                                            .notes
                                            .lines()
                                            .next()
                                            .unwrap_or("")
                                            .chars()
                                            .take(28)
                                            .collect();
                                        let resp_len = app.organizer[index].response.len();
                                        if !needle.is_empty()
                                            && !format!("{name} {host} {summary} {notes_preview}")
                                                .to_lowercase()
                                                .contains(&needle)
                                        {
                                            continue;
                                        }
                                        let is_sel = selected == Some(index);
                                        let c0 = ui.selectable_label(is_sel, (index + 1).to_string());
                                        let c1 = ui.selectable_label(
                                            is_sel,
                                            eframe::egui::RichText::new(&name).strong(),
                                        );
                                        let c2 = ui.selectable_label(is_sel, &host);
                                        let c3 = ui.selectable_label(
                                            is_sel,
                                            eframe::egui::RichText::new(&summary).monospace(),
                                        );
                                        let c4 = ui.selectable_label(is_sel, resp_len.to_string());
                                        let c5 = ui.selectable_label(
                                            is_sel,
                                            if notes_preview.is_empty() {
                                                "—"
                                            } else {
                                                notes_preview.as_str()
                                            },
                                        );
                                        if c0.clicked()
                                            || c1.clicked()
                                            || c2.clicked()
                                            || c3.clicked()
                                            || c4.clicked()
                                            || c5.clicked()
                                        {
                                            app.panels.organizer.selected = Some(index);
                                        }
                                        let (item_req, item_resp) = (
                                            app.organizer[index].request.clone(),
                                            app.organizer[index].response.clone(),
                                        );
                                        for cell in [&c0, &c1, &c2, &c3, &c4, &c5] {
                                            super::attach_message_context_menu(
                                                app,
                                                cell,
                                                &host,
                                                &item_req,
                                                &item_resp,
                                            );
                                        }
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().button_padding =
                                                eframe::egui::Vec2::new(6.0, 2.0);
                                            if ui.small_button("To Repeater").clicked() {
                                                load_into_repeater(app, index);
                                            }
                                            if ui.small_button("To Intruder").clicked() {
                                                app.send_to_intruder(&host, &item_req);
                                            }
                                            if ui.small_button("Delete").clicked() {
                                                remove = Some(index);
                                            }
                                        });
                                        ui.end_row();
                                    }
                                });
                        });
                });

            ui.add_space(6.0);

            // 2. Selected Item Properties Bar + Side-by-Side Split Request | Response Panes
            if let Some(index) = app
                .panels
                .organizer
                .selected
                .filter(|&i| i < app.organizer.len())
            {
                let item = app.organizer[index].clone();
                let mut name = app.organizer[index].name.clone();
                let mut host = app.organizer[index].host.clone();
                let mut notes = app.organizer[index].notes.clone();

                eframe::egui::Frame::new()
                    .fill(theme.color("ui.background.1"))
                    .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                    .inner_margin(eframe::egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(eframe::egui::RichText::new("Name:").strong());
                            ui.add(
                                eframe::egui::TextEdit::singleline(&mut name).desired_width(130.0),
                            );
                            ui.label(eframe::egui::RichText::new("Host:").strong());
                            ui.add(
                                eframe::egui::TextEdit::singleline(&mut host).desired_width(210.0),
                            );
                            ui.label(eframe::egui::RichText::new("Notes:").strong());
                            ui.add(
                                eframe::egui::TextEdit::singleline(&mut notes)
                                    .hint_text("Add notes for this saved item…")
                                    .desired_width(240.0),
                            );
                            if ui.button("To Repeater").clicked() {
                                load_into_repeater(app, index);
                            }
                            if ui.button("To Intruder").clicked() {
                                app.send_to_intruder(&item.host, &item.request);
                            }
                            if ui.button("Delete").clicked() {
                                remove = Some(index);
                            }
                        });
                    });

                app.organizer[index].name = name;
                app.organizer[index].host = host;
                app.organizer[index].notes = notes;

                ui.add_space(6.0);
                let pane_h = (ui.available_height() - 36.0).max(210.0);
                ui.columns(2, |columns| {
                    super::gulp_message_formatter_bar(
                        &mut columns[0],
                        &theme,
                        "org-req-fmt",
                        "Request",
                        &mut app.panels.organizer.req_fmt_mode,
                        false,
                        &mut app.panels.organizer.req_wrap,
                        &mut app.panels.organizer.req_np,
                    );
                    let r_req = super::gulp_numbered_message_view_wrapped(
                        &mut columns[0],
                        &theme,
                        "org-req",
                        pane_h,
                        &item.request,
                        app.panels.organizer.req_fmt_mode,
                        app.panels.organizer.req_np,
                        app.panels.organizer.req_wrap,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r_req,
                        &item.host,
                        &item.request,
                        &item.response,
                    );

                    super::gulp_message_formatter_bar(
                        &mut columns[1],
                        &theme,
                        "org-resp-fmt",
                        "Response",
                        &mut app.panels.organizer.resp_fmt_mode,
                        true,
                        &mut app.panels.organizer.resp_wrap,
                        &mut app.panels.organizer.resp_np,
                    );
                    let r_resp = super::gulp_numbered_message_view_wrapped(
                        &mut columns[1],
                        &theme,
                        "org-resp",
                        pane_h,
                        &item.response,
                        app.panels.organizer.resp_fmt_mode,
                        app.panels.organizer.resp_np,
                        app.panels.organizer.resp_wrap,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r_resp,
                        &item.host,
                        &item.request,
                        &item.response,
                    );
                });
            } else {
                muted(ui, &theme, "Select an item to view it.");
            }
        });
    });

    if let Some(index) = remove {
        let name = app.organizer[index].name.clone();
        app.organizer.remove(index);
        if app.panels.organizer.selected == Some(index) {
            app.panels.organizer.selected = None;
        } else if app.panels.organizer.selected.map(|s| s > index).unwrap_or(false) {
            app.panels.organizer.selected = Some(index);
        }
        app.status = format!("Deleted {name}");
    }
}

fn load_into_repeater(app: &mut App, index: usize) {
    let Some(item) = app.organizer.get(index) else {
        return;
    };
    app.panels
        .repeater
        .reuse(&item.host, &item.request, &item.response);
    app.tool = 4;
    app.status = format!("Loaded {} into Repeater", item.name);
}

/// Appends with the same ceiling and clipping the proxy history uses.
pub fn retain(app: &mut App, item: OrganizerItem) {
    let mut item = item;
    item.request = clip(&item.request, ORGANIZER_BODY_LIMIT);
    item.response = clip(&item.response, ORGANIZER_BODY_LIMIT);
    app.organizer.push(item);
    while app.organizer.len() > ORGANIZER_CAPACITY {
        app.organizer.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::app::ORGANIZER_CAPACITY;

    /// The organizer outlives a session, so its ceiling is what keeps a long-lived install honest.
    #[test]
    fn worst_case_retained_bytes_are_bounded() {
        let per_item = ORGANIZER_BODY_LIMIT * 2 + 256;
        assert!(
            ORGANIZER_CAPACITY * per_item <= 128 * 1024 * 1024,
            "ceiling would retain {} bytes",
            ORGANIZER_CAPACITY * per_item
        );
    }

    #[test]
    fn summary_is_bounded_and_never_panics_on_empty_input() {
        let mut empty = OrganizerItem::default();
        assert_eq!(empty.summary(), "empty request");
        empty.request = "GET /".into();
        assert_eq!(empty.summary(), "GET /");
        empty.request = format!("GET /{} HTTP/1.1", "x".repeat(5000));
        assert!(empty.summary().chars().count() <= 80);
    }
}
