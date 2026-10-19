//! Organizer: saved request/response collections.
//!
//! Retention is bounded exactly like the proxy history. An organizer is a long-lived store, so an
//! unbounded one would be the slowest way to run this machine out of memory.

use eframe::egui::Ui;

use crate::ui::app::{clip, App, ORGANIZER_BODY_LIMIT, ORGANIZER_CAPACITY};
use crate::ui::panels::{heading, muted};
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
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme: Theme = app.theme.clone();
    heading(ui, &theme, "Collections");

    ui.horizontal(|ui| {
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
        if ui.button("Clear").clicked() {
            let count = app.organizer.len();
            app.organizer.clear();
            app.status = format!("Cleared {count} organizer items");
        }
        ui.separator();
        muted(
            ui,
            &theme,
            &format!(
                "{} item{} (max {})",
                app.organizer.len(),
                if app.organizer.len() == 1 { "" } else { "s" },
                ORGANIZER_CAPACITY
            ),
        );
    });

    ui.add_space(4.0);

    if app.organizer.is_empty() {
        muted(ui, &theme, "No saved items. Save the Repeater request to start a collection.");
        return;
    }

    let selected = app.panels.organizer.selected;
    let mut remove = None;
    ui.columns(2, |columns| {
        columns[0].label(eframe::egui::RichText::new("Items").strong());
        eframe::egui::ScrollArea::vertical().show(&mut columns[0], |ui| {
            for index in 0..app.organizer.len() {
                // Only the short summary is copied per frame, not the stored messages.
                let summary = app.organizer[index].summary();
                let name = app.organizer[index].name.clone();
                let response = ui.selectable_label(
                    selected == Some(index),
                    eframe::egui::RichText::new(format!("{name}\n{summary}"))
                        .color(theme.color("ui.text.body")),
                );
                if response.clicked() {
                    app.panels.organizer.selected = Some(index);
                }
                ui.horizontal(|ui| {
                    if ui.small_button("To Repeater").clicked() {
                        load_into_repeater(app, index);
                    }
                    if ui.small_button("Delete").clicked() {
                        remove = Some(index);
                    }
                });
            }
        });

        columns[1].label(eframe::egui::RichText::new("Item").strong());
        if let Some(index) = selected.filter(|i| *i < app.organizer.len()) {
            // Cloning for display keeps the borrow checker happy; only one item is ever copied.
            let item = app.organizer[index].clone();
            let mut name = app.organizer[index].name.clone();
            let mut host = app.organizer[index].host.clone();
            let mut notes = app.organizer[index].notes.clone();
            columns[1].horizontal(|ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut name);
            });
            columns[1].horizontal(|ui| {
                ui.label("Host");
                ui.text_edit_singleline(&mut host);
            });
            columns[1].label("Notes");
            columns[1].add(
                eframe::egui::TextEdit::multiline(&mut notes)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            );
            columns[1].horizontal(|ui| {
                if ui.button("To Repeater").clicked() {
                    load_into_repeater(app, index);
                }
                if ui.button("Delete").clicked() {
                    remove = Some(index);
                }
            });
            columns[1].add_space(4.0);
            columns[1].label("Request");
            crate::ui::highlight::show_message(
                &mut columns[1],
                &item.request,
                &theme,
                theme.color("ui.editor.message.background"),
            );
            columns[1].label("Response");
            crate::ui::highlight::show_message(
                &mut columns[1],
                &item.response,
                &theme,
                theme.color("ui.editor.message.background"),
            );
            // Written back after the closure so the borrow of the item list ends cleanly.
            app.organizer[index].name = name;
            app.organizer[index].host = host;
            app.organizer[index].notes = notes;
        } else {
            muted(&mut columns[1], &theme, "Select an item to view it.");
        }
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
