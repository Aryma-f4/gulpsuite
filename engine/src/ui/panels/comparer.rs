//! Comparer: line diff between two messages.

use eframe::egui::Ui;

use super::heading;
use crate::logic;
use crate::ui::app::App;

#[derive(Default, Clone)]
pub struct ComparerPanel {
    pub left: String,
    pub right: String,
    pub rows: Vec<logic::DiffRow>,
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Comparer");
    ui.horizontal(|ui| {
        if ui.button("Compare").clicked() {
            app.panels.comparer.rows =
                logic::diff_lines(&app.panels.comparer.left, &app.panels.comparer.right);
            let changed = app
                .panels
                .comparer
                .rows
                .iter()
                .filter(|r| r.kind != logic::DiffKind::Same)
                .count();
            app.status = format!("{} differing line(s)", changed);
        }
        ui.label(format!("{} rows", app.panels.comparer.rows.len()));
    });
    ui.add_space(4.0);

    let available = ui.available_height();
    ui.columns(2, |columns| {
        columns[0].label("A");
        eframe::egui::ScrollArea::vertical()
            .max_height(available - 30.0)
            .show(&mut columns[0], |ui| {
                ui.add(
                    eframe::egui::TextEdit::multiline(&mut app.panels.comparer.left)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
        columns[1].label("B");
        eframe::egui::ScrollArea::vertical()
            .max_height(available - 30.0)
            .show(&mut columns[1], |ui| {
                ui.add(
                    eframe::egui::TextEdit::multiline(&mut app.panels.comparer.right)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
    });
    if !app.panels.comparer.rows.is_empty() {
        ui.add_space(4.0);
        heading(ui, &theme, "Differences");
        eframe::egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
            for row in &app.panels.comparer.rows {
                let (colour, sign) = match row.kind {
                    logic::DiffKind::Same => (theme.color("ui.icon.default"), ' '),
                    logic::DiffKind::Deleted => (theme.color("ui.icon.error"), '-'),
                    logic::DiffKind::Added => (theme.color("ui.icon.success"), '+'),
                    logic::DiffKind::Modified => (theme.color("ui.icon.warning"), '~'),
                };
                // A row carries one side or the other, depending on the change.
                let text = row.left.as_deref().or(row.right.as_deref()).unwrap_or("");
                ui.label(
                    eframe::egui::RichText::new(format!("{sign} {text}")).monospace().color(colour),
                );
            }
        });
    }
}
