//! Comparer: Burp v2026.3.3 two-table layout with right-hand action buttons and Words/Bytes diff.

use eframe::egui::Ui;

use super::heading;
use crate::logic;
use crate::ui::app::App;

#[derive(Clone)]
pub struct ComparerPanel {
    pub left: String,
    pub right: String,
    pub rows: Vec<logic::DiffRow>,
    pub byte_mode: bool,
    pub item1_height: f32,
    pub item2_height: f32,
    pub diff_window_open: bool,
}

impl Default for ComparerPanel {
    fn default() -> Self {
        Self {
            left: String::new(),
            right: String::new(),
            rows: Vec::new(),
            byte_mode: false,
            item1_height: 150.0,
            item2_height: 150.0,
            diff_window_open: false,
        }
    }
}

fn hex_lines(text: &str) -> String {
    text.as_bytes()
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            format!("{:04x}: {}", row * 16, hex.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn run_words_compare(app: &mut App) {
    app.panels.comparer.byte_mode = false;
    app.panels.comparer.rows =
        logic::diff_lines(&app.panels.comparer.left, &app.panels.comparer.right);
    let changed = app
        .panels
        .comparer
        .rows
        .iter()
        .filter(|r| r.kind != logic::DiffKind::Same)
        .count();
    app.status = format!("Words comparison: {} differing line(s)", changed);
}

fn run_bytes_compare(app: &mut App) {
    app.panels.comparer.byte_mode = true;
    let left_hex = hex_lines(&app.panels.comparer.left);
    let right_hex = hex_lines(&app.panels.comparer.right);
    app.panels.comparer.rows = logic::diff_lines(&left_hex, &right_hex);
    let changed = app
        .panels
        .comparer
        .rows
        .iter()
        .filter(|r| r.kind != logic::DiffKind::Same)
        .count();
    app.status = format!("Bytes comparison: {} differing 16-byte row(s)", changed);
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Comparer");
    super::muted(
        ui,
        &theme,
        "This function lets you do a word- or byte-level comparison between different data. \
         You can load, paste, or send data here from other tools and then select the comparison \
         you want to perform.",
    );
    ui.add_space(6.0);

    let total_w = ui.available_width().max(320.0);
    let btn_w = 100.0;
    let left_w = (total_w - btn_w - 14.0).max(180.0);
    let h1 = app.panels.comparer.item1_height;

    // Upper section: Select item 1 + right-side Paste / Load / Remove / Clear button stack
    ui.label("Select item 1:");
    ui.horizontal_top(|ui| {
        ui.allocate_ui(eframe::egui::Vec2::new(left_w, h1), |ui| {
            eframe::egui::Frame::new()
                .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                .show(ui, |ui| {
                    eframe::egui::Frame::new()
                        .fill(theme.color("ui.background.3"))
                        .inner_margin(eframe::egui::Margin::symmetric(8, 4))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(eframe::egui::RichText::new("#  1").strong());
                                ui.separator();
                                ui.label(
                                    eframe::egui::RichText::new(format!(
                                        "Length: {} bytes",
                                        app.panels.comparer.left.len()
                                    ))
                                    .strong(),
                                );
                                ui.separator();
                                ui.label(eframe::egui::RichText::new("Data").strong());
                            });
                        });
                    let rows = (((h1 - 28.0) / 16.0) as usize).clamp(4, 30);
                    eframe::egui::ScrollArea::vertical()
                        .id_salt("comparer-left")
                        .max_height((h1 - 28.0).max(60.0))
                        .show(ui, |ui| {
                            let resp = ui.add(
                                eframe::egui::TextEdit::multiline(&mut app.panels.comparer.left)
                                    .font(eframe::egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(rows),
                            );
                            comparer_context_menu(app, &resp, true);
                        });
                });
        });

        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.set_width(btn_w);
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Paste"))
                .on_hover_text("Load from Repeater request")
                .clicked()
            {
                app.panels.comparer.left = app.panels.repeater.active().raw.clone();
            }
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Load"))
                .on_hover_text("Load from Repeater response or latest Proxy history")
                .clicked()
            {
                let rep = app.panels.repeater.active().response.clone();
                if !rep.is_empty() {
                    app.panels.comparer.left = rep;
                } else if let Some(tx) = app.log.back() {
                    app.panels.comparer.left = tx.response.clone();
                }
            }
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Remove"))
                .clicked()
            {
                app.panels.comparer.left.clear();
            }
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Clear"))
                .clicked()
            {
                app.panels.comparer.left.clear();
                app.panels.comparer.right.clear();
                app.panels.comparer.rows.clear();
            }
        });
    });

    super::horizontal_resize_handle(
        ui,
        &theme,
        "comparer-item1-resize",
        &mut app.panels.comparer.item1_height,
        90.0,
        400.0,
        150.0,
    );

    let h2 = app.panels.comparer.item2_height;
    // Lower section: Select item 2 + bottom-right Compare ... Words / Bytes buttons
    ui.label("Select item 2:");
    ui.horizontal_top(|ui| {
        ui.allocate_ui(eframe::egui::Vec2::new(left_w, h2), |ui| {
            eframe::egui::Frame::new()
                .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                .show(ui, |ui| {
                    eframe::egui::Frame::new()
                        .fill(theme.color("ui.background.3"))
                        .inner_margin(eframe::egui::Margin::symmetric(8, 4))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(eframe::egui::RichText::new("#  2").strong());
                                ui.separator();
                                ui.label(
                                    eframe::egui::RichText::new(format!(
                                        "Length: {} bytes",
                                        app.panels.comparer.right.len()
                                    ))
                                    .strong(),
                                );
                                ui.separator();
                                ui.label(eframe::egui::RichText::new("Data").strong());
                            });
                        });
                    let rows = (((h2 - 28.0) / 16.0) as usize).clamp(4, 30);
                    eframe::egui::ScrollArea::vertical()
                        .id_salt("comparer-right")
                        .max_height((h2 - 28.0).max(60.0))
                        .show(ui, |ui| {
                            let resp = ui.add(
                                eframe::egui::TextEdit::multiline(&mut app.panels.comparer.right)
                                    .font(eframe::egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(rows),
                            );
                            comparer_context_menu(app, &resp, false);
                        });
                });
        });

        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.set_width(btn_w);
            ui.label("Compare ...");
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Words"))
                .clicked()
                || ui
                    .add_sized([btn_w, 24.0], eframe::egui::Button::new("Compare"))
                    .clicked()
            {
                run_words_compare(app);
            }
            if ui
                .add_sized([btn_w, 24.0], eframe::egui::Button::new("Bytes"))
                .clicked()
            {
                run_bytes_compare(app);
            }
            if !app.panels.comparer.rows.is_empty()
                && ui
                    .add_sized([btn_w, 24.0], eframe::egui::Button::new("Open window"))
                    .clicked()
            {
                app.panels.comparer.diff_window_open = true;
            }
        });
    });

    super::horizontal_resize_handle(
        ui,
        &theme,
        "comparer-item2-resize",
        &mut app.panels.comparer.item2_height,
        90.0,
        400.0,
        150.0,
    );

    if !app.panels.comparer.rows.is_empty() {
        ui.add_space(4.0);
        heading(ui, &theme, "Differences");
        eframe::egui::ScrollArea::vertical()
            .id_salt("comparer-diff-scroll")
            .max_height(180.0)
            .show(ui, |ui| {
                for row in &app.panels.comparer.rows {
                    let (colour, sign) = match row.kind {
                        logic::DiffKind::Same => (theme.color("ui.icon.default"), ' '),
                        logic::DiffKind::Deleted => (theme.color("ui.icon.error"), '-'),
                        logic::DiffKind::Added => (theme.color("ui.icon.success"), '+'),
                        logic::DiffKind::Modified => (theme.color("ui.icon.warning"), '~'),
                    };
                    let text = row.left.as_deref().or(row.right.as_deref()).unwrap_or("");
                    ui.label(
                        eframe::egui::RichText::new(format!("{sign} {text}"))
                            .monospace()
                            .color(colour),
                    );
                }
            });
    }

    if app.panels.comparer.diff_window_open {
        let mut open = true;
        let rows = app.panels.comparer.rows.clone();
        eframe::egui::Window::new("Compare items")
            .open(&mut open)
            .resizable(true)
            .default_size([780.0, 480.0])
            .show(ui.ctx(), |ui| {
                eframe::egui::ScrollArea::vertical().show(ui, |ui| {
                    for row in &rows {
                        let (colour, sign) = match row.kind {
                            logic::DiffKind::Same => (theme.color("ui.icon.default"), ' '),
                            logic::DiffKind::Deleted => (theme.color("ui.icon.error"), '-'),
                            logic::DiffKind::Added => (theme.color("ui.icon.success"), '+'),
                            logic::DiffKind::Modified => (theme.color("ui.icon.warning"), '~'),
                        };
                        let text = row.left.as_deref().or(row.right.as_deref()).unwrap_or("");
                        ui.label(
                            eframe::egui::RichText::new(format!("{sign} {text}"))
                                .monospace()
                                .color(colour),
                        );
                    }
                });
            });
        app.panels.comparer.diff_window_open = open;
    }
}

fn comparer_context_menu(app: &mut App, trigger: &eframe::egui::Response, is_left: bool) {
    super::show_persistent_context_menu(trigger, |ui| {
        if ui.button("Compare Words").clicked() {
            run_words_compare(app);
            ui.close();
        }
        if ui.button("Compare Bytes").clicked() {
            run_bytes_compare(app);
            ui.close();
        }
        ui.separator();
        if ui.button("Load from Repeater request").clicked() {
            let raw = app.panels.repeater.active().raw.clone();
            if is_left {
                app.panels.comparer.left = raw;
            } else {
                app.panels.comparer.right = raw;
            }
            ui.close();
        }
        if ui.button("Load from Repeater response").clicked() {
            let resp = app.panels.repeater.active().response.clone();
            if is_left {
                app.panels.comparer.left = resp;
            } else {
                app.panels.comparer.right = resp;
            }
            ui.close();
        }
        if ui.button("Send to Decoder").clicked() {
            app.panels.decoder.input = if is_left {
                app.panels.comparer.left.clone()
            } else {
                app.panels.comparer.right.clone()
            };
            app.tool = crate::ui::app::DECODER;
            app.view = 0;
            ui.close();
        }
        if ui.button("Clear").clicked() {
            if is_left {
                app.panels.comparer.left.clear();
            } else {
                app.panels.comparer.right.clear();
            }
            ui.close();
        }
    });
}
