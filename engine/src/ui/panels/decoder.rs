//! Decoder: Burp v2026.3.3 stacked transformation stages with right-hand control column.

use eframe::egui::Ui;

use crate::logic;
use crate::ui::app::App;

#[derive(Clone)]
pub struct DecoderPanel {
    pub input: String,
    pub output: String,
    pub op: usize,
    pub custom: bool,
    pub hex_view: bool,
    pub output_hex_view: bool,
    pub input_height: f32,
    pub output_height: f32,
}

impl Default for DecoderPanel {
    fn default() -> Self {
        DecoderPanel {
            input: String::new(),
            output: String::new(),
            op: 0,
            custom: false,
            hex_view: false,
            output_hex_view: false,
            input_height: 170.0,
            output_height: 170.0,
        }
    }
}

fn hex_dump(text: &str) -> String {
    let mut out = String::new();
    for (row, chunk) in text.as_bytes().chunks(16).enumerate() {
        out.push_str(&format!("{:04x}: ", row * 16));
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

fn run_named_op(app: &mut App, op_name: &str) {
    if let Some((idx, _)) = logic::decoder_ops()
        .iter()
        .enumerate()
        .find(|(_, o)| o.name == op_name)
    {
        app.panels.decoder.op = idx;
        app.panels.decoder.custom = false;
        apply(app);
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let total_w = ui.available_width().max(320.0);
    let right_col_w = 165.0;
    let left_col_w = (total_w - right_col_w - 14.0).max(160.0);
    let input_h = app.panels.decoder.input_height;

    // Stage 1: Left input editor box + Right vertical control column (matches ref_Decoder.png)
    ui.horizontal_top(|ui| {
        ui.allocate_ui(eframe::egui::Vec2::new(left_col_w, input_h), |ui| {
            let rows = ((input_h / 16.0) as usize).clamp(6, 40);
            eframe::egui::Frame::new()
                .fill(theme.color("ui.editor.message.background"))
                .inner_margin(6.0)
                .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                .show(ui, |ui| {
                    ui.set_min_height(input_h - 12.0);
                    eframe::egui::ScrollArea::vertical()
                        .id_salt("decoder-input-scroll")
                        .max_height(input_h - 12.0)
                        .show(ui, |ui| {
                            let resp = if app.panels.decoder.hex_view {
                                let dumped = hex_dump(&app.panels.decoder.input);
                                ui.add(
                                    eframe::egui::Label::new(
                                        eframe::egui::RichText::new(dumped)
                                            .monospace()
                                            .color(theme.color("ui.text.body")),
                                    )
                                    .sense(eframe::egui::Sense::click()),
                                )
                            } else {
                                ui.add(
                                    eframe::egui::TextEdit::multiline(
                                        &mut app.panels.decoder.input,
                                    )
                                    .font(eframe::egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(rows),
                                )
                            };
                            decoder_context_menu(app, &resp);
                        });
                });
        });

        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.set_width(right_col_w);
            ui.horizontal(|ui| {
                ui.radio_value(&mut app.panels.decoder.hex_view, false, "Text");
                ui.radio_value(&mut app.panels.decoder.hex_view, true, "Hex");
            });
            ui.add_space(4.0);

            eframe::egui::ComboBox::from_id_salt("decoder-decode-as")
                .width(right_col_w)
                .selected_text("Decode as ...")
                .show_ui(ui, |ui| {
                    for (label, op_name) in [
                        ("URL", "URL decode"),
                        ("HTML", "HTML decode"),
                        ("Base64", "Base64 decode"),
                        ("Base64 URL-safe", "Base64 URL-safe decode"),
                        ("ASCII hex", "Hex decode"),
                        ("Base32", "Base32 decode"),
                        ("Binary", "Binary decode"),
                        ("Decimal", "Decimal decode"),
                        ("Octal", "Octal decode"),
                    ] {
                        if ui.button(label).clicked() {
                            run_named_op(app, op_name);
                            ui.close();
                        }
                    }
                });

            eframe::egui::ComboBox::from_id_salt("decoder-encode-as")
                .width(right_col_w)
                .selected_text("Encode as ...")
                .show_ui(ui, |ui| {
                    for (label, op_name) in [
                        ("URL", "URL encode"),
                        ("HTML", "HTML encode"),
                        ("Base64", "Base64 encode"),
                        ("Base64 URL-safe", "Base64 encode URL-safe"),
                        ("ASCII hex", "Hex encode"),
                        ("Base32", "Base32 encode"),
                        ("Binary", "Binary encode"),
                        ("ROT13", "ROT13"),
                        ("Lowercase", "Case transform: lower"),
                        ("Uppercase", "Case transform: upper"),
                    ] {
                        if ui.button(label).clicked() {
                            run_named_op(app, op_name);
                            ui.close();
                        }
                    }
                });

            eframe::egui::ComboBox::from_id_salt("decoder-hash")
                .width(right_col_w)
                .selected_text("Hash ...")
                .show_ui(ui, |ui| {
                    for (label, op_name) in [
                        ("SHA-256", "Hash: SHA-256"),
                        ("SHA-1", "Hash: SHA-1"),
                        ("MD5", "Hash: MD5"),
                    ] {
                        if ui.button(label).clicked() {
                            run_named_op(app, op_name);
                            ui.close();
                        }
                    }
                });

            if ui
                .add_sized(
                    [right_col_w, 24.0],
                    eframe::egui::Button::new("Smart decode"),
                )
                .clicked()
            {
                app.panels.decoder.custom = true;
                apply(app);
            }
            if ui
                .add_sized([right_col_w, 24.0], eframe::egui::Button::new("Transform"))
                .clicked()
            {
                apply(app);
            }
        });
    });

    super::horizontal_resize_handle(
        ui,
        &theme,
        "decoder-input-resize",
        &mut app.panels.decoder.input_height,
        100.0,
        480.0,
        170.0,
    );

    // Stage 2: Chained output pane below Stage 1
    let output_h = app.panels.decoder.output_height;
    ui.horizontal_top(|ui| {
        ui.allocate_ui(eframe::egui::Vec2::new(left_col_w, output_h), |ui| {
            eframe::egui::Frame::new()
                .fill(theme.color("ui.editor.message.background"))
                .inner_margin(6.0)
                .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
                .show(ui, |ui| {
                    ui.set_min_height(output_h - 12.0);
                    eframe::egui::ScrollArea::vertical()
                        .id_salt("decoder-output-scroll")
                        .max_height(output_h - 12.0)
                        .show(ui, |ui| {
                            let shown = if app.panels.decoder.output_hex_view {
                                hex_dump(&app.panels.decoder.output)
                            } else {
                                app.panels.decoder.output.clone()
                            };
                            let resp = ui.add(
                                eframe::egui::Label::new(
                                    eframe::egui::RichText::new(shown)
                                        .monospace()
                                        .color(theme.color("ui.text.body")),
                                )
                                .selectable(true)
                                .sense(eframe::egui::Sense::click()),
                            );
                            decoder_context_menu(app, &resp);
                        });
                });
        });

        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.set_width(right_col_w);
            ui.horizontal(|ui| {
                let text = ui.radio_value(&mut app.panels.decoder.output_hex_view, false, "Text");
                text.widget_info(|| {
                    eframe::egui::WidgetInfo::selected(
                        eframe::egui::WidgetType::RadioButton,
                        true,
                        !app.panels.decoder.output_hex_view,
                        "Output Text",
                    )
                });
                let hex = ui.radio_value(&mut app.panels.decoder.output_hex_view, true, "Hex");
                hex.widget_info(|| {
                    eframe::egui::WidgetInfo::selected(
                        eframe::egui::WidgetType::RadioButton,
                        true,
                        app.panels.decoder.output_hex_view,
                        "Output Hex",
                    )
                });
            });
            ui.add_space(4.0);
            if ui
                .add_sized(
                    [right_col_w, 24.0],
                    eframe::egui::Button::new("Output → Input"),
                )
                .clicked()
            {
                app.panels.decoder.input = app.panels.decoder.output.clone();
                apply(app);
            }
            if ui
                .add_sized(
                    [right_col_w, 24.0],
                    eframe::egui::Button::new("Copy output"),
                )
                .clicked()
            {
                ui.ctx().copy_text(app.panels.decoder.output.clone());
                app.status = "Copied Decoder output".into();
            }
            if ui
                .add_sized([right_col_w, 24.0], eframe::egui::Button::new("Clear"))
                .clicked()
            {
                app.panels.decoder.input.clear();
                app.panels.decoder.output.clear();
            }
        });
    });

    super::horizontal_resize_handle(
        ui,
        &theme,
        "decoder-output-resize",
        &mut app.panels.decoder.output_height,
        100.0,
        480.0,
        170.0,
    );
}

fn decoder_context_menu(app: &mut App, trigger: &eframe::egui::Response) {
    super::show_persistent_context_menu(trigger, |ui| {
        if ui.button("Smart decode").clicked() {
            app.panels.decoder.custom = true;
            apply(app);
            ui.close();
        }
        ui.separator();
        for (label, op_name) in [
            ("URL decode", "URL decode"),
            ("URL encode", "URL encode"),
            ("Base64 decode", "Base64 decode"),
            ("Base64 encode", "Base64 encode"),
            ("HTML decode", "HTML decode"),
            ("HTML encode", "HTML encode"),
            ("Hex decode", "Hex decode"),
            ("Hex encode", "Hex encode"),
            ("Hash: SHA-256", "Hash: SHA-256"),
        ] {
            if ui.button(label).clicked() {
                run_named_op(app, op_name);
                ui.close();
            }
        }
        ui.separator();
        if !app.panels.decoder.output.is_empty() && ui.button("Output → Input").clicked() {
            app.panels.decoder.input = app.panels.decoder.output.clone();
            apply(app);
            ui.close();
        }
        if ui.button("Send to Comparer").clicked() {
            let val = if !app.panels.decoder.output.is_empty() {
                app.panels.decoder.output.clone()
            } else {
                app.panels.decoder.input.clone()
            };
            if app.panels.comparer.left.trim().is_empty() {
                app.panels.comparer.left = val;
            } else {
                app.panels.comparer.right = val;
            }
            app.tool = crate::ui::app::COMPARER;
            app.view = 0;
            ui.close();
        }
        if ui.button("Copy output").clicked() {
            ui.ctx().copy_text(app.panels.decoder.output.clone());
            ui.close();
        }
        if ui.button("Clear").clicked() {
            app.panels.decoder.input.clear();
            app.panels.decoder.output.clear();
            ui.close();
        }
    });
}

pub(crate) fn apply(app: &mut App) {
    let ops = logic::decoder_ops();
    let input = app.panels.decoder.input.clone();
    let result = if app.panels.decoder.custom {
        let mut current = input;
        for _ in 0..8 {
            let Some(op) = logic::magic_decode(&current).and_then(logic::find_op) else {
                break;
            };
            let Ok(next) = (op.run)(&current) else {
                break;
            };
            if next == current {
                break;
            };
            current = next;
        }
        Ok(current)
    } else {
        match ops.get(app.panels.decoder.op) {
            Some(op) => (op.run)(&input),
            None => Err("unknown operation".to_string()),
        }
    };
    match result {
        Ok(value) => {
            app.panels.decoder.output = value;
            app.status = "Decoded".into();
        }
        Err(error) => {
            app.panels.decoder.output = String::new();
            app.status = format!("Decode failed: {error}");
        }
    }
}
