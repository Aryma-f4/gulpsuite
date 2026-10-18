//! Decoder: transform the input with a named operation.

use eframe::egui::Ui;

use super::heading;
use crate::logic;
use crate::ui::app::App;

#[derive(Clone)]
pub struct DecoderPanel {
    pub input: String,
    pub output: String,
    pub op: usize,
    pub custom: bool,
}

impl Default for DecoderPanel {
    fn default() -> Self {
        DecoderPanel {
            input: String::new(),
            output: String::new(),
            op: 0,
            custom: false,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Decoder");

    ui.horizontal(|ui| {
        eframe::egui::ComboBox::from_id_salt("decoder-op")
            .selected_text(ops_label(&app.panels.decoder))
            .show_ui(ui, |ui| {
                for (index, op) in logic::decoder_ops().iter().enumerate() {
                    let label = if index + 1 == logic::decoder_ops().len() {
                        format!("{} (custom)", op.name)
                    } else {
                        op.name.to_string()
                    };
                    ui.selectable_value(
                        &mut app.panels.decoder.op,
                        index,
                        label,
                    );
                }
            });
        let mut custom = app.panels.decoder.custom;
        if ui.checkbox(&mut custom, "From list").on_hover_text("Decode Burp's magic finds automatically").changed() {
            if custom {
                app.panels.decoder.output =
                    logic::magic_decode(&app.panels.decoder.input).unwrap_or_default().to_string();
                app.panels.decoder.op = last_index();
            }
        }
        app.panels.decoder.custom = custom;
        if ui.button("Transform").clicked() {
            apply(app);
        }
    });

    ui.add_space(4.0);
    let available = ui.available_height();
    ui.columns(2, |columns| {
        columns[0].label("Input");
        eframe::egui::ScrollArea::vertical()
            .max_height(available - 30.0)
            .show(&mut columns[0], |ui| {
                ui.add(
                    eframe::egui::TextEdit::multiline(&mut app.panels.decoder.input)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );
            });
        columns[1].label("Output");
        eframe::egui::ScrollArea::vertical()
            .max_height(available - 30.0)
            .show(&mut columns[1], |ui| {
                ui.label(
                    eframe::egui::RichText::new(&app.panels.decoder.output)
                        .monospace()
                        .color(theme.color("ui.text.body")),
                );
            });
    });
}

fn last_index() -> usize {
    logic::decoder_ops().len().saturating_sub(1)
}

fn ops_label(panel: &DecoderPanel) -> String {
    let ops = logic::decoder_ops();
    if panel.custom || panel.op >= ops.len() {
        return "Auto (magic)".into();
    }
    ops[panel.op].name.to_string()
}

pub(crate) fn apply(app: &mut App) {
    let ops = logic::decoder_ops();
    let input = app.panels.decoder.input.clone();
    let result = if app.panels.decoder.custom {
        Ok(logic::magic_decode(&input).unwrap_or_default().to_string())
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
