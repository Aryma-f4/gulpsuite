//! Gulpsuite: the app itself.
//!
//! The proxy runs on Tokio threads inside this process and is driven directly by the UI, so there
//! is no subprocess and no wire protocol between them.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use gulpsuite::ui::app::App;

fn main() -> eframe::Result<()> {
    let title = format!("Gulpsuite v{} — Temporary Project", env!("CARGO_PKG_VERSION"));
    let options = eframe::NativeOptions {
        multisampling: 4,
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1360.0, 820.0])
            .with_min_inner_size([860.0, 540.0])
            .with_title(title.clone())
            .with_icon(gulpsuite::app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        &title,
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
