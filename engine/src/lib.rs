//! Gulpsuite core: the proxy, the scanner, and the analysis primitives the tools share.

pub mod analysis;
pub mod browser;
pub mod installer;
#[cfg(target_os = "macos")]
pub mod macos_menu;
pub mod platform_paths;
pub mod bambda;
pub mod automaton;
pub mod collaborator;
pub mod discover;
pub mod dns;
pub mod cookies;
pub mod logic;
pub mod http_target;
pub mod intruder;
pub mod issue_definitions;
pub mod meminfo;
pub mod project;
pub mod proxy;
pub mod ws;
pub mod replay;
pub mod scanner;
pub mod tls;
pub mod ui;
pub mod updater;
pub mod workspace;

/// Official 64×64 RGBA icon bytes for Gulpsuite (orange `#F56700` rounded square with white serif `"g"`).
pub const APP_ICON_64_RGBA: &[u8] = include_bytes!("../assets/icon_64.rgba");

/// Returns `eframe::egui::IconData` for attaching the official Gulpsuite icon to native OS windows.
pub fn app_icon() -> std::sync::Arc<eframe::egui::IconData> {
    std::sync::Arc::new(eframe::egui::IconData {
        rgba: APP_ICON_64_RGBA.to_vec(),
        width: 64,
        height: 64,
    })
}

/// Paints the official Gulpsuite logo badge at `size × size` points inside `ui`.
pub fn paint_gulp_logo(ui: &mut eframe::egui::Ui, size: f32) -> eframe::egui::Response {
    use eframe::egui::{ColorImage, TextureHandle, TextureOptions, Vec2};
    let tex_id = eframe::egui::Id::new("gulpsuite_official_logo_tex");
    let handle: TextureHandle = ui
        .ctx()
        .data_mut(|d| d.get_temp::<TextureHandle>(tex_id))
        .unwrap_or_else(|| {
            let img = ColorImage::from_rgba_unmultiplied([64, 64], APP_ICON_64_RGBA);
            let h = ui
                .ctx()
                .load_texture("gulpsuite-logo-64", img, TextureOptions::LINEAR);
            ui.ctx().data_mut(|d| d.insert_temp(tex_id, h.clone()));
            h
        });
    ui.add(eframe::egui::Image::from_texture((
        handle.id(),
        Vec2::splat(size),
    )))
}
