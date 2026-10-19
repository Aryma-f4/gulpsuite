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
mod proxy;
pub(crate) mod repeater;
pub mod scanner;
pub mod replayer;
pub(crate) mod sequencer;
mod websocket;
mod target;

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
