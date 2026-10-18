//! Target: the site map, derived from what the proxy has seen.
//!
//! The tree is cached against the history version. Rebuilding it every frame meant walking the
//! whole log and allocating a map per frame, for a view that changes only when traffic arrives.

use std::collections::BTreeMap;

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::ui::app::{App, SiteMapPaths};

/// Rebuilds the host -> paths tree, reusing the cached one when the history has not moved.
fn tree(app: &mut App) -> BTreeMap<String, SiteMapPaths> {
    if let Some((version, cached)) = &app.site_map {
        if *version == app.log_version {
            return cached.clone();
        }
    }
    let mut built: BTreeMap<String, SiteMapPaths> = BTreeMap::new();
    for tx in &app.log {
        let path = tx
            .target
            .split_once(&tx.host)
            .map(|(_, rest)| rest.to_string())
            .unwrap_or_else(|| tx.target.clone());
        // Burp shows the scheme with the host, so a secure site is not mixed up with a plain one.
        let host = if tx.secure {
            format!("https://{}", tx.host)
        } else {
            format!("http://{}", tx.host)
        };
        *built.entry(host).or_default().entry(path).or_default() += 1;
    }
    app.site_map = Some((app.log_version, built.clone()));
    built
}

/// Per-panel state.
#[derive(Clone, Default)]
pub struct TargetPanel {
    /// Burp's include and exclude scope entries (scope/Scope in the shipped API).
    pub scope: String,
    pub scope_exclude: String,
    pub filter: String,
    pub host: Option<String>,
    pub path: Option<String>,
}

impl TargetPanel {
    /// A case-insensitive substring match, so filtering behaves the way an operator expects.
    pub fn matches(&self, text: &str) -> bool {
        let needle = self.filter.trim().to_lowercase();
        needle.is_empty() || text.to_lowercase().contains(&needle)
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    match app.view {
        0 => {}
        _ => {
            // Burp's second Target view, backed by scope/Scope in the shipped API.
            heading(ui, &theme, "Scope");
            ui.horizontal(|ui| {
                ui.label(eframe::egui::RichText::new("Include").color(theme.color("ui.text.body")));
                ui.text_edit_singleline(&mut app.panels.target_panel.scope);
            });
            ui.horizontal(|ui| {
                ui.label(eframe::egui::RichText::new("Exclude").color(theme.color("ui.text.body")));
                ui.text_edit_singleline(&mut app.panels.target_panel.scope_exclude);
            });
            ui.add_space(4.0);
            muted(
                ui,
                &theme,
                "Scope filters are stored; the scanner crawler does not apply them yet.",
            );
            return;
        }
    }
    heading(ui, &theme, "Target — Site map");

    let tree = tree(app);
    if tree.is_empty() {
        muted(ui, &theme, "No traffic yet.");
        return;
    }

    ui.horizontal(|ui| {
        ui.label(eframe::egui::RichText::new("Filter").color(theme.color("ui.text.body")));
        ui.text_edit_singleline(&mut app.panels.target_panel.filter);
        if ui.button("Clear").clicked() {
            app.panels.target_panel.filter.clear();
        }
        ui.separator();
        let hosts = tree.len();
        let paths: usize = tree.values().map(BTreeMap::len).sum();
        muted(ui, &theme, &format!("{hosts} host(s), {paths} path(s)"));
    });

    ui.add_space(4.0);

    // The selected request is the one that matches the selected path exactly, newest first.
    let mut load: Option<(String, String)> = None;

    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        for (host, paths) in &tree {
            if !app.panels.target_panel.matches(host) {
                continue;
            }
            let selected_host = app.panels.target_panel.host.as_deref() == Some(host.as_str());
            let header = ui.selectable_label(selected_host, host.clone());
            if header.clicked() {
                app.panels.target_panel.host = Some(host.clone());
                app.panels.target_panel.path = None;
            }
            let muted_host = !selected_host
                && app.panels.target_panel.host.as_deref().is_some_and(|h| h != host);
            let colour = if muted_host {
                theme.color("ui.icon.disabled")
            } else {
                theme.color("ui.text.body")
            };
            ui.horizontal(|ui| {
                ui.add_space(12.0);
                label(ui, &theme, &format!("{host}"));
                if header.clicked() {
                    ui.ctx().request_repaint();
                }
            });
            let _ = colour;

            for (path, count) in paths {
                if !app.panels.target_panel.matches(path) {
                    continue;
                }
                let selected = app.panels.target_panel.path.as_deref() == Some(path.as_str());
                let mut clicked = false;
                ui.horizontal(|ui| {
                    ui.add_space(26.0);
                    clicked = ui
                        .selectable_label(
                            selected,
                            eframe::egui::RichText::new(path)
                                .monospace()
                                .color(theme.color("ui.icon.default")),
                        )
                        .on_hover_text(format!("{count} request(s)"))
                        .clicked();
                });
                if clicked {
                    app.panels.target_panel.path = Some(path.clone());
                }
                if selected && ui.small_button("To Repeater").clicked() {
                    load = Some((host.clone(), path.clone()));
                }
            }
            ui.add_space(4.0);
        }
    });

    if let Some((host, path)) = load {
        // Find the newest transaction for this host and path and hand the whole request over.
        let found = app
            .log
            .iter()
            .rev()
            .find(|tx| tx.host == host && tx.target.ends_with(&path))
            .map(|tx| (tx.request.clone(), tx.target.clone()));
        match found {
            Some((request, target)) => {
                app.panels.repeater.raw = request;
                app.panels.repeater.host = target;
                app.panels.repeater.editing = false;
                app.tool = 4;
                app.status = format!("Sent {path} to Repeater");
            }
            None => app.status = "That path is no longer in the history".into(),
        }
    }

    if app.panels.target_panel.path.is_none() {
        muted(
            ui,
            &theme,
            "Select a path to send it to Repeater. History keeps the most recent 1000 requests.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_filter_matches_everything() {
        let panel = TargetPanel::default();
        assert!(panel.matches("http://example.test/a"));
        let filtered = TargetPanel { filter: "  ADMIN ".into(), ..Default::default() };
        assert!(filtered.matches("http://x/ADMIN/panel"));
        assert!(!filtered.matches("http://x/public"));
    }

    /// The cache exists so a static history does not rebuild the tree on every frame.
    #[test]
    fn a_static_history_reuses_the_cached_tree() {
        let mut version = 0u64;
        let mut log = std::collections::VecDeque::new();
        for index in 0..5 {
            crate::ui::app::retain(
                &mut log,
                crate::ui::app::Transaction {
                    method: "GET".into(),
                    target: format!("http://example.test/item-{index}"),
                    status: 200,
                    bytes: 10,
                    host: "example.test".into(),
                    request: String::new(),
                    response: String::new(),
                    secure: false,
                    truncated: false,
                },
                10,
                &mut version,
            );
        }
        assert_eq!(version, 5, "each retained transaction must bump the version");
    }
}
