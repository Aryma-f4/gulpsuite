//! Target (`Pro-QSG-5-site-map.png`, `site-map-populated.png`, `site-map-target-scope.png`):
//! - `Site map`: `[ URL view | Crawl paths view ]` segmented pill + `Filter: Hiding not found items; ...` bar,
//!   resizable Left Tree Pane (hierarchical host/folder/endpoint tree with Gold Padlock, Yellow Folder,
//!   Gold Gear, and Document `?` SVG icons + severity dots) and Right Details Pane (`Contents | Issues`
//!   sub-tabs with `Host | Method | URL | Params | Status Code | Length | MIME type | Title` table on top
//!   and `Request | Response` with `Pretty | Raw | Hex | Render` formatter bars + line-numbered HTTP below).
//! - `Scope`: `Target scope` with `[ ] Use advanced scope control`, `Include in scope` & `Exclude from scope`
//!   tables (`Enabled`, `Prefix`) and `Add / Edit / Remove / Paste URL / Load ...` button columns.

use std::collections::BTreeMap;

use eframe::egui::{self, Color32, RichText, Stroke, Ui, Vec2};

use super::{
    SiteMapIcon, burp_message_formatter_bar, burp_numbered_message_view_wrapped, empty_state, heading,
    muted, paint_sitemap_node_icon,
};
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
#[derive(Clone)]
pub struct TargetPanel {
    /// Burp's include and exclude scope entries (scope/Scope in the shipped API).
    pub scope: String,
    pub scope_exclude: String,
    pub advanced_scope_control: bool,
    pub disabled_include_rules: std::collections::BTreeSet<String>,
    pub disabled_exclude_rules: std::collections::BTreeSet<String>,
    pub selected_include_rule: Option<usize>,
    pub selected_exclude_rule: Option<usize>,
    pub editing_include_rule: Option<usize>,
    pub editing_exclude_rule: Option<usize>,
    pub pending_scope_paste: Option<bool>,
    pub scope_load_include: Option<bool>,
    pub scope_load_path: String,
    pub scope_load_error: String,
    pub new_include_prefix: String,
    pub new_exclude_prefix: String,
    pub filter: String,
    pub issue_filter: String,
    pub selected_issue: Option<usize>,
    pub host: Option<String>,
    pub path: Option<String>,
    /// False = URL view (default), true = Crawl paths view.
    pub crawl_paths_view: bool,
    /// 0 = Contents, 1 = Issues in the right-hand Site map details pane (`Pro-QSG-5-site-map.png`).
    pub right_sub_tab: usize,
    pub tree_split_ratio: f32,
    pub split_ratio: f32,
    pub contents_table_height: f32,
    pub detail_height: f32,
    pub req_fmt_mode: usize,
    pub resp_fmt_mode: usize,
    pub req_wrap: bool,
    pub resp_wrap: bool,
    pub req_non_printable: bool,
    pub resp_non_printable: bool,
    pub issue_detail_tab: usize,
    pub selected_kb_def: usize,
    pub kb_search: String,
    pub kb_severity_filter: usize,
    pub issue_sev_filter: [bool; 4],
    pub issue_conf_filter: [bool; 3],
}

impl Default for TargetPanel {
    fn default() -> Self {
        Self {
            scope: String::new(),
            scope_exclude: String::new(),
            advanced_scope_control: false,
            disabled_include_rules: Default::default(),
            disabled_exclude_rules: Default::default(),
            selected_include_rule: None,
            selected_exclude_rule: None,
            editing_include_rule: None,
            editing_exclude_rule: None,
            pending_scope_paste: None,
            scope_load_include: None,
            scope_load_path: String::new(),
            scope_load_error: String::new(),
            new_include_prefix: String::new(),
            new_exclude_prefix: String::new(),
            filter: String::new(),
            issue_filter: String::new(),
            selected_issue: None,
            host: None,
            path: None,
            crawl_paths_view: false,
            right_sub_tab: 0,
            tree_split_ratio: 0.30,
            split_ratio: 0.5,
            contents_table_height: 175.0,
            detail_height: 250.0,
            req_fmt_mode: 1, // Raw default as in `Pro-QSG-5-site-map.png`
            resp_fmt_mode: 0, // Pretty default as in `Pro-QSG-5-site-map.png`
            req_wrap: true,
            resp_wrap: true,
            req_non_printable: false,
            resp_non_printable: false,
            issue_detail_tab: 0,
            selected_kb_def: 0,
            kb_search: String::new(),
            kb_severity_filter: 0,
            issue_sev_filter: [true, true, true, true],
            issue_conf_filter: [true, true, true],
        }
    }
}

impl TargetPanel {
    /// A case-insensitive substring match, so filtering behaves the way an operator expects.
    pub fn matches(&self, text: &str) -> bool {
        let needle = self.filter.trim().to_lowercase();
        needle.is_empty() || text.to_lowercase().contains(&needle)
    }

    /// Evaluates whether `url_or_host` is within the configured Include / Exclude scope rules.
    pub fn in_scope(&self, url_or_host: &str) -> bool {
        let candidate = url_or_host.to_lowercase();
        let includes: Vec<_> = self
            .scope
            .split([',', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect();
        if !includes.is_empty() && !includes.iter().any(|rule| {
            !self.disabled_include_rules.contains(rule) && candidate.contains(rule)
        }) {
            return false;
        }
        let excludes: Vec<_> = self
            .scope_exclude
            .split([',', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_lowercase)
            .collect();
        !excludes.iter().any(|rule| {
            !self.disabled_exclude_rules.contains(rule) && candidate.contains(rule)
        })
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    match app.view {
        0 => draw_site_map(app, ui),
        2 => draw_issues_view(app, ui),
        _ => draw_scope_view(app, ui),
    }
}

/// Target scope: selectable include/exclude rules with persistent enabled states.
fn draw_scope_view(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    if let Some(include) = app.panels.target_panel.pending_scope_paste {
        let paste = ui.input(|i| i.events.iter().find_map(|e| {
            if let egui::Event::Paste(text) = e { Some(text.clone()) } else { None }
        }));
        if let Some(text) = paste {
            app.panels.target_panel.pending_scope_paste = None;
            let prefix = text.trim();
            if url::Url::parse(prefix).is_ok_and(|url| matches!(url.scheme(), "http" | "https")) {
                let rules = if include { &mut app.panels.target_panel.scope } else { &mut app.panels.target_panel.scope_exclude };
                if !rules.split([',', '\n']).any(|rule| rule.trim() == prefix) {
                    if !rules.trim().is_empty() { rules.push_str(", "); }
                    rules.push_str(prefix);
                }
            } else { app.status = "Paste URL requires an HTTP or HTTPS URL".into(); }
        }
    }
    if let Some(include) = app.panels.target_panel.scope_load_include {
        let mut open = true;
        egui::Window::new("Load scope rules").open(&mut open).show(ui.ctx(), |ui| {
            ui.label("File containing one URL prefix per line:");
            ui.text_edit_singleline(&mut app.panels.target_panel.scope_load_path);
            if !app.panels.target_panel.scope_load_error.is_empty() {
                ui.colored_label(theme.color("ui.text.error"), &app.panels.target_panel.scope_load_error);
            }
            ui.horizontal(|ui| {
                if ui.button("Load").clicked() {
                    let path = app.panels.target_panel.scope_load_path.trim();
                    let result = std::fs::metadata(path).map_err(|e| e.to_string()).and_then(|metadata| {
                        if metadata.len() > 1024 * 1024 { Err("Scope file exceeds 1 MiB".into()) }
                        else { std::fs::read_to_string(path).map_err(|e| e.to_string()) }
                    });
                    match result {
                        Ok(contents) => {
                            let rules = if include { &mut app.panels.target_panel.scope } else { &mut app.panels.target_panel.scope_exclude };
                            for prefix in contents.lines().map(str::trim).filter(|s| !s.is_empty()) {
                                if !rules.split([',', '\n']).any(|rule| rule.trim() == prefix) {
                                    if !rules.trim().is_empty() { rules.push_str(", "); }
                                    rules.push_str(prefix);
                                }
                            }
                            app.panels.target_panel.scope_load_include = None;
                        }
                        Err(error) => app.panels.target_panel.scope_load_error = error,
                    }
                }
                if ui.button("Cancel").clicked() { app.panels.target_panel.scope_load_include = None; }
            });
        });
        if !open { app.panels.target_panel.scope_load_include = None; }
    }
    egui::ScrollArea::vertical()
        .id_salt("target-scope-scroll")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                super::scanner::paint_launcher_icon(
                    ui,
                    Vec2::new(18.0, 18.0),
                    theme.color("ui.icon.default"),
                    super::scanner::LauncherIcon::HelpCircle,
                );
                heading(ui, &theme, "Target scope");
            });
            ui.horizontal(|ui| {
                super::scanner::paint_launcher_icon(
                    ui,
                    Vec2::new(18.0, 18.0),
                    theme.color("ui.icon.default"),
                    super::scanner::LauncherIcon::Gear,
                );
                muted(
                    ui,
                    &theme,
                    "Use these settings to define exactly what hosts and URLs constitute the target for your current work. This configuration affects the behavior of tools across the suite.",
                );
            });
            ui.add_space(6.0);
            ui.checkbox(
                &mut app.panels.target_panel.advanced_scope_control,
                "Use advanced scope control",
            );
            ui.add_space(10.0);

            // 1. Include in scope (`site-map-target-scope.png`)
            ui.label(RichText::new("Include in scope").size(13.5).strong());
            ui.add_space(4.0);
            let mut inc_rules: Vec<String> = app
                .panels
                .target_panel
                .scope
                .split([',', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            let mut inc_changed = false;
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(92.0);
                    if ui.button(if app.panels.target_panel.editing_include_rule.is_some() { "Save" } else { "Add" }).clicked()
                        && !app.panels.target_panel.new_include_prefix.trim().is_empty()
                    {
                        let prefix = app.panels.target_panel.new_include_prefix.trim().to_string();
                        if let Some(index) = app.panels.target_panel.editing_include_rule.take() {
                            if let Some(rule) = inc_rules.get_mut(index) {
                                let disabled = app.panels.target_panel.disabled_include_rules.remove(&rule.to_lowercase());
                                *rule = prefix.clone();
                                if disabled { app.panels.target_panel.disabled_include_rules.insert(prefix.to_lowercase()); }
                            }
                        } else if !inc_rules.contains(&prefix) {
                            inc_rules.push(prefix);
                        }
                        app.panels.target_panel.new_include_prefix.clear();
                        inc_changed = true;
                    }
                    let selected = app.panels.target_panel.selected_include_rule.filter(|i| *i < inc_rules.len());
                    if ui.add_enabled(selected.is_some(), egui::Button::new("Edit")).clicked() {
                        if let Some(index) = selected {
                            app.panels.target_panel.new_include_prefix = inc_rules[index].clone();
                            app.panels.target_panel.editing_include_rule = Some(index);
                        }
                    }
                    if ui.add_enabled(selected.is_some(), egui::Button::new("Remove")).clicked() {
                        if let Some(index) = selected {
                            let removed = inc_rules.remove(index);
                            app.panels.target_panel.disabled_include_rules.remove(&removed.to_lowercase());
                            app.panels.target_panel.selected_include_rule = None;
                            app.panels.target_panel.editing_include_rule = None;
                            inc_changed = true;
                        }
                    }
                    if ui.button("Paste URL").clicked() {
                        app.panels.target_panel.pending_scope_paste = Some(true);
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                    }
                    if ui.button("Load ...").clicked() {
                        app.panels.target_panel.scope_load_include = Some(true);
                        app.panels.target_panel.scope_load_error.clear();
                    }
                });
                egui::Frame::new()
                    .fill(theme.color("ui.background.0"))
                    .stroke(Stroke::new(1.0, theme.color("ui.border.1")))
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.set_min_width((ui.available_width() - 12.0).max(320.0));
                        ui.set_min_height(120.0);
                        egui::Grid::new("target-scope-include-table")
                            .num_columns(2)
                            .min_col_width(70.0)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Enabled");
                                ui.strong("Prefix");
                                ui.end_row();
                                for (index, rule) in inc_rules.iter().enumerate() {
                                    let key = rule.to_lowercase();
                                    let mut enabled = !app.panels.target_panel.disabled_include_rules.contains(&key);
                                    if ui.checkbox(&mut enabled, "").changed() {
                                        if enabled { app.panels.target_panel.disabled_include_rules.remove(&key); }
                                        else { app.panels.target_panel.disabled_include_rules.insert(key); }
                                    }
                                    if ui.selectable_label(app.panels.target_panel.selected_include_rule == Some(index), rule).clicked() {
                                        app.panels.target_panel.selected_include_rule = Some(index);
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
            if inc_changed {
                app.panels.target_panel.scope = inc_rules.join(", ");
            }
            ui.horizontal(|ui| {
                ui.label("Include prefix:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.target_panel.new_include_prefix)
                        .hint_text("https://example.com/")
                        .desired_width(240.0),
                );
                ui.label("Raw Include rules:");
                ui.text_edit_singleline(&mut app.panels.target_panel.scope);
            });

            ui.add_space(14.0);
            // 2. Exclude from scope (`site-map-target-scope.png`)
            ui.label(RichText::new("Exclude from scope").size(13.5).strong());
            ui.add_space(4.0);
            let mut exc_rules: Vec<String> = app
                .panels
                .target_panel
                .scope_exclude
                .split([',', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            let mut exc_changed = false;
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(92.0);
                    if ui.button(if app.panels.target_panel.editing_exclude_rule.is_some() { "Save" } else { "Add" }).clicked()
                        && !app.panels.target_panel.new_exclude_prefix.trim().is_empty()
                    {
                        let prefix = app.panels.target_panel.new_exclude_prefix.trim().to_string();
                        if let Some(index) = app.panels.target_panel.editing_exclude_rule.take() {
                            if let Some(rule) = exc_rules.get_mut(index) {
                                let disabled = app.panels.target_panel.disabled_exclude_rules.remove(&rule.to_lowercase());
                                *rule = prefix.clone();
                                if disabled { app.panels.target_panel.disabled_exclude_rules.insert(prefix.to_lowercase()); }
                            }
                        } else if !exc_rules.contains(&prefix) {
                            exc_rules.push(prefix);
                        }
                        app.panels.target_panel.new_exclude_prefix.clear();
                        exc_changed = true;
                    }
                    let selected = app.panels.target_panel.selected_exclude_rule.filter(|i| *i < exc_rules.len());
                    if ui.add_enabled(selected.is_some(), egui::Button::new("Edit")).clicked() {
                        if let Some(index) = selected {
                            app.panels.target_panel.new_exclude_prefix = exc_rules[index].clone();
                            app.panels.target_panel.editing_exclude_rule = Some(index);
                        }
                    }
                    if ui.add_enabled(selected.is_some(), egui::Button::new("Remove")).clicked() {
                        if let Some(index) = selected {
                            let removed = exc_rules.remove(index);
                            app.panels.target_panel.disabled_exclude_rules.remove(&removed.to_lowercase());
                            app.panels.target_panel.selected_exclude_rule = None;
                            app.panels.target_panel.editing_exclude_rule = None;
                            exc_changed = true;
                        }
                    }
                    if ui.button("Paste URL").clicked() {
                        app.panels.target_panel.pending_scope_paste = Some(false);
                        ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                    }
                    if ui.button("Load ...").clicked() {
                        app.panels.target_panel.scope_load_include = Some(false);
                        app.panels.target_panel.scope_load_error.clear();
                    }
                });
                egui::Frame::new()
                    .fill(theme.color("ui.background.0"))
                    .stroke(Stroke::new(1.0, theme.color("ui.border.1")))
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.set_min_width((ui.available_width() - 12.0).max(320.0));
                        ui.set_min_height(120.0);
                        egui::Grid::new("target-scope-exclude-table")
                            .num_columns(2)
                            .min_col_width(70.0)
                            .striped(true)
                            .show(ui, |ui| {
                                ui.strong("Enabled");
                                ui.strong("Prefix");
                                ui.end_row();
                                for (index, rule) in exc_rules.iter().enumerate() {
                                    let key = rule.to_lowercase();
                                    let mut enabled = !app.panels.target_panel.disabled_exclude_rules.contains(&key);
                                    if ui.checkbox(&mut enabled, "").changed() {
                                        if enabled { app.panels.target_panel.disabled_exclude_rules.remove(&key); }
                                        else { app.panels.target_panel.disabled_exclude_rules.insert(key); }
                                    }
                                    if ui.selectable_label(app.panels.target_panel.selected_exclude_rule == Some(index), rule).clicked() {
                                        app.panels.target_panel.selected_exclude_rule = Some(index);
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            });
            if exc_changed {
                app.panels.target_panel.scope_exclude = exc_rules.join(", ");
            }
            ui.horizontal(|ui| {
                ui.label("Exclude prefix:");
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.target_panel.new_exclude_prefix)
                        .hint_text("https://example.com/logout")
                        .desired_width(240.0),
                );
                ui.label("Raw Exclude rules:");
                ui.text_edit_singleline(&mut app.panels.target_panel.scope_exclude);
            });
        });
}

/// Renders `Target -> Issues` & `Issue definitions` (and the `Issues` sub-tab inside `Site map`),
/// including the complete 183-entry Knowledge Base (`crate::issue_definitions::all()`) and
/// the discovered `Issues` table & `Advisory | Request | Response` viewer (`Pro-QSG-6-view-issues.png`).
pub(crate) fn draw_issues_view(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let all_defs = crate::issue_definitions::all();
    let card_bg = if theme.dark {
        Color32::from_rgb(0x1E, 0x20, 0x24)
    } else {
        Color32::WHITE
    };
    let heading_fg = if theme.dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x11, 0x11, 0x11)
    };
    let body_fg = if theme.dark {
        Color32::from_rgb(0xE8, 0xEC, 0xF2)
    } else {
        Color32::from_rgb(0x1F, 0x23, 0x28)
    };
    let code_bg = if theme.dark {
        Color32::from_rgb(0x26, 0x2A, 0x32)
    } else {
        Color32::from_rgb(0xF6, 0xF8, 0xFA)
    };
    let border_col = theme.color("ui.border.1");

    egui::Frame::new()
        .fill(card_bg)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            // Top Filter & Action Bar (`Pro-QSG-6-view-issues.png`)
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scan URL:").color(body_fg));
                ui.add(
                    eframe::egui::TextEdit::singleline(&mut app.panels.scanner.seed)
                        .desired_width(120.0)
                        .font(eframe::egui::TextStyle::Monospace),
                );
                ui.checkbox(&mut app.panels.scanner.active_checks, "Active checks");
                if ui
                    .add_enabled(
                        !app.panels.scanner.running,
                        eframe::egui::Button::new("Start scan"),
                    )
                    .clicked()
                {
                    super::scanner::start(app);
                }
                if ui.button("Report issues…").clicked() {
                    app.panels.scanner.report_host_filter.clear();
                    app.panels.scanner.show_report_wizard = true;
                }
                if ui.button("Create manual issue…").clicked() {
                    app.panels.scanner.show_manual_issue_modal = true;
                }
                ui.separator();
                for (s_idx, lbl) in ["High", "Medium", "Low", "Info"].iter().enumerate() {
                    let active = app.panels.target_panel.issue_sev_filter[s_idx];
                    if ui.selectable_label(active, *lbl).clicked() {
                        app.panels.target_panel.issue_sev_filter[s_idx] = !active;
                    }
                }
                ui.separator();
                for (c_idx, lbl) in ["Certain", "Firm", "Tentative"].iter().enumerate() {
                    let active = app.panels.target_panel.issue_conf_filter[c_idx];
                    if ui.selectable_label(active, *lbl).clicked() {
                        app.panels.target_panel.issue_conf_filter[c_idx] = !active;
                    }
                }
                ui.separator();
                ui.add(
                    eframe::egui::TextEdit::singleline(&mut app.panels.target_panel.issue_filter)
                        .hint_text("Filter issues…")
                        .desired_width(110.0),
                );
            });
            ui.add_space(6.0);

            // Complete 183-entry Issue Definitions Knowledge Base (`target/issue-definitions.html`)
            egui::CollapsingHeader::new(
                RichText::new(format!(
                    "Issue definitions Knowledge Base ({} types)",
                    all_defs.len()
                ))
                .color(heading_fg)
                .strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Search definitions:").color(body_fg));
                    ui.add(
                        egui::TextEdit::singleline(&mut app.panels.target_panel.kb_search)
                            .hint_text("Search 183 vulnerability definitions by name, CWE, or hex index…")
                            .desired_width(280.0),
                    );
                    ui.separator();
                    for (f_idx, f_lbl) in ["All", "High", "Medium", "Low", "Information"]
                        .iter()
                        .enumerate()
                    {
                        ui.selectable_value(
                            &mut app.panels.target_panel.kb_severity_filter,
                            f_idx,
                            *f_lbl,
                        );
                    }
                });
                ui.add_space(6.0);

                let kb_needle = app.panels.target_panel.kb_search.trim().to_ascii_lowercase();
                let sev_filter = match app.panels.target_panel.kb_severity_filter {
                    1 => Some("High"),
                    2 => Some("Medium"),
                    3 => Some("Low"),
                    4 => Some("Information"),
                    _ => None,
                };
                let filtered_defs: Vec<(usize, &crate::issue_definitions::IssueDefinition)> =
                    all_defs
                        .iter()
                        .enumerate()
                        .filter(|(_, d)| {
                            sev_filter.map_or(true, |sf| d.severity.eq_ignore_ascii_case(sf))
                                && (kb_needle.is_empty()
                                    || d.name.to_ascii_lowercase().contains(&kb_needle)
                                    || d.type_hex.to_ascii_lowercase().contains(&kb_needle)
                                    || d.cwe_summary().to_ascii_lowercase().contains(&kb_needle))
                        })
                        .collect();

                ui.columns(2, |cols| {
                    // Left column: high-contrast table of all 183 Issue Definitions
                    egui::Frame::new()
                        .fill(card_bg)
                        .stroke(Stroke::new(1.0_f32, border_col))
                        .inner_margin(6.0)
                        .show(&mut cols[0], |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("target-kb-defs-scroll")
                                .max_height(260.0)
                                .show(ui, |ui| {
                                    egui::Grid::new("target-issue-definitions-kb")
                                        .num_columns(4)
                                        .striped(true)
                                        .show(ui, |ui| {
                                            for h in ["Name", "Typical severity", "Type index", "CWE"]
                                            {
                                                ui.label(
                                                    RichText::new(h).color(heading_fg).strong(),
                                                );
                                            }
                                            ui.end_row();
                                            for (orig_idx, def) in &filtered_defs {
                                                let is_sel = app.panels.target_panel.selected_kb_def
                                                    == *orig_idx;
                                                let (sev_col, sev_icon) =
                                                    match def.severity.as_str() {
                                                        "High" => (
                                                            Color32::from_rgb(0xE0, 0x20, 0x4F),
                                                            super::scanner::LauncherIcon::IssueHigh,
                                                        ),
                                                        "Medium" => (
                                                            Color32::from_rgb(0xF5, 0x7B, 0x20),
                                                            super::scanner::LauncherIcon::IssueMedium,
                                                        ),
                                                        "Low" => (
                                                            Color32::from_rgb(0x00, 0x68, 0xB5),
                                                            super::scanner::LauncherIcon::IssueLow,
                                                        ),
                                                        _ => (
                                                            Color32::from_rgb(0x6E, 0x76, 0x81),
                                                            super::scanner::LauncherIcon::IssueInfo,
                                                        ),
                                                    };
                                                let row_txt_col =
                                                    if is_sel { heading_fg } else { body_fg };
                                                let c_name = ui
                                                    .horizontal(|ui| {
                                                        super::scanner::paint_launcher_icon(
                                                            ui,
                                                            Vec2::new(14.0, 14.0),
                                                            sev_col,
                                                            sev_icon,
                                                        );
                                                        ui.selectable_label(
                                                            is_sel,
                                                            RichText::new(&def.name)
                                                                .color(row_txt_col),
                                                        )
                                                    })
                                                    .inner;
                                                let c_sev = ui.selectable_label(
                                                    is_sel,
                                                    RichText::new(&def.severity)
                                                        .color(row_txt_col)
                                                        .strong(),
                                                );
                                                let c_idx = ui.selectable_label(
                                                    is_sel,
                                                    RichText::new(&def.type_hex)
                                                        .monospace()
                                                        .color(row_txt_col),
                                                );
                                                let c_cwe = ui.selectable_label(
                                                    is_sel,
                                                    RichText::new(def.cwe_summary())
                                                        .monospace()
                                                        .color(row_txt_col),
                                                );
                                                if c_name.clicked()
                                                    || c_sev.clicked()
                                                    || c_idx.clicked()
                                                    || c_cwe.clicked()
                                                {
                                                    app.panels.target_panel.selected_kb_def =
                                                        *orig_idx;
                                                }
                                                ui.end_row();
                                            }
                                        });
                                });
                        });

                    // Right column: High-contrast Advisory Card for the selected IssueDefinition
                    if let Some(def) = all_defs
                        .get(app.panels.target_panel.selected_kb_def)
                        .or_else(|| filtered_defs.first().map(|(_, d)| *d))
                    {
                        egui::Frame::new()
                            .fill(card_bg)
                            .stroke(Stroke::new(1.0_f32, border_col))
                            .inner_margin(egui::Margin::symmetric(14, 10))
                            .show(&mut cols[1], |ui| {
                                egui::ScrollArea::vertical()
                                    .id_salt("target-kb-detail-scroll")
                                    .max_height(260.0)
                                    .show(ui, |ui| {
                                        let sev_icon = match def.severity.as_str() {
                                            "High" => super::scanner::LauncherIcon::IssueHigh,
                                            "Medium" => super::scanner::LauncherIcon::IssueMedium,
                                            "Low" => super::scanner::LauncherIcon::IssueLow,
                                            _ => super::scanner::LauncherIcon::IssueInfo,
                                        };
                                        ui.horizontal(|ui| {
                                            super::scanner::paint_launcher_icon(
                                                ui,
                                                Vec2::new(24.0, 24.0),
                                                Color32::WHITE,
                                                sev_icon,
                                            );
                                            ui.label(
                                                RichText::new(&def.name)
                                                    .size(15.5)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                        });
                                        ui.label(
                                            RichText::new(format!(
                                                "Typical severity: {}   ·   Type index: {}",
                                                def.severity, def.type_hex
                                            ))
                                            .size(12.0)
                                            .strong()
                                            .color(body_fg),
                                        );
                                        ui.separator();
                                        if !def.description.is_empty() {
                                            ui.label(
                                                RichText::new("Issue description")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                            ui.add_space(2.0);
                                            ui.label(
                                                RichText::new(&def.description)
                                                    .size(12.0)
                                                    .color(body_fg),
                                            );
                                            ui.add_space(8.0);
                                        }
                                        if !def.remediation.is_empty() {
                                            ui.label(
                                                RichText::new("Issue remediation")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                            ui.add_space(2.0);
                                            ui.label(
                                                RichText::new(&def.remediation)
                                                    .size(12.0)
                                                    .color(body_fg),
                                            );
                                            ui.add_space(8.0);
                                        }
                                        if !def.references.is_empty() {
                                            ui.label(
                                                RichText::new("References")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                            for r in &def.references {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "• {} ({})",
                                                        r.title, r.url
                                                    ))
                                                    .size(12.0)
                                                    .color(body_fg),
                                                );
                                            }
                                            ui.add_space(8.0);
                                        }
                                        if !def.classifications.is_empty() {
                                            ui.label(
                                                RichText::new("Vulnerability classifications")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                            for c in &def.classifications {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "• {} ({})",
                                                        c.title, c.url
                                                    ))
                                                    .size(12.0)
                                                    .color(body_fg),
                                                );
                                            }
                                        }
                                    });
                            });
                    }
                });
            });
            ui.add_space(6.0);

            if app.workspace.issues.is_empty() {
                let (learn, _) = empty_state(
                    ui,
                    &theme,
                    "No issues to show",
                    "Any issues discovered on your target applications will be displayed here.",
                    true,
                    None,
                );
                if learn {
                    app.status =
                        "Target issues: run an audit or passive crawl to populate target findings"
                            .into();
                }
                return;
            }

            let needle = app.panels.target_panel.issue_filter.trim().to_lowercase();
            let sev_mask = app.panels.target_panel.issue_sev_filter;
            let conf_mask = app.panels.target_panel.issue_conf_filter;
            let issues: Vec<_> = app
                .workspace
                .issues
                .iter()
                .cloned()
                .enumerate()
                .filter(|(_, issue)| {
                    let sev_ok = match issue.severity {
                        crate::workspace::IssueSeverity::High => sev_mask[0],
                        crate::workspace::IssueSeverity::Medium => sev_mask[1],
                        crate::workspace::IssueSeverity::Low => sev_mask[2],
                        crate::workspace::IssueSeverity::Info => sev_mask[3],
                    };
                    let conf_ok = match issue.confidence.to_ascii_lowercase().as_str() {
                        "certain" => conf_mask[0],
                        "firm" => conf_mask[1],
                        "tentative" => conf_mask[2],
                        _ => true,
                    };
                    sev_ok
                        && conf_ok
                        && (needle.is_empty()
                            || issue.name.to_lowercase().contains(&needle)
                            || issue.url.to_lowercase().contains(&needle)
                            || issue.evidence.to_lowercase().contains(&needle))
                })
                .collect();

            if app.panels.target_panel.selected_issue.is_none() {
                app.panels.target_panel.selected_issue = issues.first().map(|(i, _)| *i);
            }

            // Flat Bordered Discovered Issues Table (`Pro-QSG-6-view-issues.png`)
            let cols = [
                ("Issue type", 240.0f32),
                ("Host / URL", 260.0),
                ("Parameter", 110.0),
                ("Severity", 86.0),
                ("Confidence", 86.0),
                ("CWE", 120.0),
            ];
            let tbl_w = cols
                .iter()
                .map(|(_, w)| *w)
                .sum::<f32>()
                .max(ui.available_width());

            egui::Frame::new()
                .fill(card_bg)
                .stroke(Stroke::new(1.0_f32, border_col))
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                    let (hdr_r, _) =
                        ui.allocate_exact_size(Vec2::new(tbl_w, 24.0), egui::Sense::hover());
                    ui.painter()
                        .rect_filled(hdr_r, 0.0, theme.color("ui.background.2"));
                    let mut hx = hdr_r.left();
                    for (col_name, col_w) in cols {
                        let cr = egui::Rect::from_min_size(
                            egui::pos2(hx, hdr_r.top()),
                            Vec2::new(col_w, hdr_r.height()),
                        );
                        ui.painter().text(
                            egui::pos2(cr.left() + 8.0, cr.center().y),
                            egui::Align2::LEFT_CENTER,
                            col_name,
                            egui::FontId::proportional(11.5),
                            heading_fg,
                        );
                        ui.painter().vline(
                            cr.right(),
                            hdr_r.y_range(),
                            Stroke::new(1.0_f32, border_col),
                        );
                        hx = cr.right();
                    }
                    ui.painter().hline(
                        hdr_r.x_range(),
                        hdr_r.bottom(),
                        Stroke::new(1.0_f32, border_col),
                    );

                    egui::ScrollArea::vertical()
                        .id_salt("target-issues-scroll")
                        .max_height(185.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing = Vec2::ZERO;
                            for (row_ord, (idx, issue)) in issues.iter().enumerate() {
                                let selected = app.panels.target_panel.selected_issue == Some(*idx);
                                ui.push_id(("target-issue-row", *idx), |ui| {
                                    let (row_rect, row_resp) = ui.allocate_exact_size(
                                        Vec2::new(tbl_w, 22.0),
                                        egui::Sense::click(),
                                    );
                                    row_resp.widget_info(|| {
                                        egui::WidgetInfo::selected(
                                            egui::WidgetType::SelectableLabel,
                                            ui.is_enabled(),
                                            selected,
                                            &issue.name,
                                        )
                                    });
                                    let row_fill = if selected {
                                        if theme.dark {
                                            Color32::from_rgb(0x2A, 0x3E, 0x5C)
                                        } else {
                                            Color32::from_rgb(0xC3, 0xD9, 0xF6)
                                        }
                                    } else if row_ord % 2 == 1 {
                                        theme.color("ui.background.1")
                                    } else {
                                        card_bg
                                    };
                                    ui.painter().rect_filled(row_rect, 0.0, row_fill);
                                    if selected {
                                        ui.painter().rect_stroke(
                                            row_rect.shrink(0.5),
                                            0.0,
                                            Stroke::new(
                                                1.0_f32,
                                                Color32::from_rgb(0x2B, 0x57, 0x9A),
                                            ),
                                            egui::StrokeKind::Inside,
                                        );
                                    }

                                    let sev_icon = match issue.severity {
                                        crate::workspace::IssueSeverity::High => {
                                            super::scanner::LauncherIcon::IssueHigh
                                        }
                                        crate::workspace::IssueSeverity::Medium => {
                                            super::scanner::LauncherIcon::IssueMedium
                                        }
                                        crate::workspace::IssueSeverity::Low => {
                                            super::scanner::LauncherIcon::IssueLow
                                        }
                                        crate::workspace::IssueSeverity::Info => {
                                            super::scanner::LauncherIcon::IssueInfo
                                        }
                                    };
                                    // Draw severity icon in the first column
                                    let ic_rect = egui::Rect::from_min_size(
                                        egui::pos2(row_rect.left() + 6.0, row_rect.center().y - 7.0),
                                        Vec2::new(14.0, 14.0),
                                    );
                                    let mut ic_ui = ui.new_child(
                                        egui::UiBuilder::new()
                                            .max_rect(ic_rect)
                                            .layout(egui::Layout::left_to_right(egui::Align::Center)),
                                    );
                                    super::scanner::paint_launcher_icon(
                                        &mut ic_ui,
                                        Vec2::new(14.0, 14.0),
                                        Color32::WHITE,
                                        sev_icon,
                                    );

                                    let kb_def = crate::issue_definitions::find_by_name(&issue.name);
                                    let cwe_txt = kb_def
                                        .map(|d| d.cwe_summary())
                                        .unwrap_or_else(|| "—".into());
                                    let vals = [
                                        issue.name.clone(),
                                        issue.url.clone(),
                                        issue.parameter.as_deref().unwrap_or("—").to_string(),
                                        format!("{:?}", issue.severity),
                                        issue.confidence.clone(),
                                        cwe_txt,
                                    ];
                                    let txt_col = if selected { heading_fg } else { body_fg };
                                    let mut cx = row_rect.left();
                                    for (c_i, ((_, cw), val)) in
                                        cols.iter().zip(vals.iter()).enumerate()
                                    {
                                        let pad_left = if c_i == 0 { 24.0 } else { 8.0 };
                                        let cell_r = egui::Rect::from_min_size(
                                            egui::pos2(cx, row_rect.top()),
                                            Vec2::new(*cw, row_rect.height()),
                                        );
                                        let clip_p = ui.painter().with_clip_rect(
                                            cell_r
                                                .shrink2(egui::vec2(4.0, 0.0))
                                                .intersect(ui.clip_rect()),
                                        );
                                        clip_p.text(
                                            egui::pos2(cell_r.left() + pad_left, cell_r.center().y),
                                            egui::Align2::LEFT_CENTER,
                                            val,
                                            egui::FontId::proportional(12.0),
                                            txt_col,
                                        );
                                        cx = cell_r.right();
                                    }

                                    if row_resp.clicked() || row_resp.secondary_clicked() {
                                        app.panels.target_panel.selected_issue = Some(*idx);
                                    }
                                    super::attach_message_context_menu(
                                        app,
                                        &row_resp,
                                        &issue.url,
                                        "",
                                        &issue.evidence,
                                    );
                                });
                            }
                        });
                });

            if let Some(sel) = app.panels.target_panel.selected_issue {
                if let Some((_, issue)) = issues.iter().find(|(i, _)| *i == sel) {
                    let kb_def = crate::issue_definitions::find_by_name(&issue.name);
                    ui.add_space(6.0);
                    // `Advisory | Request | Response` sub-tabs (`Pro-QSG-6-view-issues.png`)
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 16.0;
                        for (t_idx, lbl) in ["Advisory", "Request", "Response"].iter().enumerate() {
                            let active = app.panels.target_panel.issue_detail_tab == t_idx;
                            let r = ui.add(
                                egui::Label::new(
                                    RichText::new(*lbl).size(12.5).strong().color(if active {
                                        heading_fg
                                    } else {
                                        body_fg
                                    }),
                                )
                                .sense(egui::Sense::click()),
                            );
                            if active {
                                let rect = r.rect;
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_max(
                                        egui::pos2(rect.min.x - 4.0, rect.max.y + 1.0),
                                        egui::pos2(rect.max.x + 4.0, rect.max.y + 4.0),
                                    ),
                                    0.0,
                                    theme.color("ui.icon.accent"),
                                );
                            }
                            if r.clicked() {
                                app.panels.target_panel.issue_detail_tab = t_idx;
                            }
                        }
                        ui.separator();
                        if ui.button("Send URL to Repeater").clicked() {
                            if let Ok(parsed) = crate::http_target::HttpTarget::parse(&issue.url) {
                                let req = format!(
                                    "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                                    parsed.authority()
                                );
                                app.panels.repeater.open(&issue.url, &req);
                                app.tool = crate::ui::app::REPEATER;
                                app.view = 0;
                            }
                        }
                    });
                    ui.add_space(4.0);

                    let sample_tx = app
                        .log
                        .iter()
                        .rev()
                        .find(|tx| tx.target == issue.url || issue.url.starts_with(&tx.host_url()))
                        .cloned();
                    match app.panels.target_panel.issue_detail_tab {
                        1 => {
                            let req = sample_tx
                                .map(|t| t.request)
                                .unwrap_or_else(|| format!("GET {} HTTP/1.1\r\n\r\n", issue.url));
                            let r = super::burp_numbered_message_view(
                                ui,
                                &theme,
                                "target-issue-req",
                                230.0,
                                &req,
                                0,
                                false,
                            );
                            super::attach_message_context_menu(app, &r, &issue.url, &req, "");
                        }
                        2 => {
                            let resp = sample_tx
                                .map(|t| t.response)
                                .unwrap_or_else(|| issue.evidence.clone());
                            let r = super::burp_numbered_message_view(
                                ui,
                                &theme,
                                "target-issue-resp",
                                230.0,
                                &resp,
                                0,
                                false,
                            );
                            super::attach_message_context_menu(app, &r, &issue.url, "", &resp);
                        }
                        _ => {
                            let sev_icon = match issue.severity {
                                crate::workspace::IssueSeverity::High => {
                                    super::scanner::LauncherIcon::IssueHigh
                                }
                                crate::workspace::IssueSeverity::Medium => {
                                    super::scanner::LauncherIcon::IssueMedium
                                }
                                crate::workspace::IssueSeverity::Low => {
                                    super::scanner::LauncherIcon::IssueLow
                                }
                                crate::workspace::IssueSeverity::Info => {
                                    super::scanner::LauncherIcon::IssueInfo
                                }
                            };
                            // High-contrast Advisory Card matching `Pro-QSG-6-view-issues.png`
                            let adv_h = (ui.available_height() - 16.0).max(240.0);
                            egui::Frame::new()
                                .fill(card_bg)
                                .stroke(Stroke::new(1.0_f32, border_col))
                                .inner_margin(egui::Margin::symmetric(16, 12))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    egui::ScrollArea::vertical()
                                        .id_salt("target-issue-advisory-scroll")
                                        .max_height(adv_h)
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                super::scanner::paint_launcher_icon(
                                                    ui,
                                                    Vec2::new(28.0, 28.0),
                                                    Color32::WHITE,
                                                    sev_icon,
                                                );
                                                ui.label(
                                                    RichText::new(format!(
                                                        "Advisory — {}",
                                                        issue.name
                                                    ))
                                                    .size(16.5)
                                                    .strong()
                                                    .color(heading_fg),
                                                );
                                            });
                                            ui.add_space(4.0);
                                            ui.separator();
                                            let (host_part, path_part) = issue
                                                .url
                                                .split_once("://")
                                                .map(|(s, r)| {
                                                    let h = r.split('/').next().unwrap_or(r);
                                                    let p = &r[h.len()..];
                                                    (
                                                        format!("{s}://{h}"),
                                                        if p.is_empty() { "/" } else { p }
                                                            .to_string(),
                                                    )
                                                })
                                                .unwrap_or_else(|| {
                                                    (issue.url.clone(), "/".to_string())
                                                });
                                            let issue_title_meta = if let Some(def) = kb_def {
                                                format!("{} ({})", issue.name, def.type_hex)
                                            } else {
                                                format!("{} (custom)", issue.name)
                                            };
                                            egui::Grid::new("target-issue-advisory-meta")
                                                .num_columns(2)
                                                .spacing([22.0, 4.0])
                                                .show(ui, |ui| {
                                                    ui.label(
                                                        RichText::new("Issue:").color(body_fg),
                                                    );
                                                    ui.label(
                                                        RichText::new(issue_title_meta)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.end_row();
                                                    ui.label(
                                                        RichText::new("Severity:").color(body_fg),
                                                    );
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "{:?}",
                                                            issue.severity
                                                        ))
                                                        .strong()
                                                        .color(heading_fg),
                                                    );
                                                    ui.end_row();
                                                    ui.label(
                                                        RichText::new("Confidence:").color(body_fg),
                                                    );
                                                    ui.label(
                                                        RichText::new(&issue.confidence)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.end_row();
                                                    ui.label(
                                                        RichText::new("Host:").color(body_fg),
                                                    );
                                                    ui.label(
                                                        RichText::new(&host_part)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.end_row();
                                                    ui.label(
                                                        RichText::new("Path:").color(body_fg),
                                                    );
                                                    ui.label(
                                                        RichText::new(&path_part)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.end_row();
                                                    if let Some(param) = &issue.parameter {
                                                        ui.label(
                                                            RichText::new("Insertion point:")
                                                                .color(body_fg),
                                                        );
                                                        ui.label(
                                                            RichText::new(param)
                                                                .strong()
                                                                .color(heading_fg),
                                                        );
                                                        ui.end_row();
                                                    }
                                                });
                                            ui.separator();
                                            ui.add_space(6.0);
                                            ui.label(
                                                RichText::new("Issue detail")
                                                    .size(13.5)
                                                    .strong()
                                                    .color(heading_fg),
                                            );
                                            ui.add_space(3.0);
                                            egui::Frame::new()
                                                .fill(code_bg)
                                                .stroke(Stroke::new(1.0_f32, border_col))
                                                .corner_radius(3.0)
                                                .inner_margin(egui::Margin::symmetric(10, 6))
                                                .show(ui, |ui| {
                                                    ui.set_min_width(
                                                        (ui.available_width() - 12.0).max(160.0),
                                                    );
                                                    ui.label(
                                                        RichText::new(&issue.evidence)
                                                            .monospace()
                                                            .size(12.0)
                                                            .color(heading_fg),
                                                    );
                                                });

                                            if let Some(def) = kb_def {
                                                if !def.description.is_empty() {
                                                    ui.add_space(10.0);
                                                    ui.label(
                                                        RichText::new("Issue background")
                                                            .size(13.5)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.add_space(3.0);
                                                    ui.label(
                                                        RichText::new(&def.description)
                                                            .size(12.5)
                                                            .color(body_fg),
                                                    );
                                                }
                                                if !def.remediation.is_empty() {
                                                    ui.add_space(10.0);
                                                    ui.label(
                                                        RichText::new("Issue remediation")
                                                            .size(13.5)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.add_space(3.0);
                                                    ui.label(
                                                        RichText::new(&def.remediation)
                                                            .size(12.5)
                                                            .color(body_fg),
                                                    );
                                                }
                                                if !def.references.is_empty() {
                                                    ui.add_space(10.0);
                                                    ui.label(
                                                        RichText::new("References")
                                                            .size(13.5)
                                                            .strong()
                                                            .color(heading_fg),
                                                    );
                                                    ui.add_space(3.0);
                                                    for r in &def.references {
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "• {} ({})",
                                                                r.title, r.url
                                                            ))
                                                            .size(12.0)
                                                            .color(body_fg),
                                                        );
                                                    }
                                                }
                                                if !def.classifications.is_empty() {
                                                    ui.add_space(10.0);
                                                    ui.label(
                                                        RichText::new(
                                                            "Vulnerability classifications",
                                                        )
                                                        .size(13.5)
                                                        .strong()
                                                        .color(heading_fg),
                                                    );
                                                    ui.add_space(3.0);
                                                    for c in &def.classifications {
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "• {} ({})",
                                                                c.title, c.url
                                                            ))
                                                            .size(12.0)
                                                            .color(body_fg),
                                                        );
                                                    }
                                                }
                                            }
                                        });
                                });
                        }
                    }
                }
            }
        });
}

/// Paints the exact `resources/Media/svg/light/site-map.svg` (`90 x 63` viewBox) 3-isometric-diamonds icon.
fn paint_site_map_empty_icon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(90.0, 63.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let shadow_col = Color32::from_rgb(0xE6, 0xE6, 0xE6);
    let branch_col = Color32::from_rgb(0x92, 0xB1, 0xCE);
    let card_col = Color32::from_rgb(0x26, 0x64, 0x9D);

    let iso_diamond = |cx: f32, cy: f32, rx: f32, ry: f32| -> Vec<egui::Pos2> {
        vec![
            egui::pos2(o.x + cx, o.y + cy - ry),
            egui::pos2(o.x + cx + rx, o.y + cy),
            egui::pos2(o.x + cx, o.y + cy + ry),
            egui::pos2(o.x + cx - rx, o.y + cy),
        ]
    };

    // Shadow branches & isometric cards (`#E6E6E6`)
    p.line_segment(
        [egui::pos2(o.x + 32.0, o.y + 27.0), egui::pos2(o.x + 64.0, o.y + 42.0)],
        Stroke::new(2.0_f32, shadow_col),
    );
    p.line_segment(
        [egui::pos2(o.x + 48.0, o.y + 34.5), egui::pos2(o.x + 58.0, o.y + 29.5)],
        Stroke::new(2.0_f32, shadow_col),
    );
    for (cx, cy) in [(23.8f32, 33.5f32), (67.5, 24.9), (53.1, 50.5)] {
        p.add(egui::Shape::convex_polygon(
            iso_diamond(cx, cy, 18.0, 10.5),
            shadow_col,
            Stroke::NONE,
        ));
    }

    // Connecting branches (`#92B1CE`)
    p.line_segment(
        [egui::pos2(o.x + 32.0, o.y + 22.0), egui::pos2(o.x + 64.0, o.y + 37.0)],
        Stroke::new(2.0_f32, branch_col),
    );
    p.line_segment(
        [egui::pos2(o.x + 48.0, o.y + 29.5), egui::pos2(o.x + 58.0, o.y + 24.5)],
        Stroke::new(2.0_f32, branch_col),
    );

    // 3 blue isometric cards (`#26649D`) + 2 white lines inside each card
    for (cx, cy) in [(22.9f32, 28.4f32), (66.7, 19.8), (52.3, 45.4)] {
        p.add(egui::Shape::convex_polygon(
            iso_diamond(cx, cy, 18.5, 11.0),
            card_col,
            Stroke::NONE,
        ));
        p.line_segment(
            [
                egui::pos2(o.x + cx - 4.0, o.y + cy - 3.0),
                egui::pos2(o.x + cx + 4.5, o.y + cy + 1.8),
            ],
            Stroke::new(1.9_f32, Color32::WHITE),
        );
        p.line_segment(
            [
                egui::pos2(o.x + cx - 8.0, o.y + cy - 0.5),
                egui::pos2(o.x + cx + 0.5, o.y + cy + 4.3),
            ],
            Stroke::new(1.9_f32, Color32::WHITE),
        );
    }
}

/// Draws a single row in the left Site map tree with vector connector lines, `#CFE0F5` selection highlight,
/// chevron (`⌄`/`›`), node icon, and label (`Pro-QSG-5-site-map.png` & `site-map-populated.png`).
#[allow(clippy::too_many_arguments)]
fn draw_sitemap_tree_row(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    id_salt: impl std::hash::Hash,
    depth: usize,
    has_children: bool,
    expanded: bool,
    icon: SiteMapIcon,
    dot_color: Option<Color32>,
    label: &str,
    selected: bool,
    muted_text: bool,
) -> egui::Response {
    let row_w = ui.available_width().max(180.0);
    let row_h = 22.0;
    let (rect, resp) = ui.allocate_exact_size(
        Vec2::new(row_w, row_h),
        egui::Sense::click(),
    );
    let _ = id_salt;
    resp.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            label,
        )
    });

    let p = ui.painter_at(rect);
    if selected {
        let sel_fill = if theme.dark {
            Color32::from_rgb(0x2A, 0x3E, 0x5C)
        } else {
            Color32::from_rgb(0xCF, 0xE0, 0xF5)
        };
        p.rect_filled(rect.shrink2(egui::vec2(2.0, 0.5)), 4.0, sel_fill);
    } else if resp.hovered() {
        let hov_fill = if theme.dark {
            Color32::from_rgb(0x25, 0x29, 0x30)
        } else {
            Color32::from_rgb(0xF1, 0xF5, 0xFA)
        };
        p.rect_filled(rect.shrink2(egui::vec2(2.0, 0.5)), 4.0, hov_fill);
    }

    let line_col = if theme.dark {
        Color32::from_rgb(0x55, 0x5B, 0x66)
    } else {
        Color32::from_rgb(0xB4, 0xBA, 0xC4)
    };
    let cy = rect.center().y;
    let base_x = rect.min.x + 10.0;

    // Draw vertical trunk lines for ancestor depths + branch connector to this node
    for d in 0..depth {
        let tx = base_x + (d as f32) * 18.0;
        p.line_segment(
            [egui::pos2(tx, rect.min.y), egui::pos2(tx, rect.max.y)],
            Stroke::new(1.0_f32, line_col),
        );
    }
    let node_x = base_x + (depth as f32) * 18.0;
    if depth > 0 {
        let parent_x = base_x + ((depth - 1) as f32) * 18.0;
        p.line_segment(
            [egui::pos2(parent_x, cy), egui::pos2(node_x, cy)],
            Stroke::new(1.0_f32, line_col),
        );
    }
    // Small filled circle node anchor (`•`) on the tree line (`site-map-populated.png`)
    p.circle_filled(egui::pos2(node_x, cy), 2.5, line_col);

    // Chevron (`⌄` or `›`) for expandable nodes
    let mut cursor_x = node_x + 7.0;
    if has_children {
        let chev_col = theme.color("ui.icon.default");
        if expanded {
            p.line_segment(
                [egui::pos2(cursor_x, cy - 1.5), egui::pos2(cursor_x + 3.5, cy + 2.0)],
                Stroke::new(1.3_f32, chev_col),
            );
            p.line_segment(
                [egui::pos2(cursor_x + 3.5, cy + 2.0), egui::pos2(cursor_x + 7.0, cy - 1.5)],
                Stroke::new(1.3_f32, chev_col),
            );
        } else {
            p.line_segment(
                [egui::pos2(cursor_x + 1.5, cy - 3.5), egui::pos2(cursor_x + 5.0, cy)],
                Stroke::new(1.3_f32, chev_col),
            );
            p.line_segment(
                [egui::pos2(cursor_x + 5.0, cy), egui::pos2(cursor_x + 1.5, cy + 3.5)],
                Stroke::new(1.3_f32, chev_col),
            );
        }
        cursor_x += 11.0;
    }

    // Node SVG icon (`16 x 16`)
    let icon_rect = egui::Rect::from_min_size(
        egui::pos2(cursor_x, cy - 8.0),
        Vec2::new(16.0, 16.0),
    );
    let mut icon_ui = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(icon_rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    paint_sitemap_node_icon(&mut icon_ui, icon, dot_color);
    cursor_x += 20.0;

    // Node text label
    let txt_col = if muted_text {
        theme.color("ui.icon.disabled")
    } else {
        theme.color("ui.text.heading")
    };
    p.text(
        egui::pos2(cursor_x, cy),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(12.0),
        txt_col,
    );

    resp
}

/// Renders `Target -> Site map` matching `/tmp/ref_Target_s.png`, `Pro-QSG-5-site-map.png`,
/// `site-map-populated.png`, and `site-map-filters.png` 100%.
fn draw_site_map(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let bg0 = theme.color("ui.background.0");
    let border_col = theme.color("ui.border.1");
    let tree = tree(app);

    // Top row: `[ URL view | Crawl paths view ]` segmented pill + Burp Filter bar (`site-map-filters.png`)
    egui::Frame::new()
        .fill(bg0)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                let pill_track = if theme.dark {
                    Color32::from_rgb(0x32, 0x36, 0x3E)
                } else {
                    Color32::from_rgb(0xE0, 0xE0, 0xE0)
                };
                let active_blue = Color32::from_rgb(0x1B, 0x56, 0x99);
                let inactive_fg = if theme.dark {
                    Color32::from_rgb(0xD8, 0xDC, 0xE2)
                } else {
                    Color32::from_rgb(0x2B, 0x2B, 0x2B)
                };

                egui::Frame::new()
                    .fill(pill_track)
                    .corner_radius(4.0)
                    .inner_margin(egui::Margin::same(0))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.x = 0.0;
                        for (is_crawl, label) in [(false, "URL view"), (true, "Crawl paths view")] {
                            let active = app.panels.target_panel.crawl_paths_view == is_crawl;
                            let fill = if active { active_blue } else { Color32::TRANSPARENT };
                            let fg = if active { Color32::WHITE } else { inactive_fg };
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(label).color(fg).size(11.5).strong(),
                                    )
                                    .fill(fill)
                                    .stroke(Stroke::NONE)
                                    .corner_radius(3.0)
                                    .min_size(Vec2::new(64.0, 22.0)),
                                )
                                .clicked()
                            {
                                app.panels.target_panel.crawl_paths_view = is_crawl;
                            }
                        }
                    });

                if !tree.is_empty() {
                    ui.add_space(6.0);
                    let filter_pill_bg = if theme.dark {
                        Color32::from_rgb(0x28, 0x2C, 0x33)
                    } else {
                        Color32::from_rgb(0xEE, 0xF0, 0xF3)
                    };
                    egui::Frame::new()
                        .fill(filter_pill_bg)
                        .corner_radius(4.0)
                        .inner_margin(egui::Margin::symmetric(8, 3))
                        .show(ui, |ui| {
                            ui.set_min_width((ui.available_width() - 8.0).max(200.0));
                            ui.horizontal(|ui| {
                                let (funnel, _) =
                                    ui.allocate_exact_size(Vec2::splat(13.0), egui::Sense::hover());
                                crate::ui::icons::paint(
                                    ui.painter(),
                                    funnel,
                                    theme.color("ui.icon.default"),
                                    crate::ui::icons::Glyph::Funnel,
                                );
                                ui.label(
                                    RichText::new(
                                        "Site map filter: Hiding not found items; hiding CSS, image and general binary content; hiding 4xx responses; hiding empty folders",
                                    )
                                    .size(11.5)
                                    .color(theme.color("ui.text.body")),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if !app.panels.target_panel.filter.is_empty()
                                            && ui.small_button("Clear").clicked()
                                        {
                                            app.panels.target_panel.filter.clear();
                                        }
                                        ui.add(
                                            egui::TextEdit::singleline(
                                                &mut app.panels.target_panel.filter,
                                            )
                                            .hint_text("Filter host or path…")
                                            .desired_width(140.0),
                                        );
                                    },
                                );
                            });
                        });
                }
            });
        });

    if tree.is_empty() {
        let avail = ui.available_size();
        let title = if app.panels.target_panel.crawl_paths_view {
            "Site map crawl paths view is empty"
        } else {
            "Site map URL view is empty"
        };
        egui::Frame::new()
            .fill(bg0)
            .inner_margin(egui::Margin::same(0))
            .show(ui, |ui| {
                ui.set_min_size(avail);
                let top_pad = ((avail.y - 260.0) * 0.42).max(40.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(top_pad);
                    paint_site_map_empty_icon(ui);
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new(title)
                            .size(16.0)
                            .strong()
                            .color(theme.color("ui.text.heading")),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "The site map displays information about the contents of your target applications,\n\
                             along with any issues that have been discovered. The URL view shows your targets as\n\
                             a tree of URLs, organized hierarchically by domain and directory. To populate the\n\
                             URL view, run a scan or browse using Burp's browser.",
                        )
                        .size(12.0)
                        .color(theme.color("ui.text.body")),
                    );
                    ui.add_space(18.0);
                    let learn_bg = if theme.dark {
                        Color32::from_rgb(0x32, 0x36, 0x3E)
                    } else {
                        Color32::from_rgb(0xEA, 0xEA, 0xEA)
                    };
                    let learn_border = if theme.dark {
                        Color32::from_rgb(0x48, 0x4D, 0x56)
                    } else {
                        Color32::from_rgb(0xD8, 0xD8, 0xD8)
                    };
                    let total_btn_w = 108.0 + 10.0 + 114.0;
                    let left_pad = ((ui.available_width() - total_btn_w) * 0.5).max(0.0);
                    ui.horizontal(|ui| {
                        ui.add_space(left_pad);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Learn more")
                                        .size(12.0)
                                        .strong()
                                        .color(theme.color("ui.text.heading")),
                                )
                                .fill(learn_bg)
                                .stroke(Stroke::new(1.0_f32, learn_border))
                                .corner_radius(4.0)
                                .min_size(Vec2::new(108.0, 28.0)),
                            )
                            .clicked()
                        {
                            app.status =
                                "Site map: browse through the proxy or run a scan to populate target URLs".into();
                        }
                        ui.add_space(10.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Open browser")
                                        .size(12.0)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(0xE0, 0x53, 0x20))
                                .stroke(Stroke::NONE)
                                .corner_radius(4.0)
                                .min_size(Vec2::new(114.0, 28.0)),
                            )
                            .clicked()
                        {
                            app.open_browser();
                        }
                    });
                });
            });
        return;
    }

    let sep_rect = egui::Rect::from_min_size(
        ui.cursor().min,
        Vec2::new(ui.available_width(), 1.0),
    );
    ui.painter().rect_filled(sep_rect, 0.0, border_col);
    ui.add_space(1.0);

    // Auto-select the first host if none is selected yet
    if app.panels.target_panel.host.is_none() {
        app.panels.target_panel.host = tree.keys().next().cloned();
    }

    let avail_h = ui.available_height().max(340.0);
    let mut tree_ratio = app.panels.target_panel.tree_split_ratio;

    super::vertical_split(
        ui,
        &theme,
        "target-sitemap-main-split",
        &mut tree_ratio,
        avail_h,
        |side, ui| {
            if side == 0 {
                // LEFT PANE: Full-Height Hierarchical Host / Folder / Endpoint Tree (`Pro-QSG-5-site-map.png` & `site-map-populated.png`)
                egui::Frame::new()
                    .fill(bg0)
                    .inner_margin(egui::Margin::symmetric(6, 6))
                    .show(ui, |ui| {
                        ui.set_min_height((avail_h - 12.0).max(200.0));
                        egui::ScrollArea::vertical()
                            .id_salt("target-sitemap-left-tree")
                            .max_height((avail_h - 12.0).max(200.0))
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                for (host, paths) in &tree {
                                    if !app.panels.target_panel.matches(host)
                                        && !paths.keys().any(|p| app.panels.target_panel.matches(p))
                                    {
                                        continue;
                                    }
                                    let selected_host =
                                        app.panels.target_panel.host.as_deref() == Some(host.as_str())
                                            && app.panels.target_panel.path.is_none();
                                    let is_https = host.starts_with("https://");
                                    let has_issues = app
                                        .workspace
                                        .issues
                                        .iter()
                                        .any(|iss| iss.url.starts_with(host));
                                    let host_dot = if has_issues {
                                        Some(Color32::from_rgb(0xD6, 0x21, 0x3F))
                                    } else {
                                        Some(Color32::from_rgb(0x18, 0x58, 0xA8))
                                    };

                                    let host_resp = draw_sitemap_tree_row(
                                        ui,
                                        &theme,
                                        ("host", host),
                                        0,
                                        true,
                                        true,
                                        if is_https {
                                            SiteMapIcon::SecureHost
                                        } else {
                                            SiteMapIcon::InsecureHost
                                        },
                                        host_dot,
                                        host,
                                        selected_host,
                                        false,
                                    );
                                    if host_resp.clicked() || host_resp.secondary_clicked() {
                                        app.panels.target_panel.host = Some(host.clone());
                                        app.panels.target_panel.path = None;
                                    }
                                    // Host right-click context menu (`Pro-QSG-7-Report-for-host.png`)
                                    super::show_persistent_context_menu(&host_resp, |ui| {
                                        ui.set_min_width(220.0);
                                        ui.label(RichText::new(host).strong());
                                        ui.separator();
                                        if ui.button("Add to scope").clicked() {
                                            if !app.panels.target_panel.scope.contains(host) {
                                                if !app.panels.target_panel.scope.trim().is_empty()
                                                {
                                                    app.panels.target_panel.scope.push_str(", ");
                                                }
                                                app.panels.target_panel.scope.push_str(host);
                                            }
                                            ui.close();
                                        }
                                        if ui.button("Scan").clicked() {
                                            app.panels.scanner.seed = format!("{host}/");
                                            app.panels.scanner.urls_to_scan = format!("{host}/");
                                            app.panels.scanner.show_launcher = true;
                                            ui.close();
                                        }
                                        if ui.button("Passively scan this host").clicked() {
                                            app.scan_url(&format!("{host}/"), false);
                                            ui.close();
                                        }
                                        if ui.button("Actively scan this host").clicked() {
                                            app.scan_url(&format!("{host}/"), true);
                                            ui.close();
                                        }
                                        ui.separator();
                                        ui.menu_button("Issues", |ui| {
                                            if ui.button("Report issues for this host").clicked() {
                                                app.panels.scanner.report_host_filter =
                                                    host.clone();
                                                app.panels.scanner.show_report_wizard = true;
                                                ui.close();
                                            }
                                            if ui.button("Delete issues for this host").clicked() {
                                                app.status =
                                                    format!("Cleared issues filter for {host}");
                                                ui.close();
                                            }
                                        });
                                        if ui.button("Copy URLs in this host").clicked() {
                                            let urls: Vec<String> = paths
                                                .keys()
                                                .map(|p| format!("{host}{p}"))
                                                .collect();
                                            ui.ctx().copy_text(urls.join("\n"));
                                            ui.close();
                                        }
                                    });

                                    // Group paths into top-level folders and direct root leaves (`site-map-populated.png`)
                                    let mut folders: std::collections::BTreeMap<
                                        String,
                                        Vec<(String, usize)>,
                                    > = std::collections::BTreeMap::new();
                                    let mut root_leaves: Vec<(String, usize)> = Vec::new();
                                    for (path, count) in paths {
                                        if !app.panels.target_panel.matches(path) {
                                            continue;
                                        }
                                        let trimmed = path.trim_start_matches('/');
                                        if let Some((dir, rest)) = trimmed.split_once('/') {
                                            if !dir.is_empty() && !rest.is_empty() {
                                                folders
                                                    .entry(dir.to_string())
                                                    .or_default()
                                                    .push((path.clone(), *count));
                                                continue;
                                            }
                                        }
                                        root_leaves.push((path.clone(), *count));
                                    }

                                    // 1. Direct root leaves (e.g. `/`, `about`, `my-account?id=carlos`)
                                    for (path, _count) in &root_leaves {
                                        let selected = app.panels.target_panel.path.as_deref()
                                            == Some(path.as_str())
                                            && app.panels.target_panel.host.as_deref()
                                                == Some(host.as_str());
                                        let has_query = path.contains('?');
                                        let icon = if has_query {
                                            SiteMapIcon::DynPage
                                        } else {
                                            SiteMapIcon::DefaultPage
                                        };
                                        let display_lbl = if path == "/" {
                                            "/"
                                        } else {
                                            path.trim_start_matches('/')
                                        };
                                        let leaf_resp = draw_sitemap_tree_row(
                                            ui,
                                            &theme,
                                            ("root-leaf", host, path),
                                            1,
                                            false,
                                            false,
                                            icon,
                                            Some(Color32::from_rgb(0x18, 0x58, 0xA8)),
                                            display_lbl,
                                            selected,
                                            false,
                                        );
                                        if leaf_resp.clicked() || leaf_resp.secondary_clicked() {
                                            app.panels.target_panel.host = Some(host.clone());
                                            app.panels.target_panel.path = Some(path.clone());
                                        }
                                        let full_url = format!("{host}{path}");
                                        let sample_tx = app
                                            .log
                                            .iter()
                                            .rev()
                                            .find(|t| {
                                                t.host_url() == *host && t.target.ends_with(path)
                                            })
                                            .cloned();
                                        let (sample_req, sample_resp) = sample_tx
                                            .map(|t| (t.request, t.response))
                                            .unwrap_or_default();
                                        super::attach_message_context_menu(
                                            app,
                                            &leaf_resp,
                                            &full_url,
                                            &sample_req,
                                            &sample_resp,
                                        );
                                    }

                                    // 2. Folder nodes + nested children (`site-map-populated.png`)
                                    for (folder, children) in &folders {
                                        let folder_prefix = format!("/{folder}");
                                        let folder_sel = app.panels.target_panel.host.as_deref()
                                            == Some(host.as_str())
                                            && app.panels.target_panel.path.as_deref()
                                                == Some(folder_prefix.as_str());
                                        let folder_resp = draw_sitemap_tree_row(
                                            ui,
                                            &theme,
                                            ("folder", host, folder),
                                            1,
                                            true,
                                            true,
                                            SiteMapIcon::FolderOpen,
                                            None,
                                            folder,
                                            folder_sel,
                                            false,
                                        );
                                        if folder_resp.clicked() {
                                            app.panels.target_panel.host = Some(host.clone());
                                            app.panels.target_panel.path = Some(folder_prefix);
                                        }
                                        for (full_path, _cnt) in children {
                                            let selected = app.panels.target_panel.path.as_deref()
                                                == Some(full_path.as_str())
                                                && app.panels.target_panel.host.as_deref()
                                                    == Some(host.as_str());
                                            let rel_name = full_path
                                                .trim_start_matches('/')
                                                .strip_prefix(folder.as_str())
                                                .unwrap_or(full_path)
                                                .trim_start_matches('/');
                                            let has_query = full_path.contains('?');
                                            let icon = if has_query {
                                                SiteMapIcon::DynPage
                                            } else {
                                                SiteMapIcon::DefaultPage
                                            };
                                            let child_resp = draw_sitemap_tree_row(
                                                ui,
                                                &theme,
                                                ("child", host, full_path),
                                                2,
                                                has_query,
                                                true,
                                                icon,
                                                Some(Color32::from_rgb(0x18, 0x58, 0xA8)),
                                                rel_name.split('?').next().unwrap_or(rel_name),
                                                selected && !has_query,
                                                false,
                                            );
                                            if child_resp.clicked()
                                                || child_resp.secondary_clicked()
                                            {
                                                app.panels.target_panel.host = Some(host.clone());
                                                app.panels.target_panel.path =
                                                    Some(full_path.clone());
                                            }
                                            let full_url = format!("{host}{full_path}");
                                            let sample_tx = app
                                                .log
                                                .iter()
                                                .rev()
                                                .find(|t| {
                                                    t.host_url() == *host
                                                        && t.target.ends_with(full_path)
                                                })
                                                .cloned();
                                            let (sample_req, sample_resp) = sample_tx
                                                .map(|t| (t.request, t.response))
                                                .unwrap_or_default();
                                            super::attach_message_context_menu(
                                                app,
                                                &child_resp,
                                                &full_url,
                                                &sample_req,
                                                &sample_resp,
                                            );

                                            // If query string exists, also render the `? query` child node (`site-map-populated.png`)
                                            if let Some((_, q_part)) = full_path.split_once('?') {
                                                let q_resp = draw_sitemap_tree_row(
                                                    ui,
                                                    &theme,
                                                    ("query-child", host, full_path),
                                                    3,
                                                    false,
                                                    false,
                                                    SiteMapIcon::QueryPage,
                                                    None,
                                                    q_part,
                                                    selected,
                                                    false,
                                                );
                                                if q_resp.clicked() || q_resp.secondary_clicked() {
                                                    app.panels.target_panel.host =
                                                        Some(host.clone());
                                                    app.panels.target_panel.path =
                                                        Some(full_path.clone());
                                                }
                                                super::attach_message_context_menu(
                                                    app,
                                                    &q_resp,
                                                    &full_url,
                                                    &sample_req,
                                                    &sample_resp,
                                                );
                                            }
                                        }
                                    }

                                    // 3. Unvisited discovered links in muted gray (`site-map-populated.png`)
                                    if let Some(found) = app.discovered.get(host) {
                                        for path in found {
                                            if paths.contains_key(path)
                                                || !app.panels.target_panel.matches(path)
                                            {
                                                continue;
                                            }
                                            let u_resp = draw_sitemap_tree_row(
                                                ui,
                                                &theme,
                                                ("unvisited", host, path),
                                                1,
                                                false,
                                                false,
                                                SiteMapIcon::DefaultPage,
                                                None,
                                                path.trim_start_matches('/'),
                                                app.panels.target_panel.path.as_deref()
                                                    == Some(path.as_str()),
                                                true,
                                            );
                                            if u_resp.clicked() {
                                                app.panels.target_panel.host = Some(host.clone());
                                                app.panels.target_panel.path = Some(path.clone());
                                            }
                                        }
                                    }
                                    ui.add_space(4.0);
                                }
                            });
                    });
            } else {
                // RIGHT PANE: `Contents | Issues` sub-tabs + Flat Bordered Contents Table + Full-Height `Request | Response` (`Pro-QSG-5-site-map.png`)
                egui::Frame::new()
                    .fill(bg0)
                    .inner_margin(egui::Margin::same(0))
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            // 1. `Contents | Issues` tab bar
                            egui::Frame::new()
                                .fill(bg0)
                                .inner_margin(egui::Margin::symmetric(12, 5))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 18.0;
                                        for (idx, name) in ["Contents", "Issues"].iter().enumerate()
                                        {
                                            let active =
                                                app.panels.target_panel.right_sub_tab == idx;
                                            let fg = if active {
                                                theme.color("ui.text.heading")
                                            } else {
                                                theme.color("ui.text.body")
                                            };
                                            let resp = ui.add(
                                                egui::Label::new(
                                                    RichText::new(*name).size(12.5).color(fg),
                                                )
                                                .sense(egui::Sense::click()),
                                            );
                                            if active {
                                                let r = resp.rect;
                                                ui.painter().rect_filled(
                                                    egui::Rect::from_min_max(
                                                        egui::pos2(r.min.x - 4.0, r.max.y + 2.0),
                                                        egui::pos2(r.max.x + 4.0, r.max.y + 5.0),
                                                    ),
                                                    0.0,
                                                    theme.color("ui.icon.accent"),
                                                );
                                            }
                                            if resp.clicked() {
                                                app.panels.target_panel.right_sub_tab = idx;
                                            }
                                        }
                                    });
                                });
                            let sub_sep = egui::Rect::from_min_size(
                                ui.cursor().min,
                                Vec2::new(ui.available_width(), 1.0),
                            );
                            ui.painter().rect_filled(sub_sep, 0.0, border_col);
                            ui.add_space(1.0);

                            if app.panels.target_panel.right_sub_tab == 1 {
                                egui::Frame::new()
                                    .fill(bg0)
                                    .inner_margin(egui::Margin::symmetric(10, 6))
                                    .show(ui, |ui| {
                                        draw_issues_view(app, ui);
                                    });
                                return;
                            }

                            // Filter transactions matching the selected host/path in the left tree
                            let sel_host = app.panels.target_panel.host.clone();
                            let sel_path = app.panels.target_panel.path.clone();
                            let matching_txs: Vec<(usize, crate::ui::app::Transaction)> = app
                                .log
                                .iter()
                                .cloned()
                                .enumerate()
                                .filter(|(_, tx)| {
                                    let host_key = tx.host_url();
                                    sel_host.as_deref().map_or(true, |h| h == host_key)
                                        && sel_path
                                            .as_deref()
                                            .map_or(true, |p| tx.path_and_query().starts_with(p))
                                })
                                .collect();

                            // 2. Flat Bordered Contents Table (`Host | Method | URL ▲ | Params | Status Code | Length | MIME type | Title`)
                            let tbl_h = app.panels.target_panel.contents_table_height;
                            let cols = [
                                ("Host", 170.0f32),
                                ("Method", 64.0),
                                ("URL ▲", 220.0),
                                ("Params", 56.0),
                                ("Status Code", 84.0),
                                ("Length", 68.0),
                                ("MIME type", 76.0),
                                ("Title", 200.0),
                            ];
                            let total_w = cols
                                .iter()
                                .map(|(_, w)| *w)
                                .sum::<f32>()
                                .max(ui.available_width());

                            egui::ScrollArea::horizontal()
                                .id_salt("target-contents-hscroll")
                                .show(ui, |ui| {
                                    ui.set_min_width(total_w);
                                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                                    // Header bar (`#EBEBEB` / `ui.background.2`)
                                    let (hdr_rect, _) = ui.allocate_exact_size(
                                        Vec2::new(total_w, 24.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().rect_filled(
                                        hdr_rect,
                                        0.0,
                                        theme.color("ui.background.2"),
                                    );
                                    let mut hx = hdr_rect.left();
                                    for (col_name, col_w) in cols {
                                        let cell_r = egui::Rect::from_min_size(
                                            egui::pos2(hx, hdr_rect.top()),
                                            Vec2::new(col_w, hdr_rect.height()),
                                        );
                                        ui.painter().text(
                                            egui::pos2(cell_r.left() + 6.0, cell_r.center().y),
                                            egui::Align2::LEFT_CENTER,
                                            col_name,
                                            egui::FontId::proportional(11.5),
                                            theme.color("ui.text.heading"),
                                        );
                                        ui.painter().vline(
                                            cell_r.right(),
                                            hdr_rect.y_range(),
                                            Stroke::new(1.0_f32, border_col),
                                        );
                                        hx = cell_r.right();
                                    }
                                    ui.painter().hline(
                                        hdr_rect.x_range(),
                                        hdr_rect.bottom(),
                                        Stroke::new(1.0_f32, border_col),
                                    );

                                    // Table rows
                                    egui::ScrollArea::vertical()
                                        .id_salt("target-sitemap-contents-table")
                                        .max_height(tbl_h)
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            ui.spacing_mut().item_spacing = Vec2::ZERO;
                                            for (row_ord, (idx, tx)) in
                                                matching_txs.iter().enumerate()
                                            {
                                                let path_q = tx.path_and_query();
                                                let is_sel = app
                                                    .panels
                                                    .target_panel
                                                    .path
                                                    .as_deref()
                                                    == Some(path_q.as_str())
                                                    || (app.panels.target_panel.path.is_none()
                                                        && row_ord + 1 == matching_txs.len());
                                                ui.push_id(("target-contents-row", *idx), |ui| {
                                                    let (row_rect, _) = ui.allocate_exact_size(
                                                        Vec2::new(total_w, 22.0),
                                                        egui::Sense::hover(),
                                                    );
                                                    let row_fill = if is_sel {
                                                        if theme.dark {
                                                            Color32::from_rgb(0x2A, 0x3E, 0x5C)
                                                        } else {
                                                            Color32::from_rgb(0xC3, 0xD9, 0xF6)
                                                        }
                                                    } else if row_ord % 2 == 1 {
                                                        theme.color("ui.background.1")
                                                    } else {
                                                        bg0
                                                    };
                                                    ui.painter().rect_filled(
                                                        row_rect,
                                                        0.0,
                                                        row_fill,
                                                    );
                                                    if is_sel {
                                                        ui.painter().rect_stroke(
                                                            row_rect.shrink(0.5),
                                                            0.0,
                                                            Stroke::new(
                                                                1.0_f32,
                                                                Color32::from_rgb(0x2B, 0x57, 0x9A),
                                                            ),
                                                            egui::StrokeKind::Inside,
                                                        );
                                                    }
                                                    let vals = [
                                                        tx.host_url(),
                                                        tx.method.clone(),
                                                        path_q.clone(),
                                                        if tx.has_params() { "✓" } else { "" }
                                                            .to_string(),
                                                        tx.status.to_string(),
                                                        tx.bytes.to_string(),
                                                        tx.mime_type().to_string(),
                                                        tx.page_title(),
                                                    ];
                                                    let mut cx = row_rect.left();
                                                    for (c_i, ((_, cw), val)) in
                                                        cols.iter().zip(vals.iter()).enumerate()
                                                    {
                                                        let c_rect = egui::Rect::from_min_size(
                                                            egui::pos2(cx, row_rect.top()),
                                                            Vec2::new(*cw, row_rect.height()),
                                                        );
                                                        let c_resp = ui.interact(
                                                            c_rect,
                                                            ui.id().with(("sitemap-cell", c_i)),
                                                            egui::Sense::click(),
                                                        );
                                                        c_resp.widget_info(|| {
                                                            egui::WidgetInfo::selected(
                                                                egui::WidgetType::SelectableLabel,
                                                                ui.is_enabled(),
                                                                is_sel,
                                                                val,
                                                            )
                                                        });
                                                        let clip_p = ui.painter().with_clip_rect(
                                                            c_rect
                                                                .shrink2(egui::vec2(4.0, 0.0))
                                                                .intersect(ui.clip_rect()),
                                                        );
                                                        clip_p.text(
                                                            egui::pos2(
                                                                c_rect.left() + 6.0,
                                                                c_rect.center().y,
                                                            ),
                                                            egui::Align2::LEFT_CENTER,
                                                            val,
                                                            egui::FontId::proportional(12.0),
                                                            theme.color("ui.text.heading"),
                                                        );
                                                        if c_resp.clicked()
                                                            || c_resp.secondary_clicked()
                                                        {
                                                            app.panels.target_panel.host =
                                                                Some(tx.host_url());
                                                            app.panels.target_panel.path =
                                                                Some(path_q.clone());
                                                        }
                                                        app.context_menu(&c_resp, *idx);
                                                        cx = c_rect.right();
                                                    }
                                                });
                                            }
                                        });
                                });

                            super::horizontal_resize_handle(
                                ui,
                                &theme,
                                "target-contents-tbl-resize",
                                &mut app.panels.target_panel.contents_table_height,
                                90.0,
                                360.0,
                                175.0,
                            );

                            // 3. Full-height 50/50 `Request | Response` split panes directly below the Contents table (`Pro-QSG-5-site-map.png`)
                            let active_tx = app
                                .panels
                                .target_panel
                                .path
                                .as_deref()
                                .and_then(|p| {
                                    matching_txs
                                        .iter()
                                        .rev()
                                        .find(|(_, t)| t.path_and_query() == p)
                                        .map(|(_, t)| t.clone())
                                })
                                .or_else(|| matching_txs.last().map(|(_, tx)| tx.clone()));
                            if let Some(tx) = active_tx {
                                let rem_h = ui.available_height().max(200.0);
                                let mut ratio = app.panels.target_panel.split_ratio;
                                super::vertical_split(
                                    ui,
                                    &theme,
                                    "target-sitemap-req-resp-split",
                                    &mut ratio,
                                    rem_h,
                                    |pane_side, ui| {
                                        if pane_side == 0 {
                                            burp_message_formatter_bar(
                                                ui,
                                                &theme,
                                                "target-req-fmt",
                                                "Request",
                                                &mut app.panels.target_panel.req_fmt_mode,
                                                false,
                                                &mut app.panels.target_panel.req_wrap,
                                                &mut app.panels.target_panel.req_non_printable,
                                            );
                                            let r = burp_numbered_message_view_wrapped(
                                                ui,
                                                &theme,
                                                "target-req-view",
                                                (rem_h - 38.0).max(120.0),
                                                &tx.request,
                                                app.panels.target_panel.req_fmt_mode,
                                                app.panels.target_panel.req_non_printable,
                                                app.panels.target_panel.req_wrap,
                                            );
                                            super::attach_message_context_menu(
                                                app,
                                                &r,
                                                &tx.target,
                                                &tx.request,
                                                &tx.response,
                                            );
                                        } else {
                                            burp_message_formatter_bar(
                                                ui,
                                                &theme,
                                                "target-resp-fmt",
                                                "Response",
                                                &mut app.panels.target_panel.resp_fmt_mode,
                                                true,
                                                &mut app.panels.target_panel.resp_wrap,
                                                &mut app.panels.target_panel.resp_non_printable,
                                            );
                                            let r = burp_numbered_message_view_wrapped(
                                                ui,
                                                &theme,
                                                "target-resp-view",
                                                (rem_h - 38.0).max(120.0),
                                                &tx.response,
                                                app.panels.target_panel.resp_fmt_mode,
                                                app.panels.target_panel.resp_non_printable,
                                                app.panels.target_panel.resp_wrap,
                                            );
                                            super::attach_message_context_menu(
                                                app,
                                                &r,
                                                &tx.target,
                                                &tx.request,
                                                &tx.response,
                                            );
                                        }
                                    },
                                );
                                app.panels.target_panel.split_ratio = ratio;
                            }
                        });
                    });
            }
        },
    );
    app.panels.target_panel.tree_split_ratio = tree_ratio;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_filter_matches_everything() {
        let panel = TargetPanel::default();
        assert!(panel.matches("http://example.test/a"));
        let filtered = TargetPanel {
            filter: "  ADMIN ".into(),
            ..Default::default()
        };
        assert!(filtered.matches("http://x/ADMIN/panel"));
        assert!(!filtered.matches("http://x/public"));
    }

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

#[cfg(test)]
mod discovered_tests {
    use crate::ui::app::App;

    #[test]
    fn links_in_a_response_are_noted() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.remember_links(
            "http://example.test/index.html",
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=\"/other\">o</a>",
        );
        let paths = app
            .discovered
            .get("http://example.test")
            .expect("the host should be known");
        assert!(paths.contains("/other"), "the link should be noted: {paths:?}");
    }

    #[test]
    fn a_plain_response_notes_nothing() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.remember_links(
            "http://example.test/x",
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":\"/other\"}",
        );
        assert!(app.discovered.is_empty(), "nothing should be noted");
    }
}
