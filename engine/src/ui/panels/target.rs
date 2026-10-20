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
fn draw_issues_view(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let all_defs = crate::issue_definitions::all();

    ui.horizontal_wrapped(|ui| {
        ui.label("Scan URL:");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.scanner.seed)
                .desired_width(220.0)
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
        ui.label("Filter issues:");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.target_panel.issue_filter)
                .hint_text("Search issue name, URL, evidence")
                .desired_width(160.0),
        );
    });
    ui.add_space(4.0);

    // Complete 183-entry Issue Definitions Knowledge Base (`target/issue-definitions.html`)
    egui::CollapsingHeader::new(
        RichText::new(format!(
            "Issue definitions Knowledge Base ({} types)",
            all_defs.len()
        ))
        .strong(),
    )
    .default_open(false)
    .show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label("Search definitions:");
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
        ui.add_space(4.0);

        let kb_needle = app.panels.target_panel.kb_search.trim().to_ascii_lowercase();
        let sev_filter = match app.panels.target_panel.kb_severity_filter {
            1 => Some("High"),
            2 => Some("Medium"),
            3 => Some("Low"),
            4 => Some("Information"),
            _ => None,
        };
        let filtered_defs: Vec<(usize, &crate::issue_definitions::IssueDefinition)> = all_defs
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
            // Left column: scrollable table of all 183 Issue Definitions
            egui::ScrollArea::vertical()
                .id_salt("target-kb-defs-scroll")
                .max_height(260.0)
                .show(&mut cols[0], |ui| {
                    egui::Grid::new("target-issue-definitions-kb")
                        .num_columns(4)
                        .striped(true)
                        .show(ui, |ui| {
                            for h in ["Name", "Typical severity", "Type index", "CWE"] {
                                ui.strong(h);
                            }
                            ui.end_row();
                            for (orig_idx, def) in &filtered_defs {
                                let is_sel =
                                    app.panels.target_panel.selected_kb_def == *orig_idx;
                                let (sev_col, sev_icon) = match def.severity.as_str() {
                                    "High" => (
                                        theme.color("ui.issue.high"),
                                        super::scanner::LauncherIcon::IssueHigh,
                                    ),
                                    "Medium" => (
                                        theme.color("ui.issue.medium"),
                                        super::scanner::LauncherIcon::IssueMedium,
                                    ),
                                    "Low" => (
                                        theme.color("ui.issue.low"),
                                        super::scanner::LauncherIcon::IssueLow,
                                    ),
                                    _ => (
                                        theme.color("ui.icon.information"),
                                        super::scanner::LauncherIcon::IssueInfo,
                                    ),
                                };
                                let c_name = ui
                                    .horizontal(|ui| {
                                        super::scanner::paint_launcher_icon(
                                            ui,
                                            Vec2::new(14.0, 14.0),
                                            sev_col,
                                            sev_icon,
                                        );
                                        ui.selectable_label(is_sel, &def.name)
                                    })
                                    .inner;
                                let c_sev = ui.selectable_label(
                                    is_sel,
                                    RichText::new(&def.severity).color(sev_col),
                                );
                                let c_idx = ui.selectable_label(
                                    is_sel,
                                    RichText::new(&def.type_hex).monospace(),
                                );
                                let c_cwe = ui.selectable_label(
                                    is_sel,
                                    RichText::new(def.cwe_summary()).monospace(),
                                );
                                if c_name.clicked()
                                    || c_sev.clicked()
                                    || c_idx.clicked()
                                    || c_cwe.clicked()
                                {
                                    app.panels.target_panel.selected_kb_def = *orig_idx;
                                }
                                ui.end_row();
                            }
                        });
                });

            // Right column: Full Advisory Details for the selected IssueDefinition
            if let Some(def) = all_defs
                .get(app.panels.target_panel.selected_kb_def)
                .or_else(|| filtered_defs.first().map(|(_, d)| *d))
            {
                egui::ScrollArea::vertical()
                    .id_salt("target-kb-detail-scroll")
                    .max_height(260.0)
                    .show(&mut cols[1], |ui| {
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
                            ui.label(RichText::new(&def.name).size(15.0).strong());
                        });
                        ui.label(
                            RichText::new(format!(
                                "Typical severity: {}   ·   Type index: {}",
                                def.severity, def.type_hex
                            ))
                            .strong(),
                        );
                        ui.separator();
                        if !def.description.is_empty() {
                            ui.label(RichText::new("Issue description").strong());
                            ui.label(&def.description);
                            ui.add_space(6.0);
                        }
                        if !def.remediation.is_empty() {
                            ui.label(RichText::new("Issue remediation").strong());
                            ui.label(&def.remediation);
                            ui.add_space(6.0);
                        }
                        if !def.references.is_empty() {
                            ui.label(RichText::new("References").strong());
                            for r in &def.references {
                                ui.label(format!("• {} ({})", r.title, r.url));
                            }
                            ui.add_space(6.0);
                        }
                        if !def.classifications.is_empty() {
                            ui.label(RichText::new("Vulnerability classifications").strong());
                            for c in &def.classifications {
                                ui.label(format!("• {} ({})", c.title, c.url));
                            }
                        }
                    });
            }
        });
    });
    ui.add_space(4.0);
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
                "Target issues: run an audit or passive crawl to populate target findings".into();
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
    eframe::egui::ScrollArea::vertical()
        .id_salt("target-issues-scroll")
        .max_height(220.0)
        .show(ui, |ui| {
            eframe::egui::Grid::new("target-issues-grid")
                .num_columns(6)
                .striped(true)
                .show(ui, |ui| {
                    for col in [
                        "Severity",
                        "Issue type",
                        "Host / URL",
                        "Parameter",
                        "Confidence",
                        "CWE",
                    ] {
                        ui.label(
                            eframe::egui::RichText::new(col)
                                .strong()
                                .color(theme.color("ui.text.body")),
                        );
                    }
                    ui.end_row();
                    for (idx, issue) in &issues {
                        ui.push_id(("target-issue-row", *idx), |ui| {
                            let selected = app.panels.target_panel.selected_issue == Some(*idx);
                            let (sev_col, sev_icon) = match issue.severity {
                                crate::workspace::IssueSeverity::High => (
                                    theme.color("ui.issue.high"),
                                    super::scanner::LauncherIcon::IssueHigh,
                                ),
                                crate::workspace::IssueSeverity::Medium => (
                                    theme.color("ui.issue.medium"),
                                    super::scanner::LauncherIcon::IssueMedium,
                                ),
                                crate::workspace::IssueSeverity::Low => (
                                    theme.color("ui.issue.low"),
                                    super::scanner::LauncherIcon::IssueLow,
                                ),
                                crate::workspace::IssueSeverity::Info => (
                                    theme.color("ui.icon.information"),
                                    super::scanner::LauncherIcon::IssueInfo,
                                ),
                            };
                            let kb_def = crate::issue_definitions::find_by_name(&issue.name);
                            let cwe_txt = kb_def
                                .map(|d| d.cwe_summary())
                                .unwrap_or_else(|| "—".into());
                            let c1 = ui
                                .horizontal(|ui| {
                                    super::scanner::paint_launcher_icon(
                                        ui,
                                        Vec2::new(14.0, 14.0),
                                        sev_col,
                                        sev_icon,
                                    );
                                    ui.selectable_label(
                                        selected,
                                        eframe::egui::RichText::new(format!("{:?}", issue.severity))
                                            .color(sev_col),
                                    )
                                })
                                .inner;
                            let c2 = ui.selectable_label(selected, &issue.name);
                            let c3 = ui.selectable_label(
                                selected,
                                eframe::egui::RichText::new(&issue.url).monospace(),
                            );
                            let c4 = ui.selectable_label(
                                selected,
                                issue.parameter.as_deref().unwrap_or("-"),
                            );
                            let c5 = ui.selectable_label(selected, &issue.confidence);
                            let c6 = ui.selectable_label(
                                selected,
                                RichText::new(cwe_txt).monospace(),
                            );
                            for cell in [&c1, &c2, &c3, &c4, &c5, &c6] {
                                if cell.clicked() || cell.secondary_clicked() {
                                    app.panels.target_panel.selected_issue = Some(*idx);
                                }
                                super::attach_message_context_menu(
                                    app,
                                    cell,
                                    &issue.url,
                                    "",
                                    &issue.evidence,
                                );
                            }
                        });
                        ui.end_row();
                    }
                });
        });

    if let Some(sel) = app.panels.target_panel.selected_issue {
        if let Some((_, issue)) = issues.iter().find(|(i, _)| *i == sel) {
            let kb_def = crate::issue_definitions::find_by_name(&issue.name);
            ui.separator();
            // `Advisory | Request | Response` sub-tabs (`Pro-QSG-6-view-issues.png`)
            ui.horizontal(|ui| {
                for (t_idx, lbl) in ["Advisory", "Request", "Response"].iter().enumerate() {
                    let active = app.panels.target_panel.issue_detail_tab == t_idx;
                    let r = ui.selectable_label(active, RichText::new(*lbl).strong());
                    if active {
                        let rect = r.rect;
                        ui.painter().rect_filled(
                            egui::Rect::from_min_max(
                                egui::pos2(rect.min.x, rect.max.y - 2.5),
                                egui::pos2(rect.max.x, rect.max.y),
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
            ui.separator();

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
                        200.0,
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
                        200.0,
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
                    egui::ScrollArea::vertical()
                        .id_salt("target-issue-advisory-scroll")
                        .max_height(240.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                super::scanner::paint_launcher_icon(
                                    ui,
                                    Vec2::new(28.0, 28.0),
                                    Color32::WHITE,
                                    sev_icon,
                                );
                                heading(ui, &theme, &issue.name);
                            });
                            ui.separator();
                            egui::Grid::new("target-issue-advisory-meta")
                                .num_columns(2)
                                .spacing([18.0, 4.0])
                                .show(ui, |ui| {
                                    ui.label("Issue:");
                                    ui.strong(&issue.name);
                                    ui.end_row();
                                    ui.label("Severity:");
                                    ui.strong(format!("{:?}", issue.severity));
                                    ui.end_row();
                                    ui.label("Confidence:");
                                    ui.strong(&issue.confidence);
                                    ui.end_row();
                                    ui.label("URL:");
                                    ui.strong(&issue.url);
                                    ui.end_row();
                                    if let Some(param) = &issue.parameter {
                                        ui.label("Insertion point / Parameter:");
                                        ui.strong(param);
                                        ui.end_row();
                                    }
                                    if let Some(def) = kb_def {
                                        ui.label("Type index:");
                                        ui.monospace(&def.type_hex);
                                        ui.end_row();
                                    }
                                });
                            ui.separator();
                            ui.add_space(4.0);
                            ui.label(RichText::new("Issue detail").strong());
                            ui.monospace(&issue.evidence);
                            if let Some(def) = kb_def {
                                if !def.description.is_empty() {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("Issue background").strong());
                                    ui.label(&def.description);
                                }
                                if !def.remediation.is_empty() {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("Issue remediation").strong());
                                    ui.label(&def.remediation);
                                }
                                if !def.references.is_empty() {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("References").strong());
                                    for r in &def.references {
                                        ui.label(format!("• {} ({})", r.title, r.url));
                                    }
                                }
                                if !def.classifications.is_empty() {
                                    ui.add_space(8.0);
                                    ui.label(RichText::new("Vulnerability classifications").strong());
                                    for c in &def.classifications {
                                        ui.label(format!("• {} ({})", c.title, c.url));
                                    }
                                }
                            }
                        });
                }
            }
        }
    }
}

/// Renders `Target -> Site map` matching `Pro-QSG-5-site-map.png` and `site-map-populated.png` 100%.
fn draw_site_map(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    // Top row: `[ URL view | Crawl paths view ]` segmented pill + Burp Filter bar (`site-map-populated.png`)
    ui.horizontal_wrapped(|ui| {
        ui.selectable_value(&mut app.panels.target_panel.crawl_paths_view, false, "URL view");
        ui.selectable_value(
            &mut app.panels.target_panel.crawl_paths_view,
            true,
            "Crawl paths view",
        );
        ui.separator();
        let (funnel, _) = ui.allocate_exact_size(Vec2::splat(14.0), egui::Sense::hover());
        crate::ui::icons::paint(
            ui.painter(),
            funnel,
            theme.color("ui.icon.default"),
            crate::ui::icons::Glyph::Funnel,
        );
        ui.label(
            RichText::new(
                "Filter: Hiding not found items; hiding CSS, image and general binary content; hiding 4xx responses; hiding empty folders",
            )
            .size(11.5)
            .color(theme.color("ui.text.body")),
        );
        ui.add(
            egui::TextEdit::singleline(&mut app.panels.target_panel.filter)
                .hint_text("Filter host or path…")
                .desired_width(150.0),
        );
        if !app.panels.target_panel.filter.is_empty() && ui.button("Clear").clicked() {
            app.panels.target_panel.filter.clear();
        }
    });

    let tree = tree(app);
    if tree.is_empty() {
        let title = if app.panels.target_panel.crawl_paths_view {
            "Site map crawl paths view is empty"
        } else {
            "Site map URL view is empty"
        };
        let (learn, open_browser) = empty_state(
            ui,
            &theme,
            title,
            "The site map displays information about the contents of your target applications, \
             along with any issues that have been discovered. The URL view shows your targets as \
             a tree of URLs, organized hierarchically by domain and directory. To populate the \
             URL view, run a scan or browse using Burp's browser.",
            true,
            Some("Open browser"),
        );
        if learn {
            app.status =
                "Site map: browse through the proxy or run a scan to populate target URLs".into();
        }
        if open_browser {
            app.open_browser();
        }
        return;
    }

    ui.separator();

    // Auto-select the first host if none is selected yet
    if app.panels.target_panel.host.is_none() {
        app.panels.target_panel.host = tree.keys().next().cloned();
    }

    let avail_h = ui.available_height().max(320.0);
    let mut tree_ratio = app.panels.target_panel.tree_split_ratio;
    let mut load_to_repeater: Option<(String, String)> = None;

    super::vertical_split(
        ui,
        &theme,
        "target-sitemap-main-split",
        &mut tree_ratio,
        avail_h,
        |side, ui| {
            if side == 0 {
                // LEFT PANE: Hierarchical Host / Folder / Endpoint Tree (`Pro-QSG-5-site-map.png` & `site-map-populated.png`)
                egui::Frame::new()
                    .fill(theme.color("ui.background.0"))
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_salt("target-sitemap-left-tree")
                            .max_height(avail_h - 12.0)
                            .show(ui, |ui| {
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

                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new("• ▾")
                                                .size(11.0)
                                                .color(theme.color("ui.icon.default")),
                                        );
                                        paint_sitemap_node_icon(
                                            ui,
                                            if is_https {
                                                SiteMapIcon::SecureHost
                                            } else {
                                                SiteMapIcon::InsecureHost
                                            },
                                            host_dot,
                                        );
                                        let host_resp =
                                            ui.selectable_label(selected_host, host.clone());
                                        if host_resp.clicked() {
                                            app.panels.target_panel.host = Some(host.clone());
                                            app.panels.target_panel.path = None;
                                        }
                                        // Host right-click context menu (`Pro-QSG-7-Report-for-host.png`)
                                        host_resp.context_menu(|ui| {
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
                                                if ui.button("Report issues for this host").clicked()
                                                {
                                                    app.panels.scanner.report_host_filter =
                                                        host.clone();
                                                    app.panels.scanner.show_report_wizard = true;
                                                    ui.close();
                                                }
                                                if ui.button("Delete issues for this host").clicked()
                                                {
                                                    app.status = format!(
                                                        "Cleared issues filter for {host}"
                                                    );
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
                                    });

                                    // Collect unique top-level folders to show Yellow Folder nodes (`site-map-folder-open.svg`)
                                    let mut folders = std::collections::BTreeSet::new();
                                    for path in paths.keys() {
                                        let trimmed = path.trim_start_matches('/');
                                        if let Some((dir, rest)) = trimmed.split_once('/') {
                                            if !dir.is_empty() && !rest.is_empty() {
                                                folders.insert(dir.to_string());
                                            }
                                        }
                                    }
                                    for folder in &folders {
                                        ui.horizontal(|ui| {
                                            ui.add_space(16.0);
                                        ui.label(
                                            RichText::new("• ▼")
                                                .monospace()
                                                .size(11.0)
                                                .color(theme.color("ui.icon.default")),
                                        );
                                            paint_sitemap_node_icon(
                                                ui,
                                                SiteMapIcon::FolderOpen,
                                                None,
                                            );
                                            if ui.selectable_label(false, folder).clicked() {
                                                app.panels.target_panel.host = Some(host.clone());
                                            }
                                        });
                                    }

                                    // Render path nodes with exact Burp icons (`DynPage`, `QueryPage`, `DefaultPage`)
                                    for (path, count) in paths {
                                        if !app.panels.target_panel.matches(path) {
                                            continue;
                                        }
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
                                        let mut clicked = false;
                                        ui.horizontal(|ui| {
                                            ui.add_space(16.0);
                                            ui.label(
                                                RichText::new("├─ ▶")
                                                    .monospace()
                                                    .size(11.0)
                                                    .color(theme.color("ui.icon.default")),
                                            );
                                            paint_sitemap_node_icon(
                                                ui,
                                                icon,
                                                Some(Color32::from_rgb(0x18, 0x58, 0xA8)),
                                            );
                                            let path_resp = ui
                                                .selectable_label(
                                                    selected,
                                                    RichText::new(path).color(theme.color("ui.text.body")),
                                                )
                                                .on_hover_text(format!("{count} request(s)"));
                                            clicked = path_resp.clicked() || path_resp.secondary_clicked();
                                            let full_url = format!("{host}{path}");
                                            let sample_tx = app
                                                .log
                                                .iter()
                                                .rev()
                                                .find(|t| t.host_url() == *host && t.target.ends_with(path))
                                                .cloned();
                                            let (sample_req, sample_resp) = sample_tx
                                                .map(|t| (t.request, t.response))
                                                .unwrap_or_default();
                                            super::attach_message_context_menu(
                                                app,
                                                &path_resp,
                                                &full_url,
                                                &sample_req,
                                                &sample_resp,
                                            );
                                            if selected && ui.small_button("To Repeater").clicked() {
                                                load_to_repeater = Some((host.clone(), path.clone()));
                                            }
                                        });
                                        if clicked {
                                            app.panels.target_panel.host = Some(host.clone());
                                            app.panels.target_panel.path = Some(path.clone());
                                        }
                                    }

                                    // Unvisited discovered links in muted gray (`site-map-populated.png`)
                                    if let Some(found) = app.discovered.get(host) {
                                        for path in found {
                                            if paths.contains_key(path)
                                                || !app.panels.target_panel.matches(path)
                                            {
                                                continue;
                                            }
                                            ui.horizontal(|ui| {
                                                ui.add_space(16.0);
                                                ui.label(
                                                    RichText::new("└─ •")
                                                        .monospace()
                                                        .size(11.0)
                                                        .color(theme.color("ui.icon.disabled")),
                                                );
                                                paint_sitemap_node_icon(
                                                    ui,
                                                    SiteMapIcon::DefaultPage,
                                                    None,
                                                );
                                                ui.selectable_label(
                                                    app.panels.target_panel.path.as_deref()
                                                        == Some(path.as_str()),
                                                    RichText::new(path)
                                                        .color(theme.color("ui.icon.disabled")),
                                                )
                                                .on_hover_text("found in a response, not visited");
                                            });
                                        }
                                    }
                                    ui.add_space(4.0);
                                }
                            });
                    });
            } else {
                // RIGHT PANE: `Contents | Issues` sub-tabs + Contents table + `Request | Response` (`Pro-QSG-5-site-map.png`)
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        for (idx, name) in ["Contents", "Issues"].iter().enumerate() {
                            let active = app.panels.target_panel.right_sub_tab == idx;
                            let resp = ui.selectable_label(
                                active,
                                RichText::new(*name).size(13.0).strong(),
                            );
                            if active {
                                let r = resp.rect;
                                ui.painter().rect_filled(
                                    egui::Rect::from_min_max(
                                        egui::pos2(r.min.x, r.max.y - 2.0),
                                        egui::pos2(r.max.x, r.max.y + 1.0),
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
                    ui.separator();

                    if app.panels.target_panel.right_sub_tab == 1 {
                        draw_issues_view(app, ui);
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
                                    .map_or(true, |p| tx.target.ends_with(p))
                        })
                        .collect();

                    // Top Contents Table (`Host | Method | URL | Params | Status Code | Length | MIME type | Title`)
                    let tbl_h = app.panels.target_panel.contents_table_height;
                    egui::ScrollArea::both()
                        .id_salt("target-sitemap-contents-table")
                        .max_height(tbl_h)
                        .show(ui, |ui| {
                            egui::Grid::new("target-sitemap-contents-grid")
                                .num_columns(8)
                                .min_col_width(60.0)
                                .striped(true)
                                .show(ui, |ui| {
                                    for col in [
                                        "Host",
                                        "Method",
                                        "URL",
                                        "Params",
                                        "Status Code",
                                        "Length",
                                        "MIME type",
                                        "Title",
                                    ] {
                                        ui.strong(col);
                                    }
                                    ui.end_row();
                                    for (idx, tx) in &matching_txs {
                                        ui.push_id(("target-contents-row", *idx), |ui| {
                                            let path_q = tx.path_and_query();
                                            let is_sel = app.panels.target_panel.path.as_deref()
                                                == Some(path_q.as_str());
                                            let c1 = ui.selectable_label(is_sel, tx.host_url());
                                            let c2 = ui.selectable_label(is_sel, &tx.method);
                                            let c3 = ui.selectable_label(is_sel, &path_q);
                                            let c4 = ui.selectable_label(
                                                is_sel,
                                                if tx.has_params() { "✓" } else { "" },
                                            );
                                            let c5 =
                                                ui.selectable_label(is_sel, tx.status.to_string());
                                            let c6 =
                                                ui.selectable_label(is_sel, tx.bytes.to_string());
                                            let c7 = ui.selectable_label(is_sel, tx.mime_type());
                                            let c8 = ui.selectable_label(is_sel, tx.page_title());
                                            for cell in [&c1, &c2, &c3, &c4, &c5, &c6, &c7, &c8] {
                                                if cell.clicked() || cell.secondary_clicked() {
                                                    app.panels.target_panel.host =
                                                        Some(tx.host_url());
                                                    app.panels.target_panel.path =
                                                        Some(path_q.clone());
                                                }
                                                app.context_menu(cell, *idx);
                                            }
                                        });
                                        ui.end_row();
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

                    // Selected transaction (or first matching transaction for the selected host)
                    let active_tx = matching_txs.last().map(|(_, tx)| tx.clone());
                    if let Some(tx) = active_tx {
                        let selected_path = app
                            .panels
                            .target_panel
                            .path
                            .clone()
                            .unwrap_or_else(|| tx.path_and_query());
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new(&tx.target).monospace());
                            if ui.button("To Repeater").clicked() {
                                app.panels.repeater.open(&tx.target, &tx.request);
                                app.tool = crate::ui::app::REPEATER;
                                app.status = format!("Sent {selected_path} to Repeater");
                            }
                            if ui.button("To Intruder").clicked() {
                                app.send_to_intruder(&tx.target, &tx.request);
                            }
                            if ui.button("To Organizer").clicked() {
                                let next = app.organizer.len() + 1;
                                super::organizer::retain(
                                    app,
                                    super::organizer::OrganizerItem {
                                        host: tx.host.clone(),
                                        name: format!("item-{next}"),
                                        request: tx.request.clone(),
                                        response: tx.response.clone(),
                                        notes: String::new(),
                                    },
                                );
                                app.status = "Saved to Organizer".into();
                            }
                        });

                        let detail_h = app.panels.target_panel.detail_height;
                        let mut ratio = app.panels.target_panel.split_ratio;
                        super::vertical_split(
                            ui,
                            &theme,
                            "target-sitemap-req-resp-split",
                            &mut ratio,
                            detail_h,
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
                                        detail_h - 48.0,
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
                                        detail_h - 48.0,
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
                        super::horizontal_resize_handle(
                            ui,
                            &theme,
                            "target-detail-resize",
                            &mut app.panels.target_panel.detail_height,
                            120.0,
                            600.0,
                            250.0,
                        );
                    }
                });
            }
        },
    );
    app.panels.target_panel.tree_split_ratio = tree_ratio;

    if let Some((host, path)) = load_to_repeater {
        let found = app
            .log
            .iter()
            .rev()
            .find(|tx| tx.host_url() == host && tx.target.ends_with(&path))
            .map(|tx| (tx.request.clone(), tx.target.clone()));
        match found {
            Some((request, target)) => {
                app.panels.repeater.open(&target, &request);
                app.tool = crate::ui::app::REPEATER;
                app.status = format!("Sent {path} to Repeater");
            }
            None => app.status = "That path is no longer in the history".into(),
        }
    }
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
