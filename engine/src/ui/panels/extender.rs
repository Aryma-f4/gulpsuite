//! Extensions: a Bambda-style transform editor plus the placeholder for installed extensions.

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::ui::app::App;

#[derive(Clone)]
pub struct ExtenderPanel {
    /// A transform script, applied on demand to whichever message is selected.
    pub script: String,
    pub apply_to: BambdaTarget,
    /// When set, the script also rewrites traffic as it is sent, not just on preview.
    pub live: bool,
}

/// Which message the script acts on.
#[derive(Clone, Copy, PartialEq, Default)]
pub enum BambdaTarget {
    #[default]
    RepeaterRequest,
    RepeaterResponse,
    ProxyHistory,
}

impl Default for ExtenderPanel {
    fn default() -> Self {
        ExtenderPanel {
            script: "# Bambda-style transform script\n\
                     set_header \"X-Forwarded-For\" \"10.0.0.1\"\n\
                     remove_header \"User-Agent\""
                .into(),
            apply_to: BambdaTarget::RepeaterRequest,
            live: false,
        }
    }
}

impl ExtenderPanel {
    /// The message to actually send.
    ///
    /// With `live` set and a script present, the script rewrites the request; a broken script is
    /// reported rather than silently sending the untouched original.
    pub fn apply_live(&self, raw: &str) -> Result<String, String> {
        if !self.live || self.script.trim().is_empty() {
            return Ok(raw.to_string());
        }
        crate::bambda::apply(&self.script, raw).map_err(|e| e.to_string())
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    if app.view != 0 {
        ui.horizontal(|ui| {
            ui.label("GApp Store catalog and updates are work in progress.");
            if ui.button("Open GApp Store (WIP)").clicked() {
                app.wip.open(crate::ui::wip::WipFeature::GappStore);
            }
        });
        ui.separator();
    }
    match app.view {
        0 => bambda(app, ui),
        1 => installed(app, ui),
        _ => updates(app, ui),
    }
}

/// The script store: the scripts on disk this build can load, and the ability to save one.
///
/// Rather than require a remote extension repository and credentials, this lists the scripts in the
/// local extension folder and lets a script be saved, loaded, or removed offline.
fn updates(app: &mut App, ui: &mut Ui) {
    app.draw_update_ui(ui);
    ui.add_space(8.0);
    ui.separator();
    let theme = app.theme.clone();
    heading(ui, &theme, "Local Extension Scripts");
    ui.horizontal(|ui| {
        label(ui, &theme, "Folder");
        ui.text_edit_singleline(&mut app.panels.extender_folder);
        if ui.button("Open").clicked() {
            app.status = format!("Reading {}", app.panels.extender_folder);
        }
    });

    ui.add_space(4.0);
    let folder = app.panels.extender_folder.trim().to_string();
    let scripts = list_scripts(&folder);
    if scripts.is_empty() {
        muted(ui, &theme, "No scripts in that folder yet.");
    } else {
        eframe::egui::ScrollArea::vertical().max_height(220.0).show(ui, |ui| {
            for script in scripts.iter() {
                ui.horizontal(|ui| {
                    ui.label(eframe::egui::RichText::new(&script.name).monospace());
                    ui.label(
                        eframe::egui::RichText::new(format!("{} bytes", script.size))
                            .small()
                            .color(theme.color("ui.text.disabled")),
                    );
                    if ui.small_button("Load").clicked() {
                        match std::fs::read_to_string(&script.path) {
                            Ok(text) => {
                                app.panels.extender.script = text;
                                app.panels.extender_path = script.path.clone();
                                app.status = format!("Loaded {}", script.name);
                            }
                            Err(why) => app.status = format!("Could not read {}: {why}", script.name),
                        }
                    }
                    if ui.small_button("Delete").clicked() {
                        match std::fs::remove_file(&script.path) {
                            Ok(()) => app.status = format!("Removed {}", script.name),
                            Err(why) => app.status = format!("Could not remove {}: {why}", script.name),
                        }
                    }
                });
            }
        });
    }

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        label(ui, &theme, "Save current script as");
        ui.text_edit_singleline(&mut app.panels.extender_new_name);
        if ui.button("Save").clicked() {
            let name = app.panels.extender_new_name.trim().to_string();
            match save_script(&folder, &name, &app.panels.extender.script) {
                Ok(path) => {
                    app.panels.extender_path = path.clone();
                    app.status = format!("Saved {path}");
                }
                Err(why) => app.status = format!("Could not save: {why}"),
            }
        }
    });
}

/// One script found in the extension folder.
pub struct Script {
    pub name: String,
    pub path: String,
    pub size: u64,
}

/// The scripts in `folder`, sorted by name. An unreadable folder yields an empty list.
pub fn list_scripts(folder: &str) -> Vec<Script> {
    if folder.trim().is_empty() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("bambda") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        out.push(Script {
            name: path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string(),
            path: path.to_string_lossy().to_string(),
            size: meta.len(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Writes a script into the folder, refusing a name that would escape it.
pub fn save_script(folder: &str, name: &str, source: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a name is needed".into());
    }
    if name.contains('/') || name.contains("..") {
        return Err("a script name cannot contain a path".into());
    }
    let file = if name.ends_with(".bambda") {
        name.to_string()
    } else {
        format!("{name}.bambda")
    };
    let folder = std::path::Path::new(folder);
    std::fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    let path = folder.join(file);
    std::fs::write(&path, source).map_err(|e| e.to_string())?;
    Ok(path.to_string_lossy().to_string())
}

/// The transform editor, with a live preview.
///
/// Gulp's Bambda runs on messages passing through the proxy; this runs on demand so a script can be
/// checked against a real message before it is trusted with live traffic.
fn bambda(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Bambda — transform scripts");

    ui.horizontal(|ui| {
        label(ui, &theme, "Target");
        for (name, target) in [
            ("Repeater request", BambdaTarget::RepeaterRequest),
            ("Repeater response", BambdaTarget::RepeaterResponse),
            ("Proxy history", BambdaTarget::ProxyHistory),
        ] {
            if ui
                .selectable_label(app.panels.extender.apply_to == target, name)
                .clicked()
            {
                app.panels.extender.apply_to = target;
            }
        }
    });

    ui.horizontal(|ui| {
        label(ui, &theme, "Live traffic");
        if ui
            .checkbox(&mut app.panels.extender.live, "rewrite requests as they are sent")
            .changed()
        {
            app.status = if app.panels.extender.live {
                "Bambda is live: Repeater requests will be rewritten".into()
            } else {
                "Bambda is preview only".to_string()
            };
        }
    });
    if app.panels.extender.live {
        muted(ui, &theme, "Requests leaving the Repeater run through the script. A broken script blocks the send.");
    }

    ui.add_space(4.0);
    muted(
        ui,
        &theme,
        "Statements: replace, replace_first, replace_body, regex, set_header, remove_header. \
         Values are quoted; backslash escapes are kept so regex classes work.",
    );
    let source = match app.panels.extender.apply_to {
        BambdaTarget::RepeaterRequest => app.panels.repeater.active().raw.clone(),
        BambdaTarget::RepeaterResponse => app.panels.repeater.active().response.clone(),
        BambdaTarget::ProxyHistory => app
            .log
            .back()
            .map(|tx| tx.response.clone())
            .unwrap_or_default(),
    };

    ui.add_space(6.0);
    let pane_h = (ui.available_height() - 28.0).max(220.0);
    ui.columns(2, |columns| {
        eframe::egui::Frame::new()
            .fill(theme.color("ui.background.1"))
            .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
            .inner_margin(eframe::egui::Margin::symmetric(10, 8))
            .show(&mut columns[0], |ui| {
                label(ui, &theme, "Bambda Script");
                ui.add_space(4.0);
                ui.add(
                    eframe::egui::TextEdit::multiline(&mut app.panels.extender.script)
                        .font(eframe::egui::TextStyle::Monospace)
                        .desired_rows(12)
                        .desired_width(f32::INFINITY),
                );
            });

        eframe::egui::Frame::new()
            .fill(theme.color("ui.background.1"))
            .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
            .inner_margin(eframe::egui::Margin::symmetric(10, 8))
            .show(&mut columns[1], |ui| {
                if source.trim().is_empty() {
                    muted(ui, &theme, "No source message selected.");
                    return;
                }
                match crate::bambda::apply(&app.panels.extender.script, &source) {
                    Ok(output) => {
                        label(
                            ui,
                            &theme,
                            if output == source {
                                "Preview: unchanged"
                            } else {
                                "Preview"
                            },
                        );
                        ui.add_space(4.0);
                        let _ = super::gulp_numbered_message_view_wrapped(
                            ui,
                            &theme,
                            "bambda-preview-msg",
                            (pane_h - 36.0).max(160.0),
                            &output,
                            0,
                            false,
                            true,
                        );
                    }
                    Err(error) => {
                        ui.label(
                            eframe::egui::RichText::new(format!("Script error — {error}"))
                                .color(theme.color("ui.icon.error")),
                        );
                    }
                }
            });
    });
}

/// Installed extensions view.
fn installed(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    ui.horizontal(|ui| {
        ui.label("Total estimated system impact:");
        ui.label(
            eframe::egui::RichText::new("None")
                .strong()
                .color(theme.color("ui.text.body")),
        );
    });
    ui.separator();
    heading(ui, &theme, "Gulp extensions");
    muted(
        ui,
        &theme,
        "Extensions let you customize Gulp's behavior using your own or third-party code.",
    );
    ui.add_space(4.0);
    eframe::egui::Grid::new("installed-extensions-grid")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            for col in ["Loaded", "Type", "Name", "System impact"] {
                ui.label(
                    eframe::egui::RichText::new(col)
                        .strong()
                        .color(theme.color("ui.text.body")),
                );
            }
            ui.end_row();
            let mut live = app.panels.extender.live;
            if ui.checkbox(&mut live, "").changed() {
                app.panels.extender.live = live;
            }
            ui.label("Bambda");
            ui.label("Active transform script");
            ui.label("Low");
            ui.end_row();
            for script in list_scripts(&app.panels.extender_folder) {
                ui.label("✓");
                ui.label("Bambda");
                ui.label(eframe::egui::RichText::new(&script.name).monospace());
                ui.label("Low");
                ui.end_row();
            }
        });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Load script into editor").clicked() {
            let path = app.panels.extender_path.clone();
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    app.panels.extender.script = text;
                    app.status = format!("Loaded {path}");
                }
                Err(why) => app.status = format!("Could not read {path}: {why}"),
            }
        }
    });
    label(ui, &theme, "Script path");
    ui.text_edit_singleline(&mut app.panels.extender_path);

    let path = app.panels.extender_path.clone();
    if !path.is_empty() {
        match std::fs::metadata(&path) {
            Ok(meta) => muted(
                ui,
                &theme,
                &format!("{} bytes on disk", meta.len()),
            ),
            Err(_) => muted(ui, &theme, "Not on disk yet. Save your script there to reuse it."),
        }
    }

    ui.add_space(6.0);
    muted(
        ui,
        &theme,
        "Gulp loads third-party code through its extension API (Rust, Python and Bambda). This \
         build ships the Bambda transform language only; there is no loader for compiled extensions.",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST: &str = "GET /a HTTP/1.1\r\nHost: example.test\r\nUser-Agent: probe\r\n\r\n";

    #[test]
    fn a_panel_that_is_not_live_leaves_the_message_alone() {
        let panel = ExtenderPanel::default();
        assert_eq!(panel.apply_live(REQUEST).unwrap(), REQUEST);
    }

    #[test]
    fn a_live_script_rewrites_the_message() {
        let panel = ExtenderPanel {
            script: "set_header \"X-Test\" \"1\"\nremove_header \"User-Agent\"".into(),
            live: true,
            ..Default::default()
        };
        let out = panel.apply_live(REQUEST).unwrap();
        assert!(out.contains("X-Test: 1"), "{out}");
        assert!(!out.contains("User-Agent"), "{out}");
    }

    #[test]
    fn a_broken_script_blocks_the_send() {
        let panel = ExtenderPanel {
            script: "set_header \"X-Test\"".into(),
            live: true,
            ..Default::default()
        };
        let result = panel.apply_live(REQUEST);
        assert!(result.is_err(), "a malformed script must not pass through");
    }

    #[test]
    fn an_empty_script_is_ignored_even_when_live() {
        let panel = ExtenderPanel { script: "   \n ".into(), live: true, ..Default::default() };
        assert_eq!(panel.apply_live(REQUEST).unwrap(), REQUEST);
    }
}

#[cfg(test)]
mod script_store_tests {
    use super::*;

    fn temp_folder(tag: &str) -> String {
        let base = std::env::temp_dir().join(format!("gulpsuite-ext-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        base.to_string_lossy().to_string()
    }

    #[test]
    fn a_saved_script_is_listed_again() {
        let folder = temp_folder("list");
        let path = save_script(&folder, "demo", "set_header \"X\" \"1\"\n").expect("save");
        assert!(path.ends_with("demo.bambda"), "{path}");
        let scripts = list_scripts(&folder);
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].name, "demo.bambda");
        assert!(scripts[0].size > 0);
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn only_bambda_files_are_listed() {
        let folder = temp_folder("filter");
        save_script(&folder, "good", "x").expect("save");
        std::fs::write(std::path::Path::new(&folder).join("notes.txt"), "ignored").expect("write");
        let scripts = list_scripts(&folder);
        assert_eq!(scripts.len(), 1);
        assert_eq!(scripts[0].name, "good.bambda");
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn a_name_cannot_escape_the_folder() {
        let folder = temp_folder("escape");
        assert!(save_script(&folder, "../outside", "x").is_err());
        assert!(save_script(&folder, "sub/dir", "x").is_err());
        assert!(save_script(&folder, "  ", "x").is_err());
        let _ = std::fs::remove_dir_all(&folder);
    }

    #[test]
    fn an_unreadable_folder_lists_nothing() {
        assert!(list_scripts("").is_empty());
        assert!(list_scripts("/definitely/not/here").is_empty());
    }

    #[test]
    fn a_saved_script_can_be_read_back() {
        let folder = temp_folder("readback");
        let source = "replace \"a\" \"b\"\n";
        let path = save_script(&folder, "round", source).expect("save");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
        let _ = std::fs::remove_dir_all(&folder);
    }
}
