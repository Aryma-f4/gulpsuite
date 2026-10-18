//! Collaborator: issues a unique hostname per server-side interaction and lists what came back.
//!
//! Burp's Collaborator talks to a PortSwigger-operated server over DNS or HTTP. There is no such
//! service available here, so the panel is honest about that: it runs a **local** Collaborator
//! server instead, which gives the same workflow — generate a token, watch callbacks arrive — with
//! no external dependency. The remote mode is left unimplemented rather than faked.

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::ui::app::App;

pub fn draw(app: &mut App, ui: &mut Ui) {
    // The server thread records into a shared store, so the panel drains it every frame.
    for hit in crate::collaborator::take_hits() {
        app.panels.collaborator_hits.push(hit);
    }
    match app.view {
        0 => server(app, ui),
        _ => project(app, ui),
    }
}

fn server(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Collaborator — Server");

    label(ui, &theme, "Server");
    ui.horizontal(|ui| {
        ui.selectable_value(&mut app.panels.collaborator_local, true, "Local");
        ui.selectable_value(&mut app.panels.collaborator_local, false, "Burp Collaborator");
        if !app.panels.collaborator_local {
            muted(
                ui,
                &theme,
                "Burp's hosted server needs a PortSwigger account; not implemented here.",
            );
        }
    });

    if !app.panels.collaborator_local {
        return;
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Start").clicked() {
            if app.panels.collaborator_token.is_empty() {
                app.panels.collaborator_token = crate::collaborator::new_token();
            }
            match crate::collaborator::start() {
                Ok(port) => {
                    app.panels.collaborator_port = Some(port);
                    app.panels.collaborator_stop = false;
                    app.status = format!("Local Collaborator listening on 127.0.0.1:{port}");
                }
                Err(why) => app.status = format!("Collaborator start failed: {why}"),
            }
        }
        if ui.button("Stop").clicked() {
            crate::collaborator::stop();
            app.panels.collaborator_stop = true;
            app.panels.collaborator_port = None;
            app.status = "Collaborator stopped".into();
        }
    });

    ui.add_space(4.0);
    if app.panels.collaborator_hits.len() > crate::collaborator::MAX_HITS {
        let excess = app.panels.collaborator_hits.len() - crate::collaborator::MAX_HITS;
        app.panels.collaborator_hits.drain(..excess);
    }
    if let Some(port) = app.panels.collaborator_port {
        label(ui, &theme, "Base URL");
        ui.monospace(format!("http://127.0.0.1:{port}/{}.burpcollaborator.test", app.panels.collaborator_token));
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        label(ui, &theme, "Token");
        ui.text_edit_singleline(&mut app.panels.collaborator_token);
        if ui.button("New token").clicked() {
            app.panels.collaborator_token = crate::collaborator::new_token();
        }
    });
    muted(ui, &theme, "Any request to a generated hostname is reported below.");

    ui.add_space(6.0);
    label(ui, &theme, "Interactions");
    if app.panels.collaborator_hits.is_empty() {
        muted(ui, &theme, "None yet.");
        return;
    }
    eframe::egui::ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
        for hit in app.panels.collaborator_hits.iter().rev() {
            ui.label(eframe::egui::RichText::new(format!("{} {}", hit.method, hit.path)).monospace());
            ui.label(eframe::egui::RichText::new(format!("  from {}", hit.peer)).small().color(theme.color("ui.icon.default")));
        }
    });
}

fn project(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Collaborator — Project");
    muted(
        ui,
        &theme,
        "Burp groups Collaborator servers into projects with shared secret keys. This build runs a \\
         single local server and has no project store.",
    );
    let _ = app;
}
