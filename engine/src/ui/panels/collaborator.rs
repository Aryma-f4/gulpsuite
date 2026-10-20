//! Collaborator: Burp Collaborator payload generator, polling controls, protocol filters,
//! CSV export, and interaction table backed by the local HTTP + DNS Collaborator listeners.

use eframe::egui::Ui;

use super::{empty_state, heading, label, muted};
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

fn generate_payloads(app: &App, count: usize, include_location: bool) -> Vec<String> {
    let base_tok = if app.panels.collaborator_token.trim().is_empty() {
        crate::collaborator::new_token()
    } else {
        app.panels.collaborator_token.trim().to_string()
    };
    (0..count.clamp(1, 50))
        .map(|i| {
            let tok = if i == 0 {
                base_tok.clone()
            } else {
                format!("{base_tok}-{i}")
            };
            let host = format!("{tok}.{}", crate::collaborator::DOMAIN);
            if include_location {
                if let Some(port) = app.panels.collaborator_port {
                    format!("http://127.0.0.1:{port}/{host}")
                } else {
                    host
                }
            } else {
                host
            }
        })
        .collect()
}

fn server(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    ui.horizontal(|ui| {
        super::scanner::paint_launcher_icon(
            ui,
            eframe::egui::Vec2::new(18.0, 18.0),
            theme.color("ui.icon.accent"),
            super::scanner::LauncherIcon::ScanType,
        );
        heading(ui, &theme, "Payload generator");
    });
    muted(
        ui,
        &theme,
        "Generate Collaborator payloads to insert into requests, then poll to observe out-of-band DNS and HTTP callbacks.",
    );
    ui.add_space(4.0);

    ui.horizontal_wrapped(|ui| {
        if crate::ui::app::primary_button(ui, &theme, "Copy to clipboard").clicked() {
            let payloads = generate_payloads(app, 1, app.panels.collaborator_local);
            let joined = payloads.join("\n");
            ui.ctx().copy_text(joined.clone());
            app.status = format!("Copied Collaborator payload to clipboard: {joined}");
        }
        if ui.button("New token").clicked() {
            app.panels.collaborator_token = crate::collaborator::new_token();
        }
        ui.checkbox(
            &mut app.panels.collaborator_local,
            "Include Collaborator server location",
        );
        label(ui, &theme, "Token:");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.collaborator_token)
                .desired_width(170.0)
                .font(eframe::egui::TextStyle::Monospace),
        );
    });

    ui.add_space(6.0);
    ui.horizontal_wrapped(|ui| {
        label(ui, &theme, "HTTP listener:");
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
        ui.separator();
        label(ui, &theme, "DNS resolver:");
        if ui.button("Start DNS").clicked() {
            match crate::collaborator::start_dns() {
                Ok(port) => {
                    app.panels.collaborator_dns_port = Some(port);
                    app.status = format!("Collaborator resolver listening on 127.0.0.1:{port}");
                }
                Err(why) => app.status = format!("Resolver start failed: {why}"),
            }
        }
        if ui.button("Stop DNS").clicked() {
            crate::collaborator::stop_dns();
            app.panels.collaborator_dns_port = None;
            app.status = "Collaborator resolver stopped".into();
        }
        ui.separator();
        if ui.button("Poll now").clicked() {
            for hit in crate::collaborator::take_hits() {
                app.panels.collaborator_hits.push(hit);
            }
            app.status = format!(
                "Polled Collaborator: {} interaction(s) recorded",
                app.panels.collaborator_hits.len()
            );
        }
        if !app.panels.collaborator_hits.is_empty() && ui.button("Export as CSV").clicked() {
            use base64::Engine;
            let mut csv = String::from("index,type,peer,host,method,path,resolved_base64\n");
            for (idx, hit) in app.panels.collaborator_hits.iter().enumerate() {
                let raw = format!("{} {} ({:?})", hit.method, hit.path, hit.resolved);
                let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    idx + 1,
                    hit.kind,
                    hit.peer,
                    hit.host,
                    hit.method,
                    hit.path,
                    b64
                ));
            }
            let _ = std::fs::write("collaborator-interactions.csv", &csv);
            ui.ctx().copy_text(csv);
            app.status =
                "Exported Collaborator interactions to collaborator-interactions.csv and clipboard"
                    .into();
        }
        if !app.panels.collaborator_hits.is_empty() && ui.button("Clear").clicked() {
            app.panels.collaborator_hits.clear();
            app.status = "Cleared Collaborator interactions".into();
        }
    });

    if app.panels.collaborator_hits.len() > crate::collaborator::MAX_HITS {
        let excess = app.panels.collaborator_hits.len() - crate::collaborator::MAX_HITS;
        app.panels.collaborator_hits.drain(..excess);
    }
    if let Some(port) = app.panels.collaborator_port {
        ui.horizontal(|ui| {
            label(ui, &theme, "Base URL");
            ui.monospace(format!(
                "http://127.0.0.1:{port}/{}.{}",
                app.panels.collaborator_token,
                crate::collaborator::DOMAIN
            ));
        });
    }
    if let Some(port) = app.panels.collaborator_dns_port {
        ui.monospace(format!(
            "{}.{} resolves to 127.0.0.1 via 127.0.0.1:{port}",
            app.panels.collaborator_token,
            crate::collaborator::DOMAIN
        ));
    }

    ui.add_space(6.0);
    ui.separator();
    label(ui, &theme, "Interactions");
    if app.panels.collaborator_hits.is_empty() {
        let primary = if app.panels.collaborator_port.is_none() {
            Some("Get started")
        } else {
            None
        };
        let (learn, start_clicked) = empty_state(
            ui,
            &theme,
            "Burp Collaborator",
            "Burp Collaborator enables you to test whether you can induce an application to \
             interact with an external service via DNS, HTTP, or SMTP. This type of testing \
             makes it easier to discover blind or asynchronous vulnerabilities.",
            true,
            primary,
        );
        if learn {
            app.status =
                "Collaborator: start the local server and DNS resolver to capture out-of-band callbacks"
                    .into();
        }
        if start_clicked {
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
        return;
    }

    let hits = app.panels.collaborator_hits.clone();
    eframe::egui::ScrollArea::vertical()
        .id_salt("collaborator-hits-scroll")
        .max_height(280.0)
        .show(ui, |ui| {
            eframe::egui::Grid::new("collaborator-hits-grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    for col in ["#", "Type", "Client IP", "Method / Query", "Path / Resolution"] {
                        ui.label(
                            eframe::egui::RichText::new(col)
                                .strong()
                                .color(theme.color("ui.text.body")),
                        );
                    }
                    ui.end_row();
                    for (idx, hit) in hits.iter().enumerate().rev() {
                        ui.label(format!("{}", idx + 1));
                        ui.label(
                            eframe::egui::RichText::new(&hit.kind)
                                .strong()
                                .color(theme.color("ui.icon.link")),
                        );
                        ui.monospace(&hit.peer);
                        ui.monospace(&hit.method);
                        let detail = match &hit.resolved {
                            Some(addr) => format!("{} → {addr}", hit.path),
                            None => hit.path.clone(),
                        };
                        let r = ui.monospace(detail);
                        let url = format!("http://{}{}", hit.host, hit.path);
                        let raw_req = format!(
                            "{} {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: {}\r\n\r\n",
                            hit.method, hit.path, hit.host, hit.peer
                        );
                        super::attach_message_context_menu(app, &r, &url, &raw_req, "");
                        ui.end_row();
                    }
                });
        });
}

fn project(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    muted(
        ui,
        &theme,
        "Burp groups Collaborator servers into projects with shared secret keys. This build runs a \
         single local server and has no remote project store.",
    );
    let _ = app;
}
