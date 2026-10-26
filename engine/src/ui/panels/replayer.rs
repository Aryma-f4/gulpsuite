//! Recorded login replayer. The last of Gulp's non-AI tools.
//!
//! Capture the exchange for one host from the proxy history, then send it again and report where
//! the replay diverged. Session handling lives in the proxy's cookie jar, so a replayed login
//! carries the cookies it learns as it goes.

use std::sync::mpsc;

use eframe::egui::Ui;

use super::{heading, label, muted};
use crate::proxy::host_port;
use crate::replay::{Outcome, Recording, ReplayReport, Step};
use crate::ui::app::App;

#[derive(Clone, Default)]
pub struct ReplayerPanel {
    pub host: String,
    pub recording: Option<Recording>,
    pub report: Option<ReplayReport>,
    pub running: bool,
}

/// What one replayed step produced.
pub struct ReplayResult {
    pub index: usize,
    pub outcome: Outcome,
}

/// Replays on a worker thread; the UI polls the receiver each frame.
pub enum ReplayUpdate {
    Done(ReplayResult),
    Finished,
    Error(String),
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Recorded login replayer");

    ui.horizontal_wrapped(|ui| {
        label(ui, &theme, "Host");
        ui.text_edit_singleline(&mut app.panels.replayer.host);
        if ui.button("Record from history").clicked() {
            record(app);
        }
        if ui
            .add_enabled(
                app.panels.replayer.recording.as_ref().is_some_and(|r| !r.is_empty()),
                eframe::egui::Button::new("Replay"),
            )
            .clicked()
        {
            start(app);
        }
        if ui
            .add_enabled(app.panels.replayer.running, eframe::egui::Button::new("Stop"))
            .clicked()
        {
            app.panels.replayer.running = false;
            app.replay_updates = None;
            app.status = "Replay stopped".into();
        }
    });

    ui.add_space(4.0);

    let Some(recording) = app.panels.replayer.recording.clone() else {
        muted(
            ui,
            &theme,
            "No recording. Type a host and press Record: this captures the request/response pairs the \
             proxy has already seen for it.",
        );
        return;
    };

    ui.horizontal(|ui| {
        muted(
            ui,
            &theme,
            &format!(
                "{} — {} step(s){}",
                recording.name,
                recording.len(),
                if crate::replay::looks_like_login(&recording) {
                    "  (looks like a login)"
                } else {
                    "  (no session cookie or redirect found)"
                }
            ),
        );
    });

    eframe::egui::ScrollArea::vertical()
        .max_height(220.0)
        .show(ui, |ui| {
            eframe::egui::Grid::new("replay-grid")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["#", "Method", "URL", "Recorded"] {
                        ui.label(
                            eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")),
                        );
                    }
                    ui.end_row();
                    for (index, step) in recording.steps.iter().enumerate() {
                        ui.label(eframe::egui::RichText::new(index.to_string())
                            .color(theme.color("ui.icon.disabled")));
                        ui.label(eframe::egui::RichText::new(&step.method).color(theme.color("ui.text.body")));
                        ui.label(eframe::egui::RichText::new(&step.url).color(theme.color("ui.icon.default")));
                        ui.label(eframe::egui::RichText::new(step.recorded_status_line())
                            .color(theme.color("ui.icon.default")));
                        ui.end_row();
                    }
                });
        });

    ui.add_space(6.0);
    heading(ui, &theme, "Replay");

    // Drain whatever the worker has produced since the last frame.
    let mut finished = false;
    if let Some(receiver) = &app.replay_updates {
        let mut outcomes = app
            .panels
            .replayer
            .report
            .take()
            .map(|r| r.outcomes)
            .unwrap_or_default();
        while let Ok(update) = receiver.try_recv() {
            match update {
                ReplayUpdate::Done(result) => {
                    while outcomes.len() <= result.index {
                        outcomes.push(Outcome::Failed("not replayed".into()));
                    }
                    outcomes[result.index] = result.outcome;
                }
                ReplayUpdate::Finished => finished = true,
                ReplayUpdate::Error(why) => {
                    app.status = format!("Replay failed: {why}");
                    finished = true;
                }
            }
        }
        let matched = outcomes.iter().filter(|o| !o.is_problem()).count();
        let total = outcomes.len();
        app.panels.replayer.report = Some(ReplayReport { outcomes });
        if finished {
            app.panels.replayer.running = false;
            app.status = format!("Replay finished: {matched} of {total} matched");
        }
    }

    let Some(report) = &app.panels.replayer.report else {
        muted(ui, &theme, "No replay yet.");
        return;
    };

    if report.outcomes.is_empty() {
        muted(ui, &theme, "Replay in progress...");
        return;
    }

    ui.label(eframe::egui::RichText::new(report.summary()).color(
        if report.problems() == 0 {
            theme.color("ui.icon.success")
        } else {
            theme.color("ui.icon.warning")
        },
    ));

    eframe::egui::ScrollArea::vertical()
        .max_height(200.0)
        .show(ui, |ui| {
            for (index, outcome) in report.outcomes.iter().enumerate() {
                let colour = if outcome.is_problem() {
                    theme.color("ui.icon.warning")
                } else {
                    theme.color("ui.icon.success")
                };
                ui.horizontal(|ui| {
                    ui.label(
                        eframe::egui::RichText::new(index.to_string())
                            .color(theme.color("ui.icon.disabled")),
                    );
                    ui.label(eframe::egui::RichText::new(outcome.label()).color(colour));
                });
            }
        });
}

/// Captures the exchange for the typed host from the proxy history.
fn record(app: &mut App) {
    let host = app.panels.replayer.host.trim().to_string();
    if host.is_empty() {
        app.status = "Type a host first".into();
        return;
    }
    let steps: Vec<Step> = app
        .log
        .iter()
        .map(|tx| Step {
            method: tx.method.clone(),
            url: tx.target.clone(),
            request: tx.request.clone(),
            response: tx.response.clone(),
            status: tx.status,
        })
        .filter(|step| step.url.contains(&host) && !step.request.is_empty())
        .collect();
    if steps.is_empty() {
        app.status = format!("Nothing captured for {host} yet");
        return;
    }
    let count = steps.len();
    app.panels.replayer.recording = Some(Recording {
        name: host.clone(),
        host,
        steps,
    });
    app.panels.replayer.report = None;
    app.status = format!("Recorded {count} step(s)");
}

/// Sends the recording again through the proxy, one step at a time.
fn start(app: &mut App) {
    let Some(recording) = app.panels.replayer.recording.clone() else {
        return;
    };
    let proxy = app.proxy.clone();
    let runtime = app.runtime.handle().clone();
    let (tx, rx) = mpsc::channel();

    app.panels.replayer.running = true;
    app.panels.replayer.report = Some(ReplayReport {
        outcomes: Vec::new(),
    });
    app.replay_updates = Some(rx);
    app.status = "Replay started".into();

    // The names a recording wants filled at replay time, e.g. `{{csrf}}`.
    let wanted = crate::replay::markers(recording.steps.iter().map(|s| s.request.clone()));

    std::thread::spawn(move || {
        runtime.block_on(async move {
            // Values captured from earlier responses, so a later step can send a live token.
            let mut live: Vec<(String, String)> = Vec::new();
            for (index, step) in recording.steps.iter().enumerate() {
                let Some((host, port)) = host_port(&step.request, &step.url) else {
                    let _ = tx.send(ReplayUpdate::Done(ReplayResult {
                        index,
                        outcome: Outcome::Failed("cannot resolve target".into()),
                    }));
                    continue;
                };
                // Fill any placeholders with the values seen so far.
                let request = crate::replay::substitute(&step.request, &live);
                let secure = step.url.starts_with("https://");
                let outcome = match proxy.one_shot_secure(&host, port, &request, secure, 15_000).await {
                    Ok((status, body)) => {
                        // Harvest whatever this response offers for the placeholders still missing.
                        for name in &wanted {
                            if live.iter().any(|(key, _)| key == name) {
                                continue;
                            }
                            let value = if let Some(rest) = name.strip_prefix("cookie:") {
                                crate::replay::cookie_from(&body, rest)
                            } else {
                                crate::replay::token_from(&body, name)
                            };
                            if let Some(value) = value {
                                live.push((name.clone(), value));
                            }
                        }
                        if status == step.status {
                            Outcome::Matched
                        } else {
                            Outcome::Changed {
                                recorded: step.status,
                                replayed: status,
                            }
                        }
                    }
                    Err(why) => Outcome::Failed(why),
                };
                if tx.send(ReplayUpdate::Done(ReplayResult { index, outcome })).is_err() {
                    return;
                }
                tokio::time::sleep(crate::replay::default_pace()).await;
            }
            let _ = tx.send(ReplayUpdate::Finished);
        });
    });
}
