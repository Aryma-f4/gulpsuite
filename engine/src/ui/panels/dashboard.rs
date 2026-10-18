//! Dashboard: Burp's first tool, laid out as a task list beside a tabbed detail pane.
//!
//! Geometry follows a 1440x790 Burp v2026.3.3 capture: the split sits at 500px, so the task
//! column takes roughly the first third of the window, and the detail pane carries its own tab
//! row, two cards side by side and a task list on the left.

use eframe::egui::{self, Color32, FontId, Sense, Ui, Vec2};

use super::{heading, muted};
use crate::scanner::Severity;
use crate::ui::app::App;
use crate::ui::icons::Glyph;

/// Width of the task column, as a fraction of the window.
const SPLIT: f32 = 500.0 / 1440.0;

pub fn draw(app: &mut App, ui: &mut Ui) {
    let left = (ui.available_width() * SPLIT).max(200.0);
    ui.horizontal_top(|ui| {
        tasks_column(app, ui, left);
        ui.separator();
        detail_pane(app, ui);
    });
}

/// The task list: the two task kinds Burp ships, the filter row, and what this session found.
fn tasks_column(app: &mut App, ui: &mut Ui, width: f32) {
    let theme = app.theme.clone();
    ui.vertical(|ui| {
        ui.set_width(width);
        ui.horizontal(|ui| {
            heading(ui, &theme, "Tasks");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                pane_icons(app, ui, &theme);
                if crate::ui::app::primary_button(ui, &theme, "New live task").clicked() {
                    app.status = "Live audit task started".into();
                    app.tool = crate::ui::app::PROXY;
                }
                if crate::ui::app::primary_button(ui, &theme, "New scan").clicked() {
                    app.tool = crate::ui::app::PROXY;
                }
            });
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let (funnel, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
            crate::ui::icons::paint(ui.painter(), funnel, theme.color("ui.icon.default"), Glyph::Funnel);
            ui.allocate_space(Vec2::new(4.0, 0.0));
            ui.label("Filter");
            // Burp's filter is a bare dropdown arrow rather than a labelled combo box.
            let (chevron, response) = ui.allocate_exact_size(Vec2::new(14.0, 14.0), Sense::click());
            if response.clicked() {
                app.status = "Filter: all tasks".into();
            }
            let centre = chevron.center();
            ui.painter().add(egui::Shape::line(
                vec![
                    egui::pos2(centre.x - 4.0, centre.y - 2.0),
                    egui::pos2(centre.x, centre.y + 2.0),
                    egui::pos2(centre.x + 4.0, centre.y - 2.0),
                ],
                egui::Stroke::new(1.4, theme.color("ui.icon.default")),
            ));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut search = String::new();
                ui.add(
                    egui::TextEdit::singleline(&mut search)
                        .hint_text("Search")
                        .desired_width(120.0),
                );
            });
        });
        ui.add_space(6.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            // Burp lists the live audit first and the passive crawl second, and marks the selected
            // card with a blue edge.
            task_card(
                app,
                ui,
                "2. Live audit from Proxy (all traffic)",
                "Audit checks - passive",
                app.dashboard_task == 0,
            );
            task_card(
                app,
                ui,
                "1. Live passive crawl from Proxy (all traffic)",
                "Add links. Add item itself, same domain and URLs in suite scope.",
                app.dashboard_task == 1,
            );
        });
    });
}

/// The three icons Burp puts at the top right of a pane: pause, settings and help.
fn pane_icons(app: &mut App, ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    for glyph in [Glyph::Help, Glyph::Gear, Glyph::Pause] {
        let (rect, response) = ui.allocate_exact_size(Vec2::splat(16.0), Sense::click());
        crate::ui::icons::paint(ui.painter(), rect, theme.color("ui.icon.default"), glyph);
        if response.clicked() {
            match glyph {
                Glyph::Gear => app.show_settings = true,
                Glyph::Pause => {
                    app.capturing = false;
                    app.panels.scanner.running = false;
                    app.status = "Capture paused".into();
                }
                _ => app.status = "Help is not available in this build".into(),
            }
        }
        ui.allocate_space(Vec2::new(4.0, 0.0));
    }
}

/// One task card: name, what it does, whether it is capturing, and issue counters.
fn task_card(app: &mut App, ui: &mut Ui, name: &str, description: &str, selected: bool) {
    let theme = app.theme.clone();
    let accent = theme.color("palette.secondary.core");
    let border = theme.color("ui.border.1");
    let mut capturing = app.capturing;
    let mut picked = selected;
    let frame = egui::Frame {
        fill: theme.color("ui.background.1"),
        stroke: egui::Stroke::new(1.0, border),
        corner_radius: egui::CornerRadius::same(4),
        inner_margin: egui::Margin::symmetric(12, 10),
        outer_margin: egui::Margin::symmetric(0, 4),
        shadow: egui::Shadow::NONE,
    };
    let response = frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            let title =
                crate::ui::app::bold_click_label(ui, name, 12.0, theme.color("ui.text.body"));
            if title.clicked() {
                picked = true;
                app.dashboard_task = if name.starts_with('2') { 0 } else { 1 };
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                for glyph in [Glyph::Ellipsis, Glyph::Pause] {
                    let (rect, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                    crate::ui::icons::paint(
                        ui.painter(),
                        rect,
                        theme.color("ui.icon.default"),
                        glyph,
                    );
                    ui.allocate_space(Vec2::new(4.0, 0.0));
                }
            });
        });
        ui.label(
            egui::RichText::new(description).color(theme.color("ui.text.disabled")),
        );
        ui.horizontal(|ui| {
            ui.label("Capturing");
            ui.allocate_space(Vec2::new(6.0, 0.0));
            switch(ui, &mut capturing, accent);
        });
        ui.horizontal(|ui| {
            let counts = app.panels.scanner.findings.iter().fold([0usize; 4], |mut acc, f| {
                acc[severity_index(f.severity)] += 1;
                acc
            });
            // Burp puts the counters on the right of the card, highest severity first.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label("Issues:");
                for (index, severity) in [
                    Severity::High,
                    Severity::Medium,
                    Severity::Low,
                    Severity::Info,
                ]
                .into_iter()
                .enumerate()
                {
                    let colour = match severity {
                        Severity::High => theme.color("ui.issue.high"),
                        Severity::Medium => theme.color("ui.issue.medium"),
                        Severity::Low => theme.color("ui.issue.low"),
                        Severity::Info => theme.color("palette.mono.5"),
                    };
                    issue_pill(ui, counts[index], colour);
                }
            });
        });
    });
    if picked && !selected {
        app.dashboard_task = if name.starts_with('2') { 0 } else { 1 };
    }
    if selected {
        // Burp marks the selected card with a blue edge down its left side.
        let rect = response.response.rect;
        ui.painter().rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(rect.min.x + 1.0, rect.min.y + 1.0),
                egui::pos2(rect.min.x + 4.0, rect.max.y - 1.0),
            ),
            0.0,
            accent,
        );
    }
    if capturing != app.capturing {
        app.capturing = capturing;
    }
}

/// The pill switch Burp uses for "Capturing".
fn switch(ui: &mut Ui, on: &mut bool, accent: Color32) {
    let size = Vec2::new(30.0, 16.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if response.clicked() {
        *on = !*on;
    }
    let painter = ui.painter_at(rect);
    let track = if *on {
        accent
    } else {
        ui.visuals().widgets.inactive.bg_fill
    };
    painter.rect_filled(rect, 8.0, track);
    let knob = if *on {
        egui::pos2(rect.max.x - 8.0, rect.center().y)
    } else {
        egui::pos2(rect.min.x + 8.0, rect.center().y)
    };
    painter.circle_filled(knob, 5.5, Color32::WHITE);
}

/// A small rounded counter, as Burp draws the issue totals.
fn issue_pill(ui: &mut Ui, count: usize, colour: Color32) {
    let text = format!("{count}");
    let font = FontId::proportional(10.0);
    let galley = ui.painter().layout_no_wrap(text.clone(), font.clone(), Color32::WHITE);
    let size = Vec2::new(galley.size().x + 14.0, 16.0);
    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 8.0, colour);
    painter.text(rect.center(), egui::Align2::CENTER_CENTER, text, font, Color32::WHITE);
}

fn severity_index(severity: Severity) -> usize {
    match severity {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
        Severity::Info => 3,
    }
}

/// The right-hand pane: the selected task's header, then whichever of Burp's six tabs is open.
fn detail_pane(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.horizontal(|ui| {
                let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    icon,
                    theme.color("ui.icon.default"),
                    Glyph::Diamond,
                );
                ui.allocate_space(Vec2::new(4.0, 0.0));
                heading(ui, &theme, task_title(app));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                pane_icons(app, ui, &theme);
                ui.horizontal(|ui| {
                    let (star, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
                    crate::ui::icons::paint(
                        ui.painter(),
                        star,
                        theme.color("icon.link"),
                        Glyph::Star,
                    );
                    ui.allocate_space(Vec2::new(4.0, 0.0));
                    ui.label(
                        egui::RichText::new("Rate this scan").color(theme.color("icon.link")),
                    );
                });
            });
        });
        ui.add_space(8.0);
        // Burp draws this tab row inside the detail pane rather than across the whole window.
        app.tab_row(ui, crate::ui::app::TOOL_VIEWS[crate::ui::app::SUITE], false, 30.0);
        match app.view {
            0 => summary(app, ui),
            1 => audit_items(app, ui),
            2 => issues(app, ui),
            3 => event_log(app, ui),
            4 => logger(app, ui),
            _ => audit_log(app, ui),
        }
    });
}

fn task_title(app: &App) -> &'static str {
    if app.dashboard_task == 0 {
        "2. Live audit from Proxy (all traffic)"
    } else {
        "1. Live passive crawl from Proxy (all traffic)"
    }
}

fn summary(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let card = egui::Frame {
        fill: theme.color("ui.background.1"),
        stroke: egui::Stroke::new(1.0, theme.color("ui.border.1")),
        corner_radius: egui::CornerRadius::same(4),
        inner_margin: egui::Margin::symmetric(14, 12),
        outer_margin: egui::Margin::symmetric(0, 4),
        shadow: egui::Shadow::NONE,
    };
    ui.columns(2, |columns| {
        columns[0].set_min_width(280.0);
        card.show(&mut columns[0], |ui| {
            ui.horizontal(|ui| {
                ui.horizontal(|ui| {
                    let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                    crate::ui::icons::paint(
                        ui.painter(),
                        icon,
                        theme.color("ui.icon.warning"),
                        Glyph::Warning,
                    );
                    ui.allocate_space(Vec2::new(4.0, 0.0));
                    heading(ui, &theme, "Most serious vulnerabilities found (live)");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(
                            false,
                            egui::RichText::new("View all").color(theme.color("icon.link")),
                        )
                        .clicked()
                    {
                        // "View all" leads to the Issues tab.
                        app.view = 2;
                    }
                });
            });
            ui.add_space(8.0);
            vulnerabilities_table(app, ui);
        });
        card.show(&mut columns[1], |ui| {
            ui.horizontal(|ui| {
                ui.horizontal(|ui| {
                    let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
                    crate::ui::icons::paint(
                        ui.painter(),
                        icon,
                        theme.color("ui.icon.default"),
                        Glyph::Diamond,
                    );
                    ui.allocate_space(Vec2::new(4.0, 0.0));
                    heading(ui, &theme, "Task configuration");
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .selectable_label(
                            false,
                            egui::RichText::new("View configuration").color(theme.color("icon.link")),
                        )
                        .clicked()
                    {
                        app.show_settings = true;
                    }
                });
            });
            ui.add_space(6.0);
            task_configuration(app, ui);
            ui.add_space(10.0);
            task_progress(app, ui);
            ui.add_space(10.0);
            task_log(app, ui);
        });
    });
}

/// The issue table, with Burp's grey header row and its empty state.
fn vulnerabilities_table(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let header = egui::Frame {
        fill: theme.color("ui.background.3"),
        stroke: egui::Stroke::NONE,
        corner_radius: egui::CornerRadius::same(0),
        inner_margin: egui::Margin::symmetric(10, 6),
        outer_margin: egui::Margin::ZERO,
        shadow: egui::Shadow::NONE,
    };
    header.show(ui, |ui| {
        egui::Grid::new("vuln-header")
            .num_columns(3)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                crate::ui::app::bold_text(ui, "Issue type", 12.0, theme.color("ui.text.body"));
                crate::ui::app::bold_text(ui, "Host", 12.0, theme.color("ui.text.body"));
                crate::ui::app::bold_text(ui, "Time", 12.0, theme.color("ui.text.body"));
                ui.end_row();
            });
    });
    let findings = app.panels.scanner.findings.clone();
    if findings.is_empty() {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            empty_state(ui, theme.color("palette.secondary.core"));
            ui.add_space(12.0);
            ui.label(egui::RichText::new("No issues to show").strong());
            ui.label(
                egui::RichText::new("Any issues found during the audit will be displayed here.")
                    .color(theme.color("ui.text.disabled")),
            );
        });
    } else {
        for finding in findings.iter().take(16) {
            ui.label(format!("{} · {}", finding.severity.as_str(), finding.name));
        }
    }
}

/// The stacked-cards illustration Burp shows when a panel has nothing in it.
fn empty_state(ui: &mut Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(110.0, 64.0), Sense::hover());
    let painter = ui.painter_at(rect);
    for (dx, dy, angle) in [(-26.0, 4.0, -0.3f32), (0.0, -12.0, 0.0), (26.0, 14.0, 0.3)] {
        let center = rect.center() + Vec2::new(dx, dy);
        let (sin, cos) = angle.sin_cos();
        let corner = |x: f32, y: f32| center + Vec2::new(x * cos - y * sin, x * sin + y * cos);
        let points = vec![
            corner(-14.0, -8.0),
            corner(14.0, -8.0),
            corner(14.0, 8.0),
            corner(-14.0, 8.0),
        ];
        painter.add(egui::Shape::convex_polygon(points, colour, egui::Stroke::NONE));
        // The light slot across the middle of each card.
        painter.add(egui::Shape::line(
            vec![corner(-16.0, 0.0), corner(16.0, 0.0)],
            egui::Stroke::new(2.0, Color32::WHITE),
        ));
    }
}

fn audit_items(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Audit items");
    if app.panels.scanner.pages.is_empty() {
        muted(ui, &theme, "No audit items yet.");
        return;
    }
    for (url, status) in app.panels.scanner.pages.iter().take(64) {
        ui.label(format!("{status}  {url}"));
    }
}

fn issues(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Issues");
    let findings = &app.panels.scanner.findings;
    if findings.is_empty() {
        muted(ui, &theme, "No issues reported.");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for finding in findings.iter() {
            ui.label(format!("{} · {}", finding.severity.as_str(), finding.name));
        }
    });
}

fn event_log(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Event log");
    if app.log.is_empty() {
        muted(
            ui,
            &theme,
            "Start the listener on the Proxy tool, then point a browser at 127.0.0.1:8080.",
        );
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for entry in app.log.iter().rev().take(64) {
            ui.label(format!("{}  {}", entry.method, entry.target));
        }
    });
}

fn logger(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Logger");
    muted(
        ui,
        &theme,
        &format!("{} request(s) in the Logger tool.", app.log.len()),
    );
}

fn audit_log(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    heading(ui, &theme, "Audit log");
    let running = app.panels.scanner.running;
    muted(
        ui,
        &theme,
        if running {
            "Audit in progress."
        } else {
            "No audit has run yet."
        },
    );
}

fn task_configuration(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let mut capturing = app.capturing;
    egui::Grid::new("task-config")
        .num_columns(2)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            crate::ui::app::bold_text(ui, "Task type:", 12.0, theme.color("ui.text.body"));
            ui.label("Live audit");
            ui.end_row();
            crate::ui::app::bold_text(ui, "Scope:", 12.0, theme.color("ui.text.body"));
            ui.label("Proxy (all traffic)");
            ui.end_row();
            crate::ui::app::bold_text(ui, "Configuration:", 12.0, theme.color("ui.text.body"));
            ui.label("Audit checks - passive");
            ui.end_row();
            crate::ui::app::bold_text(ui, "Capturing", 12.0, theme.color("ui.text.body"));
            switch(ui, &mut capturing, theme.color("palette.secondary.core"));
            ui.end_row();
        });
    app.capturing = capturing;
}

fn task_progress(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal(|ui| {
        let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        crate::ui::icons::paint(ui.painter(), icon, theme.color("ui.icon.default"), Glyph::Clock);
        ui.allocate_space(Vec2::new(4.0, 0.0));
        heading(ui, &theme, "Task progress");
    });
    let pages = app.panels.scanner.pages.len();
    let items = app.panels.scanner.findings.len();
    egui::Grid::new("task-progress")
        .num_columns(4)
        .spacing([16.0, 6.0])
        .show(ui, |ui| {
            crate::ui::app::bold_text(ui, "Total audit items:", 12.0, theme.color("ui.text.body"));
            ui.label(pages.to_string());
            crate::ui::app::bold_text(ui, "Requests:", 12.0, theme.color("ui.text.body"));
            ui.label(app.log.len().to_string());
            ui.end_row();
            crate::ui::app::bold_text(ui, "Audit items pending:", 12.0, theme.color("ui.text.body"));
            ui.label("0");
            crate::ui::app::bold_text(ui, "Network errors:", 12.0, theme.color("ui.text.body"));
            ui.label("0");
            ui.end_row();
            crate::ui::app::bold_text(ui, "Audit items in progress:", 12.0, theme.color("ui.text.body"));
            ui.label("0");
            ui.end_row();
            crate::ui::app::bold_text(ui, "Audit items completed:", 12.0, theme.color("ui.text.body"));
            ui.label(items.to_string());
            ui.end_row();
        });
}

fn task_log(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.horizontal(|ui| {
        let (icon, _) = ui.allocate_exact_size(Vec2::splat(14.0), Sense::hover());
        crate::ui::icons::paint(ui.painter(), icon, theme.color("ui.icon.default"), Glyph::Clock);
        ui.allocate_space(Vec2::new(4.0, 0.0));
        heading(ui, &theme, "Task log");
    });
}
