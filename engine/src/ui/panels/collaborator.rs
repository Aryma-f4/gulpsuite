//! Collaborator: multi-tab out-of-band (OOB) interaction client & local DNS/HTTP/SMTP server
//! matching `burp-collaborator-tut-4-polling-for-interactions.png`, `collaborator/index.html`,
//! `settings/project/collaborator.html`, and `resources/Media/svg/light/collaborator.svg`.

use eframe::egui::{self, pos2, Color32, FontId, Rect, RichText, Sense, Stroke, Ui, Vec2};

use crate::ui::app::App;

#[derive(Clone, Debug)]
pub struct CollaboratorPanel {
    /// `(tab_name, tab_token)` for each Collaborator result tab (`1 × | 2 × | +`).
    pub tabs: Vec<(String, String)>,
    pub active_tab: usize,
    /// Number of Collaborator payloads to generate (`1..=50`).
    pub payloads_to_generate: String,
    pub smtp_port: Option<u16>,
    pub selected_hit: Option<usize>,
    /// `0 = Description`, `1 = Request to Collaborator / DNS query / SMTP conversation`, `2 = Response from Collaborator / Email message`.
    pub detail_tab: usize,
    /// `0 = Pretty`, `1 = Raw`, `2 = Hex`.
    pub detail_msg_mode: usize,
    pub detail_wrap: bool,
    pub detail_np: bool,
    pub filter_dns: bool,
    pub filter_http: bool,
    pub filter_smtp: bool,
    pub search: String,
    pub sort_ascending: bool,
    pub show_all_tabs_hits: bool,
    pub table_height: f32,
}

impl Default for CollaboratorPanel {
    fn default() -> Self {
        let tok = crate::collaborator::new_token();
        Self {
            tabs: vec![("1".into(), tok)],
            active_tab: 0,
            payloads_to_generate: "1".into(),
            smtp_port: None,
            selected_hit: None,
            detail_tab: 0,
            detail_msg_mode: 0,
            detail_wrap: true,
            detail_np: false,
            filter_dns: true,
            filter_http: true,
            filter_smtp: true,
            search: String::new(),
            sort_ascending: true,
            show_all_tabs_hits: true,
            table_height: 220.0,
        }
    }
}

/// Ensures the local Collaborator HTTP, DNS, and SMTP listeners are started.
pub fn ensure_listeners_started(app: &mut App) {
    if app.panels.collaborator_token.trim().is_empty() {
        app.panels.collaborator_token = crate::collaborator::new_token();
    }
    if app.panels.collaborator_port.is_none() || !crate::collaborator::is_running() {
        if let Ok(port) = crate::collaborator::start() {
            app.panels.collaborator_port = Some(port);
            app.panels.collaborator_stop = false;
        }
    }
    if app.panels.collaborator_dns_port.is_none() || !crate::collaborator::dns_running() {
        if let Ok(dport) = crate::collaborator::start_dns() {
            app.panels.collaborator_dns_port = Some(dport);
        }
    }
    if app.panels.collaborator_panel.smtp_port.is_none() || !crate::collaborator::smtp_running() {
        if let Ok(sport) = crate::collaborator::start_smtp() {
            app.panels.collaborator_panel.smtp_port = Some(sport);
        }
    }
}

/// Generates `count` Collaborator payloads for the active tab.
pub fn generate_payloads(app: &mut App, count: usize, include_location: bool) -> Vec<String> {
    let base_tok = if app.panels.collaborator_token.trim().is_empty() {
        let t = crate::collaborator::new_token();
        app.panels.collaborator_token = t.clone();
        t
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
            if include_location {
                let host = format!("{tok}.{}", crate::collaborator::DOMAIN);
                if let Some(port) = app.panels.collaborator_port {
                    format!("http://127.0.0.1:{port}/{host}")
                } else {
                    host
                }
            } else {
                tok
            }
        })
        .collect()
}

/// Paints the exact `resources/Media/svg/light/collaborator.svg` (`112 x 67` viewBox) isometric
/// radar dish with 3 `#FF7648` orange ping dots and `#7B61FF` sweep cone.
fn paint_collaborator_radar_svg(ui: &mut Ui, dark: bool) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(112.0, 67.0), Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let iso = |cx: f32, cy: f32, r: f32| -> Vec<egui::Pos2> {
        (0..36)
            .map(|i| {
                let a = (i as f32) * std::f32::consts::TAU / 36.0;
                let (s, c) = a.sin_cos();
                let x = 0.866_025 * r * c - 0.866_025 * r * s + cx;
                let y = 0.5 * r * c + 0.5 * r * s + cy;
                pos2(o.x + x, o.y + y)
            })
            .collect()
    };

    let shadow_fill = if dark {
        Color32::from_rgb(0x2A, 0x2E, 0x36)
    } else {
        Color32::from_rgb(0xCA, 0xCA, 0xCD)
    };
    let dish_fill = if dark {
        Color32::from_rgb(0x1E, 0x33, 0x4A)
    } else {
        Color32::from_rgb(0xBD, 0xD0, 0xE1)
    };
    let blue_stroke = Color32::from_rgb(0x26, 0x64, 0x9D);
    let ping_orange = Color32::from_rgb(0xFF, 0x76, 0x48);

    // Base shadow ellipse & main dish ellipse
    p.add(egui::Shape::convex_polygon(
        iso(56.0, 38.68, 31.8),
        shadow_fill,
        Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        iso(56.0, 32.32, 30.3),
        dish_fill,
        Stroke::new(2.2_f32, blue_stroke),
    ));

    // Isometric crosshairs
    p.line_segment(
        [pos2(o.x + 81.35, o.y + 17.68), pos2(o.x + 30.10, o.y + 47.27)],
        Stroke::new(1.0_f32, blue_stroke),
    );
    p.line_segment(
        [pos2(o.x + 81.35, o.y + 47.27), pos2(o.x + 30.10, o.y + 17.68)],
        Stroke::new(1.0_f32, blue_stroke),
    );

    // Inner concentric isometric rings
    p.add(egui::Shape::closed_line(
        iso(56.0, 32.32, 21.9),
        Stroke::new(
            1.4_f32,
            Color32::from_rgba_unmultiplied(0x26, 0x64, 0x9D, 130),
        ),
    ));
    p.add(egui::Shape::closed_line(
        iso(56.0, 32.32, 13.0),
        Stroke::new(
            1.4_f32,
            Color32::from_rgba_unmultiplied(0x26, 0x64, 0x9D, 190),
        ),
    ));

    // `#7B61FF` radar sweep sector (`M89.62 24.36 L55.45 32.00 L87.41 41.55 Z`)
    p.add(egui::Shape::convex_polygon(
        vec![
            pos2(o.x + 89.62, o.y + 24.36),
            pos2(o.x + 55.45, o.y + 32.00),
            pos2(o.x + 87.41, o.y + 41.55),
        ],
        Color32::from_rgba_unmultiplied(0x7B, 0x61, 0xFF, 110),
        Stroke::NONE,
    ));

    // 3 `#FF7648` ping dots + center `#26649D` hub dot
    for (px, py) in [(53.80_f32, 17.05_f32), (61.51, 40.59), (20.73, 39.95)] {
        p.add(egui::Shape::convex_polygon(
            iso(px, py, 3.8),
            ping_orange,
            Stroke::NONE,
        ));
    }
    p.add(egui::Shape::convex_polygon(
        iso(56.0, 32.32, 2.55),
        blue_stroke,
        Stroke::NONE,
    ));
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    // Drain any new interactions recorded by the background HTTP / DNS / SMTP Collaborator threads.
    for hit in crate::collaborator::take_hits() {
        app.panels.collaborator_hits.push(hit);
    }
    if app.panels.collaborator_hits.len() > crate::collaborator::MAX_HITS {
        let excess = app.panels.collaborator_hits.len() - crate::collaborator::MAX_HITS;
        app.panels.collaborator_hits.drain(..excess);
    }

    let theme = app.theme.clone();
    let card_bg = if theme.dark {
        Color32::from_rgb(0x1E, 0x20, 0x24)
    } else {
        Color32::WHITE
    };
    let bar_bg = theme.color("ui.background.1");
    let border_col = theme.color("ui.border.1");
    let heading_fg = if theme.dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x11, 0x11, 0x11)
    };
    let body_fg = if theme.dark {
        Color32::from_rgb(0xE4, 0xE8, 0xF0)
    } else {
        Color32::from_rgb(0x1F, 0x23, 0x28)
    };
    let muted_fg = if theme.dark {
        Color32::from_rgb(0x9E, 0xA6, 0xB2)
    } else {
        Color32::from_rgb(0x57, 0x60, 0x6A)
    };

    // Row 0: Collaborator Result Tabs Bar (`1 × | 2 × | +` from `burp-collaborator-tut-4-polling-for-interactions.png`)
    if app.panels.collaborator_panel.tabs.is_empty() {
        let tok = if app.panels.collaborator_token.trim().is_empty() {
            crate::collaborator::new_token()
        } else {
            app.panels.collaborator_token.clone()
        };
        app.panels.collaborator_panel.tabs.push(("1".into(), tok));
        app.panels.collaborator_panel.active_tab = 0;
    }

    egui::Frame::new()
        .fill(bar_bg)
        .inner_margin(egui::Margin::same(0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let mut close_tab = None;
                let unread_total = app
                    .panels
                    .collaborator_hits
                    .iter()
                    .filter(|h| !h.read)
                    .count();
                let tabs_len = app.panels.collaborator_panel.tabs.len();
                for idx in 0..tabs_len {
                    let (tab_title, tab_tok) = app.panels.collaborator_panel.tabs[idx].clone();
                    let active = app.panels.collaborator_panel.active_tab == idx;
                    let cell_bg = if active { card_bg } else { bar_bg };
                    let display_lbl = if active && unread_total > 0 {
                        format!("{tab_title} ({unread_total})")
                    } else {
                        tab_title
                    };
                    let cell_out = egui::Frame::new()
                        .fill(cell_bg)
                        .inner_margin(egui::Margin::symmetric(12, 5))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                let lbl = RichText::new(display_lbl)
                                    .size(12.0)
                                    .strong()
                                    .color(if active { heading_fg } else { body_fg });
                                let tab_resp =
                                    ui.add(egui::Label::new(lbl).sense(Sense::click()));
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("×").size(12.0).color(muted_fg),
                                        )
                                        .frame(false),
                                    )
                                    .on_hover_text("Close Collaborator tab")
                                    .clicked()
                                {
                                    close_tab = Some(idx);
                                }
                                tab_resp
                            })
                            .inner
                        });
                    let cell_rect = cell_out.response.rect;
                    ui.painter().line_segment(
                        [
                            pos2(cell_rect.max.x, cell_rect.min.y),
                            pos2(cell_rect.max.x, cell_rect.max.y),
                        ],
                        Stroke::new(1.0_f32, border_col),
                    );
                    if active {
                        ui.painter().rect_filled(
                            Rect::from_min_max(
                                pos2(cell_rect.min.x, cell_rect.max.y - 3.0),
                                pos2(cell_rect.max.x, cell_rect.max.y),
                            ),
                            0.0,
                            Color32::from_rgb(0xE0, 0x53, 0x20),
                        );
                    }
                    if cell_out.inner.clicked() {
                        app.panels.collaborator_panel.active_tab = idx;
                        app.panels.collaborator_token = tab_tok;
                    }
                }
                if let Some(idx) = close_tab {
                    if app.panels.collaborator_panel.tabs.len() > 1 {
                        app.panels.collaborator_panel.tabs.remove(idx);
                        if app.panels.collaborator_panel.active_tab
                            >= app.panels.collaborator_panel.tabs.len()
                        {
                            app.panels.collaborator_panel.active_tab =
                                app.panels.collaborator_panel.tabs.len() - 1;
                        }
                        if let Some((_, tok)) = app
                            .panels
                            .collaborator_panel
                            .tabs
                            .get(app.panels.collaborator_panel.active_tab)
                        {
                            app.panels.collaborator_token = tok.clone();
                        }
                    }
                }
                ui.add_space(6.0);
                if ui
                    .button("+")
                    .on_hover_text("Open new Collaborator result tab")
                    .clicked()
                {
                    let next_num = app.panels.collaborator_panel.tabs.len() + 1;
                    let new_tok = crate::collaborator::new_token();
                    app.panels
                        .collaborator_panel
                        .tabs
                        .push((next_num.to_string(), new_tok.clone()));
                    app.panels.collaborator_panel.active_tab =
                        app.panels.collaborator_panel.tabs.len() - 1;
                    app.panels.collaborator_token = new_tok;
                }
                ui.add_space(10.0);
                // Keep accessible "Payload generator" label for parity tests
                ui.label(
                    RichText::new("Payload generator")
                        .size(11.5)
                        .strong()
                        .color(muted_fg),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(8.0);
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if ui
                        .small_button("Run health check")
                        .on_hover_text(
                            "Start local DNS/HTTP/SMTP Collaborator listeners and verify OOB callbacks",
                        )
                        .clicked()
                    {
                        ensure_listeners_started(app);
                        crate::collaborator::send_health_check_probes(
                            &app.panels.collaborator_token,
                            app.panels.collaborator_port,
                            app.panels.collaborator_dns_port,
                            app.panels.collaborator_panel.smtp_port,
                        );
                        app.status =
                            "Collaborator health check: sent DNS, HTTP, and SMTP out-of-band probes"
                                .into();
                    }
                    if let Some(sport) = app.panels.collaborator_panel.smtp_port {
                        ui.label(
                            RichText::new(format!("SMTP :{sport}"))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(0x1F, 0x88, 0x3D)),
                        );
                    }
                    if let Some(dport) = app.panels.collaborator_dns_port {
                        ui.label(
                            RichText::new(format!("DNS :{dport}"))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(0x1F, 0x88, 0x3D)),
                        );
                    }
                    if let Some(hport) = app.panels.collaborator_port {
                        ui.label(
                            RichText::new(format!("HTTP :{hport}"))
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(0x1F, 0x88, 0x3D)),
                        );
                    }
                });
            });
        });

    let sep1 = Rect::from_min_size(ui.cursor().min, Vec2::new(ui.available_width(), 1.0));
    ui.painter().rect_filled(sep1, 0.0, border_col);
    ui.add_space(1.0);

    // Row 1: Collaborator Control Bar (`burp-collaborator-tut-4-polling-for-interactions.png`)
    // `Payloads to generate: [ 1 ]  [ Copy to clipboard ]  [✓] Include Collaborator server location  |  [ Poll now ]  Polling automatically every 60 seconds`
    egui::Frame::new()
        .fill(card_bg)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 8.0;
                ui.label(RichText::new("Payloads to generate:").color(body_fg));
                ui.add(
                    egui::TextEdit::singleline(
                        &mut app.panels.collaborator_panel.payloads_to_generate,
                    )
                    .desired_width(54.0),
                );
                if crate::ui::app::primary_button(ui, &theme, "Copy to clipboard").clicked() {
                    ensure_listeners_started(app);
                    let count = app
                        .panels
                        .collaborator_panel
                        .payloads_to_generate
                        .trim()
                        .parse::<usize>()
                        .unwrap_or(1)
                        .clamp(1, 50);
                    let payloads = generate_payloads(app, count, app.panels.collaborator_local);
                    let joined = payloads.join("\n");
                    ui.ctx().copy_text(joined.clone());
                    app.status = format!(
                        "Copied {} Collaborator payload(s) to clipboard: {}",
                        payloads.len(),
                        payloads.first().cloned().unwrap_or_default()
                    );
                }
                ui.checkbox(
                    &mut app.panels.collaborator_local,
                    RichText::new("Include Collaborator server location").color(body_fg),
                );
                ui.separator();
                let btn_bg = if theme.dark {
                    Color32::from_rgb(0x2B, 0x2E, 0x36)
                } else {
                    Color32::WHITE
                };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Poll now").color(heading_fg).strong(),
                        )
                        .fill(btn_bg)
                        .stroke(Stroke::new(1.0_f32, border_col))
                        .corner_radius(4.0)
                        .min_size(Vec2::new(82.0, 26.0)),
                    )
                    .clicked()
                {
                    ensure_listeners_started(app);
                    for hit in crate::collaborator::take_hits() {
                        app.panels.collaborator_hits.push(hit);
                    }
                    app.status = format!(
                        "Polled Collaborator: {} interaction(s) recorded",
                        app.panels.collaborator_hits.len()
                    );
                }
                ui.label(
                    RichText::new("Polling automatically every 60 seconds")
                        .size(12.0)
                        .color(muted_fg),
                );
            });
        });

    let sep2 = Rect::from_min_size(ui.cursor().min, Vec2::new(ui.available_width(), 1.0));
    ui.painter().rect_filled(sep2, 0.0, border_col);
    ui.add_space(1.0);

    // Filter & Search bar (`collaborator/index.html#viewing-results`: HTTP, DNS, SMTP filter buttons + Search)
    egui::Frame::new()
        .fill(bar_bg)
        .inner_margin(egui::Margin::symmetric(12, 4))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let (funnel, _) = ui.allocate_exact_size(Vec2::splat(13.0), Sense::hover());
                crate::ui::icons::paint(
                    ui.painter(),
                    funnel,
                    theme.color("ui.icon.default"),
                    crate::ui::icons::Glyph::Funnel,
                );
                ui.label(RichText::new("Filter:").size(11.5).color(muted_fg));
                for (lbl, flag) in [
                    ("DNS", &mut app.panels.collaborator_panel.filter_dns),
                    ("HTTP", &mut app.panels.collaborator_panel.filter_http),
                    ("SMTP", &mut app.panels.collaborator_panel.filter_smtp),
                ] {
                    if ui.selectable_label(*flag, lbl).clicked() {
                        *flag = !*flag;
                    }
                }
                ui.separator();
                ui.add(
                    egui::TextEdit::singleline(&mut app.panels.collaborator_panel.search)
                        .hint_text("Search interactions…")
                        .desired_width(220.0),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    if !app.panels.collaborator_hits.is_empty() {
                        if ui.small_button("Clear").clicked() {
                            app.panels.collaborator_hits.clear();
                            app.panels.collaborator_panel.selected_hit = None;
                            app.status = "Cleared Collaborator interactions".into();
                        }
                        if ui.small_button("Export as CSV").clicked() {
                            export_collaborator_csv(app, ui.ctx(), None);
                        }
                    }
                    if ui
                        .small_button("New token")
                        .on_hover_text("Rotate Collaborator payload token")
                        .clicked()
                    {
                        let tok = crate::collaborator::new_token();
                        app.panels.collaborator_token = tok.clone();
                        let tab_idx = app.panels.collaborator_panel.active_tab;
                        if let Some(entry) = app.panels.collaborator_panel.tabs.get_mut(tab_idx) {
                            entry.1 = tok;
                        }
                    }
                });
            });
        });

    let sep2b = Rect::from_min_size(ui.cursor().min, Vec2::new(ui.available_width(), 1.0));
    ui.painter().rect_filled(sep2b, 0.0, border_col);
    ui.add_space(1.0);

    // Empty state with exact `collaborator.svg` radar graphic when no interactions exist yet
    if app.panels.collaborator_hits.is_empty() {
        let avail = ui.available_size();
        egui::Frame::new()
            .fill(card_bg)
            .inner_margin(egui::Margin::same(0))
            .show(ui, |ui| {
                ui.set_min_size(avail);
                let top_pad = ((avail.y - 260.0) * 0.40).max(36.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(top_pad);
                    paint_collaborator_radar_svg(ui, theme.dark);
                    ui.add_space(16.0);
                    ui.label(
                        RichText::new("Collaborator")
                            .size(16.5)
                            .strong()
                            .color(heading_fg),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "Collaborator enables you to test whether you can induce an application to\n\
                             interact with an external service via DNS, HTTP, or SMTP. This type of testing\n\
                             makes it easier to discover blind or asynchronous vulnerabilities.",
                        )
                        .size(12.0)
                        .color(body_fg),
                    );
                    ui.add_space(18.0);
                    let total_btn_w = 108.0 + 10.0 + 140.0;
                    let left_pad = ((ui.available_width() - total_btn_w) * 0.5).max(0.0);
                    ui.horizontal(|ui| {
                        ui.add_space(left_pad);
                        let learn_bg = if theme.dark {
                            Color32::from_rgb(0x32, 0x36, 0x3E)
                        } else {
                            Color32::from_rgb(0xEA, 0xEA, 0xEA)
                        };
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Learn more")
                                        .size(12.0)
                                        .strong()
                                        .color(heading_fg),
                                )
                                .fill(learn_bg)
                                .stroke(Stroke::new(1.0_f32, border_col))
                                .corner_radius(4.0)
                                .min_size(Vec2::new(108.0, 28.0)),
                            )
                            .clicked()
                        {
                            app.status =
                                "Collaborator: click Copy to clipboard or Run health check to capture DNS, HTTP, and SMTP callbacks"
                                    .into();
                        }
                        ui.add_space(10.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    RichText::new("Get started")
                                        .size(12.0)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(0xE0, 0x53, 0x20))
                                .stroke(Stroke::NONE)
                                .corner_radius(4.0)
                                .min_size(Vec2::new(120.0, 28.0)),
                            )
                            .clicked()
                        {
                            ensure_listeners_started(app);
                            crate::collaborator::send_health_check_probes(
                                &app.panels.collaborator_token,
                                app.panels.collaborator_port,
                                app.panels.collaborator_dns_port,
                                app.panels.collaborator_panel.smtp_port,
                            );
                            app.status =
                                "Started Collaborator DNS, HTTP, and SMTP listeners and sent health-check probes"
                                    .into();
                        }
                    });
                });
            });
        return;
    }

    // Filter & sort interactions (`DNS`, `HTTP`, `SMTP` + search)
    let f_dns = app.panels.collaborator_panel.filter_dns;
    let f_http = app.panels.collaborator_panel.filter_http;
    let f_smtp = app.panels.collaborator_panel.filter_smtp;
    let needle = app
        .panels
        .collaborator_panel
        .search
        .trim()
        .to_ascii_lowercase();

    let mut filtered_indices: Vec<usize> = app
        .panels
        .collaborator_hits
        .iter()
        .enumerate()
        .filter(|(_, h)| {
            let kind_ok = match h.kind.as_str() {
                "DNS" => f_dns,
                "HTTP" => f_http,
                "SMTP" => f_smtp,
                _ => true,
            };
            let search_ok = needle.is_empty()
                || h.host.to_ascii_lowercase().contains(&needle)
                || h.path.to_ascii_lowercase().contains(&needle)
                || h.peer.to_ascii_lowercase().contains(&needle)
                || h.kind.to_ascii_lowercase().contains(&needle)
                || h.comment.to_ascii_lowercase().contains(&needle)
                || h.display_payload().to_ascii_lowercase().contains(&needle);
            kind_ok && search_ok
        })
        .map(|(i, _)| i)
        .collect();

    if !app.panels.collaborator_panel.sort_ascending {
        filtered_indices.reverse();
    }

    if app.panels.collaborator_panel.selected_hit.is_none() {
        app.panels.collaborator_panel.selected_hit = filtered_indices.first().copied();
    }

    // Row 2: Flat Bordered Interactions Table (`# ▲ | Time | Type | Payload | Source IP | Comment`)
    let avail_w = (ui.available_width() - 2.0).max(560.0);
    let base_w = 56.0 + 215.0 + 90.0 + 280.0 + 150.0 + 150.0;
    let extra = (avail_w - base_w).max(0.0);
    let scale = if avail_w < base_w {
        avail_w / base_w
    } else {
        1.0
    };
    let sort_arrow = if app.panels.collaborator_panel.sort_ascending {
        "# ▲"
    } else {
        "# ▼"
    };
    let cols = [
        (sort_arrow, 56.0 * scale),
        ("Time", 215.0 * scale + extra * 0.18),
        ("Type", 90.0 * scale),
        ("Payload", 280.0 * scale + extra * 0.44),
        ("Source IP", 150.0 * scale + extra * 0.16),
        ("Comment", 150.0 * scale + extra * 0.22),
    ];
    let tbl_w = cols.iter().map(|(_, w)| *w).sum::<f32>();
    let tbl_h = app
        .panels
        .collaborator_panel
        .table_height
        .min((ui.available_height() * 0.42).max(130.0));

    let mut delete_hit = None;
    let mut clear_all = false;
    let mut csv_export_idx = None;
    let mut send_to_repeater = None;
    let mut send_to_intruder = None;

    egui::Frame::new()
        .fill(card_bg)
        .stroke(Stroke::new(1.0_f32, border_col))
        .inner_margin(egui::Margin::same(0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing = Vec2::ZERO;
            let (hdr_r, hdr_resp) =
                ui.allocate_exact_size(Vec2::new(tbl_w, 24.0), Sense::click());
            ui.painter()
                .rect_filled(hdr_r, 0.0, theme.color("ui.background.2"));
            if hdr_resp.clicked() {
                app.panels.collaborator_panel.sort_ascending =
                    !app.panels.collaborator_panel.sort_ascending;
            }
            let mut hx = hdr_r.left();
            for (cn, cw) in cols {
                let cr = Rect::from_min_size(pos2(hx, hdr_r.top()), Vec2::new(cw, hdr_r.height()));
                ui.painter().text(
                    pos2(cr.left() + 8.0, cr.center().y),
                    egui::Align2::LEFT_CENTER,
                    cn,
                    FontId::proportional(11.5),
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
                .id_salt("collaborator-hits-scroll")
                .max_height(tbl_h)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing = Vec2::ZERO;
                    for (row_ord, &hit_idx) in filtered_indices.iter().enumerate() {
                        let Some(hit_snapshot) = app.panels.collaborator_hits.get(hit_idx).cloned()
                        else {
                            continue;
                        };
                        let selected = app.panels.collaborator_panel.selected_hit == Some(hit_idx);
                        ui.push_id(("collab-hit-row", hit_idx), |ui| {
                            let (row_rect, row_resp) = ui.allocate_exact_size(
                                Vec2::new(tbl_w, 22.0),
                                Sense::click(),
                            );
                            let row_fill = if selected {
                                if theme.dark {
                                    Color32::from_rgb(0x4A, 0x35, 0x25)
                                } else {
                                    Color32::from_rgb(0xF6, 0xC6, 0x9F) // Exact peach/orange selection from `burp-collaborator-tut-4-polling-for-interactions.png`
                                }
                            } else if let Some(hl) = hit_snapshot.highlight {
                                match hl {
                                    1 => Color32::from_rgba_unmultiplied(0xE0, 0x20, 0x4F, 45),
                                    2 => Color32::from_rgba_unmultiplied(0xF5, 0x7B, 0x20, 45),
                                    3 => Color32::from_rgba_unmultiplied(0xE8, 0xB8, 0x00, 45),
                                    4 => Color32::from_rgba_unmultiplied(0x1F, 0x88, 0x3D, 45),
                                    _ => Color32::from_rgba_unmultiplied(0x00, 0x68, 0xB5, 45),
                                }
                            } else if row_ord % 2 == 1 {
                                theme.color("ui.background.1")
                            } else {
                                card_bg
                            };
                            ui.painter().rect_filled(row_rect, 0.0, row_fill);

                            let vals = [
                                (hit_idx + 1).to_string(),
                                hit_snapshot.display_time().to_string(),
                                hit_snapshot.kind.clone(),
                                hit_snapshot.display_payload(),
                                hit_snapshot.display_source_ip().to_string(),
                                hit_snapshot.comment.clone(),
                            ];
                            // Unread rows are bold (`collaborator/index.html#viewing-results`)
                            let txt_col = if !hit_snapshot.read || selected {
                                heading_fg
                            } else {
                                body_fg
                            };
                            let mut cx = row_rect.left();
                            for ((_, cw), val) in cols.iter().zip(vals.iter()) {
                                let cell_r = Rect::from_min_size(
                                    pos2(cx, row_rect.top()),
                                    Vec2::new(*cw, row_rect.height()),
                                );
                                let clip_p = ui.painter().with_clip_rect(
                                    cell_r
                                        .shrink2(egui::vec2(4.0, 0.0))
                                        .intersect(ui.clip_rect()),
                                );
                                let text_pos = pos2(cell_r.left() + 8.0, cell_r.center().y);
                                clip_p.text(
                                    text_pos,
                                    egui::Align2::LEFT_CENTER,
                                    val,
                                    FontId::proportional(12.0),
                                    txt_col,
                                );
                                if !hit_snapshot.read {
                                    // Faux bold pass for unread Collaborator rows
                                    clip_p.text(
                                        pos2(text_pos.x + 0.5, text_pos.y),
                                        egui::Align2::LEFT_CENTER,
                                        val,
                                        FontId::proportional(12.0),
                                        txt_col,
                                    );
                                }
                                cx = cell_r.right();
                            }

                            if row_resp.clicked() || row_resp.secondary_clicked() {
                                app.panels.collaborator_panel.selected_hit = Some(hit_idx);
                                if let Some(h) = app.panels.collaborator_hits.get_mut(hit_idx) {
                                    h.read = true;
                                }
                            }

                            super::show_persistent_context_menu(&row_resp, |ui| {
                                ui.set_min_width(210.0);
                                if let Some(h) = app.panels.collaborator_hits.get_mut(hit_idx) {
                                    if ui
                                        .button(if h.read {
                                            "Mark as unread"
                                        } else {
                                            "Mark as read"
                                        })
                                        .clicked()
                                    {
                                        h.read = !h.read;
                                        ui.close();
                                    }
                                    ui.menu_button("Highlight", |ui| {
                                        for (code, lbl) in [
                                            (Some(1u8), "Red"),
                                            (Some(2), "Orange"),
                                            (Some(3), "Yellow"),
                                            (Some(4), "Green"),
                                            (Some(5), "Blue"),
                                            (None, "None"),
                                        ] {
                                            if ui.button(lbl).clicked() {
                                                h.highlight = code;
                                                ui.close();
                                            }
                                        }
                                    });
                                }
                                ui.separator();
                                if ui.button("Copy payload").clicked() {
                                    ui.ctx().copy_text(hit_snapshot.display_payload());
                                    ui.close();
                                }
                                if ui.button("Copy Source IP").clicked() {
                                    ui.ctx()
                                        .copy_text(hit_snapshot.display_source_ip().to_string());
                                    ui.close();
                                }
                                if hit_snapshot.kind == "HTTP" {
                                    let url =
                                        format!("http://{}{}", hit_snapshot.host, hit_snapshot.path);
                                    let req = if hit_snapshot.raw_request.is_empty() {
                                        format!(
                                            "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                                            hit_snapshot.method,
                                            hit_snapshot.path,
                                            hit_snapshot.host
                                        )
                                    } else {
                                        hit_snapshot.raw_request.clone()
                                    };
                                    if ui.button("Send to Repeater").clicked() {
                                        send_to_repeater = Some((url.clone(), req.clone()));
                                        ui.close();
                                    }
                                    if ui.button("Send to Intruder").clicked() {
                                        send_to_intruder = Some((url, req));
                                        ui.close();
                                    }
                                }
                                ui.separator();
                                if ui.button("Export as CSV").clicked() {
                                    csv_export_idx = Some(Some(hit_idx));
                                    ui.close();
                                }
                                if ui.button("Export all as CSV").clicked() {
                                    csv_export_idx = Some(None);
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Delete interaction").clicked() {
                                    delete_hit = Some(hit_idx);
                                    ui.close();
                                }
                                if ui.button("Clear all interactions").clicked() {
                                    clear_all = true;
                                    ui.close();
                                }
                            });
                        });
                    }
                });
        });

    if let Some((url, req)) = send_to_repeater {
        app.panels.repeater.open(&url, &req);
        app.tool = crate::ui::app::REPEATER;
        app.view = 0;
        app.status = "Sent Collaborator HTTP interaction to Repeater".into();
    }
    if let Some((url, req)) = send_to_intruder {
        app.send_to_intruder(&url, &req);
    }
    if let Some(target_idx) = csv_export_idx {
        export_collaborator_csv(app, ui.ctx(), target_idx);
    }
    if clear_all {
        app.panels.collaborator_hits.clear();
        app.panels.collaborator_panel.selected_hit = None;
        return;
    }
    if let Some(del_idx) = delete_hit {
        if del_idx < app.panels.collaborator_hits.len() {
            app.panels.collaborator_hits.remove(del_idx);
            app.panels.collaborator_panel.selected_hit = None;
        }
        return;
    }

    super::horizontal_resize_handle(
        ui,
        &theme,
        "collaborator-table-resize",
        &mut app.panels.collaborator_panel.table_height,
        110.0,
        480.0,
        220.0,
    );

    // Row 3: Lower Interaction Inspector Pane (`Description | DNS query` or `Description | Request to Collaborator | Response from Collaborator`)
    if let Some(sel_idx) = app.panels.collaborator_panel.selected_hit {
        if let Some(hit) = app.panels.collaborator_hits.get(sel_idx).cloned() {
            let sub_tabs: &[&str] = match hit.kind.as_str() {
                "DNS" => &["Description", "DNS query"],
                "SMTP" => &["Description", "SMTP conversation", "Email message"],
                _ => &[
                    "Description",
                    "Request to Collaborator",
                    "Response from Collaborator",
                ],
            };
            if app.panels.collaborator_panel.detail_tab >= sub_tabs.len() {
                app.panels.collaborator_panel.detail_tab = 0;
            }

            egui::Frame::new()
                .fill(bar_bg)
                .inner_margin(egui::Margin::symmetric(12, 5))
                .show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 18.0;
                        for (t_idx, lbl) in sub_tabs.iter().enumerate() {
                            let active = app.panels.collaborator_panel.detail_tab == t_idx;
                            let r = ui.add(
                                egui::Label::new(
                                    RichText::new(*lbl)
                                        .size(12.5)
                                        .strong()
                                        .color(if active { heading_fg } else { body_fg }),
                                )
                                .sense(Sense::click()),
                            );
                            if active {
                                let rect = r.rect;
                                ui.painter().rect_filled(
                                    Rect::from_min_max(
                                        pos2(rect.min.x - 4.0, rect.max.y + 2.0),
                                        pos2(rect.max.x + 4.0, rect.max.y + 5.0),
                                    ),
                                    0.0,
                                    Color32::from_rgb(0xE0, 0x53, 0x20),
                                );
                            }
                            if r.clicked() {
                                app.panels.collaborator_panel.detail_tab = t_idx;
                            }
                        }

                        if app.panels.collaborator_panel.detail_tab > 0 {
                            ui.separator();
                            for (m_idx, m_lbl) in ["Pretty", "Raw", "Hex"].iter().enumerate() {
                                ui.selectable_value(
                                    &mut app.panels.collaborator_panel.detail_msg_mode,
                                    m_idx,
                                    *m_lbl,
                                );
                            }
                        }
                    });
                });

            let sep3 = Rect::from_min_size(ui.cursor().min, Vec2::new(ui.available_width(), 1.0));
            ui.painter().rect_filled(sep3, 0.0, border_col);
            ui.add_space(1.0);

            let detail_h = (ui.available_height() - 12.0).max(120.0);
            match app.panels.collaborator_panel.detail_tab {
                0 => {
                    egui::Frame::new()
                        .fill(card_bg)
                        .inner_margin(egui::Margin::symmetric(16, 14))
                        .show(ui, |ui| {
                            ui.set_min_size(Vec2::new(ui.available_width(), detail_h));
                            match hit.kind.as_str() {
                                "DNS" => {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 4.0;
                                        ui.label(
                                            RichText::new(format!(
                                                "The Collaborator server received a DNS lookup of type {} for the domain name",
                                                hit.method
                                            ))
                                            .size(13.0)
                                            .color(body_fg),
                                        );
                                        ui.label(
                                            RichText::new(format!("{}.", hit.host))
                                                .size(13.0)
                                                .strong()
                                                .color(heading_fg),
                                        );
                                    });
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "The lookup was received from IP address {} at {}.",
                                            hit.display_source_ip(),
                                            hit.display_time()
                                        ))
                                        .size(13.0)
                                        .color(body_fg),
                                    );
                                }
                                "SMTP" => {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 4.0;
                                        ui.label(
                                            RichText::new(
                                                "The Collaborator server received an SMTP message for",
                                            )
                                            .size(13.0)
                                            .color(body_fg),
                                        );
                                        ui.label(
                                            RichText::new(format!("{}.", hit.path))
                                                .size(13.0)
                                                .strong()
                                                .color(heading_fg),
                                        );
                                    });
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "The SMTP connection was received from IP address {} at {}.",
                                            hit.display_source_ip(),
                                            hit.display_time()
                                        ))
                                        .size(13.0)
                                        .color(body_fg),
                                    );
                                }
                                _ => {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.spacing_mut().item_spacing.x = 4.0;
                                        ui.label(
                                            RichText::new(format!(
                                                "The Collaborator server received an HTTP {} request for",
                                                hit.method
                                            ))
                                            .size(13.0)
                                            .color(body_fg),
                                        );
                                        ui.label(
                                            RichText::new(format!(
                                                "http://{}{}.",
                                                hit.host, hit.path
                                            ))
                                            .size(13.0)
                                            .strong()
                                            .color(heading_fg),
                                        );
                                    });
                                    ui.add_space(8.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "The request was received from IP address {} at {}.",
                                            hit.display_source_ip(),
                                            hit.display_time()
                                        ))
                                        .size(13.0)
                                        .color(body_fg),
                                    );
                                }
                            }
                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Comment:").color(body_fg));
                                if let Some(h_mut) = app.panels.collaborator_hits.get_mut(sel_idx) {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut h_mut.comment)
                                            .hint_text("Add a comment for this interaction…")
                                            .desired_width(320.0),
                                    );
                                }
                            });
                        });
                }
                1 => {
                    let req_msg = if hit.raw_request.is_empty() {
                        format!(
                            "{} {} HTTP/1.1\r\nHost: {}\r\nX-Forwarded-For: {}\r\n\r\n",
                            hit.method, hit.path, hit.host, hit.peer
                        )
                    } else {
                        hit.raw_request.clone()
                    };
                    let url = format!("http://{}{}", hit.host, hit.path);
                    let r = super::burp_numbered_message_view_wrapped(
                        ui,
                        &theme,
                        "collab-detail-req",
                        detail_h,
                        &req_msg,
                        app.panels.collaborator_panel.detail_msg_mode,
                        app.panels.collaborator_panel.detail_np,
                        app.panels.collaborator_panel.detail_wrap,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r,
                        &url,
                        &req_msg,
                        &hit.raw_response,
                    );
                }
                _ => {
                    let resp_msg = if hit.raw_response.is_empty() {
                        "HTTP/1.1 200 OK\r\nServer: Collaborator\r\n\r\ncollaborator".to_string()
                    } else {
                        hit.raw_response.clone()
                    };
                    let url = format!("http://{}{}", hit.host, hit.path);
                    let r = super::burp_numbered_message_view_wrapped(
                        ui,
                        &theme,
                        "collab-detail-resp",
                        detail_h,
                        &resp_msg,
                        app.panels.collaborator_panel.detail_msg_mode,
                        app.panels.collaborator_panel.detail_np,
                        app.panels.collaborator_panel.detail_wrap,
                    );
                    super::attach_message_context_menu(
                        app,
                        &r,
                        &url,
                        &hit.raw_request,
                        &resp_msg,
                    );
                }
            }
        }
    }
}

fn export_collaborator_csv(app: &mut App, ctx: &egui::Context, single_idx: Option<usize>) {
    use base64::Engine;
    let mut csv = String::from(
        "#,Time,Type,Payload,Source IP,Request/Query (Base64),Response/Answer (Base64),Comment\n",
    );
    let iter: Vec<(usize, &crate::collaborator::Hit)> = match single_idx {
        Some(idx) => app
            .panels
            .collaborator_hits
            .get(idx)
            .into_iter()
            .map(|h| (idx, h))
            .collect(),
        None => app.panels.collaborator_hits.iter().enumerate().collect(),
    };
    for (idx, hit) in iter {
        let req_b64 = base64::engine::general_purpose::STANDARD.encode(hit.raw_request.as_bytes());
        let resp_b64 =
            base64::engine::general_purpose::STANDARD.encode(hit.raw_response.as_bytes());
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            idx + 1,
            hit.display_time(),
            hit.kind,
            hit.display_payload(),
            hit.display_source_ip(),
            req_b64,
            resp_b64,
            hit.comment.replace(',', ";")
        ));
    }
    let _ = std::fs::write("collaborator-interactions.csv", &csv);
    ctx.copy_text(csv);
    app.status =
        "Exported Collaborator interactions to collaborator-interactions.csv and clipboard".into();
}
