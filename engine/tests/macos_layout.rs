//! Layout regressions from GitHub #1. Geometry remains logical at Retina scale.
use eframe::egui::{self, Vec2};
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::{app::App, theme::Theme};

#[test]
fn split_panes_do_not_displace_their_sibling_with_oversized_content() {
    for scale in [1.0, 2.0] {
        let mut h = Harness::builder()
            .with_size(Vec2::new(600., 300.))
            .with_pixels_per_point(scale)
            .build_ui(|ui| {
                gulpsuite::ui::panels::vertical_split(
                    ui,
                    &Theme::load(true),
                    "bounded-split",
                    &mut 0.5,
                    220.,
                    |side, ui| {
                        if side == 0 {
                            ui.add(egui::Label::new("oversized".repeat(300)).extend());
                        } else {
                            ui.label("Right pane stays visible");
                        }
                    },
                );
            });
        h.run();
        let right = h.get_by_label("Right pane stays visible").rect();
        assert!(
            right.right() < 600. * scale,
            "Retina scale {scale}: sibling pushed outside viewport: {right:?}"
        );
    }
}

#[test]
fn logger_content_cannot_paint_over_the_status_bar() {
    for scale in [1.0, 2.0] {
        let mut h = Harness::builder()
            .with_size(Vec2::new(900., 540.))
            .with_pixels_per_point(scale)
            .build_eframe(|cc| {
                let mut app = App::with_context(&cc.egui_ctx);
                app.tool = gulpsuite::ui::app::LOGGER;
                app.panels.logger.table_height = 400.;
                app.log.push_back(gulpsuite::ui::app::Transaction {
                    method: "GET".into(),
                    target: "http://layout.test/".into(),
                    status: 200,
                    bytes: 2,
                    host: "layout.test".into(),
                    secure: false,
                    request: format!(
                        "GET / HTTP/1.1\r\nHost: layout.test\r\n\r\n{}",
                        "overflow-regression-marker\n".repeat(80)
                    ),
                    response: "HTTP/1.1 200 OK\r\n\r\nOK".into(),
                    truncated: false,
                });
                app
            });
        h.run();
        let status_top = h
            .get_all_by_label_contains("Event log (")
            .next()
            .unwrap()
            .rect()
            .top()
            / scale;
        let matching: Vec<_> = h
            .output()
            .shapes
            .iter()
            .filter(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    text.galley.job.text.contains("overflow-regression-marker")
                } else {
                    false
                }
            })
            .collect();
        assert!(!matching.is_empty(), "Expected actual message paint output");
        for shape in matching {
            assert!(
                shape.clip_rect.bottom() <= status_top,
                "scale {scale}: editor clip {:?} overlaps status at {status_top}",
                shape.clip_rect
            );
        }
    }
}

#[test]
fn scope_action_buttons_remain_equal_width_and_single_line_on_retina() {
    let mut h = Harness::builder()
        .with_size(Vec2::new(900., 700.))
        .with_pixels_per_point(2.)
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = gulpsuite::ui::app::TARGET;
            app.view = 1;
            app.panels.target_panel.scope = "https://first.test/, https://second.test/".into();
            app
        });
    h.run();
    assert!(
        h.get_by_label("https://first.test/").rect().right() <= 1800.,
        "Scope rows must stay within the Retina viewport"
    );
    if let Some(out) = std::env::var_os("GULPSUITE_LAYOUT_SCREENSHOTS") {
        std::fs::create_dir_all(&out).unwrap();
        h.render()
            .unwrap()
            .save(std::path::PathBuf::from(out).join("scope-2x.png"))
            .unwrap();
    }
    for label in ["Add", "Edit", "Remove", "Paste URL", "Load ..."] {
        for button in h.get_all_by_label(label) {
            assert!(
                (button.rect().width() / 2. - 104.).abs() < 2.,
                "{label}: {:?}",
                button.rect()
            );
            assert!(button.rect().height() / 2. <= 30., "{label} must not wrap");
        }
    }
}

#[test]
fn bounded_split_divider_still_resizes_at_retina_scale() {
    for scale in [1., 2.] {
        let mut h = Harness::builder()
            .with_size(Vec2::new(600., 300.))
            .with_pixels_per_point(scale)
            .build_ui_state(
                |ui, ratio: &mut f32| {
                    gulpsuite::ui::panels::vertical_split(
                        ui,
                        &Theme::load(true),
                        "resize-regression",
                        ratio,
                        220.,
                        |side, ui| {
                            ui.label(if side == 0 { "Left pane" } else { "Right pane" });
                        },
                    );
                },
                0.5,
            );
        h.run();
        let start = egui::pos2(300., 110.);
        h.input_mut().events.extend([
            egui::Event::PointerMoved(start),
            egui::Event::PointerButton {
                pos: start,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
        ]);
        h.step();
        let end = start + egui::vec2(60., 0.);
        h.input_mut().events.push(egui::Event::PointerMoved(end));
        h.step();
        h.input_mut().events.push(egui::Event::PointerButton {
            pos: end,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Default::default(),
        });
        h.run();
        assert!(
            *h.state() > 0.58 && *h.state() < 0.63,
            "scale {scale}: unexpected ratio {}",
            h.state()
        );
        assert!(h.get_by_label("Right pane").rect().right() < 600. * scale);
    }
}

#[test]
fn issue_one_logger_headers_align_with_populated_rows() {
    for scale in [1., 2.] {
        let mut h = Harness::builder()
            .with_size(Vec2::new(900., 700.))
            .with_pixels_per_point(scale)
            .build_eframe(|cc| {
                let mut app = App::with_context(&cc.egui_ctx);
                app.tool = gulpsuite::ui::app::LOGGER;
                app.log.push_back(gulpsuite::ui::app::Transaction {
                    method: "POST".into(),
                    target: format!("https://layout.test/{}", "long-url".repeat(50)),
                    status: 201,
                    bytes: 12345,
                    host: "layout.test".into(),
                    secure: true,
                    request: "POST / HTTP/1.1\r\nHost: layout.test\r\n\r\n".into(),
                    response: "HTTP/1.1 201 Created\r\n\r\nOK".into(),
                    truncated: false,
                });
                app
            });
        h.run();
        for (header, value) in [("Method", "POST"), ("Status", "201"), ("Bytes", "12345")] {
            let header_left = h.get_by_label(header).rect().left() / scale;
            let text = h
                .output()
                .shapes
                .iter()
                .find_map(|s| {
                    if let egui::epaint::Shape::Text(text) = &s.shape {
                        (text.galley.job.text == value).then_some(text)
                    } else {
                        None
                    }
                })
                .unwrap();
            assert!(
                (text.pos.x - header_left - 8.).abs() < 2.,
                "{header} must align at scale {scale}"
            );
        }
        if let Some(out) = std::env::var_os("GULPSUITE_LAYOUT_SCREENSHOTS") {
            std::fs::create_dir_all(&out).unwrap();
            h.render()
                .unwrap()
                .save(std::path::PathBuf::from(out).join(format!("logger-{scale}x.png")))
                .unwrap();
        }
    }
}

#[test]
fn intruder_side_panel_remains_visible_with_long_payloads_on_retina() {
    let mut h = Harness::builder()
        .with_size(Vec2::new(1000., 740.))
        .with_pixels_per_point(2.)
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = gulpsuite::ui::app::INTRUDER;
            app.panels.intruder.show_getting_started = false;
            app.panels.intruder.payload_sets[0].values = "long-unbroken-payload".repeat(100);
            app
        });
    h.run();
    let payload = h.get_by_label("Payload type:").rect();
    assert!(
        payload.left() > 0. && payload.right() < 2000.,
        "Payload controls moved off-screen: {payload:?}"
    );
    if let Some(out) = std::env::var_os("GULPSUITE_LAYOUT_SCREENSHOTS") {
        std::fs::create_dir_all(&out).unwrap();
        h.render()
            .unwrap()
            .save(std::path::PathBuf::from(out).join("intruder-2x.png"))
            .unwrap();
    }
}
