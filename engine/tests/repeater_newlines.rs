use eframe::egui::{self, Vec2};
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::app::{App, REPEATER};

fn repeater() -> Harness<'static, App> {
    Harness::builder()
        .with_size(Vec2::new(1280., 800.))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = REPEATER;
            app.panels.repeater.open(
                "http://newline.test/",
                "POST / HTTP/1.1\r\nHost: newline.test\r\n\r\nfirst\nsecond\tend\r",
            );
            app.panels.repeater.active_mut().response =
                "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nfirst\nsecond\tend".into();
            app
        })
}
fn painted(h: &Harness<App>, marker: &str) -> bool {
    h.output().shapes.iter().any(
        |s| matches!(&s.shape, egui::epaint::Shape::Text(t) if t.galley.job.text.contains(marker)),
    )
}
#[test]
fn repeater_request_newline_toggle_marks_breaks_without_changing_request() {
    let mut h = repeater();
    h.run();
    let original = h.state().panels.repeater.active().raw.clone();
    h.get_all_by_label("\\n").next().unwrap().click();
    h.run();
    assert!(h.state().panels.repeater.active().show_non_printable);
    assert!(
        painted(&h, "\\r\\n"),
        "request CRLF markers must be visible"
    );
    assert!(painted(&h, "\\n"), "request LF markers must be visible");
    assert_eq!(h.state().panels.repeater.active().raw, original);
    if let Ok(path) = std::env::var("GULPSUITE_EDITOR_SCREENSHOT") {
        h.render().unwrap().save(path).unwrap();
    }
    assert!(!h.state().panels.repeater.active().response_non_printable);
    h.get_all_by_role(egui::accesskit::Role::MultilineTextInput)
        .next()
        .unwrap()
        .focus();
    h.run();
    h.get_all_by_role(egui::accesskit::Role::MultilineTextInput)
        .next()
        .unwrap()
        .type_text("typed-with-markers");
    h.run();
    assert!(h
        .state()
        .panels
        .repeater
        .active()
        .raw
        .contains("typed-with-markers"));
    assert!(!h.state().panels.repeater.active().raw.contains("\\r\\n"));
}
#[test]
fn repeater_response_toggle_marks_lf_only_lines() {
    let mut h = repeater();
    h.run();
    let original = h.state().panels.repeater.active().response.clone();
    h.get_all_by_label("\\n").last().unwrap().click();
    h.run();
    assert!(
        painted(&h, "first\\n"),
        "LF-only response newlines must be marked"
    );
    assert!(painted(&h, "\\t"));
    assert_eq!(h.state().panels.repeater.active().response, original);
}

#[test]
#[ignore = "requires installed bundled Chromium and image renderer"]
fn repeater_render_loads_browser_image_without_changing_response() {
    let mut h = repeater();
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><style>body{background:#18445c;color:white}</style><h1>Real Chromium preview</h1></html>";
    h.state_mut().panels.repeater.active_mut().response = response.into();
    h.state_mut().panels.repeater.active_mut().response_mode = 3;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        h.step();
        if h.query_by_label("Rendered HTTP response").is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "browser image did not reach Repeater"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(h.state().panels.repeater.active().response, response);
    if let Ok(path) = std::env::var("GULPSUITE_RENDER_UI_SCREENSHOT") {
        h.render().unwrap().save(path).unwrap();
    }
}

#[test]
fn adjacent_carriage_return_markers_have_separate_layout_space() {
    let mut h=repeater();
    let raw="GET / HTTP/1.1\r\nHost: newline.test\r\n\r\na\r\rb";
    h.state_mut().panels.repeater.active_mut().raw=raw.into();
    h.state_mut().panels.repeater.active_mut().show_non_printable=true;h.run();
    let mut positions:Vec<f32>=h.output().shapes.iter().filter_map(|s| match &s.shape {
        egui::epaint::Shape::Text(t) if t.galley.job.text=="\\r"=>Some(t.pos.x),_=>None,
    }).collect();
    positions.sort_by(f32::total_cmp);
    assert_eq!(positions.len(),2);
    assert!(positions[1]-positions[0]>=12.,"adjacent CR markers must not overlap: {positions:?}");
    assert_eq!(h.state().panels.repeater.active().raw,raw);
}

#[test]
fn external_preview_permission_does_not_carry_to_another_response() {
    use egui_kittest::kittest::NodeT;
    let mut h=repeater();
    h.state_mut().panels.repeater.active_mut().response="HTTP/1.1 200 OK\r\n\r\n<html>first document</html>".into();
    h.state_mut().panels.repeater.active_mut().response_mode=3;h.run();
    let label="Load external HTTP(S) resources (sends network requests)";
    h.get_by_label(label).click();h.run();
    assert_eq!(h.get_by_label(label).accesskit_node().toggled(),Some(egui::accesskit::Toggled::True));
    h.state_mut().panels.repeater.active_mut().response="HTTP/1.1 200 OK\r\n\r\n<html>different document</html>".into();h.run();
    assert_eq!(h.get_by_label(label).accesskit_node().toggled(),Some(egui::accesskit::Toggled::False));
}
