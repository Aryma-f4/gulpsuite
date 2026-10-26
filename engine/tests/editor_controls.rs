use eframe::egui::Vec2;
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::app::App;

fn repeater() -> Harness<'static, App> {
    let mut h = Harness::builder()
        .with_size(Vec2::new(1280.0, 800.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = gulpsuite::ui::app::REPEATER;
            app.panels.repeater.open(
                "http://editor.test/",
                "GET /editor HTTP/1.1\r\nHost: editor.test\r\n\r\n",
            );
            app.panels.repeater.active_mut().response =
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nresponse-unique-marker".into();
            app
        });
    h.run();
    h
}

#[test]
fn request_hex_does_not_change_response_raw_mode_or_double_encode() {
    let mut h = repeater();
    h.get_all_by_label("Raw").last().unwrap().click();
    h.run();
    h.get_all_by_label("Hex").next().unwrap().click();
    h.run();
    assert!(
        h.query_by_label_contains("response-unique-marker")
            .is_some(),
        "Request formatting must not change the response mode"
    );
    assert!(
        h.query_by_label_contains("47 45 54 20").is_some(),
        "Request Hex must encode the HTTP message once"
    );
}

#[test]
fn render_mode_explains_unsupported_content() {
    let mut h = repeater();
    h.get_by_label("Render").click();
    h.run();
    assert!(
        h.query_all_by_label_contains("HTML preview")
            .next()
            .is_some(),
        "Render must show an honest supported-content preview rather than silently showing source"
    );
}

#[test]
fn wrapping_changes_message_layout_without_changing_text() {
    let text = "long-unbroken-message-".repeat(40);
    let mut h = Harness::builder()
        .with_size(Vec2::new(340.0, 400.0))
        .build_ui_state(
            |ui, state: &mut (String, bool)| {
                gulpsuite::ui::panels::gulp_numbered_message_view_wrapped(
                    ui,
                    &gulpsuite::ui::theme::Theme::load(false),
                    "wrap-test",
                    350.0,
                    &state.0,
                    1,
                    false,
                    state.1,
                );
            },
            (text.clone(), false),
        );
    h.run();
    let unwrapped_height = h.get_by_label(&text).rect().height();
    h.state_mut().1 = true;
    h.run();
    assert!(
        h.get_by_label(&text).rect().height() > unwrapped_height * 4.0,
        "Wrap must change the rendered message geometry"
    );
    assert_eq!(h.state().0, text);
}

#[test]
fn html_preview_shows_text_and_never_executes_or_displays_script_contents() {
    let mut h = repeater();
    h.state_mut().panels.repeater.active_mut().response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hello &amp; world</h1><script>SECRET_SCRIPT_MARKER</script></body></html>".into();
    h.run();
    h.get_by_label("Render").click();
    h.run();
    assert!(h.query_by_label("Hello & world").is_some());
    assert!(h.query_by_label_contains("SECRET_SCRIPT_MARKER").is_none());
}

#[test]
fn raw_request_edits_survive_format_switches() {
    let mut h = repeater();
    h.get_all_by_label("Raw").next().unwrap().click();
    h.run();
    let before = h.state().panels.repeater.active().raw.clone();
    h.get_all_by_role(eframe::egui::accesskit::Role::MultilineTextInput)
        .next()
        .unwrap()
        .focus();
    h.run();
    h.get_all_by_role(eframe::egui::accesskit::Role::MultilineTextInput)
        .next()
        .unwrap()
        .type_text("edited-token");
    h.run();
    let edited = h.state().panels.repeater.active().raw.clone();
    assert_ne!(edited, before);
    assert!(edited.contains("edited-token"));
    h.get_all_by_label("Hex").next().unwrap().click();
    h.run();
    h.get_all_by_label("Pretty").next().unwrap().click();
    h.run();
    assert_eq!(h.state().panels.repeater.active().raw, edited);
}

#[test]
fn pretty_json_is_display_only_and_raw_keeps_the_original_body() {
    let raw =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"key\":\"value\"}".to_string();
    let mut h = Harness::builder()
        .with_size(Vec2::new(440.0, 300.0))
        .build_ui_state(
            |ui, state: &mut (String, usize)| {
                gulpsuite::ui::panels::gulp_numbered_message_view(
                    ui,
                    &gulpsuite::ui::theme::Theme::load(false),
                    "json-test",
                    250.0,
                    &state.0,
                    state.1,
                    false,
                );
            },
            (raw.clone(), 0),
        );
    h.run();
    assert!(h.query_by_label_contains("\n  \"key\"").is_some());
    assert_eq!(h.state().0, raw);
    h.state_mut().1 = 1;
    h.run();
    assert!(h.query_by_label_contains("{\"key\":\"value\"}").is_some());
    assert_eq!(h.state().0, raw);
}
