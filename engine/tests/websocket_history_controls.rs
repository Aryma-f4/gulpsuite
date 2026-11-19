use eframe::egui::{self, Vec2};
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::app::{App, WsConnection, WsMessage, PROXY, REPEATER};

fn history() -> Harness<'static, App> {
    let mut h = Harness::builder()
        .with_size(Vec2::new(1280.0, 850.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = PROXY;
            app.view = 2;
            app.memory_checked = std::time::Instant::now();
            app.websockets.push(WsConnection {
                id: 7,
                host: "localhost:8080".into(),
                request: "GET /chat HTTP/1.1\r\nHost: localhost:8080\r\nUpgrade: websocket\r\n\r\n"
                    .into(),
                response: "HTTP/1.1 101 Switching Protocols\r\n\r\n".into(),
                open: true,
                secure: Some(false),
                listener_port: Some(8080),
                messages: ["twenty bytes", "a", "bbbb"]
                    .into_iter()
                    .map(|text| WsMessage {
                        to_server: true,
                        opcode: 1,
                        bytes: text.len(),
                        text: text.into(),
                        ..Default::default()
                    })
                    .collect(),
            });
            app
        });
    h.run();
    h
}

#[test]
fn arrows_move_selection_and_stop_at_the_table_bounds() {
    let mut h = history();
    h.get_by_label("1 B").click();
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 1)));
    h.key_press(egui::Key::ArrowUp);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 0)));
    h.key_press(egui::Key::ArrowUp);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 0)));
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 1)));
}

#[test]
fn length_header_cycles_and_arrows_follow_visible_order() {
    let mut h = history();
    h.get_by_label("1 B").click();
    h.run();
    h.get_by_label("Length").click();
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 1)));
    assert!(h.query_by_label("Length ▲").is_some());
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 2)));
    h.get_by_label("Length ▲").click();
    h.run();
    assert!(h.query_by_label("Length ▼").is_some());
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 1)));
    h.get_by_label("Length ▼").click();
    h.run();
    assert!(h.query_by_label("Length").is_some());
    h.key_press(egui::Key::ArrowUp);
    h.run();
    assert_eq!(h.state().panels.ws_selected, Some((7, 0)));
}

#[test]
fn send_to_repeater_preserves_the_handshake_and_displays_the_frame_separately() {
    let mut h = history();
    h.get_by_label("1 B").click();
    h.run();
    let request = h.state().websockets[0].request.clone();
    h.get_all_by_label("Send to Repeater")
        .next()
        .unwrap()
        .click();
    h.run();
    assert_eq!(h.state().tool, REPEATER);
    assert_eq!(h.state().panels.repeater.active().raw, request);
    assert!(h.query_by_label("Captured WebSocket message").is_some());
    assert!(h.get_all_by_label("a").next().is_some());
    assert!(h.query_by_label("Send").is_none());
}

#[test]
fn websocket_repeater_split_keeps_original_and_history_selection_separate() {
    let mut h = history();
    h.get_by_label("1 B").click();
    h.run();
    h.get_all_by_label("Send to Repeater")
        .next()
        .unwrap()
        .click();
    h.run();
    assert!(
        h.query_by_label("Message").is_some(),
        "history table header"
    );
    assert!(
        h.query_by_label("WebSocket ID").is_some(),
        "connection column"
    );
    assert!(
        h.query_by_label("Captured WebSocket message").is_some(),
        "left pane"
    );
    assert!(
        h.query_by_label("Selected history message").is_some(),
        "right pane"
    );
    assert_eq!(h.get_all_by_label("Raw").count(), 2);
    let left = h.get_by_label("Captured WebSocket message").rect();
    let table = h.get_by_label("Message").rect();
    let detail = h.get_by_label("Selected history message").rect();
    assert!(table.left() > left.right(), "history sits to the right");
    assert!(detail.top() > table.bottom(), "detail sits beneath history");
    h.get_by_label("twenty bytes").click();
    h.run();
    assert!(
        h.get_all_by_label("twenty bytes").count() >= 2,
        "opens the history preview"
    );
    assert!(
        h.get_all_by_label("a").next().is_some(),
        "original message stays available"
    );
    h.key_press(egui::Key::ArrowDown);
    h.run();
    assert!(
        h.get_all_by_label("a").count() >= 3,
        "arrows update the history preview"
    );
    assert!(
        h.query_by_label("Send").is_none(),
        "capture view never sends"
    );
    if let Some(path) = std::env::var_os("GULPSUITE_WS_PREVIEW") {
        h.render()
            .expect("render WebSocket Repeater UI")
            .save(path)
            .expect("save preview");
    }
}

#[test]
fn proxy_websocket_history_message_right_click_opens_capture_menu() {
    let mut h = history();
    h.state_mut().set_dark(false);
    h.run();
    assert!(
        h.query_by_label("WebSocket ID").is_some(),
        "history columns"
    );
    let row = h.get_by_label("1 B").rect();
    h.get_by_label("1 B").click();
    h.run();
    let message = h.get_by_label("Message").rect();
    let notes = h.get_by_label("Notes panel").rect();
    assert!(message.top() > row.bottom());
    assert!(notes.left() > message.right());
    let pos = message.left_bottom() + egui::vec2(36.0, 92.0);
    for pressed in [true, false] {
        h.input_mut().events.push(egui::Event::PointerMoved(pos));
        h.input_mut().events.push(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Secondary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        });
        h.step();
    }
    h.run();
    assert!(
        h.query_by_label("Copy prettified").is_some(),
        "message context menu"
    );
    assert!(
        h.query_by_label("Paste").is_some(),
        "read-only editor action shown"
    );
    if let Some(path) = std::env::var_os("GULPSUITE_PROXY_WS_PREVIEW") {
        h.render()
            .expect("render menu")
            .save(path)
            .expect("save menu preview");
    }
    h.get_by_label("Send to Decoder").click();
    h.run();
    assert_eq!(h.state().tool, gulpsuite::ui::app::DECODER);
    assert_eq!(h.state().panels.decoder.input, "a");
}
