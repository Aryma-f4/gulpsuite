use eframe::egui::{self, Vec2};
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::app::{App, COMPARER, DECODER};

fn harness(tool: usize) -> Harness<'static, App> {
    let mut h = Harness::builder()
        .with_size(Vec2::new(1280.0, 800.0))
        .build_eframe(move |cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = tool;
            app.view = 0;
            app.memory_checked = std::time::Instant::now();
            app
        });
    h.run();
    h
}

#[test]
fn decoder_output_hex_format_is_independent_of_input_format() {
    let mut h = harness(DECODER);
    h.state_mut().panels.decoder.input = "source".into();
    h.state_mut().panels.decoder.output = "Hi".into();
    h.state_mut().panels.decoder.hex_view = true;
    h.state_mut().panels.decoder.output_hex_view = false;
    h.run();
    assert!(
        h.query_by_label("Hi").is_some(),
        "Input Hex must not change output Text"
    );
    h.state_mut().panels.decoder.hex_view = false;
    h.state_mut().panels.decoder.output_hex_view = true;
    h.run();
    assert!(
        h.query_by_label("Hi").is_none(),
        "Output Hex must use its own format state"
    );
}

#[test]
fn comparer_paste_requests_the_clipboard_for_the_focused_side() {
    let mut h = harness(COMPARER);
    h.state_mut().panels.repeater.active_mut().raw = "unrelated Repeater request".into();
    h.ctx
        .memory_mut(|m| m.request_focus(egui::Id::new("comparer-right-data")));
    h.run();
    h.get_by_label("Paste").click();
    h.step();
    assert!(
        h.output().viewport_output.values().any(|v| {
            v.commands
                .iter()
                .any(|c| matches!(c, egui::ViewportCommand::RequestPaste))
        }),
        "Paste must request the desktop clipboard"
    );
    h.input_mut()
        .events
        .push(egui::Event::Paste("clipboard contents".into()));
    h.run();
    assert_eq!(h.state().panels.comparer.right, "clipboard contents");
    assert!(h.state().panels.comparer.left.is_empty());
}

#[test]
fn comparer_load_reads_the_chosen_file_and_preserves_data_on_failure() {
    let mut h = harness(COMPARER);
    h.state_mut().panels.repeater.active_mut().response = "unrelated response".into();
    h.state_mut().panels.comparer.left = "keep until successful load".into();
    h.get_by_label("Load").click();
    h.run();
    assert!(h.query_by_label("Load comparer data").is_some());
    assert_eq!(h.state().panels.comparer.left, "keep until successful load");
    let path = std::env::temp_dir().join(format!(
        "gulpsuite-comparer-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, "data from selected file\n").unwrap();
    h.ctx
        .memory_mut(|m| m.request_focus(egui::Id::new("comparer-load-path")));
    h.input_mut()
        .events
        .push(egui::Event::Paste(path.to_string_lossy().to_string()));
    h.run();
    h.get_by_label("Load file").click();
    h.run();
    assert_eq!(h.state().panels.comparer.left, "data from selected file\n");
    std::fs::remove_file(&path).unwrap();
    h.get_by_label("Load").click();
    h.run();
    h.get_by_label("Load file").click();
    h.run();
    assert!(
        h.query_by_label("Load comparer data").is_some(),
        "Read errors must keep the dialog open"
    );
    assert_eq!(h.state().panels.comparer.left, "data from selected file\n");
}

#[test]
fn comparer_load_rejects_oversized_files_without_replacing_the_selected_item() {
    let mut h = harness(COMPARER);
    h.state_mut().panels.comparer.left = "preserve data".into();
    let path = std::env::temp_dir().join(format!(
        "gulpsuite-comparer-large-{}.txt",
        std::process::id()
    ));
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(4 * 1024 * 1024 + 1).unwrap();
    drop(file);
    h.get_by_label("Load").click();
    h.run();
    h.state_mut().panels.comparer.load_path = path.to_string_lossy().into_owned();
    h.run();
    h.get_by_label("Load file").click();
    h.run();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(h.state().panels.comparer.left, "preserve data");
    assert!(h
        .query_by_label("File exceeds the 4 MiB size limit")
        .is_some());
}
