//! Logger must search all retained traffic, not only the latest viewport window.
use eframe::egui::Vec2;
use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::ui::app::{App, Transaction, LOGGER};

fn fixture(filter: &str, errors_only: bool) -> Harness<App> {
    Harness::builder().with_size(Vec2::new(1000., 740.)).build_eframe(|cc| {
        let mut app = App::with_context(&cc.egui_ctx);
        app.tool = LOGGER;
        app.panels.logger.filter = filter.into();
        app.panels.logger.only_errors = errors_only;
        for i in 0..501 {
            app.log.push_back(Transaction {
                method: "GET".into(), target: format!("https://logger.test/item-{i}"),
                status: if i == 0 { 500 } else { 200 }, bytes: 2,
                host: "logger.test".into(), secure: true,
                request: format!("GET /item-{i} HTTP/1.1\r\nHost: logger.test\r\n\r\n"),
                response: "HTTP/1.1 200 OK\r\n\r\nOK".into(), truncated: false,
            });
        }
        app
    })
}

#[test]
fn logger_filter_finds_traffic_older_than_500_rows() {
    let mut h = fixture("item-0", false);
    h.run();
    assert_eq!(h.state().panels.logger.selected, Some(0));
    assert!(h.query_by_label("Logger is empty").is_none());
}

#[test]
fn logger_error_filter_finds_errors_older_than_500_rows() {
    let mut h = fixture("", true);
    h.run();
    assert_eq!(h.state().panels.logger.selected, Some(0));
}

#[test]
fn logger_no_matches_is_not_reported_as_empty_capture() {
    let mut h = fixture("no-such-request", false);
    h.run();
    assert!(h.query_by_label("No matching traffic").is_some());
    assert!(h.query_by_label("Logger is empty").is_none());
}

#[test]
fn logger_sort_includes_all_retained_rows() {
    let mut h = fixture("", false);
    h.state_mut().panels.logger.sort_column = Some(0);
    h.state_mut().panels.logger.sort_ascending = true;
    h.state_mut().panels.logger.selected = None;
    h.run();
    assert_eq!(h.state().panels.logger.selected, Some(0));
}

#[test]
fn logger_without_traffic_still_shows_empty_capture() {
    let mut h = fixture("", false);
    h.state_mut().log.clear();
    h.run();
    assert!(h.query_by_label("Logger is empty").is_some());
    assert!(h.query_by_label("No matching traffic").is_none());
}
