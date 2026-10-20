use eframe::egui::{self, Vec2};
use egui_kittest::{Harness, kittest::Queryable};
use gulpsuite::ui::app::App;

fn scope_harness() -> Harness<'static, App> {
    let mut h = Harness::builder().with_size(Vec2::new(1440., 900.)).build_eframe(|cc| {
        let mut app = App::with_context(&cc.egui_ctx);
        app.tool = gulpsuite::ui::app::TARGET;
        app.view = 1;
        app.panels.target_panel.scope = "https://first.test/, https://second.test/".into();
        app
    });
    h.run(); h
}

#[test]
fn scope_remove_acts_on_the_selected_rule() {
    let mut h = scope_harness();
    h.get_by_label("https://first.test/").click(); h.run();
    h.get_all_by_label("Remove").next().unwrap().click(); h.run();
    assert!(!h.state().panels.target_panel.scope.contains("first.test"));
    assert!(h.state().panels.target_panel.scope.contains("second.test"));
}

#[test]
fn scope_disabled_rule_stays_disabled_and_stops_matching() {
    let mut h = scope_harness();
    h.get_all_by_role_and_label(egui::accesskit::Role::CheckBox, "").next().unwrap().click();
    h.run(); h.run();
    assert!(!h.state().panels.target_panel.in_scope("https://first.test/path"));
    assert!(h.state().panels.target_panel.in_scope("https://second.test/path"));
}
