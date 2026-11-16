//! Opt-in native regression for GitHub #1:
//! cargo run --example native_layout_smoke
//! Exercises real macOS window chrome and tool layouts without sending traffic.
#[cfg(target_os = "macos")]
fn main() -> eframe::Result<()> {
    use gulpsuite::ui::app::{App, Transaction, INTRUDER, LOGGER, TARGET};
    struct Smoke {
        app: App,
        frames: usize,
    }
    impl eframe::App for Smoke {
        fn update(&mut self, ctx: &eframe::egui::Context, frame: &mut eframe::Frame) {
            let phase = self.frames / 12;
            (self.app.tool, self.app.view) = match phase {
                0 => (LOGGER, 0),
                1 => (TARGET, 1),
                2 => (INTRUDER, 0),
                3 => (TARGET, 0),
                _ => (TARGET, 2),
            };
            if self.frames % 12 == 0 {
                let size = if phase % 2 == 0 {
                    [900., 700.]
                } else {
                    [1360., 820.]
                };
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::InnerSize(size.into()));
                self.app.set_dark(phase % 2 == 0);
                eprintln!(
                    "phase {phase}: tool {}, view {}, pixels_per_point {}",
                    self.app.tool,
                    self.app.view,
                    ctx.pixels_per_point()
                );
            }
            eframe::App::update(&mut self.app, ctx, frame);
            self.frames += 1;
            if self.frames >= 72 {
                eprintln!("Native macOS issue #1 layout smoke passed (72 frames)");
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);
            } else {
                ctx.request_repaint();
            }
        }
    }
    eframe::run_native(
        "Gulpsuite issue #1 native verification",
        eframe::NativeOptions::default(),
        Box::new(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.use_native_macos_menu = true;
            app.show_menu_bar = false;
            app.panels.target_panel.scope = "https://layout.test/, https://second.test/".into();
            app.panels.target_panel.host = Some("https://layout.test".into());
            app.panels.target_panel.path = Some("/layout".into());
            app.panels.intruder.payload_sets[0].values = "payload-".repeat(200);
            app.log.push_back(Transaction {
                method: "GET".into(),
                target: "https://layout.test/layout".into(),
                status: 200,
                bytes: 2,
                host: "layout.test".into(),
                secure: true,
                request: format!(
                    "GET /layout HTTP/1.1\r\nHost: layout.test\r\n\r\n{}",
                    "long-content-".repeat(200)
                ),
                response: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK".into(),
                truncated: false,
            });
            app.log_version += 1;
            app.workspace
                .issues
                .upsert(gulpsuite::workspace::IssueRecord::new(
                    gulpsuite::workspace::TaskId(1),
                    "Native layout verification issue",
                    gulpsuite::workspace::IssueSeverity::Info,
                    "Certain",
                    "https://layout.test/layout",
                    None,
                    "Local fixture for populated Target Issues layout",
                    1,
                ));
            Ok(Box::new(Smoke { app, frames: 0 }))
        }),
    )
}

#[cfg(not(target_os = "macos"))]
fn main() {}
