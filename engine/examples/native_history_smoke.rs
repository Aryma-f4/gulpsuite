//! Opt-in native AppKit regression: cargo run --example native_history_smoke.
//! Headless egui tests cannot exercise Touch Bar responder observers.
#![allow(unexpected_cfgs)]

#[cfg(target_os = "macos")]
fn main() -> eframe::Result<()> {
    use objc::runtime::Object;
    use objc::{class, msg_send, sel, sel_impl};
    struct Smoke {
        app: gulpsuite::ui::app::App,
        frames: usize,
    }
    impl eframe::App for Smoke {
        fn update(&mut self, ctx: &eframe::egui::Context, frame: &mut eframe::Frame) {
            self.app.tool = if self.frames % 10 < 5 {
                gulpsuite::ui::app::PROXY
            } else {
                0
            };
            self.app.view = if self.app.tool == gulpsuite::ui::app::PROXY {
                1
            } else {
                0
            };
            eframe::App::update(&mut self.app, ctx, frame);
            self.frames += 1;
            if self.frames > 80 {
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close);
            }
            ctx.request_repaint();
        }
    }
    // Reproduce the same KVO lifecycle as AppKit's Touch Bar finder: it
    // observes nextResponder after AccessKit has installed its view subclass.
    struct Handler;
    impl eframe::egui::accesskit::ActivationHandler for Handler {
        fn request_initial_tree(&mut self) -> Option<eframe::egui::accesskit::TreeUpdate> {
            None
        }
    }
    impl eframe::egui::accesskit::ActionHandler for Handler {
        fn do_action(&mut self, _: eframe::egui::accesskit::ActionRequest) {}
    }
    unsafe {
        let pool: *mut Object = msg_send![class!(NSAutoreleasePool), new];
        let view: *mut Object = msg_send![class!(NSView), new];
        let observer: *mut Object = msg_send![class!(NSObject), new];
        let key: *mut Object =
            msg_send![class!(NSString), stringWithUTF8String: c"nextResponder".as_ptr()];
        // Unobserved views must still support normal detach and reattachment.
        drop(accesskit_macos::SubclassingAdapter::new(
            view.cast(),
            Handler,
            Handler,
        ));
        drop(accesskit_macos::SubclassingAdapter::new(
            view.cast(),
            Handler,
            Handler,
        ));
        let adapter = accesskit_macos::SubclassingAdapter::new(view.cast(), Handler, Handler);
        let _: () = msg_send![view, addObserver: observer forKeyPath: key options: 0usize context: std::ptr::null_mut::<std::ffi::c_void>()];
        eprintln!("nextResponder observer registered; dropping adapter");
        drop(adapter);
        eprintln!("adapter dropped; removing nextResponder observer");
        // Previously throws NSRangeException: observer is no longer registered.
        let _: () = msg_send![view, removeObserver: observer forKeyPath: key];
        let _: () = msg_send![observer, release];
        let _: () = msg_send![view, release];
        let _: () = msg_send![pool, drain];
    }
    eprintln!("Native nextResponder observer lifecycle passed");
    eframe::run_native(
        "Native history regression",
        eframe::NativeOptions::default(),
        Box::new(|cc| {
            let mut app = gulpsuite::ui::app::App::new(cc);
            app.log.push_back(gulpsuite::ui::app::Transaction {
                method: "GET".into(),
                target: "http://127.0.0.1/test".into(),
                status: 200,
                bytes: 2,
                host: "127.0.0.1".into(),
                secure: false,
                request: "GET /test HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".into(),
                response: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".into(),
                truncated: false,
            });
            Ok(Box::new(Smoke { app, frames: 0 }))
        }),
    )
}

#[cfg(not(target_os = "macos"))]
fn main() {}
