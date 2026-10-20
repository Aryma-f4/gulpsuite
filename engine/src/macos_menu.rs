//! Native macOS Menu Bar (`NSMenu` outside the window at the top of the screen):
//! `Gulpsuite`, `Project`, `Intruder`, `Repeater`, `View`, `Help`.

#![allow(unexpected_cfgs)]

use std::ffi::CString;
use std::sync::{Mutex, Once};

use objc::declare::ClassDecl;
use objc::runtime::{Class, Object, Sel};
use objc::{class, msg_send, sel, sel_impl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeMenuAction {
    GulpSettings,
    ToggleTheme,
    Quit,
    NewProject,
    OpenProject,
    SaveProject,
    SaveProjectAs,
    ProjectSettings,
    IntruderStart,
    IntruderPauseResume,
    IntruderCancel,
    IntruderClear,
    RepeaterSend,
    RepeaterNewTab,
    RepeaterDuplicateTab,
    RepeaterToggleMethod,
    SelectTool(usize),
    ToggleEventLog,
    ToggleAllIssues,
    SetDark(bool),
    CommandPalette,
    OpenBrowser,
    BrowserConsole,
    GenerateCsrfPoc,
}

static QUEUE: Mutex<Vec<NativeMenuAction>> = Mutex::new(Vec::new());
static INIT: Once = Once::new();

pub fn take_actions() -> Vec<NativeMenuAction> {
    let Ok(mut guard) = QUEUE.lock() else {
        return Vec::new();
    };
    std::mem::take(&mut *guard)
}

extern "C" fn on_menu_item(_this: &Object, _cmd: Sel, sender: *mut Object) {
    if sender.is_null() {
        return;
    }
    let tag: isize = unsafe { msg_send![sender, tag] };
    let action = match tag {
        101 => Some(NativeMenuAction::GulpSettings),
        102 => Some(NativeMenuAction::ToggleTheme),
        109 => Some(NativeMenuAction::Quit),
        201 => Some(NativeMenuAction::NewProject),
        202 => Some(NativeMenuAction::OpenProject),
        203 => Some(NativeMenuAction::SaveProject),
        204 => Some(NativeMenuAction::SaveProjectAs),
        205 => Some(NativeMenuAction::ProjectSettings),
        301 => Some(NativeMenuAction::IntruderStart),
        302 => Some(NativeMenuAction::IntruderPauseResume),
        303 => Some(NativeMenuAction::IntruderCancel),
        304 => Some(NativeMenuAction::IntruderClear),
        401 => Some(NativeMenuAction::RepeaterSend),
        402 => Some(NativeMenuAction::RepeaterNewTab),
        403 => Some(NativeMenuAction::RepeaterDuplicateTab),
        404 => Some(NativeMenuAction::RepeaterToggleMethod),
        500..=512 => Some(NativeMenuAction::SelectTool((tag - 500) as usize)),
        520 => Some(NativeMenuAction::ToggleEventLog),
        521 => Some(NativeMenuAction::ToggleAllIssues),
        522 => Some(NativeMenuAction::SetDark(true)),
        523 => Some(NativeMenuAction::SetDark(false)),
        601 => Some(NativeMenuAction::CommandPalette),
        602 => Some(NativeMenuAction::OpenBrowser),
        603 => Some(NativeMenuAction::BrowserConsole),
        604 => Some(NativeMenuAction::GenerateCsrfPoc),
        _ => None,
    };
    if let Some(act) = action {
        if let Ok(mut guard) = QUEUE.lock() {
            guard.push(act);
        }
    }
}

unsafe fn nsstring(s: &str) -> *mut Object {
    let c = CString::new(s).unwrap_or_default();
    msg_send![class!(NSString), stringWithUTF8String: c.as_ptr()]
}

unsafe fn add_item(
    menu: *mut Object,
    target: *mut Object,
    title: &str,
    key: &str,
    tag: isize,
) {
    let item: *mut Object = msg_send![class!(NSMenuItem), alloc];
    let item: *mut Object = msg_send![
        item,
        initWithTitle: nsstring(title)
        action: sel!(gulpMenuAction:)
        keyEquivalent: nsstring(key)
    ];
    let _: () = msg_send![item, setTarget: target];
    let _: () = msg_send![item, setTag: tag];
    let _: () = msg_send![menu, addItem: item];
}

unsafe fn add_separator(menu: *mut Object) {
    let sep: *mut Object = msg_send![class!(NSMenuItem), separatorItem];
    let _: () = msg_send![menu, addItem: sep];
}

unsafe fn add_submenu(bar: *mut Object, title: &str) -> *mut Object {
    let holder: *mut Object = msg_send![class!(NSMenuItem), alloc];
    let holder: *mut Object = msg_send![
        holder,
        initWithTitle: nsstring(title)
        action: std::ptr::null::<Sel>()
        keyEquivalent: nsstring("")
    ];
    let sub: *mut Object = msg_send![class!(NSMenu), alloc];
    let sub: *mut Object = msg_send![sub, initWithTitle: nsstring(title)];
    let _: () = msg_send![sub, setAutoenablesItems: false];
    let _: () = msg_send![holder, setSubmenu: sub];
    let _: () = msg_send![bar, addItem: holder];
    sub
}

/// Installs the native macOS menu bar once on the main thread.
pub fn install_once() {
    INIT.call_once(|| unsafe {
        let superclass = class!(NSObject);
        let target_cls = Class::get("GulpMenuTarget").unwrap_or_else(|| {
            let mut decl = ClassDecl::new("GulpMenuTarget", superclass).expect("class decl");
            decl.add_method(
                sel!(gulpMenuAction:),
                on_menu_item as extern "C" fn(&Object, Sel, *mut Object),
            );
            decl.register()
        });
        let target: *mut Object = msg_send![target_cls, new];

        let app: *mut Object = msg_send![class!(NSApplication), sharedApplication];
        if app.is_null() {
            return;
        }
        let bar: *mut Object = msg_send![class!(NSMenu), new];

        // 1. Application Menu ("Gulpsuite")
        let app_menu = add_submenu(bar, "Gulpsuite");
        add_item(app_menu, target, "Gulp Settings…", ",", 101);
        add_item(app_menu, target, "Switch Theme (Dark / Light)", "", 102);
        add_separator(app_menu);
        add_item(app_menu, target, "Quit Gulpsuite", "q", 109);

        // 2. Project Menu
        let project_menu = add_submenu(bar, "Project");
        add_item(project_menu, target, "New temporary project", "n", 201);
        add_item(project_menu, target, "Open project…", "o", 202);
        add_item(project_menu, target, "Save project", "s", 203);
        add_item(project_menu, target, "Save project as…", "S", 204);
        add_separator(project_menu);
        add_item(project_menu, target, "Project settings…", "", 205);

        // 3. Intruder Menu
        let intruder_menu = add_submenu(bar, "Intruder");
        add_item(intruder_menu, target, "Start attack", "", 301);
        add_item(intruder_menu, target, "Pause / Resume attack", "", 302);
        add_item(intruder_menu, target, "Cancel attack", "", 303);
        add_separator(intruder_menu);
        add_item(intruder_menu, target, "Clear results", "", 304);

        // 4. Repeater Menu
        let repeater_menu = add_submenu(bar, "Repeater");
        add_item(repeater_menu, target, "Send", "r", 401);
        add_item(repeater_menu, target, "New tab", "t", 402);
        add_item(repeater_menu, target, "Duplicate tab", "", 403);
        add_item(
            repeater_menu,
            target,
            "Change request method (GET ↔ POST)",
            "",
            404,
        );

        // 5. View Menu
        let view_menu = add_submenu(bar, "View");
        for (idx, name) in crate::ui::app::TOOLS.iter().enumerate() {
            add_item(view_menu, target, name, "", 500 + idx as isize);
        }
        add_separator(view_menu);
        add_item(view_menu, target, "Event log", "", 520);
        add_item(view_menu, target, "All issues", "", 521);
        add_separator(view_menu);
        add_item(view_menu, target, "Dark theme", "", 522);
        add_item(view_menu, target, "Light theme", "", 523);

        // 6. Help Menu
        let help_menu = add_submenu(bar, "Help");
        add_item(help_menu, target, "Command palette & Search…", "k", 601);
        add_item(help_menu, target, "Open integrated Chromium browser", "", 602);
        add_item(help_menu, target, "Browser console", "", 603);
        add_item(help_menu, target, "Generate CSRF PoC", "", 604);

        let _: () = msg_send![app, setMainMenu: bar];
    });
}
