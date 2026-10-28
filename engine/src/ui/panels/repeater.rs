//! Gulpsuite Professional Repeater (`quick-start-pro-repeater.png`,
//! `quick-start-pro-repeater-history.png`, `send-group.html`, `tab-settings.html`, `groups.html`):
//! - Multi-tab strip with 3px orange `#FF6633` underline, tab groups & colors, right-click
//!   tab management (`Rename`, `Duplicate`, `Add to group`, `Close other/left/right`, `Reopen closed tab`),
//!   and `...` tab jump menu
//! - `Send` + `▾` Group Send modes (`Send group in sequence (single connection)`,
//!   `Send group in sequence (separate connections)`, `Send group in parallel`)
//! - `<` (`Previous response`), `>` (`Next response`), and `▾` numbered history dropdown list
//! - `⚙` Tab-specific settings (`HTTP/1 & HTTP/2 connection reuse`, `Update Content-Length`,
//!   `Unpack compressed responses`, `Normalize HTTP/1 line endings`, `Follow redirects: Never / On-site / In-scope / Always`,
//!   `Process cookies in redirects`, `Restore global default`)
//! - `Target:` bar with `✎` Target & `Override SNI` popup
//! - Line-numbered `Request` & `Response` panes with orange headers and `Pretty | Raw | Hex | Render | \n | ≡` pill bar.

use eframe::egui::{self, Color32, RichText, Ui, Vec2};

use crate::ui::app::App;

#[derive(Clone)]
pub struct RepeaterExchange {
    pub host: String,
    pub request: String,
    pub response: String,
    pub status: Option<u16>,
    pub elapsed_ms: u128,
}

/// One request in the Repeater. Gulp keeps several open at once, each in its own tab.
#[derive(Clone)]
pub struct RepeaterTab {
    /// The name on the tab, taken from the target.
    pub name: String,
    pub host: String,
    pub raw: String,
    pub response: String,
    pub status: Option<u16>,
    pub elapsed_ms: u128,
    pub sending: bool,
    /// The in-flight request id, if any.
    pub pending: Option<u64>,
    /// The raw editor is shown only on demand; the coloured view is the default.
    pub editing: bool,
    pub hex_view: bool,
    pub render_view: bool,
    /// Response formatting is independent from the editable request.
    pub response_mode: usize,
    pub response_non_printable: bool,
    pub show_non_printable: bool,
    pub notes: String,
    pub group_name: String,
    /// 0 = None, 1 = Purple, 2 = Red, 3 = Yellow, 4 = Green, 5 = Blue, 6 = Teal, 7 = Magenta
    pub group_color: u8,
    pub override_sni_enabled: bool,
    pub override_sni: String,
    pub custom_tab_settings: bool,
    pub http1_reuse: bool,
    pub http2_reuse: bool,
    pub allow_http2_alpn_override: bool,
    pub update_content_length: bool,
    pub unpack_compressed: bool,
    pub normalize_line_endings: bool,
    pub strip_conn_over_http2: bool,
    /// 0 = Never, 1 = On-site only, 2 = In-scope only, 3 = Always
    pub follow_redirects_mode: usize,
    pub process_cookies_in_redirects: bool,
    pub parallel_order_badge: Option<(usize, usize)>,
    pub history: Vec<RepeaterExchange>,
    pub history_cursor: Option<usize>,
    in_flight: Option<(String, String, std::time::Instant)>,
}

impl Default for RepeaterTab {
    fn default() -> Self {
        RepeaterTab {
            name: "1".into(),
            host: "http://example.com/".into(),
            raw: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
            response: String::new(),
            status: None,
            elapsed_ms: 0,
            sending: false,
            pending: None,
            editing: false,
            hex_view: false,
            render_view: false,
            response_mode: 0,
            response_non_printable: false,
            show_non_printable: false,
            notes: String::new(),
            group_name: String::new(),
            group_color: 0,
            override_sni_enabled: false,
            override_sni: String::new(),
            custom_tab_settings: false,
            http1_reuse: false,
            http2_reuse: true,
            allow_http2_alpn_override: false,
            update_content_length: true,
            unpack_compressed: true,
            normalize_line_endings: true,
            strip_conn_over_http2: true,
            follow_redirects_mode: 0,
            process_cookies_in_redirects: false,
            parallel_order_badge: None,
            history: Vec::new(),
            history_cursor: None,
            in_flight: None,
        }
    }
}

impl RepeaterTab {
    pub fn restore_default_settings(&mut self) {
        self.custom_tab_settings = false;
        self.http1_reuse = false;
        self.http2_reuse = true;
        self.allow_http2_alpn_override = false;
        self.update_content_length = true;
        self.unpack_compressed = true;
        self.normalize_line_endings = true;
        self.strip_conn_over_http2 = true;
        self.follow_redirects_mode = 0;
        self.process_cookies_in_redirects = false;
    }

    pub fn navigate_history(&mut self, direction: isize) -> bool {
        if self.sending || self.history.is_empty() {
            return false;
        }
        let current = self.history_cursor.unwrap_or(self.history.len() - 1);
        let Some(next) = current
            .checked_add_signed(direction)
            .filter(|next| *next < self.history.len())
        else {
            return false;
        };
        self.jump_to_history(next)
    }

    pub fn jump_to_history(&mut self, index: usize) -> bool {
        let Some(exchange) = self.history.get(index).cloned() else {
            return false;
        };
        self.host = exchange.host;
        self.raw = exchange.request;
        self.response = exchange.response;
        self.status = exchange.status;
        self.elapsed_ms = exchange.elapsed_ms;
        self.history_cursor = Some(index);
        true
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
        self.history_cursor = None;
    }
}

#[derive(Clone)]
pub struct RepeaterPanel {
    pub tabs: Vec<RepeaterTab>,
    pub closed_tabs: Vec<RepeaterTab>,
    /// The tab that is open.
    pub active: usize,
    /// False = side-by-side (2 columns), true = top/bottom stacked layout.
    pub stacked_layout: bool,
    /// Draggable left/right split ratio between Request and Response (`0.18..=0.82`).
    pub split_ratio: f32,
    /// Draggable height of the Request/Response editors.
    pub editor_height: f32,
    /// Opens the active Repeater tab in a freely resizable floating window.
    pub detached_open: bool,
    /// 0 = Send single tab, 1 = Send group in sequence (single conn),
    /// 2 = Send group in sequence (separate conns), 3 = Send group in parallel.
    pub send_group_mode: usize,
    pub rename_tab: Option<usize>,
    pub rename_draft: String,
    pub show_target_modal: bool,
    pub new_group_name: String,
    pub new_group_color: u8,
    pub show_getting_started: bool,
    pub force_getting_started: bool,
    pub hide_getting_started_forever: bool,
    pub show_analysis_drawer: bool,
    pub sidebar_open: bool,
    pub sidebar_tab: usize,
    pub sidebar_dock_left: bool,
    pub sidebar_ratio: f32,
    pub req_wrap: bool,
    pub resp_wrap: bool,
}

impl Default for RepeaterPanel {
    fn default() -> Self {
        RepeaterPanel {
            tabs: vec![RepeaterTab::default()],
            closed_tabs: Vec::new(),
            active: 0,
            stacked_layout: false,
            split_ratio: 0.5,
            editor_height: 460.0,
            detached_open: false,
            send_group_mode: 0,
            rename_tab: None,
            rename_draft: String::new(),
            show_target_modal: false,
            new_group_name: "Group 1".into(),
            new_group_color: 1,
            show_getting_started: true,
            force_getting_started: false,
            hide_getting_started_forever: false,
            show_analysis_drawer: false,
            sidebar_open: true,
            sidebar_tab: 0,
            sidebar_dock_left: false,
            sidebar_ratio: 0.74,
            req_wrap: true,
            resp_wrap: true,
        }
    }
}

impl RepeaterPanel {
    /// The tab that is open. There is always one, because a new panel starts with a tab.
    pub fn active(&self) -> &RepeaterTab {
        self.tabs.get(self.active).unwrap_or(&self.tabs[0])
    }

    pub fn active_mut(&mut self) -> &mut RepeaterTab {
        let index = self.active.min(self.tabs.len().saturating_sub(1));
        &mut self.tabs[index]
    }

    /// Opens a request in a new tab, the way Gulp does when something is sent to the Repeater.
    pub fn open(&mut self, host: &str, raw: &str) {
        self.show_getting_started = false;
        self.force_getting_started = false;
        let name = name_for(host, self.tabs.len() + 1);
        self.tabs.push(RepeaterTab {
            name,
            host: host.to_string(),
            raw: raw.to_string(),
            ..Default::default()
        });
        self.active = self.tabs.len() - 1;
    }

    pub fn duplicate_active(&mut self) {
        self.show_getting_started = false;
        self.force_getting_started = false;
        let mut cloned = self.active().clone();
        cloned.name = format!("{} (copy)", cloned.name);
        cloned.pending = None;
        cloned.sending = false;
        cloned.in_flight = None;
        self.tabs.push(cloned);
        self.active = self.tabs.len() - 1;
    }

    /// Puts a request into the tab that is open, replacing what is in it.
    pub fn reuse(&mut self, host: &str, raw: &str, response: &str) {
        self.show_getting_started = false;
        self.force_getting_started = false;
        let count = self.tabs.len();
        let tab = self.active_mut();
        tab.name = name_for(host, count);
        tab.host = host.to_string();
        tab.raw = raw.to_string();
        tab.response = response.to_string();
        tab.status = None;
        tab.elapsed_ms = 0;
        tab.editing = false;
        tab.hex_view = false;
        tab.render_view = false;
        tab.response_mode = 0;
        tab.response_non_printable = false;
        tab.pending = None;
        tab.sending = false;
        tab.in_flight = None;
        tab.history.clear();
        tab.history_cursor = None;
    }

    /// Closes a tab, keeping at least one open, and saves the closed tab for `Reopen closed tab`.
    pub fn close(&mut self, index: usize) {
        if self.tabs.len() <= 1 || index >= self.tabs.len() {
            return;
        }
        let removed = self.tabs.remove(index);
        if self.closed_tabs.len() >= 20 {
            self.closed_tabs.remove(0);
        }
        self.closed_tabs.push(removed);
        if index < self.active {
            self.active -= 1;
        } else if self.active >= self.tabs.len() {
            self.active = self.tabs.len() - 1;
        }
    }

    pub fn reopen_closed_tab(&mut self) -> bool {
        if let Some(mut tab) = self.closed_tabs.pop() {
            tab.pending = None;
            tab.sending = false;
            tab.in_flight = None;
            self.tabs.push(tab);
            self.active = self.tabs.len() - 1;
            true
        } else {
            false
        }
    }

    pub fn close_other_tabs(&mut self, keep_index: usize) {
        if keep_index >= self.tabs.len() {
            return;
        }
        let kept = self.tabs[keep_index].clone();
        for (i, t) in self.tabs.drain(..).enumerate() {
            if i != keep_index {
                self.closed_tabs.push(t);
            }
        }
        self.tabs.push(kept);
        self.active = 0;
    }

    pub fn clear_all_history(&mut self) {
        for tab in &mut self.tabs {
            tab.clear_history();
        }
    }

    pub fn complete(&mut self, id: u64, status: u16, response: String) -> bool {
        let Some(tab) = self.tabs.iter_mut().find(|tab| tab.pending == Some(id)) else {
            return false;
        };
        let (host, request, elapsed_ms) = tab
            .in_flight
            .take()
            .map(|(host, request, start)| (host, request, start.elapsed().ms()))
            .unwrap_or_else(|| (tab.host.clone(), tab.raw.clone(), 0));
        tab.status = (status != 0).then_some(status);
        tab.elapsed_ms = elapsed_ms;
        tab.response = response.clone();
        tab.pending = None;
        tab.sending = false;
        if tab.history.len() >= 100 {
            tab.history.remove(0);
        }
        tab.history.push(RepeaterExchange {
            host,
            request,
            response,
            status: tab.status,
            elapsed_ms,
        });
        while tab.history.len() > 1
            && tab
                .history
                .iter()
                .map(|exchange| exchange.request.len() + exchange.response.len())
                .sum::<usize>()
                > 64 * 1024 * 1024
        {
            tab.history.remove(0);
        }
        tab.history_cursor = Some(tab.history.len() - 1);
        true
    }
}

trait DurationMs {
    fn ms(&self) -> u128;
}
impl DurationMs for std::time::Duration {
    fn ms(&self) -> u128 {
        self.as_millis()
    }
}

fn truncate_host_text(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// The name on a tab: the host, with a number when the name is taken.
fn name_for(host: &str, fallback: usize) -> String {
    let rest = host
        .strip_prefix("http://")
        .or_else(|| host.strip_prefix("https://"))
        .unwrap_or(host);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        fallback.to_string()
    } else {
        truncate_host_text(authority, 22)
    }
}

fn group_color_swatch(code: u8) -> Option<Color32> {
    match code {
        1 => Some(Color32::from_rgb(0x5B, 0x4F, 0xFF)), // Purple
        2 => Some(Color32::from_rgb(0xD6, 0x21, 0x3F)), // Red
        3 => Some(Color32::from_rgb(0xD3, 0x8C, 0x01)), // Yellow
        4 => Some(Color32::from_rgb(0x3B, 0xA3, 0x17)), // Green
        5 => Some(Color32::from_rgb(0x26, 0x64, 0x9D)), // Blue
        6 => Some(Color32::from_rgb(0x00, 0xA2, 0xB9)), // Teal
        7 => Some(Color32::from_rgb(0xC3, 0x11, 0xA8)), // Magenta
        _ => None,
    }
}

fn group_color_name(code: u8) -> &'static str {
    match code {
        1 => "Purple",
        2 => "Red",
        3 => "Yellow",
        4 => "Green",
        5 => "Blue",
        6 => "Teal",
        7 => "Magenta",
        _ => "No group",
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    {
        let w = &mut ui.style_mut().visuals.widgets;
        let r = egui::CornerRadius::same(4);
        w.inactive.corner_radius = r;
        w.hovered.corner_radius = r;
        w.active.corner_radius = r;
        w.open.corner_radius = r;
        w.noninteractive.corner_radius = r;
    }

    let is_untouched_default = app.panels.repeater.tabs.len() == 1
        && app.panels.repeater.tabs[0].host == "http://example.com/"
        && app.panels.repeater.tabs[0].raw == "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        && app.panels.repeater.tabs[0].response.is_empty()
        && !app.panels.repeater.tabs[0].sending;
    if !app.panels.repeater.hide_getting_started_forever
        && (app.panels.repeater.force_getting_started
            || (app.panels.repeater.show_getting_started && is_untouched_default))
    {
        draw_repeater_getting_started(app, ui, &theme);
        return;
    }

    tabs(app, ui, &theme);

    let redirect_target = redirect_url(
        &app.panels.repeater.active().host,
        app.panels.repeater.active().status,
        &app.panels.repeater.active().response,
    );

    // Auto-follow redirect if tab-specific `follow_redirects_mode` allows it
    if let Some((ref next_host, ref next_path)) = redirect_target {
        let mode = app.panels.repeater.active().follow_redirects_mode;
        let should_auto = match mode {
            3 => true, // Always
            1 => next_host == &app.panels.repeater.active().host, // On-site only
            2 => app.panels.target_panel.in_scope(next_host), // In-scope only
            _ => false,
        };
        if should_auto && !app.panels.repeater.active().sending {
            let nh = next_host.clone();
            let np = next_path.clone();
            follow_redirect(app, &nh, &np);
        }
    }

    // Single-row Gulp Repeater Action Toolbar (`quick-start-pro-repeater.png` & `quick-start-pro-repeater-history.png`)
    let bar_bg = theme.color("ui.background.0");
    let border_col = theme.color("ui.border.1");
    egui::Frame::new()
        .fill(bar_bg)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                // 1. Orange `Send` button (`#E05320`) + `▾` Group send menu
                if ui
                    .add_enabled_ui(!app.panels.repeater.active().sending, |ui| {
                        let btn = egui::Button::new(
                            RichText::new("Send")
                                .color(Color32::WHITE)
                                .strong()
                                .size(12.5),
                        )
                        .fill(Color32::from_rgb(0xE0, 0x53, 0x20))
                        .corner_radius(4.0)
                        .min_size(Vec2::new(66.0, 26.0));
                        ui.add(btn)
                    })
                    .inner
                    .clicked()
                {
                    if app.panels.repeater.send_group_mode == 0 {
                        send(app);
                    } else {
                        send_group(app);
                    }
                }

                let active_grp_color = app.panels.repeater.active().group_color;
                let active_grp_name = app.panels.repeater.active().group_name.trim().to_string();
                let grp_member_count = if active_grp_color == 0 {
                    app.panels.repeater.tabs.len()
                } else {
                    app.panels
                        .repeater
                        .tabs
                        .iter()
                        .filter(|t| t.group_color == active_grp_color)
                        .count()
                };
                let group_btn_label = if active_grp_color > 0 {
                    let gtitle = if active_grp_name.is_empty() {
                        group_color_name(active_grp_color)
                    } else {
                        active_grp_name.as_str()
                    };
                    format!("Group: {gtitle} ({grp_member_count})")
                } else {
                    "Group".to_string()
                };
                ui.menu_button(group_btn_label, |ui| {
                    ui.set_min_width(310.0);
                    ui.label(RichText::new("Tab group assignment").strong());
                    ui.horizontal(|ui| {
                        ui.label("Group name:");
                        ui.add(
                            egui::TextEdit::singleline(
                                &mut app.panels.repeater.active_mut().group_name,
                            )
                            .hint_text("e.g. Auth, Checkout, Admin")
                            .desired_width(175.0),
                        );
                    });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().button_padding = Vec2::new(8.0, 3.0);
                        let cur_code = app.panels.repeater.active().group_color;
                        if ui.selectable_label(cur_code == 0, "None").clicked() {
                            app.panels.repeater.active_mut().group_color = 0;
                        }
                        for code in 1u8..=7 {
                            let swatch = group_color_swatch(code).unwrap_or(Color32::GRAY);
                            let is_sel = cur_code == code;
                            let btn = egui::Button::new(
                                RichText::new(group_color_name(code))
                                    .size(11.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(swatch)
                            .stroke(if is_sel {
                                egui::Stroke::new(2.0, Color32::WHITE)
                            } else {
                                egui::Stroke::NONE
                            })
                            .corner_radius(4.0);
                            if ui.add(btn).clicked() {
                                app.panels.repeater.active_mut().group_color = code;
                                if app.panels.repeater.active().group_name.trim().is_empty() {
                                    app.panels.repeater.active_mut().group_name =
                                        format!("{} group", group_color_name(code));
                                }
                            }
                        }
                    });
                    if active_grp_color > 0 {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.label(format!(
                                "Tabs in this group: {grp_member_count}"
                            ));
                            if ui.small_button("+ Add tab to this group").clicked() {
                                let host = app.panels.repeater.active().host.clone();
                                let raw = app.panels.repeater.active().raw.clone();
                                let gname = app.panels.repeater.active().group_name.clone();
                                app.panels.repeater.open(&host, &raw);
                                app.panels.repeater.active_mut().group_color = active_grp_color;
                                app.panels.repeater.active_mut().group_name = gname;
                                ui.close();
                            }
                        });
                    }
                    ui.separator();
                    ui.label(RichText::new("Group send options").strong());
                    for (idx, lbl) in [
                        (0usize, "Send single tab"),
                        (1usize, "Send group in sequence (single connection)"),
                        (2usize, "Send group in sequence (separate connections)"),
                        (3usize, "Send group in parallel"),
                    ] {
                        if ui
                            .radio_value(&mut app.panels.repeater.send_group_mode, idx, lbl)
                            .clicked()
                        {
                            ui.close();
                        }
                    }
                    ui.add_space(4.0);
                    if crate::ui::app::primary_button(
                        ui,
                        &theme,
                        &format!("Send group now ({grp_member_count} tab(s))"),
                    )
                    .clicked()
                    {
                        if app.panels.repeater.send_group_mode == 0 {
                            app.panels.repeater.send_group_mode = 1;
                        }
                        send_group(app);
                        ui.close();
                    }
                });

                // 2. Outlined `Cancel` button
                if ui
                    .add_enabled(
                        app.panels.repeater.active().sending,
                        eframe::egui::Button::new("Cancel").min_size(Vec2::new(66.0, 26.0)),
                    )
                    .clicked()
                {
                    cancel(app);
                }

                // 3. `< | ▾` and `> | ▾` split history buttons (`quick-start-pro-repeater-history.png`)
                let hist_items: Vec<(usize, String)> = app
                    .panels
                    .repeater
                    .active()
                    .history
                    .iter()
                    .enumerate()
                    .map(|(idx, ex)| {
                        let first_line = ex.request.lines().next().unwrap_or("GET /");
                        let path = first_line.split_whitespace().nth(1).unwrap_or("/");
                        let full_entry = format!(
                            "{}. {}{}",
                            idx + 1,
                            ex.host.trim_end_matches('/'),
                            path
                        );
                        (idx, truncate_host_text(&full_entry, 56))
                    })
                    .rev()
                    .collect();
                let cur_hist = app.panels.repeater.active().history_cursor;
                let can_back = !app.panels.repeater.active().sending
                    && cur_hist.unwrap_or(0) > 0;
                let can_fwd = !app.panels.repeater.active().sending
                    && cur_hist
                        .map(|c| c + 1 < app.panels.repeater.active().history.len())
                        .unwrap_or(false);

                if ui
                    .add_enabled(can_back, egui::Button::new("<").min_size(Vec2::new(24.0, 26.0)))
                    .on_hover_text("Previous response")
                    .clicked()
                {
                    app.panels.repeater.active_mut().navigate_history(-1);
                }
                ui.menu_button("History", |ui| {
                    ui.set_min_width(320.0);
                    ui.label(
                        RichText::new(format!("Tab history ({} entries)", hist_items.len()))
                            .strong(),
                    );
                    ui.separator();
                    if hist_items.is_empty() {
                        ui.label("No requests sent in this tab yet.");
                    } else {
                        for (idx, label) in &hist_items {
                            let is_cur = cur_hist == Some(*idx);
                            if ui.selectable_label(is_cur, label).clicked() {
                                app.panels.repeater.active_mut().jump_to_history(*idx);
                                ui.close();
                            }
                        }
                    }
                    ui.separator();
                    let any_history = app
                        .panels
                        .repeater
                        .tabs
                        .iter()
                        .any(|t| !t.history.is_empty());
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !hist_items.is_empty(),
                                egui::Button::new("Clear history"),
                            )
                            .clicked()
                        {
                            app.panels.repeater.active_mut().clear_history();
                            app.status = "Cleared Repeater tab history".into();
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                any_history,
                                egui::Button::new("Clear all tabs history"),
                            )
                            .clicked()
                        {
                            app.panels.repeater.clear_all_history();
                            app.status = "Cleared history across all Repeater tabs".into();
                            ui.close();
                        }
                    });
                });
                if ui
                    .add_enabled(can_fwd, egui::Button::new(">").min_size(Vec2::new(24.0, 26.0)))
                    .on_hover_text("Next response")
                    .clicked()
                {
                    app.panels.repeater.active_mut().navigate_history(1);
                }

                if let Some((next_host, next_path)) = redirect_target {
                    if ui.button("Follow redirection").clicked() {
                        follow_redirect(app, &next_host, &next_path);
                    }
                }

                // Layout & Tab-specific Repeater settings (`tab-settings.html`) with vector gear icon
                let custom_settings = app.panels.repeater.active().custom_tab_settings;
                let gear_col = if custom_settings {
                    theme.color("palette.secondary.core")
                } else {
                    theme.color("ui.icon.default")
                };
                let menu_resp = ui.menu_button("   ", |ui| {
                    ui.set_min_width(270.0);
                    let tab = app.panels.repeater.active_mut();
                    ui.label(RichText::new("Connections").strong());
                    if ui
                        .checkbox(&mut tab.http1_reuse, "HTTP/1 connection reuse")
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    if ui
                        .checkbox(&mut tab.http2_reuse, "HTTP/2 connection reuse")
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    if ui
                        .checkbox(
                            &mut tab.allow_http2_alpn_override,
                            "Allow HTTP/2 ALPN override",
                        )
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    ui.separator();
                    ui.label(RichText::new("Message modification").strong());
                    if ui
                        .checkbox(&mut tab.update_content_length, "Update Content-Length")
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    if ui
                        .checkbox(&mut tab.unpack_compressed, "Unpack compressed responses")
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    if ui
                        .checkbox(
                            &mut tab.normalize_line_endings,
                            "Normalize HTTP/1 line endings",
                        )
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    if ui
                        .checkbox(
                            &mut tab.strip_conn_over_http2,
                            "Strip Connection header over HTTP/2",
                        )
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    ui.separator();
                    ui.label(RichText::new("Redirects").strong());
                    for (m_idx, lbl) in ["Never", "On-site only", "In-scope only", "Always"]
                        .iter()
                        .enumerate()
                    {
                        if ui
                            .radio_value(&mut tab.follow_redirects_mode, m_idx, *lbl)
                            .changed()
                        {
                            tab.custom_tab_settings = true;
                        }
                    }
                    if ui
                        .checkbox(
                            &mut tab.process_cookies_in_redirects,
                            "Process cookies in redirects",
                        )
                        .changed()
                    {
                        tab.custom_tab_settings = true;
                    }
                    ui.separator();
                    if ui.button("Restore global default").clicked() {
                        tab.restore_default_settings();
                        ui.close();
                    }
                });
                crate::ui::icons::paint(
                    ui.painter(),
                    egui::Rect::from_center_size(
                        menu_resp.response.rect.center(),
                        Vec2::splat(14.0),
                    ),
                    gear_col,
                    crate::ui::icons::Glyph::Gear,
                );

                let layout_lbl = if app.panels.repeater.stacked_layout {
                    "Top/Bottom"
                } else {
                    "Side-by-side"
                };
                if ui
                    .button(layout_lbl)
                    .on_hover_text("Toggle Side-by-side / Top-Bottom layout")
                    .clicked()
                {
                    app.panels.repeater.stacked_layout = !app.panels.repeater.stacked_layout;
                }

                if ui
                    .button("Change method")
                    .on_hover_text("Toggle GET <-> POST")
                    .clicked()
                {
                    let toggled = crate::ui::app::Transaction::toggle_request_method(
                        &app.panels.repeater.active().raw,
                    );
                    app.panels.repeater.active_mut().raw = toggled;
                    app.status = "Toggled request method (GET <-> POST)".into();
                }
                if ui.button("Send to Intruder").clicked() {
                    let tab = app.panels.repeater.active();
                    let (host, raw) = (tab.host.clone(), tab.raw.clone());
                    app.send_to_intruder(&host, &raw);
                }

                // Right-aligned `Target: https://...` + `Inspector` & `Notes` side-panel buttons
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    let has_notes = !app.panels.repeater.active().notes.trim().is_empty();
                    for (tab_idx, tab_lbl) in [(1usize, "Notes"), (0usize, "Inspector")] {
                        let is_active = app.panels.repeater.sidebar_open
                            && app.panels.repeater.sidebar_tab == tab_idx;
                        let icon_col = if is_active {
                            Color32::from_rgb(0xFF, 0x66, 0x33)
                        } else if tab_idx == 1 && has_notes {
                            theme.color("ui.icon.accent.blue")
                        } else {
                            theme.color("ui.text.body")
                        };
                        let resp = ui
                            .horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 3.0;
                                if tab_idx == 0 {
                                    super::paint_inspector_icon(ui, icon_col);
                                } else {
                                    super::paint_notes_icon(ui, icon_col);
                                }
                                ui.selectable_label(
                                    is_active,
                                    RichText::new(tab_lbl).size(11.5).strong().color(icon_col),
                                )
                            })
                            .inner;
                        if resp
                            .on_hover_text(format!("Toggle {tab_lbl} side panel"))
                            .clicked()
                        {
                            if is_active {
                                app.panels.repeater.sidebar_open = false;
                            } else {
                                app.panels.repeater.sidebar_open = true;
                                app.panels.repeater.sidebar_tab = tab_idx;
                            }
                        }
                    }
                    ui.separator();

                    let (edit_rect, edit_resp) =
                        ui.allocate_exact_size(Vec2::new(22.0, 22.0), egui::Sense::click());
                    let ep = ui.painter_at(edit_rect);
                    let ec = theme.color("ui.icon.default");
                    ep.line_segment(
                        [
                            egui::pos2(edit_rect.min.x + 5.0, edit_rect.max.y - 5.0),
                            egui::pos2(edit_rect.max.x - 5.0, edit_rect.min.y + 5.0),
                        ],
                        egui::Stroke::new(1.6, ec),
                    );
                    ep.circle_filled(
                        egui::pos2(edit_rect.min.x + 5.0, edit_rect.max.y - 5.0),
                        1.5,
                        ec,
                    );
                    if edit_resp
                        .on_hover_text("Configure target host, port, HTTPS, and Override SNI")
                        .clicked()
                    {
                        app.panels.repeater.show_target_modal =
                            !app.panels.repeater.show_target_modal;
                    }
                    let host_txt = app.panels.repeater.active().host.clone();
                    let rem_w = ui.available_width();
                    if rem_w > 58.0 {
                        let max_chars = (((rem_w - 58.0) / 7.2) as usize).clamp(4, 34);
                        let display_host = truncate_host_text(&host_txt, max_chars);
                        if ui
                            .add(
                                egui::Label::new(
                                    RichText::new(format!("Target: {display_host}"))
                                        .strong()
                                        .size(12.5)
                                        .color(theme.color("ui.text.heading")),
                                )
                                .truncate()
                                .sense(egui::Sense::click()),
                            )
                            .on_hover_text(format!(
                                "Target: {host_txt}\nClick to edit Target URL and SNI settings"
                            ))
                            .clicked()
                        {
                            app.panels.repeater.show_target_modal = true;
                        }
                    }
                });
            });
        });

    // 1px separator line below the Action Toolbar (`quick-start-pro-repeater.png`)
    let sep_rect = egui::Rect::from_min_size(
        ui.cursor().min,
        Vec2::new(ui.available_width(), 1.0),
    );
    ui.painter().rect_filled(sep_rect, 0.0, border_col);
    ui.add_space(1.0);

    // Target & SNI override dialog (`http-messages/index.html#http-repeater-tab`)
    if app.panels.repeater.show_target_modal {
        let mut open = true;
        egui::Window::new("Target details")
            .open(&mut open)
            .resizable(false)
            .default_width(340.0)
            .show(ui.ctx(), |ui| {
                let tab = app.panels.repeater.active_mut();
                ui.label("Target URL / Host:");
                ui.text_edit_singleline(&mut tab.host);
                ui.add_space(4.0);
                ui.checkbox(&mut tab.override_sni_enabled, "Override SNI");
                if tab.override_sni_enabled {
                    ui.label("SNI hostname (e.g. Collaborator payload):");
                    ui.text_edit_singleline(&mut tab.override_sni);
                }
            });
        app.panels.repeater.show_target_modal = open;
    }

    let message_bg = theme.color("ui.editor.message.background");
    let colour = match app.panels.repeater.active().status {
        Some(200..=399) => theme.color("ui.icon.success"),
        Some(400..=499) => theme.color("ui.icon.warning"),
        Some(_) => theme.color("ui.icon.error"),
        None => theme.color("ui.icon.default"),
    };
    let response = app.panels.repeater.active().response.clone();
    let request = app.panels.repeater.active().raw.clone();
    let elapsed_ms = app.panels.repeater.active().elapsed_ms;
    let stacked = app.panels.repeater.stacked_layout;
    let avail_h = (ui.available_height()
        - if app.panels.repeater.show_analysis_drawer {
            190.0
        } else {
            30.0
        })
    .max(220.0);
    let editor_h = (avail_h - 68.0).max(160.0);

    egui::Frame::new()
        .fill(bar_bg)
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            let sidebar_open = app.panels.repeater.sidebar_open;
            let dock_left = app.panels.repeater.sidebar_dock_left;
            if sidebar_open {
                let mut outer_ratio = if dock_left {
                    (1.0 - app.panels.repeater.sidebar_ratio).clamp(0.20, 0.45)
                } else {
                    app.panels.repeater.sidebar_ratio.clamp(0.55, 0.82)
                };
                let mut collapsed = false;
                let mut active_tab = app.panels.repeater.sidebar_tab;
                let mut side_dock_left = dock_left;
                let tab_idx = app.panels.repeater.active;
                let sidebar_id = format!("repeater-sidebar-{tab_idx}");
                super::vertical_split(
                    ui,
                    &theme,
                    "repeater-outer-inspector-split",
                    &mut outer_ratio,
                    avail_h - 12.0,
                    |pane, ui| {
                        let is_sidebar_pane = (dock_left && pane == 0) || (!dock_left && pane == 1);
                        if is_sidebar_pane {
                            let mut raw_edit = app.panels.repeater.active().raw.clone();
                            let mut notes_edit = app.panels.repeater.active().notes.clone();
                            super::draw_inspector_and_notes_sidebar(
                                ui,
                                &theme,
                                &sidebar_id,
                                &mut raw_edit,
                                &response,
                                &mut notes_edit,
                                &mut active_tab,
                                &mut side_dock_left,
                                &mut collapsed,
                            );
                            if raw_edit != app.panels.repeater.active().raw {
                                app.panels.repeater.active_mut().raw = raw_edit;
                            }
                            if notes_edit != app.panels.repeater.active().notes {
                                app.panels.repeater.active_mut().notes = notes_edit;
                            }
                        } else if stacked {
                            let half_h = (editor_h * 0.5).max(110.0);
                            draw_request_pane(app, ui, &theme, &request, half_h, message_bg);
                            ui.separator();
                            draw_response_pane(
                                app,
                                ui,
                                &theme,
                                &response,
                                colour,
                                elapsed_ms,
                                half_h,
                                message_bg,
                            );
                        } else {
                            let mut ratio = app.panels.repeater.split_ratio;
                            super::vertical_split(
                                ui,
                                &theme,
                                "repeater-side-by-side-split",
                                &mut ratio,
                                avail_h - 12.0,
                                |side, ui| {
                                    if side == 0 {
                                        draw_request_pane(
                                            app, ui, &theme, &request, editor_h, message_bg,
                                        );
                                    } else {
                                        draw_response_pane(
                                            app,
                                            ui,
                                            &theme,
                                            &response,
                                            colour,
                                            elapsed_ms,
                                            editor_h,
                                            message_bg,
                                        );
                                    }
                                },
                            );
                            app.panels.repeater.split_ratio = ratio;
                        }
                    },
                );
                app.panels.repeater.sidebar_tab = active_tab;
                app.panels.repeater.sidebar_dock_left = side_dock_left;
                app.panels.repeater.sidebar_ratio = if dock_left {
                    (1.0 - outer_ratio).clamp(0.55, 0.82)
                } else {
                    outer_ratio.clamp(0.55, 0.82)
                };
                if collapsed {
                    app.panels.repeater.sidebar_open = false;
                }
            } else if stacked {
                let half_h = (editor_h * 0.5).max(110.0);
                draw_request_pane(app, ui, &theme, &request, half_h, message_bg);
                ui.separator();
                draw_response_pane(
                    app,
                    ui,
                    &theme,
                    &response,
                    colour,
                    elapsed_ms,
                    half_h,
                    message_bg,
                );
            } else {
                let mut ratio = app.panels.repeater.split_ratio;
                super::vertical_split(
                    ui,
                    &theme,
                    "repeater-side-by-side-split",
                    &mut ratio,
                    avail_h - 12.0,
                    |side, ui| {
                        if side == 0 {
                            draw_request_pane(app, ui, &theme, &request, editor_h, message_bg);
                        } else {
                            draw_response_pane(
                                app,
                                ui,
                                &theme,
                                &response,
                                colour,
                                elapsed_ms,
                                editor_h,
                                message_bg,
                            );
                        }
                    },
                );
                app.panels.repeater.split_ratio = ratio;
            }
        });

    if app.panels.repeater.detached_open {
        let mut open = true;
        let mut ratio = app.panels.repeater.split_ratio;
        let tab_name = app.panels.repeater.active().name.clone();
        let tab_host = app.panels.repeater.active().host.clone();
        eframe::egui::Window::new(format!("Repeater [{tab_name}] — {tab_host}"))
            .open(&mut open)
            .resizable(true)
            .default_size([900.0, 560.0])
            .show(ui.ctx(), |ui| {
                let h = (ui.available_height() - 36.0).max(160.0);
                super::vertical_split(
                    ui,
                    &theme,
                    "repeater-detached-split",
                    &mut ratio,
                    h,
                    |side, ui| {
                        if side == 0 {
                            draw_request_pane(app, ui, &theme, &request, h - 64.0, message_bg);
                        } else {
                            draw_response_pane(
                                app,
                                ui,
                                &theme,
                                &response,
                                colour,
                                elapsed_ms,
                                h - 64.0,
                                message_bg,
                            );
                        }
                    },
                );
            });
        app.panels.repeater.split_ratio = ratio;
        app.panels.repeater.detached_open = open;
    }

    // Compact bottom Inspector & Response analysis toggle bar
    egui::Frame::new()
        .fill(theme.color("ui.background.1"))
        .inner_margin(egui::Margin::symmetric(10, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let arrow = if app.panels.repeater.show_analysis_drawer {
                    "▼ Inspector & Response analysis"
                } else {
                    "▶ Inspector & Response analysis"
                };
                if ui.small_button(arrow).clicked() {
                    app.panels.repeater.show_analysis_drawer =
                        !app.panels.repeater.show_analysis_drawer;
                }
                if let Some((ord, tot)) = app.panels.repeater.active().parallel_order_badge {
                    super::muted(ui, &theme, &format!("Parallel arrival: {ord}/{tot}"));
                }
            });
            if app.panels.repeater.show_analysis_drawer {
                super::draw_inspector(ui, &theme, "repeater-insp", &request, &response);
                ui.separator();
                analyzers(app, ui, &response);
            }
        });
}

fn draw_repeater_pill_bar(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    id_salt: &str,
    modes: &[&str],
    active_mode: &mut usize,
    show_non_printable: &mut bool,
    wrap: &mut bool,
) -> egui::Response {
    let pill_track_bg = if theme.dark {
        Color32::from_rgb(0x32, 0x36, 0x3E)
    } else {
        Color32::from_rgb(0xE0, 0xE0, 0xE0)
    };
    let active_pill_bg = Color32::from_rgb(0x2B, 0x57, 0x9A);
    let inactive_txt = if theme.dark {
        Color32::from_rgb(0xD8, 0xDC, 0xE2)
    } else {
        Color32::from_rgb(0x2B, 0x2B, 0x2B)
    };

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        egui::Frame::new()
            .fill(pill_track_bg)
            .corner_radius(4.0)
            .inner_margin(egui::Margin::same(0))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for (idx, label) in modes.iter().enumerate() {
                    let is_active = *active_mode == idx;
                    let fill = if is_active {
                        active_pill_bg
                    } else {
                        Color32::TRANSPARENT
                    };
                    let fg = if is_active {
                        Color32::WHITE
                    } else {
                        inactive_txt
                    };
                    let btn = egui::Button::new(RichText::new(*label).color(fg).size(12.0).strong())
                        .fill(fill)
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(3.0)
                        .min_size(Vec2::new(46.0, 22.0));
                    if ui.add(btn).clicked() {
                        *active_mode = idx;
                    }
                }
            });

        // `[\n]` non-printable characters pill button
        let np_fill = if *show_non_printable {
            active_pill_bg
        } else {
            pill_track_bg
        };
        let np_fg = if *show_non_printable {
            Color32::WHITE
        } else {
            inactive_txt
        };
        if ui
            .add(
                egui::Button::new(RichText::new("\\n").color(np_fg).monospace().size(11.5).strong())
                    .fill(np_fill)
                    .stroke(egui::Stroke::NONE)
                    .corner_radius(4.0)
                    .min_size(Vec2::new(26.0, 22.0)),
            )
            .on_hover_text("Show non-printable characters")
            .clicked()
        {
            *show_non_printable = !*show_non_printable;
        }

        // `[≡]` line-wrap pill button
        let wrap_fill = if *wrap { active_pill_bg } else { pill_track_bg };
        let wrap_fg = if *wrap { Color32::WHITE } else { inactive_txt };
        let (wrap_rect, wrap_resp) =
            ui.allocate_exact_size(Vec2::new(26.0, 22.0), egui::Sense::click());
        if wrap_resp.on_hover_text("Toggle line wrapping").clicked() {
            *wrap = !*wrap;
        }
        let p = ui.painter_at(wrap_rect);
        p.rect_filled(wrap_rect, 4.0, wrap_fill);
        for dy in [-4.0f32, 0.0, 4.0] {
            p.line_segment(
                [
                    egui::pos2(wrap_rect.min.x + 6.0, wrap_rect.center().y + dy),
                    egui::pos2(wrap_rect.max.x - 6.0, wrap_rect.center().y + dy),
                ],
                egui::Stroke::new(1.5, wrap_fg),
            );
        }
        let _ = id_salt;
    })
    .response
}

fn draw_request_pane(
    app: &mut App,
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    request: &str,
    height: f32,
    _message_bg: eframe::egui::Color32,
) {
    // Orange `Request` header + `[ Pretty | Raw | Hex ]  [\n] [≡]` pill bar (`quick-start-pro-repeater.png`)
    ui.label(
        RichText::new("Request")
            .size(15.0)
            .strong()
            .color(Color32::from_rgb(0xE0, 0x53, 0x20)),
    );
    let mut mode = if app.panels.repeater.active().hex_view {
        2
    } else if app.panels.repeater.active().editing {
        1
    } else {
        0
    };
    let mut np = app.panels.repeater.active().show_non_printable;
    let mut wrap = app.panels.repeater.req_wrap;
    let header_resp = draw_repeater_pill_bar(
        ui,
        theme,
        "repeater-req-pills",
        &["Pretty", "Raw", "Hex"],
        &mut mode,
        &mut np,
        &mut wrap,
    );
    {
        let tab = app.panels.repeater.active_mut();
        tab.editing = mode == 1;
        tab.hex_view = mode == 2;
        tab.show_non_printable = np;
    }
    app.panels.repeater.req_wrap = wrap;
    ui.add_space(4.0);

    super::show_persistent_context_menu(&header_resp, |ui| {
        repeater_actions_menu(app, ui);
    });
    let resp = if mode == 2 {
        super::gulp_numbered_message_view_wrapped(
            ui,
            theme,
            "repeater-req-hex",
            height,
            request,
            2,
            false,
            wrap,
        )
    } else {
        let (r, _) = super::gulp_numbered_message_editor_wrapped(
            ui,
            theme,
            "repeater-req-edit",
            height,
            &mut app.panels.repeater.active_mut().raw,
            mode,
            wrap,
        );
        r
    };
    super::show_persistent_context_menu(&resp, |ui| {
        repeater_actions_menu(app, ui);
    });
}

fn draw_response_pane(
    app: &mut App,
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    response: &str,
    colour: eframe::egui::Color32,
    elapsed_ms: u128,
    height: f32,
    _message_bg: eframe::egui::Color32,
) {
    // Orange `Response` header + status & timing (`quick-start-pro-repeater.png`)
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.label(
            RichText::new("Response")
                .size(15.0)
                .strong()
                .color(Color32::from_rgb(0xE0, 0x53, 0x20)),
        );
        if let Some(status) = app.panels.repeater.active().status {
            ui.label(
                eframe::egui::RichText::new(status.to_string())
                    .color(colour)
                    .strong(),
            );
        } else if !response.is_empty() {
            ui.label(eframe::egui::RichText::new("error").color(colour));
        }
        if !response.is_empty() {
            super::muted(
                ui,
                theme,
                &format!("{} ms · {} bytes", elapsed_ms, response.len()),
            );
        }
    });
    let mut mode = app.panels.repeater.active().response_mode;
    let mut np = app.panels.repeater.active().response_non_printable;
    let mut wrap = app.panels.repeater.resp_wrap;
    let header_resp = draw_repeater_pill_bar(
        ui,
        theme,
        "repeater-resp-pills",
        &["Pretty", "Raw", "Hex", "Render"],
        &mut mode,
        &mut np,
        &mut wrap,
    );
    {
        let tab = app.panels.repeater.active_mut();
        tab.response_mode = mode;
        tab.render_view = mode == 3;
        tab.response_non_printable = np;
    }
    app.panels.repeater.resp_wrap = wrap;
    ui.add_space(4.0);

    super::show_persistent_context_menu(&header_resp, |ui| {
        repeater_actions_menu(app, ui);
    });
    let resp = super::gulp_numbered_message_view_wrapped(
        ui,
        theme,
        "repeater-resp-pretty",
        height,
        response,
        mode,
        np,
        wrap,
    );
    super::show_persistent_context_menu(&resp, |ui| {
        repeater_actions_menu(app, ui);
    });
}

fn repeater_actions_menu(app: &mut App, ui: &mut Ui) {
    ui.set_min_width(235.0);
    let tab = app.panels.repeater.active().clone();
    if let Some(sel_txt) = super::latest_selected_text() {
        if ui.button("Copy selection").clicked() {
            ui.ctx().copy_text(sel_txt.clone());
            app.status = format!("Copied {} selected character(s)", sel_txt.chars().count());
            ui.close();
        }
        if ui.button("Base64 encode selection").clicked() {
            super::apply_convert_selection(app, ui.ctx(), "Base64 encode", &tab.raw, &tab.response);
            ui.close();
        }
        if ui.button("Base64 decode selection").clicked() {
            super::apply_convert_selection(app, ui.ctx(), "Base64 decode", &tab.raw, &tab.response);
            ui.close();
        }
        if ui.button("URL encode selection").clicked() {
            super::apply_convert_selection(app, ui.ctx(), "URL encode", &tab.raw, &tab.response);
            ui.close();
        }
        if ui.button("URL decode selection").clicked() {
            super::apply_convert_selection(app, ui.ctx(), "URL decode", &tab.raw, &tab.response);
            ui.close();
        }
        if ui.button("Send selection to Decoder").clicked() {
            app.panels.decoder.input = sel_txt.clone();
            app.tool = crate::ui::app::DECODER;
            app.view = 0;
            app.status = "Sent selected text to Decoder".into();
            ui.close();
        }
        if ui.button("Send selection to Comparer").clicked() {
            if app.panels.comparer.left.trim().is_empty() {
                app.panels.comparer.left = sel_txt;
            } else {
                app.panels.comparer.right = sel_txt;
            }
            app.tool = crate::ui::app::COMPARER;
            app.view = 0;
            app.status = "Sent selected text to Comparer".into();
            ui.close();
        }
        ui.separator();
    }
    ui.menu_button("Convert selection", |ui| {
        for op_name in [
            "URL encode",
            "URL decode",
            "Base64 encode",
            "Base64 decode",
            "HTML encode",
            "HTML decode",
            "Hex encode",
            "Hex decode",
        ] {
            if ui.button(op_name).clicked() {
                super::apply_convert_selection(app, ui.ctx(), op_name, &tab.raw, &tab.response);
                ui.close();
            }
        }
    });
    ui.separator();
    if ui.button("Scan / Do active scan").clicked() {
        app.scan_url(&tab.host, true);
        ui.close();
    }
    if ui
        .add_enabled(
            !tab.response.is_empty(),
            eframe::egui::Button::new("Do passive scan"),
        )
        .clicked()
    {
        app.passive_scan_transaction(&tab.host, &tab.response);
        ui.close();
    }
    ui.menu_button("Engagement tools", |ui| {
        if ui.button("Generate CSRF PoC").clicked() {
            app.open_csrf_poc(&tab.host, &tab.raw);
            ui.close();
        }
    });
    ui.separator();
    if ui.button("Send to Repeater").clicked() {
        app.panels.repeater.open(&tab.host, &tab.raw);
        app.status = "Sent request to a new Repeater tab".into();
        ui.close();
    }
    if ui.button("Send to Intruder").clicked() {
        app.send_to_intruder(&tab.host, &tab.raw);
        ui.close();
    }
    if ui.button("Send to Comparer (request)").clicked() {
        if app.panels.comparer.left.trim().is_empty() {
            app.panels.comparer.left = tab.raw.clone();
        } else {
            app.panels.comparer.right = tab.raw.clone();
        }
        app.tool = crate::ui::app::COMPARER;
        app.view = 0;
        app.status = "Repeater request sent to Comparer".into();
        ui.close();
    }
    if ui.button("Send to Comparer (response)").clicked() {
        if app.panels.comparer.left.trim().is_empty() {
            app.panels.comparer.left = tab.response.clone();
        } else {
            app.panels.comparer.right = tab.response.clone();
        }
        app.tool = crate::ui::app::COMPARER;
        app.view = 0;
        app.status = "Repeater response sent to Comparer".into();
        ui.close();
    }
    if ui.button("Send to Decoder").clicked() {
        app.panels.decoder.input = tab.raw.clone();
        app.tool = crate::ui::app::DECODER;
        app.view = 0;
        app.status = "Repeater request sent to Decoder".into();
        ui.close();
    }
    if ui.button("Send to Sequencer").clicked() {
        app.panels.sequencer.text = tab.response.clone();
        app.tool = crate::ui::app::SEQUENCER;
        app.view = 0;
        app.status = "Repeater response sent to Sequencer".into();
        ui.close();
    }
    if ui.button("Change request method (GET ↔ POST)").clicked() {
        app.panels.repeater.active_mut().raw =
            crate::ui::app::Transaction::toggle_request_method(&tab.raw);
        app.status = "Toggled request method (GET <-> POST)".into();
        ui.close();
    }
    if ui.button("Insert Collaborator payload").clicked() {
        super::insert_collaborator_payload_in_place(app, ui.ctx(), &tab.raw, &tab.response);
        ui.close();
    }
    if ui
        .add_enabled(
            !tab.history.is_empty(),
            eframe::egui::Button::new("Clear history"),
        )
        .clicked()
    {
        app.panels.repeater.active_mut().clear_history();
        app.status = "Cleared Repeater tab history".into();
        ui.close();
    }
    ui.separator();
    if ui.button("Copy URL").clicked() {
        ui.ctx().copy_text(tab.host.clone());
        app.status = "Copied Repeater target URL".into();
        ui.close();
    }
    if ui.button("Copy as curl command").clicked() {
        let curl = crate::ui::app::Transaction::to_curl_command(&tab.host, &tab.raw);
        ui.ctx().copy_text(curl);
        app.status = "Copied Repeater request as curl command".into();
        ui.close();
    }
    if ui.button("Duplicate tab").clicked() {
        app.panels.repeater.duplicate_active();
        app.status = "Duplicated Repeater tab".into();
        ui.close();
    }
}

/// Renders the exact 50/50 split Repeater Getting Started screen from `/tmp/ref_Repeater_s.png`,
/// using the exact SVG polygon coordinates from `resources/Media/svg/light/repeater.svg`
/// and `resources/Media/svg/light/repeater-illustration.svg`.
fn draw_repeater_getting_started(app: &mut App, ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    let avail = ui.available_size();
    let left_bg = if theme.dark {
        Color32::from_rgb(0x23, 0x27, 0x2D)
    } else {
        Color32::from_rgb(0xEA, 0xEE, 0xF2)
    };
    let right_bg = if theme.dark {
        Color32::from_rgb(0x1E, 0x20, 0x24)
    } else {
        Color32::from_rgb(0xFA, 0xFA, 0xFA)
    };

    ui.spacing_mut().item_spacing.x = 0.0;
    ui.columns(2, |cols| {
        // LEFT 50%: "To get started, send a request to Repeater from anywhere in Gulp." + `repeater-illustration.svg`
        egui::Frame::new()
            .fill(left_bg)
            .inner_margin(egui::Margin::same(0))
            .show(&mut cols[0], |ui| {
                let col_w = ui.available_width();
                ui.set_min_size(Vec2::new(col_w, avail.y));
                let top_pad = ((avail.y - 310.0) * 0.45).max(36.0);
                let left_pad = ((col_w - 321.0) * 0.5).max(24.0);
                ui.add_space(top_pad);
                ui.horizontal(|ui| {
                    ui.add_space(left_pad);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(
                                "To get started, send a request to Repeater\nfrom anywhere in Gulp.",
                            )
                            .size(18.0)
                            .strong()
                            .color(theme.color("ui.text.heading")),
                        );
                        ui.add_space(22.0);
                        paint_repeater_onboarding_illustration(ui, theme);
                    });
                });
            });

        // RIGHT 50%: Top-right `✕`, `repeater.svg` two-arrows icon, "Repeater", description, "Learn more", "Don't show this again"
        egui::Frame::new()
            .fill(right_bg)
            .inner_margin(egui::Margin::symmetric(20, 14))
            .show(&mut cols[1], |ui| {
                let col_w = ui.available_width();
                ui.set_min_size(Vec2::new(
                    col_w.max(160.0),
                    (avail.y - 28.0).max(240.0),
                ));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                    let (x_rect, x_resp) =
                        ui.allocate_exact_size(Vec2::new(20.0, 20.0), egui::Sense::click());
                    let xp = ui.painter_at(x_rect);
                    let xc = theme.color("ui.text.heading");
                    xp.line_segment(
                        [
                            egui::pos2(x_rect.min.x + 5.0, x_rect.min.y + 5.0),
                            egui::pos2(x_rect.max.x - 5.0, x_rect.max.y - 5.0),
                        ],
                        egui::Stroke::new(1.5, xc),
                    );
                    xp.line_segment(
                        [
                            egui::pos2(x_rect.max.x - 5.0, x_rect.min.y + 5.0),
                            egui::pos2(x_rect.min.x + 5.0, x_rect.max.y - 5.0),
                        ],
                        egui::Stroke::new(1.5, xc),
                    );
                    if x_resp
                        .on_hover_text("Close Getting started and open Repeater tab")
                        .clicked()
                    {
                        app.panels.repeater.show_getting_started = false;
                        app.panels.repeater.force_getting_started = false;
                    }
                });

                let right_top_pad = ((avail.y - 280.0) * 0.42).max(32.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(right_top_pad);
                    paint_repeater_two_arrows_icon(ui);
                    ui.add_space(18.0);
                    ui.label(
                        RichText::new("Repeater")
                            .size(16.0)
                            .strong()
                            .color(theme.color("ui.text.heading")),
                    );
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(
                            "Modify and resend individual requests to test how the server's\nresponse changes based on your input.",
                        )
                        .size(12.0)
                        .color(theme.color("ui.text.body")),
                    );
                    ui.add_space(20.0);
                    let learn_bg = if theme.dark {
                        Color32::from_rgb(0x32, 0x36, 0x3E)
                    } else {
                        Color32::from_rgb(0xEA, 0xEA, 0xEA)
                    };
                    let learn_border = if theme.dark {
                        Color32::from_rgb(0x48, 0x4D, 0x56)
                    } else {
                        Color32::from_rgb(0xD8, 0xD8, 0xD8)
                    };
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Learn more")
                                    .size(12.0)
                                    .strong()
                                    .color(theme.color("ui.text.heading")),
                            )
                            .fill(learn_bg)
                            .stroke(egui::Stroke::new(1.0, learn_border))
                            .corner_radius(4.0)
                            .min_size(Vec2::new(108.0, 28.0)),
                        )
                        .clicked()
                    {
                        app.status =
                            "Repeater documentation: Right-click any HTTP request and select Send to Repeater, or click + to open a manual Repeater tab.".into();
                    }
                    ui.add_space(18.0);
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Don't show this again")
                                    .color(Color32::from_rgb(0xC8, 0x5A, 0x28))
                                    .size(12.0),
                            )
                            .frame(false),
                        )
                        .clicked()
                    {
                        app.panels.repeater.hide_getting_started_forever = true;
                        app.panels.repeater.show_getting_started = false;
                        app.panels.repeater.force_getting_started = false;
                    }
                });
            });
    });
}

/// Paints the exact `resources/Media/svg/light/repeater.svg` (`90 x 63` viewBox) two-arrows icon.
fn paint_repeater_two_arrows_icon(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(90.0, 63.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let map = |pts: &[(f32, f32)]| -> Vec<egui::Pos2> {
        pts.iter().map(|(x, y)| egui::pos2(o.x + *x, o.y + *y)).collect()
    };
    let shadow_col = Color32::from_rgb(0xE6, 0xE6, 0xE6);
    let dark_blue = Color32::from_rgb(0x26, 0x64, 0x9D);
    let light_blue = Color32::from_rgb(0x92, 0xB1, 0xCE);

    // 1. Shadow for lower-right arrow (`fill="#E6E6E6"`)
    // Note: concave arrow polygon split into shaft quad + arrowhead triangle
    p.add(egui::Shape::convex_polygon(
        map(&[
            (37.46, 47.63),
            (64.11, 32.24),
            (72.79, 37.26),
            (46.14, 52.64),
        ]),
        shadow_col,
        egui::Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[(33.02, 45.07), (50.58, 55.21), (30.90, 56.43)]),
        shadow_col,
        egui::Stroke::NONE,
    ));

    // 2. Shadow for upper-left arrow (`fill="#E6E6E6"`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (16.87, 35.74),
            (43.51, 20.36),
            (52.19, 25.37),
            (25.55, 40.75),
        ]),
        shadow_col,
        egui::Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[(39.07, 17.79), (58.76, 16.57), (56.64, 27.93)]),
        shadow_col,
        egui::Stroke::NONE,
    ));

    // 3. Lower-right dark-blue arrow (`fill="#26649D"`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (37.46, 41.63),
            (64.11, 26.24),
            (72.79, 31.26),
            (46.14, 46.64),
        ]),
        dark_blue,
        egui::Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[(33.02, 39.07), (50.58, 49.21), (30.90, 50.43)]),
        dark_blue,
        egui::Stroke::NONE,
    ));

    // 4. Upper-left light-blue arrow (`fill="#92B1CE"`)
    p.add(egui::Shape::convex_polygon(
        map(&[
            (16.87, 29.74),
            (43.51, 14.36),
            (52.19, 19.37),
            (25.55, 34.75),
        ]),
        light_blue,
        egui::Stroke::NONE,
    ));
    p.add(egui::Shape::convex_polygon(
        map(&[(39.07, 11.79), (58.76, 10.57), (56.64, 21.93)]),
        light_blue,
        egui::Stroke::NONE,
    ));
}

/// Paints the exact `resources/Media/svg/light/repeater-illustration.svg` (`321 x 215` viewBox).
fn paint_repeater_onboarding_illustration(ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(321.0, 215.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let o = rect.min;
    let r = |x: f32, y: f32, w: f32, h: f32| {
        egui::Rect::from_min_size(egui::pos2(o.x + x, o.y + y), Vec2::new(w, h))
    };

    let top_card_bg = if theme.dark {
        Color32::from_rgb(0x2D, 0x31, 0x38)
    } else {
        Color32::from_rgb(0xFB, 0xFC, 0xFD)
    };
    let req_card_bg = if theme.dark {
        Color32::from_rgb(0x2B, 0x2F, 0x36)
    } else {
        Color32::WHITE
    };
    let resp_card_bg = if theme.dark {
        Color32::from_rgb(0x27, 0x2B, 0x31)
    } else {
        Color32::from_rgb(0xF5, 0xF8, 0xFB)
    };
    let bar_col = if theme.dark {
        Color32::from_rgb(0x43, 0x48, 0x52)
    } else {
        Color32::from_rgb(0xE6, 0xE6, 0xE6)
    };
    let menu_bg = if theme.dark {
        Color32::from_rgb(0x36, 0x3B, 0x44)
    } else {
        Color32::from_rgb(0xF8, 0xF8, 0xF8)
    };
    let menu_bar_col = if theme.dark {
        Color32::from_rgb(0x52, 0x58, 0x64)
    } else {
        Color32::from_rgb(0xD5, 0xD5, 0xD5)
    };
    let muted_txt = Color32::from_rgba_unmultiplied(0x2B, 0x2B, 0x2B, 140);

    // 1. Top table card (`320.3 x 70.5`) + 4 rounded gray bars
    p.rect_filled(r(0.7, 0.0, 320.3, 70.5), 2.0, top_card_bg);
    for y in [11.5f32, 24.3, 37.2, 50.0] {
        p.rect_filled(r(10.9, y, 298.5, 6.4), 3.2, bar_col);
    }

    // 2. Bottom-left `Request` card (`157.6 x 116.6` at `y = 76.9`) + Bottom-right `Response` card
    p.rect_filled(r(0.7, 76.9, 157.6, 116.6), 2.0, req_card_bg);
    p.rect_filled(r(164.7, 76.9, 156.3, 116.6), 2.0, resp_card_bg);
    p.text(
        egui::pos2(o.x + 8.0, o.y + 84.0),
        egui::Align2::LEFT_TOP,
        "Request",
        egui::FontId::proportional(11.0),
        if theme.dark {
            Color32::from_gray(160)
        } else {
            muted_txt
        },
    );
    p.text(
        egui::pos2(o.x + 172.0, o.y + 84.0),
        egui::Align2::LEFT_TOP,
        "Response",
        egui::FontId::proportional(11.0),
        if theme.dark {
            Color32::from_gray(160)
        } else {
            muted_txt
        },
    );

    // 3. Pointer cursor arrow + "Right-click"
    let cursor_col = if theme.dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(0x16, 0x16, 0x16)
    };
    p.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(o.x + 33.7, o.y + 102.0),
            egui::pos2(o.x + 43.3, o.y + 107.1),
            egui::pos2(o.x + 39.2, o.y + 108.1),
            egui::pos2(o.x + 36.7, o.y + 112.1),
        ],
        cursor_col,
        egui::Stroke::NONE,
    ));
    p.line_segment(
        [
            egui::pos2(o.x + 38.4, o.y + 107.8),
            egui::pos2(o.x + 41.8, o.y + 112.4),
        ],
        egui::Stroke::new(1.8, cursor_col),
    );
    p.text(
        egui::pos2(o.x + 51.5, o.y + 102.5),
        egui::Align2::LEFT_TOP,
        "Right-click",
        egui::FontId::proportional(10.5),
        cursor_col,
    );

    // 4. Context menu popup card (`92.2 x 90.9` at `x = 48.3, y = 123.9`)
    p.rect_filled(
        r(50.3, 125.9, 92.2, 90.9),
        2.0,
        Color32::from_rgba_unmultiplied(0, 0, 0, 18),
    );
    p.rect_filled(r(48.3, 123.9, 92.2, 90.9), 2.0, menu_bg);
    for (y, w) in [(131.8f32, 76.4f32), (141.2, 68.2), (150.6, 54.1)] {
        p.rect_filled(r(56.3, y, w, 5.8), 2.9, menu_bar_col);
    }
    // Blue `#26659E` highlight row with "Send to Repeater"
    p.rect_filled(
        r(48.3, 159.7, 92.2, 19.2),
        0.0,
        Color32::from_rgb(0x26, 0x65, 0x9E),
    );
    p.text(
        egui::pos2(o.x + 55.0, o.y + 169.3),
        egui::Align2::LEFT_CENTER,
        "Send to Repeater",
        egui::FontId::proportional(9.8),
        Color32::WHITE,
    );
    for (y, w) in [(183.0f32, 55.8f32), (192.4, 68.2), (201.8, 54.1)] {
        p.rect_filled(r(56.3, y, w, 5.8), 2.9, menu_bar_col);
    }

    // 5. Curved dashed arc from `(99, 108)` around `(194, 138)` to `(143, 169)`
    let arc_pts = [
        (104.0f32, 108.0f32),
        (148.0, 108.0),
        (175.0, 114.0),
        (190.0, 126.0),
        (194.0, 140.0),
        (188.0, 154.0),
        (172.0, 165.0),
        (143.0, 169.0),
    ];
    let dash_col = Color32::from_rgb(0xCC, 0xCC, 0xCC);
    for pair in arc_pts.windows(2) {
        let a = egui::pos2(o.x + pair[0].0, o.y + pair[0].1);
        let b = egui::pos2(o.x + pair[1].0, o.y + pair[1].1);
        let mid = egui::pos2((a.x + b.x) * 0.5, (a.y + b.y) * 0.5);
        p.line_segment([a, mid], egui::Stroke::new(1.0, dash_col));
    }
    // Arrowhead at `(143, 169)`
    p.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(o.x + 142.3, o.y + 169.4),
            egui::pos2(o.x + 145.9, o.y + 167.3),
            egui::pos2(o.x + 145.9, o.y + 171.5),
        ],
        dash_col,
        egui::Stroke::NONE,
    ));
}

/// The row of tabs, matching `quick-start-pro-repeater.png`, `managing-tabs.html`, and `groups.html`.
fn tabs(app: &mut App, ui: &mut Ui, theme: &crate::ui::theme::Theme) {
    let tab_bar_bg = theme.color("ui.background.1");
    let border_col = theme.color("ui.border.1");

    egui::Frame::new()
        .fill(tab_bar_bg)
        .inner_margin(egui::Margin::symmetric(0, 0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                let mut close_action: Option<usize> = None;
                let mut close_others: Option<usize> = None;
                let mut reopen_closed = false;

                for index in 0..app.panels.repeater.tabs.len() {
                    let selected = index == app.panels.repeater.active;
                    let name = app.panels.repeater.tabs[index].name.clone();
                    let grp_color = app.panels.repeater.tabs[index].group_color;
                    let grp_name = app.panels.repeater.tabs[index].group_name.trim().to_string();
                    let cell_bg = if selected {
                        theme.color("ui.background.0")
                    } else if let Some(swatch) = group_color_swatch(grp_color) {
                        swatch.gamma_multiply(0.14)
                    } else {
                        tab_bar_bg
                    };

                    let cell_out = egui::Frame::new()
                        .fill(cell_bg)
                        .inner_margin(egui::Margin::symmetric(10, 5))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                if let Some(swatch) = group_color_swatch(grp_color) {
                                    let badge_txt = if grp_name.is_empty() {
                                        group_color_name(grp_color).to_string()
                                    } else {
                                        truncate_host_text(&grp_name, 12)
                                    };
                                    egui::Frame::new()
                                        .fill(swatch)
                                        .corner_radius(3.0)
                                        .inner_margin(egui::Margin::symmetric(5, 1))
                                        .show(ui, |ui| {
                                            ui.label(
                                                RichText::new(badge_txt)
                                                    .size(10.0)
                                                    .strong()
                                                    .color(Color32::WHITE),
                                            );
                                        });
                                }
                                let label = eframe::egui::RichText::new(&name)
                                    .size(12.0)
                                    .color(theme.color(if selected {
                                        "ui.text.heading"
                                    } else {
                                        "ui.text.body"
                                    }));
                                let tab_resp = ui.add(
                                    egui::Label::new(label).sense(egui::Sense::click()),
                                );
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("×")
                                                .size(12.0)
                                                .color(theme.color("ui.icon.default")),
                                        )
                                        .frame(false),
                                    )
                                    .on_hover_text("Close this tab")
                                    .clicked()
                                    && app.panels.repeater.tabs.len() > 1
                                {
                                    close_action = Some(index);
                                }
                                tab_resp
                            })
                            .inner
                        });

                    let cell_rect = cell_out.response.rect;
                    if let Some(swatch) = group_color_swatch(grp_color) {
                        ui.painter().rect_filled(
                            egui::Rect::from_min_max(
                                egui::pos2(cell_rect.min.x, cell_rect.min.y),
                                egui::pos2(cell_rect.max.x, cell_rect.min.y + 3.0),
                            ),
                            0.0,
                            swatch,
                        );
                    }
                    // Right vertical divider line between tab cells (`quick-start-pro-repeater.png`)
                    ui.painter().line_segment(
                        [
                            egui::pos2(cell_rect.max.x, cell_rect.min.y),
                            egui::pos2(cell_rect.max.x, cell_rect.max.y),
                        ],
                        egui::Stroke::new(1.0, border_col),
                    );
                    if selected {
                        ui.painter().rect_filled(
                            egui::Rect::from_min_max(
                                egui::pos2(cell_rect.min.x, cell_rect.max.y - 3.0),
                                egui::pos2(cell_rect.max.x, cell_rect.max.y),
                            ),
                            0.0,
                            theme.color("ui.icon.accent"),
                        );
                    }

                    let mut tab_resp = cell_out.inner;
                    tab_resp.rect = cell_rect;
                    if ui.rect_contains_pointer(cell_rect) {
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    }
                    if tab_resp.clicked()
                        || (close_action != Some(index)
                            && ui.rect_contains_pointer(cell_rect)
                            && ui.input(|i| i.pointer.primary_clicked()))
                    {
                        app.panels.repeater.active = index;
                    }
                    if tab_resp.double_clicked() {
                        app.panels.repeater.rename_tab = Some(index);
                        app.panels.repeater.rename_draft = name.clone();
                    }
                    super::show_persistent_context_menu(&tab_resp, |ui| {
                        if ui.button("Send to Repeater").clicked() {
                            let host = app.panels.repeater.tabs[index].host.clone();
                            let raw = app.panels.repeater.tabs[index].raw.clone();
                            app.panels.repeater.open(&host, &raw);
                            app.status = "Sent request to a new Repeater tab".into();
                            ui.close();
                        }
                        if ui.button("Duplicate tab").clicked() {
                            app.panels.repeater.active = index;
                            app.panels.repeater.duplicate_active();
                            ui.close();
                        }
                        if ui.button("Rename tab").clicked() {
                            app.panels.repeater.rename_tab = Some(index);
                            app.panels.repeater.rename_draft = name.clone();
                            ui.close();
                        }
                        if ui
                            .add_enabled(
                                !app.panels.repeater.tabs[index].history.is_empty(),
                                egui::Button::new("Clear tab history"),
                            )
                            .clicked()
                        {
                            app.panels.repeater.tabs[index].clear_history();
                            app.status = "Cleared Repeater tab history".into();
                            ui.close();
                        }
                        ui.menu_button("Add tab to group / color", |ui| {
                            ui.set_min_width(220.0);
                            ui.horizontal(|ui| {
                                ui.label("Group name:");
                                ui.text_edit_singleline(
                                    &mut app.panels.repeater.tabs[index].group_name,
                                );
                            });
                            ui.separator();
                            if ui.selectable_label(grp_color == 0, "No group").clicked() {
                                app.panels.repeater.tabs[index].group_color = 0;
                                app.panels.repeater.tabs[index].group_name.clear();
                                ui.close();
                            }
                            for code in 1u8..=7 {
                                let cname = format!("{} group", group_color_name(code));
                                let swatch = group_color_swatch(code).unwrap_or(Color32::GRAY);
                                ui.horizontal(|ui| {
                                    let (dot, _) = ui.allocate_exact_size(
                                        Vec2::new(10.0, 14.0),
                                        egui::Sense::hover(),
                                    );
                                    ui.painter().circle_filled(dot.center(), 4.5, swatch);
                                    if ui.selectable_label(grp_color == code, &cname).clicked() {
                                        app.panels.repeater.tabs[index].group_color = code;
                                        if app.panels.repeater.tabs[index]
                                            .group_name
                                            .trim()
                                            .is_empty()
                                        {
                                            app.panels.repeater.tabs[index].group_name = cname;
                                        }
                                        ui.close();
                                    }
                                });
                            }
                        });
                        ui.separator();
                        if ui.button("Close tab").clicked() {
                            close_action = Some(index);
                            ui.close();
                        }
                        if ui.button("Close other tabs").clicked() {
                            close_others = Some(index);
                            ui.close();
                        }
                        if !app.panels.repeater.closed_tabs.is_empty()
                            && ui.button("Reopen closed tab").clicked()
                        {
                            reopen_closed = true;
                            ui.close();
                        }
                    });
                }

                if let Some(idx) = close_action {
                    if let Some(id) = app.panels.repeater.tabs.get(idx).and_then(|t| t.pending) {
                        app.cancel_request(id);
                    }
                    app.panels.repeater.close(idx);
                }
                if let Some(idx) = close_others {
                    app.panels.repeater.close_other_tabs(idx);
                }
                if reopen_closed {
                    app.panels.repeater.reopen_closed_tab();
                }

                ui.add_space(6.0);
                // `...` tab list menu (`quick-start-pro-repeater.png`)
                ui.menu_button("...", |ui| {
                    for idx in 0..app.panels.repeater.tabs.len() {
                        let tname = format!(
                            "{}. {} ({})",
                            idx + 1,
                            app.panels.repeater.tabs[idx].name,
                            app.panels.repeater.tabs[idx].host
                        );
                        if ui
                            .selectable_label(app.panels.repeater.active == idx, tname)
                            .clicked()
                        {
                            app.panels.repeater.active = idx;
                            ui.close();
                        }
                    }
                    if !app.panels.repeater.closed_tabs.is_empty() {
                        ui.separator();
                        if ui.button("Reopen closed tab").clicked() {
                            app.panels.repeater.reopen_closed_tab();
                            ui.close();
                        }
                    }
                    if app
                        .panels
                        .repeater
                        .tabs
                        .iter()
                        .any(|t| !t.history.is_empty())
                    {
                        ui.separator();
                        if ui.button("Clear all tabs history").clicked() {
                            app.panels.repeater.clear_all_history();
                            app.status = "Cleared history across all Repeater tabs".into();
                            ui.close();
                        }
                    }
                });
                ui.add_space(4.0);
                if ui.button("+").on_hover_text("New tab").clicked() {
                    let host = app.panels.repeater.active().host.clone();
                    app.panels.repeater.open(&host, "");
                }
                ui.add_space(4.0);
                ui.menu_button("Create group", |ui| {
                    ui.set_min_width(240.0);
                    ui.label(RichText::new("Create / Assign Tab Group").strong());
                    ui.horizontal(|ui| {
                        ui.label("Name:");
                        ui.add(
                            egui::TextEdit::singleline(&mut app.panels.repeater.new_group_name)
                                .hint_text("Group name (e.g. Auth)")
                                .desired_width(155.0),
                        );
                    });
                    ui.add_space(4.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().button_padding = Vec2::new(7.0, 2.5);
                        for code in 1u8..=7 {
                            let swatch = group_color_swatch(code).unwrap_or(Color32::GRAY);
                            let is_sel = app.panels.repeater.new_group_color == code;
                            let btn = egui::Button::new(
                                RichText::new(group_color_name(code))
                                    .size(11.0)
                                    .strong()
                                    .color(Color32::WHITE),
                            )
                            .fill(swatch)
                            .stroke(if is_sel {
                                egui::Stroke::new(2.0, Color32::WHITE)
                            } else {
                                egui::Stroke::NONE
                            })
                            .corner_radius(4.0);
                            if ui.add(btn).clicked() {
                                app.panels.repeater.new_group_color = code;
                            }
                        }
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        if crate::ui::app::primary_button(ui, theme, "Assign active tab").clicked()
                        {
                            let gcolor = app.panels.repeater.new_group_color.max(1);
                            let gname = app.panels.repeater.new_group_name.trim().to_string();
                            let tab = app.panels.repeater.active_mut();
                            tab.group_color = gcolor;
                            tab.group_name = if gname.is_empty() {
                                format!("{} group", group_color_name(gcolor))
                            } else {
                                gname
                            };
                            ui.close();
                        }
                        if ui.button("Remove from group").clicked() {
                            let tab = app.panels.repeater.active_mut();
                            tab.group_color = 0;
                            tab.group_name.clear();
                            ui.close();
                        }
                    });
                });
                ui.add_space(6.0);
                if ui
                    .small_button("? Getting started")
                    .on_hover_text("Open Repeater Getting Started guide")
                    .clicked()
                {
                    app.panels.repeater.hide_getting_started_forever = false;
                    app.panels.repeater.force_getting_started = true;
                }
            });
        });

    let sep_rect = egui::Rect::from_min_size(
        ui.cursor().min,
        Vec2::new(ui.available_width(), 1.0),
    );
    ui.painter().rect_filled(sep_rect, 0.0, border_col);
    ui.add_space(1.0);

    if let Some(r_idx) = app.panels.repeater.rename_tab {
        if r_idx < app.panels.repeater.tabs.len() {
            ui.horizontal(|ui| {
                ui.label("Rename tab:");
                ui.text_edit_singleline(&mut app.panels.repeater.rename_draft);
                if ui.button("Apply").clicked() {
                    app.panels.repeater.tabs[r_idx].name =
                        app.panels.repeater.rename_draft.trim().to_string();
                    app.panels.repeater.rename_tab = None;
                }
                if ui.button("Cancel").clicked() {
                    app.panels.repeater.rename_tab = None;
                }
            });
        } else {
            app.panels.repeater.rename_tab = None;
        }
    }
}

/// Gulp's response analyzers. Backed by `http/message/responses/analysis/*` in the shipped API:
/// a keywords analyser, a variations analyser and attribute extraction.
fn analyzers(app: &mut App, ui: &mut Ui, response: &str) {
    let theme = app.theme.clone();
    let (head, body) = crate::analysis::split_message(response);
    let content_type = head
        .lines()
        .find(|line| line.to_lowercase().starts_with("content-type:"))
        .map(|line| line[13..].trim().to_string())
        .unwrap_or_default();

    if body.is_empty() {
        super::muted(ui, &theme, "No response body to analyse.");
        return;
    }

    let markup = crate::analysis::is_markup(&content_type, body);
    let keywords = crate::analysis::keywords(body, 40);
    let attributes = if markup {
        crate::analysis::attributes(body, 40)
    } else {
        Vec::new()
    };
    let host = app.panels.repeater.active().host.clone();
    let siblings: Vec<String> = app
        .log
        .iter()
        .rev()
        .filter(|tx| !tx.response.is_empty() && tx.target != host && host.ends_with(&tx.host))
        .take(20)
        .map(|tx| crate::analysis::split_message(&tx.response).1.to_string())
        .collect();
    let variations = crate::analysis::variations(body, &siblings);
    let (unique, partial, shared) = crate::analysis::variation_summary(&variations);

    ui.horizontal_wrapped(|ui| {
        super::label(ui, &theme, &format!("Keywords: {}", keywords.len()));
        super::label(
            ui,
            &theme,
            &format!("Attributes: {}", if markup { attributes.len() } else { 0 }),
        );
        super::label(
            ui,
            &theme,
            &format!("Variations: {unique} unique, {partial} partial, {shared} shared"),
        );
        super::muted(
            ui,
            &theme,
            &format!("(compared against {} response(s))", siblings.len()),
        );
    });

    ui.columns(3, |columns| {
        super::label(&mut columns[0], &theme, "Keywords");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[0], |ui| {
                for keyword in &keywords {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(keyword.text.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &keyword.count.to_string());
                    });
                }
            });

        super::label(&mut columns[1], &theme, "Attributes");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[1], |ui| {
                if !markup {
                    super::muted(ui, &theme, "Not a markup response.");
                }
                for attribute in &attributes {
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(attribute.name.as_str())
                                .monospace()
                                .color(theme.color("ui.text.body")),
                        );
                        super::muted(ui, &theme, &attribute.count.to_string());
                    });
                }
            });

        super::label(&mut columns[2], &theme, "Variations");
        eframe::egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(&mut columns[2], |ui| {
                if siblings.is_empty() {
                    super::muted(
                        ui,
                        &theme,
                        "No comparable responses yet. Send a few requests to the same host.",
                    );
                }
                for (index, row) in variations.iter().take(80).enumerate() {
                    let text = match row {
                        crate::analysis::Variation::Unique => "unique".to_string(),
                        crate::analysis::Variation::Shared(n) => format!("in {n}"),
                        crate::analysis::Variation::Partial(n, total) => {
                            format!("in {n} of {total}")
                        }
                    };
                    let colour = match row {
                        crate::analysis::Variation::Unique => theme.color("ui.icon.warning"),
                        crate::analysis::Variation::Partial(_, _) => {
                            theme.color("ui.icon.information")
                        }
                        crate::analysis::Variation::Shared(_) => theme.color("ui.icon.default"),
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            eframe::egui::RichText::new(format!("{index}"))
                                .color(theme.color("ui.icon.disabled")),
                        );
                        ui.label(eframe::egui::RichText::new(text).color(colour));
                    });
                }
            });
    });
}

/// Resolves a `3xx` `Location` header into `(new_host_origin, new_request_path)`.
pub fn redirect_url(
    current_host: &str,
    status: Option<u16>,
    response: &str,
) -> Option<(String, String)> {
    let code = status?;
    if !matches!(code, 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let (head, _) = crate::analysis::split_message(response);
    let location = head.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case("location")
            .then(|| v.trim().to_string())
    })?;
    if location.is_empty() {
        return None;
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        let parsed = url::Url::parse(&location).ok()?;
        let origin = format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str()?,
            parsed.port().map(|p| format!(":{p}")).unwrap_or_default()
        );
        let mut path = parsed.path().to_string();
        if path.is_empty() {
            path.push('/');
        }
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }
        Some((origin, path))
    } else {
        let path = if location.starts_with('/') {
            location
        } else {
            format!("/{location}")
        };
        Some((current_host.to_string(), path))
    }
}

pub(crate) fn follow_redirect(app: &mut App, next_host: &str, next_path: &str) {
    let authority = next_host
        .strip_prefix("http://")
        .or_else(|| next_host.strip_prefix("https://"))
        .unwrap_or(next_host)
        .split('/')
        .next()
        .unwrap_or("localhost")
        .to_string();
    let tab = app.panels.repeater.active_mut();
    let preserve_method = matches!(tab.status, Some(307 | 308));
    let (old_head, old_body) = crate::analysis::split_message(&tab.raw);
    let mut old_lines = old_head.lines();
    let first_line = old_lines.next().unwrap_or("GET / HTTP/1.1");
    let orig_method = first_line.split_whitespace().next().unwrap_or("GET");
    let proto = first_line.split_whitespace().nth(2).unwrap_or("HTTP/1.1");
    let new_method = if preserve_method { orig_method } else { "GET" };

    // Extract any `Set-Cookie` from the redirect response
    let (resp_head, _) = crate::analysis::split_message(&tab.response);
    let mut new_cookies: Vec<String> = Vec::new();
    for rline in resp_head.lines() {
        if let Some((k, v)) = rline.split_once(':') {
            if k.trim().eq_ignore_ascii_case("set-cookie") {
                if let Some(pair) = v.split(';').next() {
                    let trimmed = pair.trim();
                    if !trimmed.is_empty() {
                        new_cookies.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    let mut headers_out = vec![
        format!("{new_method} {next_path} {proto}"),
        format!("Host: {authority}"),
    ];
    let mut had_cookie = false;
    for line in old_lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let kt = k.trim();
        if kt.eq_ignore_ascii_case("host") {
            continue;
        }
        if !preserve_method
            && (kt.eq_ignore_ascii_case("content-length")
                || kt.eq_ignore_ascii_case("content-type"))
        {
            continue;
        }
        if kt.eq_ignore_ascii_case("cookie") {
            had_cookie = true;
            if new_cookies.is_empty() {
                headers_out.push(format!("Cookie: {}", v.trim()));
            } else {
                headers_out.push(format!("Cookie: {}; {}", v.trim(), new_cookies.join("; ")));
            }
        } else {
            headers_out.push(format!("{kt}: {}", v.trim()));
        }
    }
    if !had_cookie && !new_cookies.is_empty() {
        headers_out.push(format!("Cookie: {}", new_cookies.join("; ")));
    }
    if !headers_out
        .iter()
        .any(|h| h.to_ascii_lowercase().starts_with("connection:"))
    {
        headers_out.push("Connection: close".into());
    }
    tab.host = next_host.to_string();
    if preserve_method && !old_body.is_empty() {
        tab.raw = format!("{}\r\n\r\n{old_body}", headers_out.join("\r\n"));
    } else {
        tab.raw = format!("{}\r\n\r\n", headers_out.join("\r\n"));
    }
    send(app);
}

/// Normalizes HTTP/1.1 header line endings (`\r\n`) and optionally recalculates `Content-Length`
/// to match the current request body byte length.
pub fn normalize_http_request(
    raw: &str,
    normalize_newlines: bool,
    update_content_length: bool,
) -> String {
    let (head, body) = crate::analysis::split_message(raw);
    if !normalize_newlines && !update_content_length {
        return raw.to_string();
    }
    let mut lines: Vec<String> = head.lines().map(|l| l.trim_end_matches('\r').to_string()).collect();
    if lines.is_empty() {
        return raw.to_string();
    }
    if update_content_length {
        let first_method = lines[0]
            .split_whitespace()
            .next()
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let has_body_or_cl = !body.is_empty()
            || matches!(first_method.as_str(), "POST" | "PUT" | "PATCH")
            || lines
                .iter()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("content-length:"));
        if has_body_or_cl {
            let body_len = body.len();
            let mut updated = false;
            for line in lines.iter_mut().skip(1) {
                if line.to_ascii_lowercase().starts_with("content-length:") {
                    *line = format!("Content-Length: {body_len}");
                    updated = true;
                }
            }
            if !updated && !body.is_empty() {
                lines.push(format!("Content-Length: {body_len}"));
            }
        }
    }
    format!("{}\r\n\r\n{body}", lines.join("\r\n"))
}

/// Sends all tabs in the active group (or all tabs when ungrouped) in sequence or parallel (`send-group.html`).
pub(crate) fn send_group(app: &mut App) {
    let active_grp = app.panels.repeater.active().group_color;
    let indices: Vec<usize> = (0..app.panels.repeater.tabs.len())
        .filter(|&i| active_grp == 0 || app.panels.repeater.tabs[i].group_color == active_grp)
        .collect();
    let total = indices.len();
    let prev_active = app.panels.repeater.active;
    for (ord, idx) in indices.into_iter().enumerate() {
        app.panels.repeater.active = idx;
        app.panels.repeater.tabs[idx].parallel_order_badge = Some((ord + 1, total));
        send(app);
    }
    app.panels.repeater.active = prev_active;
    app.status = format!("Sent {total} grouped Repeater request(s)");
}

pub(crate) fn send(app: &mut App) {
    if app.panels.repeater.active().sending {
        return;
    }
    let host = app.panels.repeater.active().host.trim().to_string();
    let target = match crate::http_target::HttpTarget::parse(&host) {
        Ok(target) => target,
        Err(error) => {
            app.status = error;
            return;
        }
    };
    let norm_nl = app.panels.repeater.active().normalize_line_endings;
    let upd_cl = app.panels.repeater.active().update_content_length;
    let normalized_raw = normalize_http_request(
        &app.panels.repeater.active().raw,
        norm_nl,
        upd_cl,
    );
    let raw = match app.panels.extender.apply_live(&normalized_raw) {
        Ok(raw) => raw,
        Err(why) => {
            app.status = format!("Bambda rejected the request: {why}");
            return;
        }
    };
    let tab = app.panels.repeater.active_mut();
    tab.status = None;
    tab.response.clear();
    tab.in_flight = Some((host, raw.clone(), std::time::Instant::now()));
    let id = app.send_request(target.host, target.port, raw, target.secure);
    let tab = app.panels.repeater.active_mut();
    tab.pending = Some(id);
    tab.sending = true;
    app.status = format!("Sent request #{id}");
}

pub(crate) fn cancel(app: &mut App) {
    if let Some(id) = app.panels.repeater.active_mut().pending.take() {
        app.cancel_request(id);
        let tab = app.panels.repeater.active_mut();
        tab.sending = false;
        tab.in_flight = None;
        tab.response = "Request cancelled".into();
        app.status = "Repeater request cancelled".into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::app::App;

    #[test]
    fn closing_an_earlier_tab_preserves_the_selected_request() {
        let mut panel = RepeaterPanel::default();
        panel.open("http://a.test", "GET /a HTTP/1.1\r\n\r\n");
        panel.open("http://b.test", "GET /b HTTP/1.1\r\n\r\n");
        panel.open("http://c.test", "GET /c HTTP/1.1\r\n\r\n");
        panel.active = 2;
        panel.close(0);
        assert_eq!(panel.active().host, "http://b.test");
        assert!(panel.reopen_closed_tab());
    }

    #[test]
    fn replies_land_in_the_owning_tab_and_history_restores_the_exchange() {
        let mut panel = RepeaterPanel::default();
        panel.active_mut().pending = Some(1);
        panel.active_mut().sending = true;
        panel.open("http://b.test", "GET /b HTTP/1.1\r\n\r\n");
        panel.active_mut().pending = Some(2);
        assert!(panel.complete(1, 201, "first response".into()));
        assert!(!panel.tabs[0].sending);
        assert_eq!(panel.tabs[0].response, "first response");
        assert_eq!(panel.active().pending, Some(2));
        assert!(panel.complete(2, 202, "second response".into()));
        panel.active_mut().pending = Some(3);
        panel.active_mut().raw = "GET /changed HTTP/1.1\r\n\r\n".into();
        panel.complete(3, 200, "third response".into());
        assert!(panel.active_mut().navigate_history(-1));
        assert!(panel.active().raw.contains("/b"));
        assert_eq!(panel.active().response, "second response");
        assert!(panel.active_mut().navigate_history(1));
        assert!(panel.active().raw.contains("/changed"));
        assert_eq!(panel.active().response, "third response");
        assert!(!panel.complete(1, 500, "stale response".into()));
    }

    #[test]
    fn the_repeater_keeps_several_requests_open() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.panels.repeater.open(
            "http://a.test/one",
            "GET /one HTTP/1.1\r\nHost: a.test\r\n\r\n",
        );
        app.panels.repeater.open(
            "http://b.test/two",
            "GET /two HTTP/1.1\r\nHost: b.test\r\n\r\n",
        );

        assert_eq!(app.panels.repeater.tabs.len(), 3, "the first tab plus two");
        assert_eq!(app.panels.repeater.active, 2, "the last one sent is open");
        assert!(
            app.panels.repeater.active().raw.contains("/two"),
            "the open tab is the one that was sent last"
        );

        app.panels.repeater.close(2);
        assert_eq!(app.panels.repeater.tabs.len(), 2);
        app.panels.repeater.close(0);
        app.panels.repeater.close(0);
        assert_eq!(app.panels.repeater.tabs.len(), 1, "one tab always remains");
    }

    #[test]
    fn the_repeater_draws_its_tabs() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.panels.repeater.open(
            "http://b.test/two",
            "GET /two HTTP/1.1\r\nHost: b.test\r\n\r\n",
        );

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                draw(&mut app, ui);
            });
        });
        let texts: Vec<String> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                eframe::egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect();
        let all = texts.join("\n");
        assert!(
            all.contains("b.test"),
            "the tab should be named after the host: {all}"
        );
        assert!(
            all.contains("/two"),
            "the open request should be in the editor: {all}"
        );
    }

    #[test]
    fn repeater_clear_history_and_group_badges_work() {
        let mut panel = RepeaterPanel::default();
        panel.active_mut().pending = Some(1);
        panel.active_mut().sending = true;
        assert!(panel.complete(1, 200, "HTTP/1.1 200 OK\r\n\r\nok".into()));
        assert_eq!(panel.active().history.len(), 1);
        assert_eq!(panel.active().history_cursor, Some(0));

        panel.active_mut().clear_history();
        assert!(panel.active().history.is_empty());
        assert_eq!(panel.active().history_cursor, None);

        panel.active_mut().group_color = 1;
        panel.active_mut().group_name = "Auth".into();
        let host = panel.active().host.clone();
        let raw = panel.active().raw.clone();
        panel.open(&host, &raw);
        assert_eq!(panel.tabs.len(), 2);
        assert_eq!(panel.active, 1);
    }
}
