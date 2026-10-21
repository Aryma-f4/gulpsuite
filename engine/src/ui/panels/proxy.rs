//! Proxy: listener control, interception, and the held-request queue.

use eframe::egui::Ui;

use super::{empty_state, heading, horizontal_resize_handle, muted, vertical_split};
use crate::ui::app::App;

#[derive(Clone)]
pub struct ProxyPanel {
    pub port: u16,
    /// Index into the log of the row whose detail is open.
    pub selected: Option<usize>,
    /// Row index opened in a detached resizable popup window.
    pub detached_row: Option<usize>,
    /// Which parked request is open in the intercept editor.
    pub held_selected: Option<u64>,
    /// The edited message waiting to be forwarded, with the id of the message it belongs to.
    pub held_edit: Option<(u64, String)>,
    /// Resizable height of the Intercept request/response editor.
    pub intercept_height: f32,
    /// Resizable height of the HTTP history table.
    pub table_height: f32,
    /// Resizable height of the lower Request/Response detail pane.
    pub detail_height: f32,
    /// Draggable horizontal split ratio (`0.18..=0.82`) between Request and Response panes.
    pub split_ratio: f32,
    ///Drags the detached window's Request/Response split.
    pub detached_split_ratio: f32,
    /// User-resizable widths, independent of the contents of captured requests.
    pub history_column_widths: [f32; 19],
    /// Active sort column in HTTP history.
    pub sort_column: Option<usize>,
    pub sort_ascending: bool,
    /// Filter query for HTTP history.
    pub filter: String,
    /// Master switch for HTTP history filters (`Filter on` / `Filter off` in Burp).
    pub filter_enabled: bool,
    /// Opens Burp's detailed `HTTP history filter` modal window.
    pub show_filter_window: bool,
    /// Restrict HTTP history to Target Scope rules.
    pub in_scope_only: bool,
    /// Restrict HTTP history to requests carrying query/body parameters.
    pub params_only: bool,
    /// Restrict HTTP history to 4xx/5xx responses.
    pub errors_only: bool,
    pub status_2xx: bool,
    pub status_3xx: bool,
    pub status_4xx: bool,
    pub status_5xx: bool,
    pub regex_search: bool,
    pub case_sensitive: bool,
    pub negative_search: bool,
    pub hide_extensions_enabled: bool,
    pub hide_extensions: String,
    pub show_extensions: String,
    pub only_notes: bool,
    pub only_highlighted: bool,
    /// Restrict HTTP history by MIME type (`All`, `HTML`, `JSON`, `script`, `CSS`, `XML`, `image`).
    pub mime_filter: String,
    /// Hex dump toggle for the selected HTTP history request/response viewer.
    pub hex_view: bool,
    /// User-annotated notes keyed by history row index.
    pub notes: std::collections::HashMap<usize, String>,
    /// User highlight colour code (`1..=5`) keyed by history row index.
    pub highlights: std::collections::HashMap<usize, u8>,
    // ---- Burp Proxy settings (all 9 sections from settings/tools/proxy.html) ----
    pub bind_address_mode: usize,
    pub redirect_host: String,
    pub redirect_port: String,
    pub force_tls: bool,
    pub support_invisible_proxy: bool,
    pub cert_mode: usize,
    pub cert_specific_host: String,
    pub auto_update_content_length: bool,
    pub auto_fix_newlines: bool,
    pub intercept_in_scope_only: bool,
    pub ws_intercept_c2s: bool,
    pub ws_intercept_s2c: bool,
    pub ws_intercept_in_scope_only: bool,
    pub resp_mod_unhide_fields: bool,
    pub resp_mod_highlight_unhidden: bool,
    pub resp_mod_enable_disabled: bool,
    pub resp_mod_remove_maxlength: bool,
    pub resp_mod_remove_js_validation: bool,
    pub resp_mod_remove_all_js: bool,
    pub resp_mod_https_to_http: bool,
    pub resp_mod_strip_cookie_secure: bool,
    pub tls_passthrough_hosts: String,
    pub tls_auto_passthrough_on_error: bool,
    pub tls_passthrough_out_of_scope: bool,
    pub default_history_display: usize,
    pub default_interception_state: usize,
    pub misc_http10_server: bool,
    pub misc_http10_client: bool,
    pub misc_keep_alive: bool,
    pub misc_resp_conn_close: bool,
    pub misc_req_conn_close: bool,
    pub misc_strip_proxy_headers: bool,
    pub misc_strip_unsupported_encoding: bool,
    pub misc_strip_ws_extensions: bool,
    pub misc_unpack_compressed_req: bool,
    pub misc_unpack_compressed_resp: bool,
    pub misc_disable_portal: bool,
    pub misc_suppress_errors: bool,
    pub misc_dont_log_history: bool,
    pub dont_log_out_of_scope: bool,
    // Formatter & Configure filter modal fields (`quick-start-pro-intercepted-request.png`, `filter-settings-http.png`)
    pub intercept_fmt_mode: usize,
    pub intercept_wrap: bool,
    pub intercept_non_printable: bool,
    pub history_req_fmt_mode: usize,
    pub history_resp_fmt_mode: usize,
    pub history_req_wrap: bool,
    pub history_resp_wrap: bool,
    pub history_req_np: bool,
    pub history_resp_np: bool,
    pub filter_mode_bambda: bool,
    pub filter_bambda_script: String,
    pub filter_hide_no_response: bool,
    pub filter_show_extensions_enabled: bool,
    pub filter_listener_port: String,
    pub mime_html: bool,
    pub mime_script: bool,
    pub mime_xml: bool,
    pub mime_css: bool,
    pub mime_other_text: bool,
    pub mime_images: bool,
    pub mime_flash: bool,
    pub mime_other_binary: bool,
}

impl Default for ProxyPanel {
    fn default() -> Self {
        ProxyPanel {
            port: 8080,
            selected: None,
            detached_row: None,
            held_selected: None,
            held_edit: None,
            intercept_height: 320.0,
            table_height: 240.0,
            detail_height: 280.0,
            split_ratio: 0.5,
            detached_split_ratio: 0.5,
            history_column_widths: [
                34., 185., 62., 300., 50., 50., 82., 62., 85., 70., 140., 90., 40.,
                110., 130., 100., 100., 140., 140.,
            ],
            sort_column: None,
            sort_ascending: true,
            filter: String::new(),
            filter_enabled: true,
            show_filter_window: false,
            in_scope_only: false,
            params_only: false,
            errors_only: false,
            status_2xx: true,
            status_3xx: true,
            status_4xx: true,
            status_5xx: true,
            regex_search: false,
            case_sensitive: false,
            negative_search: false,
            hide_extensions_enabled: false,
            hide_extensions: "gif, jpg, png, ico, woff, woff2".into(),
            show_extensions: String::new(),
            only_notes: false,
            only_highlighted: false,
            mime_filter: "All".into(),
            hex_view: false,
            notes: std::collections::HashMap::new(),
            highlights: std::collections::HashMap::new(),
            bind_address_mode: 0,
            redirect_host: String::new(),
            redirect_port: String::new(),
            force_tls: false,
            support_invisible_proxy: false,
            cert_mode: 0,
            cert_specific_host: String::new(),
            auto_update_content_length: true,
            auto_fix_newlines: true,
            intercept_in_scope_only: false,
            ws_intercept_c2s: false,
            ws_intercept_s2c: false,
            ws_intercept_in_scope_only: false,
            resp_mod_unhide_fields: false,
            resp_mod_highlight_unhidden: false,
            resp_mod_enable_disabled: false,
            resp_mod_remove_maxlength: false,
            resp_mod_remove_js_validation: false,
            resp_mod_remove_all_js: false,
            resp_mod_https_to_http: false,
            resp_mod_strip_cookie_secure: false,
            tls_passthrough_hosts: String::new(),
            tls_auto_passthrough_on_error: false,
            tls_passthrough_out_of_scope: false,
            default_history_display: 0,
            default_interception_state: 1,
            misc_http10_server: false,
            misc_http10_client: false,
            misc_keep_alive: true,
            misc_resp_conn_close: false,
            misc_req_conn_close: true,
            misc_strip_proxy_headers: true,
            misc_strip_unsupported_encoding: true,
            misc_strip_ws_extensions: true,
            misc_unpack_compressed_req: false,
            misc_unpack_compressed_resp: false,
            misc_disable_portal: false,
            misc_suppress_errors: false,
            misc_dont_log_history: false,
            dont_log_out_of_scope: false,
            intercept_fmt_mode: 0,
            intercept_wrap: true,
            intercept_non_printable: false,
            history_req_fmt_mode: 0,
            history_resp_fmt_mode: 0,
            history_req_wrap: true,
            history_resp_wrap: true,
            history_req_np: false,
            history_resp_np: false,
            filter_mode_bambda: false,
            filter_bambda_script: "return requestResponse.request().isInScope();".into(),
            filter_hide_no_response: false,
            filter_show_extensions_enabled: false,
            filter_listener_port: String::new(),
            mime_html: true,
            mime_script: true,
            mime_xml: true,
            mime_css: false,
            mime_other_text: true,
            mime_images: false,
            mime_flash: true,
            mime_other_binary: false,
        }
    }
}

pub fn draw(app: &mut App, ui: &mut Ui) {
    match app.view {
        0 => intercept(app, ui),
        1 => history(app, ui),
        2 => super::websocket::draw(app, ui, "Proxy"),
        3 => match_and_replace(app, ui),
        _ => settings(app, ui),
    }
}

/// Burp's match-and-replace view: the rules that rewrite traffic on its way out.
///
/// The rules use the same Bambda language as the Extensions tab, so one script serves both: here
/// it is a set of live rules, there it is a script being written.
fn match_and_replace(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();

    let active = app.proxy.has_rules();
    ui.horizontal(|ui| {
        if ui
            .checkbox(&mut app.panels.match_replace_enabled, "Enable rules")
            .changed()
        {
            if app.panels.match_replace_enabled {
                match app.proxy.set_rules(&app.panels.extender.script) {
                    Ok(()) => app.status = "Match and replace rules are live".into(),
                    Err(why) => {
                        app.panels.match_replace_enabled = false;
                        app.status = format!("Rules rejected: {why}");
                    }
                }
            } else {
                app.proxy.clear_rules();
                app.status = "Match and replace rules are off".into();
            }
        }
        if ui.button("Apply now").clicked() {
            match app.proxy.set_rules(&app.panels.extender.script) {
                Ok(()) => app.status = "Match and replace rules reloaded".into(),
                Err(why) => app.status = format!("Rules rejected: {why}"),
            }
        }
        muted(
            ui,
            &theme,
            if active {
                "rules are live"
            } else {
                "no rules active"
            },
        );
    });

    ui.add_space(6.0);
    let script = app.panels.extender.script.clone();
    match crate::bambda::parse(&script) {
        Ok(statements) => {
            if statements.is_empty() {
                muted(
                    ui,
                    &theme,
                    "No rules. Edit the script in the Extensions tab.",
                );
                return;
            }
            eframe::egui::Grid::new("match-replace-grid")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(eframe::egui::RichText::new("Rule").strong());
                    ui.label(eframe::egui::RichText::new("Effect").strong());
                    ui.end_row();
                    for statement in statements.iter() {
                        ui.label(statement.describe());
                        ui.label(statement.effect());
                        ui.end_row();
                    }
                });
        }
        Err(error) => {
            ui.label(
                eframe::egui::RichText::new(format!("Script error — {error}"))
                    .color(theme.color("ui.issue.high")),
            );
        }
    }
}

/// Complete Burp Suite Pro v2026.3.3 `Proxy settings` view (`settings/tools/proxy.html`),
/// shared by both `Proxy -> Proxy settings` and `Settings -> Tools -> Proxy`.
pub fn settings(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    eframe::egui::ScrollArea::vertical()
        .id_salt("proxy-settings-scroll")
        .show(ui, |ui| {
            // 1. Proxy listeners (Binding, Request handling, Certificate, TLS Protocols, HTTP)
            heading(ui, &theme, "Proxy listeners");
            muted(
                ui,
                &theme,
                "Burp's proxy listener accepts HTTP and HTTPS traffic on loopback and routes the integrated browser.",
            );
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                let listening = app.listening.is_some();
                if ui
                    .add_enabled(!listening, eframe::egui::Button::new("Start"))
                    .clicked()
                {
                    app.start_proxy(app.panels.proxy_panel.port);
                }
                if ui
                    .add_enabled(listening, eframe::egui::Button::new("Stop"))
                    .clicked()
                {
                    app.stop_proxy();
                }
                ui.separator();
                ui.label("Bind to port");
                let mut port_text = app.panels.proxy_panel.port.to_string();
                if ui
                    .add(eframe::egui::TextEdit::singleline(&mut port_text).desired_width(68.0))
                    .changed()
                {
                    if let Ok(port) = port_text.trim().parse::<u16>() {
                        app.panels.proxy_panel.port = port;
                    }
                }
                ui.separator();
                ui.label("Bind to address:");
                eframe::egui::ComboBox::from_id_salt("proxy-bind-addr")
                    .selected_text(match app.panels.proxy_panel.bind_address_mode {
                        1 => "All interfaces",
                        2 => "Specific address",
                        _ => "Loopback only (127.0.0.1)",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut app.panels.proxy_panel.bind_address_mode,
                            0,
                            "Loopback only (127.0.0.1)",
                        );
                        ui.selectable_value(
                            &mut app.panels.proxy_panel.bind_address_mode,
                            1,
                            "All interfaces",
                        );
                        ui.selectable_value(
                            &mut app.panels.proxy_panel.bind_address_mode,
                            2,
                            "Specific address",
                        );
                    });
                ui.separator();
                ui.label(
                    app.listening
                        .map(|port| format!("Running on 127.0.0.1:{port}"))
                        .unwrap_or_else(|| "Stopped".into()),
                );
                if ui.button("Open browser").clicked() {
                    app.open_browser();
                }
            });

            ui.add_space(6.0);
            eframe::egui::CollapsingHeader::new(
                eframe::egui::RichText::new("Listener request handling & TLS certificate").strong(),
            )
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Redirect to host:");
                    ui.add(
                        eframe::egui::TextEdit::singleline(
                            &mut app.panels.proxy_panel.redirect_host,
                        )
                        .desired_width(160.0),
                    );
                    ui.label("Redirect to port:");
                    ui.add(
                        eframe::egui::TextEdit::singleline(
                            &mut app.panels.proxy_panel.redirect_port,
                        )
                        .desired_width(68.0),
                    );
                });
                ui.checkbox(
                    &mut app.panels.proxy_panel.force_tls,
                    "Force use of TLS on outgoing connections",
                );
                ui.checkbox(
                    &mut app.panels.proxy_panel.support_invisible_proxy,
                    "Support invisible proxying (enable only if needed)",
                );
                ui.separator();
                ui.label(eframe::egui::RichText::new("Server TLS certificate:").strong());
                ui.radio_value(
                    &mut app.panels.proxy_panel.cert_mode,
                    0,
                    "Generate CA-signed per-host certificates (default)",
                );
                ui.radio_value(
                    &mut app.panels.proxy_panel.cert_mode,
                    1,
                    "Use a self-signed certificate",
                );
                ui.horizontal(|ui| {
                    ui.radio_value(
                        &mut app.panels.proxy_panel.cert_mode,
                        2,
                        "Generate a CA-signed certificate with a specific hostname:",
                    );
                    ui.add(
                        eframe::egui::TextEdit::singleline(
                            &mut app.panels.proxy_panel.cert_specific_host,
                        )
                        .desired_width(160.0),
                    );
                });
            });

            ui.add_space(8.0);
            heading(ui, &theme, "CA certificate");
            muted(
                ui,
                &theme,
                "The integrated Chromium browser trusts this session CA automatically via SPKI pinning. \
                 External browsers can download the certificate from http://burp/cert or http://burpsuite/cert.",
            );
            if let Some(path) = app.proxy.authority_path() {
                ui.horizontal(|ui| {
                    ui.label("PEM file:");
                    ui.monospace(path.display().to_string());
                });
                ui.horizontal(|ui| {
                    ui.label("DER file:");
                    ui.monospace(path.with_extension("der").display().to_string());
                });
            }
            ui.horizontal_wrapped(|ui| {
                if ui.button("Copy CA PEM").clicked() {
                    if let Some(pem) = app.proxy.authority_pem() {
                        ui.ctx().copy_text(pem);
                        app.status = "Copied proxy CA PEM certificate to clipboard".into();
                    }
                }
                if ui.button("Copy SPKI pin").clicked() {
                    if let Ok(pin) = app.proxy.browser_ca_pin() {
                        ui.ctx().copy_text(pin.clone());
                        app.status = format!("Copied session CA SPKI pin: {pin}");
                    }
                }
                ui.monospace("http://burp/cert");
            });

            // 2. Request and response interception rules
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "Request and response interception rules");
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut app.intercepting, "Intercept");
                app.proxy.set_intercept(app.intercepting);
                ui.separator();
                let mut responses = app.intercepting_responses;
                if ui.checkbox(&mut responses, "Responses").changed() {
                    app.intercepting_responses = responses;
                    app.proxy.set_intercept_response(responses);
                }
                let mut tls = app.tls_intercepting;
                if ui.checkbox(&mut tls, "TLS").changed() {
                    app.tls_intercepting = tls;
                    app.proxy.set_tls_interception(tls);
                }
            });
            ui.checkbox(
                &mut app.panels.proxy_panel.intercept_in_scope_only,
                "Only intercept in-scope requests (URL is in Target scope)",
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.auto_update_content_length,
                "Automatically update Content-Length header when the request / response is edited",
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.auto_fix_newlines,
                "Automatically fix missing or superfluous new lines at end of request",
            );

            // 3. WebSocket interception rules
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "WebSocket interception rules");
            ui.checkbox(
                &mut app.panels.proxy_panel.ws_intercept_c2s,
                "Intercept client-to-server messages",
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.ws_intercept_s2c,
                "Intercept server-to-client messages",
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.ws_intercept_in_scope_only,
                "Only intercept in-scope WebSocket messages",
            );

            // 4. Response modification rules
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "Response modification rules");
            ui.columns(2, |cols| {
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_unhide_fields,
                    "Unhide hidden form fields",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_highlight_unhidden,
                    "Prominently highlight unhidden fields",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_enable_disabled,
                    "Enable disabled form fields",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_remove_maxlength,
                    "Remove input field length limits",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_remove_js_validation,
                    "Remove JavaScript form validation",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_remove_all_js,
                    "Remove all JavaScript",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_https_to_http,
                    "Convert HTTPS links to HTTP",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.resp_mod_strip_cookie_secure,
                    "Remove secure flag from cookies",
                );
            });

            // 5. HTTP and WebSocket match and replace rules
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "HTTP and WebSocket match and replace rules");
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut app.panels.match_replace_enabled,
                    "Enable HTTP match and replace rules",
                );
                if ui.button("Open Match and replace rules").clicked() {
                    app.tool = crate::ui::app::PROXY;
                    app.view = 3;
                }
            });

            // 6. TLS pass through
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "TLS pass through");
            muted(
                ui,
                &theme,
                "Connections to these hosts or IP ranges will pass straight through without TLS interception.",
            );
            ui.add(
                eframe::egui::TextEdit::multiline(&mut app.panels.proxy_panel.tls_passthrough_hosts)
                    .hint_text("Host or IP range patterns, one per line (e.g. pinned.example.com)")
                    .font(eframe::egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(3),
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.tls_auto_passthrough_on_error,
                "Automatically add entries on client TLS negotiation failure",
            );
            ui.checkbox(
                &mut app.panels.proxy_panel.tls_passthrough_out_of_scope,
                "Apply TLS pass through to out-of-scope items",
            );

            // 7. Default Proxy history message display & Proxy history logging
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "Default Proxy history message display & logging");
            ui.horizontal_wrapped(|ui| {
                ui.label("Default message display:");
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_history_display,
                    0,
                    "Original",
                );
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_history_display,
                    1,
                    "Edited",
                );
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_history_display,
                    2,
                    "Auto-modified",
                );
            });

            // 8. Default Proxy interception state
            ui.add_space(6.0);
            heading(ui, &theme, "Default Proxy interception state");
            ui.horizontal_wrapped(|ui| {
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_interception_state,
                    0,
                    "Enable interception",
                );
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_interception_state,
                    1,
                    "Disable interception (default)",
                );
                ui.radio_value(
                    &mut app.panels.proxy_panel.default_interception_state,
                    2,
                    "Restore setting from last session",
                );
            });

            // 9. Miscellaneous
            ui.add_space(10.0);
            ui.separator();
            heading(ui, &theme, "Miscellaneous");
            ui.columns(2, |cols| {
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_http10_server,
                    "Use HTTP/1.0 in requests to server",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_http10_client,
                    "Use HTTP/1.0 in responses to client",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_keep_alive,
                    "Use keep-alive for HTTP/1 if the server supports it",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_resp_conn_close,
                    "Set response header \"Connection: close\"",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_req_conn_close,
                    "Set \"Connection: close\" on incoming requests",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_strip_proxy_headers,
                    "Strip Proxy-* headers in incoming requests",
                );
                cols[0].checkbox(
                    &mut app.panels.proxy_panel.misc_strip_unsupported_encoding,
                    "Remove unsupported encodings from Accept-Encoding headers",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_strip_ws_extensions,
                    "Strip Sec-WebSocket-Extensions headers in incoming requests",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_unpack_compressed_req,
                    "Unpack compressed requests",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_unpack_compressed_resp,
                    "Unpack compressed in responses",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_disable_portal,
                    "Disable web interface at http://burpsuite",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_suppress_errors,
                    "Suppress Burp error messages in browser",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.misc_dont_log_history,
                    "Don't send items to Proxy history or live tasks",
                );
                cols[1].checkbox(
                    &mut app.panels.proxy_panel.dont_log_out_of_scope,
                    "Don't send items to Proxy history or live tasks, if out of scope",
                );
            });
        });
}

/// Burp's Intercept view (`quick-start-pro-intercept-on.png` & `quick-start-pro-intercepted-request.png`):
/// - Blue `#1858A8` `Intercept is on` toggle button, Orange `#FF6633` `→ Forward` button, `Drop` button
/// - Held queue table (`Time | Type | Direction | Host | Method | URL`)
/// - `Request` / `Response` header + `Pretty | Raw | Hex` formatter bar (with 3px orange `#FF6633` underline,
///   `eye-crossed-out`, `line-wrap` blue pill, `\n`, `≡`) + line-numbered (`1, 2, 3...`) syntax-highlighted HTTP editor.
fn intercept(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    let has_held = !app.held.is_empty();

    ui.horizontal_wrapped(|ui| {
        let intercept_label = if app.intercepting {
            "Intercept is on"
        } else {
            "Intercept is off"
        };
        let intercept_btn = if app.intercepting {
            eframe::egui::Button::new(
                eframe::egui::RichText::new(intercept_label)
                    .color(eframe::egui::Color32::WHITE)
                    .strong(),
            )
            .fill(eframe::egui::Color32::from_rgb(0x18, 0x58, 0xA8))
            .min_size(eframe::egui::Vec2::new(136.0, 26.0))
        } else {
            eframe::egui::Button::new(eframe::egui::RichText::new(intercept_label).strong())
                .min_size(eframe::egui::Vec2::new(136.0, 26.0))
        };
        if ui.add(intercept_btn).clicked() {
            app.intercepting = !app.intercepting;
            app.proxy.set_intercept(app.intercepting);
        }

        if !has_held {
            ui.add_enabled(
                false,
                eframe::egui::Button::new("Forward")
                    .min_size(eframe::egui::Vec2::new(116.0, 26.0)),
            );
            ui.add_enabled(
                false,
                eframe::egui::Button::new("Drop").min_size(eframe::egui::Vec2::new(104.0, 26.0)),
            );
        }
        if ui
            .checkbox(&mut app.intercepting_responses, "Intercept responses")
            .changed()
        {
            app.proxy.set_intercept_response(app.intercepting_responses);
        }
        ui.label(
            app.listening
                .map(|port| format!("127.0.0.1:{port}"))
                .unwrap_or_else(|| "Listener stopped".into()),
        );
        if has_held && ui.button("Open browser").clicked() {
            app.open_browser();
        }
    });

    if app.held.is_empty() {
        let title = if app.intercepting {
            "Waiting for traffic to intercept"
        } else {
            "Intercept is off — traffic passes through"
        };
        let (learn, open_browser) = empty_state(
            ui,
            &theme,
            title,
            "If you turn Intercept on, messages between Burp's browser and your target servers \
             are held here. This enables you to analyze and modify these messages, before you \
             forward them.",
            true,
            Some("Open browser"),
        );
        if learn {
            app.status =
                "Proxy Intercept: turn Intercept on to inspect and modify HTTP requests and responses"
                    .into();
        }
        if open_browser {
            app.open_browser();
        }
        return;
    }

    ui.add_space(4.0);
    let selected = app
        .panels
        .proxy_panel
        .held_selected
        .filter(|id| app.held.iter().any(|item| item.id == *id))
        .unwrap_or(app.held[0].id);
    let current = app
        .held
        .iter()
        .find(|item| item.id == selected)
        .cloned()
        .unwrap_or_else(|| app.held[0].clone());

    let mut edited = app
        .panels
        .proxy_panel
        .held_edit
        .as_ref()
        .filter(|(id, _)| *id == selected)
        .map(|(_, text)| text.clone())
        .unwrap_or_else(|| current.raw.clone());
    let is_response = current.kind == crate::proxy::HeldKind::Response;
    let destination =
        crate::http_target::request_url(&edited, current.target.starts_with("https://"));

    // Action row for the currently parked message (`Forward` in orange `#FF6633`, `Drop`, `Action` buttons)
    ui.horizontal_wrapped(|ui| {
        if ui
            .add(
                eframe::egui::Button::new(
                    eframe::egui::RichText::new("Forward")
                        .color(eframe::egui::Color32::WHITE)
                        .strong(),
                )
                .fill(theme.color("ui.icon.accent"))
                .min_size(eframe::egui::Vec2::new(116.0, 26.0)),
            )
            .clicked()
        {
            app.forward_edited(selected, &edited);
        }
        if ui
            .add(
                eframe::egui::Button::new(if is_response { "Cancel" } else { "Drop" })
                    .min_size(eframe::egui::Vec2::new(104.0, 26.0)),
            )
            .clicked()
        {
            app.release(selected, false);
        }
        if ui.button("Forward all").clicked() {
            app.release_all();
        }
        ui.separator();
        if !is_response && ui.button("To Repeater").clicked() {
            match &destination {
                Ok(target) => {
                    app.panels.repeater.open(target, &edited);
                    app.tool = crate::ui::app::REPEATER;
                    app.view = 0;
                    app.status = format!("Held request #{} sent to Repeater", selected);
                }
                Err(error) => app.status = error.clone(),
            }
        }
        if !is_response && ui.button("To Intruder").clicked() {
            match &destination {
                Ok(target) => app.send_to_intruder(target, &edited),
                Err(error) => app.status = error.clone(),
            }
        }
        if !is_response && ui.button("To Organizer").clicked() {
            let host = destination.clone().unwrap_or_else(|_| current.target.clone());
            let next = app.organizer.len() + 1;
            super::organizer::retain(
                app,
                super::organizer::OrganizerItem {
                    host,
                    name: format!("item-{next}"),
                    request: edited.clone(),
                    response: String::new(),
                    notes: String::new(),
                },
            );
            app.status = format!("Held request #{} saved to Organizer", selected);
        }
        if ui.button("Reset").clicked() {
            app.panels.proxy_panel.held_edit = None;
        }
    });

    ui.add_space(4.0);
    // Held Queue Table matching `quick-start-pro-intercepted-request.png` (`Time | Type | Direction | Host | Method | URL`)
    eframe::egui::Frame::new()
        .fill(theme.color("ui.background.0"))
        .stroke(eframe::egui::Stroke::new(1.0, theme.color("ui.border.1")))
        .inner_margin(4.0)
        .show(ui, |ui| {
            eframe::egui::ScrollArea::vertical()
                .id_salt("proxy-intercept-queue-table")
                .max_height(88.0)
                .show(ui, |ui| {
                    eframe::egui::Grid::new("proxy-intercept-queue-grid")
                        .num_columns(6)
                        .min_col_width(80.0)
                        .striped(true)
                        .show(ui, |ui| {
                            for h in ["Time", "Type", "Direction", "Host", "Method", "URL"] {
                                ui.strong(h);
                            }
                            ui.end_row();
                            for item in app.held.clone() {
                                let is_sel = item.id == selected;
                                let dir = match item.kind {
                                    crate::proxy::HeldKind::Request => "→ Request",
                                    crate::proxy::HeldKind::Response => "← Response",
                                };
                                let host_str = item
                                    .target
                                    .split("://")
                                    .nth(1)
                                    .and_then(|s| s.split('/').next())
                                    .unwrap_or(&item.target);
                                let c1 = ui.selectable_label(is_sel, format!("#{}", item.id));
                                let c2 = ui.selectable_label(is_sel, "HTTP");
                                let c3 = ui.selectable_label(is_sel, dir);
                                let c4 = ui.selectable_label(is_sel, host_str);
                                let c5 = ui.selectable_label(is_sel, &item.method);
                                let c6 = ui.selectable_label(is_sel, truncate(&item.target, 48));
                                if c1.clicked()
                                    || c2.clicked()
                                    || c3.clicked()
                                    || c4.clicked()
                                    || c5.clicked()
                                    || c6.clicked()
                                {
                                    app.panels.proxy_panel.held_selected = Some(item.id);
                                    app.panels.proxy_panel.held_edit = None;
                                }
                                ui.end_row();
                            }
                        });
                });
        });

    ui.add_space(6.0);
    let intercept_h = app.panels.proxy_panel.intercept_height;
    let fmt_mode = app.panels.proxy_panel.intercept_fmt_mode;
    let target_url = destination.clone().unwrap_or_else(|_| current.target.clone());
    let mut intercept_split = 0.72f32;
    let mut insp_tab = 0usize;
    let mut insp_left = false;
    let mut insp_collapsed = false;
    let mut intercept_notes = String::new();
    let mut edited_changed = false;
    vertical_split(
        ui,
        &theme,
        "proxy-intercept-inspector-split",
        &mut intercept_split,
        intercept_h + 36.0,
        |pane, ui| {
            if pane == 0 {
                // Burp Message Formatter Bar (`Request` / `Response` + `Pretty | Raw | Hex` with 3px orange `#FF6633` underline + right icons)
                super::burp_message_formatter_bar(
                    ui,
                    &theme,
                    "proxy-intercept-fmt",
                    if is_response { "Response" } else { "Request" },
                    &mut app.panels.proxy_panel.intercept_fmt_mode,
                    is_response,
                    &mut app.panels.proxy_panel.intercept_wrap,
                    &mut app.panels.proxy_panel.intercept_non_printable,
                );
                let (response, changed) = super::burp_numbered_message_editor_wrapped(
                    ui,
                    &theme,
                    "proxy-intercept-editor",
                    intercept_h,
                    &mut edited,
                    fmt_mode,
                    app.panels.proxy_panel.intercept_wrap,
                );
                if changed {
                    edited_changed = true;
                }
                if is_response {
                    super::attach_message_context_menu(app, &response, &target_url, "", &edited);
                } else {
                    super::attach_message_context_menu(app, &response, &target_url, &edited, "");
                }
            } else if is_response {
                let mut empty_req = String::new();
                super::draw_inspector_and_notes_sidebar(
                    ui,
                    &theme,
                    "proxy-intercept-sidebar",
                    &mut empty_req,
                    &edited,
                    &mut intercept_notes,
                    &mut insp_tab,
                    &mut insp_left,
                    &mut insp_collapsed,
                );
            } else {
                let before = edited.clone();
                super::draw_inspector_and_notes_sidebar(
                    ui,
                    &theme,
                    "proxy-intercept-sidebar",
                    &mut edited,
                    "",
                    &mut intercept_notes,
                    &mut insp_tab,
                    &mut insp_left,
                    &mut insp_collapsed,
                );
                if edited != before {
                    edited_changed = true;
                }
            }
        },
    );
    if edited_changed {
        app.panels.proxy_panel.held_edit = Some((selected, edited.clone()));
    }
    horizontal_resize_handle(
        ui,
        &theme,
        "proxy-intercept-resize",
        &mut app.panels.proxy_panel.intercept_height,
        120.0,
        640.0,
        320.0,
    );
}

/// Shortens a label so a row of held requests still fits.
fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut out: String = text.chars().take(limit.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// The session cookie jar. Burp keeps this under its session settings rather than a tool tab, so
/// it sits at the end of the HTTP history view.
fn cookie_jar(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    ui.add_space(6.0);
    heading(ui, &theme, "Cookie jar");
    ui.horizontal(|ui| {
        if ui.button("Evict expired").clicked() {
            let removed = app.proxy.cookies().evict_expired();
            app.status = format!("Evicted {removed} expired cookie(s)");
        }
        if ui.button("Clear all").clicked() {
            app.proxy.cookies().clear();
            app.status = "Cookie jar cleared".into();
        }
        ui.separator();
        muted(
            ui,
            &theme,
            &format!("{} cookie(s) stored", app.proxy.cookies().len()),
        );
    });

    let cookies = app.proxy.cookies().all();
    if cookies.is_empty() {
        muted(
            ui,
            &theme,
            "No cookies yet. The proxy stores them from Set-Cookie and replays them on later requests.",
        );
        return;
    }

    eframe::egui::ScrollArea::vertical().show(ui, |ui| {
        eframe::egui::Grid::new("cookie-grid")
            .num_columns(6)
            .striped(true)
            .show(ui, |ui| {
                for name in ["Name", "Value", "Domain", "Path", "Flags", "Expires"] {
                    ui.label(
                        eframe::egui::RichText::new(name)
                            .strong()
                            .color(theme.color("ui.text.body")),
                    );
                }
                ui.end_row();
                for cookie in &cookies {
                    ui.label(
                        eframe::egui::RichText::new(&cookie.name)
                            .color(theme.color("ui.text.body")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(&cookie.value)
                            .color(theme.color("ui.text.disabled")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(&cookie.domain)
                            .color(theme.color("ui.icon.default")),
                    );
                    ui.label(
                        eframe::egui::RichText::new(&cookie.path)
                            .color(theme.color("ui.icon.default")),
                    );
                    let mut flags = String::new();
                    if cookie.secure {
                        flags.push_str("Secure ");
                    }
                    if cookie.http_only {
                        flags.push_str("HttpOnly");
                    }
                    ui.label(
                        eframe::egui::RichText::new(if flags.is_empty() { "-" } else { &flags })
                            .color(theme.color("ui.icon.default")),
                    );
                    let expires = cookie
                        .expires
                        .map(|at| {
                            let secs = at
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            format!("{secs}s")
                        })
                        .unwrap_or_else(|| "session".into());
                    ui.label(
                        eframe::egui::RichText::new(expires).color(theme.color("ui.icon.default")),
                    );
                    ui.end_row();
                }
            });
    });
}

fn highlight_colour(theme: &crate::ui::theme::Theme, code: Option<u8>, selected: bool) -> eframe::egui::Color32 {
    match code {
        Some(1) => theme.color("ui.issue.high"),
        Some(2) => theme.color("ui.issue.medium"),
        Some(3) => theme.color("ui.icon.warning"),
        Some(4) => theme.color("ui.icon.success"),
        Some(5) => theme.color("ui.icon.information"),
        _ if selected => theme.color("icon.linkHover"),
        _ => theme.color("ui.text.body"),
    }
}

/// A flat, single-line table cell. Its entire rectangle is interactive, including
/// empty metadata cells; the accessible label retains the untruncated value.
fn history_cell(
    ui: &mut Ui,
    col: usize,
    rect: eframe::egui::Rect,
    text: &str,
    color: eframe::egui::Color32,
    selected: bool,
) -> eframe::egui::Response {
    use eframe::egui::{self, text::LayoutJob, Sense};
    let response = ui.interact(rect, ui.id().with(("history-cell", col)), Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            text,
        )
    });
    let text_rect = rect.shrink2(egui::vec2(4.0, 0.0));
    if text.is_empty() || text_rect.width() <= 2.0 {
        return response;
    }
    if text == "✓" {
        let center = text_rect.center();
        let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
        painter.line_segment(
            [
                center + egui::vec2(-4.0, 0.0),
                center + egui::vec2(-1.0, 3.0),
            ],
            egui::Stroke::new(1.4_f32, color),
        );
        painter.line_segment(
            [
                center + egui::vec2(-1.0, 3.0),
                center + egui::vec2(5.0, -4.0),
            ],
            egui::Stroke::new(1.4_f32, color),
        );
        return response;
    }
    // Bound the shaped prefix to what can physically fit inside `text_rect.width()` so multi-KB URLs
    // never stall the font shaper on every frame (while `widget_info` above keeps the full `text`).
    let max_chars = ((text_rect.width() / 5.2) as usize + 6).clamp(12, 140);
    let display_slice: std::borrow::Cow<'_, str> =
        if text.len() > max_chars && text.chars().nth(max_chars).is_some() {
            let end_b = text
                .char_indices()
                .nth(max_chars)
                .map(|(i, _)| i)
                .unwrap_or(text.len());
            std::borrow::Cow::Borrowed(&text[..end_b])
        } else {
            std::borrow::Cow::Borrowed(text)
        };
    let mut job = LayoutJob::simple_singleline(
        display_slice.into_owned(),
        egui::FontId::proportional(12.0),
        color,
    );
    job.wrap.max_width = text_rect.width();
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
    ui.painter()
        .with_clip_rect(text_rect.intersect(ui.clip_rect()))
        .galley(
            egui::pos2(
                text_rect.left(),
                text_rect.center().y - galley.size().y / 2.0,
            ),
            galley,
            color,
        );
    response
}

/// Burp's History view: everything the proxy has forwarded.
fn history(app: &mut App, ui: &mut Ui) {
    let theme = app.theme.clone();
    if app.log.is_empty() {
        let (learn, open_browser) = empty_state(
            ui,
            &theme,
            "HTTP history is empty",
            "The HTTP history displays all HTTP traffic passed through Burp's proxy. Browse \
             using Burp's browser to populate the history.",
            true,
            Some("Open browser"),
        );
        if learn {
            app.status =
                "HTTP history: browse through the proxy to record HTTP requests and responses".into();
        }
        if open_browser {
            app.open_browser();
        }
        cookie_jar(app, ui);
        return;
    }

    ui.horizontal_wrapped(|ui| {
        let (funnel, _) = ui.allocate_exact_size(
            eframe::egui::Vec2::splat(14.0),
            eframe::egui::Sense::hover(),
        );
        crate::ui::icons::paint(
            ui.painter(),
            funnel,
            theme.color("ui.icon.default"),
            crate::ui::icons::Glyph::Funnel,
        );
        if ui
            .button(if app.panels.proxy_panel.filter_enabled {
                "Filter on"
            } else {
                "Filter off"
            })
            .clicked()
        {
            app.panels.proxy_panel.filter_enabled = !app.panels.proxy_panel.filter_enabled;
        }
        if ui.button("Filter settings").clicked() {
            app.panels.proxy_panel.show_filter_window = !app.panels.proxy_panel.show_filter_window;
        }
        ui.label("Search:");
        ui.add(
            eframe::egui::TextEdit::singleline(&mut app.panels.proxy_panel.filter)
                .hint_text("Search URL, host, method, MIME, title, notes")
                .desired_width(190.0),
        );
        ui.checkbox(&mut app.panels.proxy_panel.in_scope_only, "In-scope only");
        ui.checkbox(&mut app.panels.proxy_panel.params_only, "Params only");
        ui.checkbox(&mut app.panels.proxy_panel.errors_only, "4xx/5xx only");
        eframe::egui::ComboBox::from_id_salt("proxy-mime-filter")
            .selected_text(format!("MIME: {}", app.panels.proxy_panel.mime_filter))
            .show_ui(ui, |ui| {
                for mime in ["All", "HTML", "JSON", "script", "CSS", "XML", "image"] {
                    ui.selectable_value(
                        &mut app.panels.proxy_panel.mime_filter,
                        mime.to_string(),
                        mime,
                    );
                }
            });
        if (!app.panels.proxy_panel.filter.is_empty()
            || app.panels.proxy_panel.in_scope_only
            || app.panels.proxy_panel.params_only
            || app.panels.proxy_panel.errors_only
            || !app.panels.proxy_panel.status_2xx
            || !app.panels.proxy_panel.status_3xx
            || !app.panels.proxy_panel.status_4xx
            || !app.panels.proxy_panel.status_5xx
            || app.panels.proxy_panel.only_notes
            || app.panels.proxy_panel.only_highlighted
            || app.panels.proxy_panel.hide_extensions_enabled
            || !app.panels.proxy_panel.show_extensions.trim().is_empty()
            || app.panels.proxy_panel.mime_filter != "All")
            && ui.button("Clear filter").clicked()
        {
            app.panels.proxy_panel.filter.clear();
            app.panels.proxy_panel.in_scope_only = false;
            app.panels.proxy_panel.params_only = false;
            app.panels.proxy_panel.errors_only = false;
            app.panels.proxy_panel.status_2xx = true;
            app.panels.proxy_panel.status_3xx = true;
            app.panels.proxy_panel.status_4xx = true;
            app.panels.proxy_panel.status_5xx = true;
            app.panels.proxy_panel.regex_search = false;
            app.panels.proxy_panel.case_sensitive = false;
            app.panels.proxy_panel.negative_search = false;
            app.panels.proxy_panel.hide_extensions_enabled = false;
            app.panels.proxy_panel.show_extensions.clear();
            app.panels.proxy_panel.only_notes = false;
            app.panels.proxy_panel.only_highlighted = false;
            app.panels.proxy_panel.mime_filter = "All".into();
        }
        if ui.button("Open browser").clicked() {
            app.open_browser();
        }
    });
    ui.add_space(4.0);

    if app.panels.proxy_panel.show_filter_window {
        let mut open = true;
        eframe::egui::Window::new("Configure filter")
            .open(&mut open)
            .resizable(true)
            .default_pos([340.0, 120.0])
            .default_width(760.0)
            .show(ui.ctx(), |ui| {
                let p = &mut app.panels.proxy_panel;
                // Top row: `[ Settings mode | Bambda mode ]` segmented toggle + `?` & `⚙` icons (`filter-settings-http.png`)
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut p.filter_mode_bambda, false, "Settings mode");
                    ui.selectable_value(&mut p.filter_mode_bambda, true, "Bambda mode");
                    ui.with_layout(
                        eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                        |ui| {
                            super::scanner::paint_launcher_icon(
                                ui,
                                eframe::egui::Vec2::new(18.0, 18.0),
                                theme.color("ui.icon.default"),
                                super::scanner::LauncherIcon::Gear,
                            );
                            super::scanner::paint_launcher_icon(
                                ui,
                                eframe::egui::Vec2::new(18.0, 18.0),
                                theme.color("ui.icon.default"),
                                super::scanner::LauncherIcon::HelpCircle,
                            );
                        },
                    );
                });
                ui.add_space(6.0);

                if p.filter_mode_bambda {
                    ui.label("Bambda filter script:");
                    ui.add(
                        eframe::egui::TextEdit::multiline(&mut p.filter_bambda_script)
                            .font(eframe::egui::TextStyle::Monospace)
                            .desired_rows(6)
                            .desired_width(f32::INFINITY),
                    );
                } else {
                    // Row 1: 3 side-by-side grouped boxes (`Filter by request type`, `Filter by MIME type`, `Filter by status code`)
                    ui.columns(3, |cols| {
                        eframe::egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by request type").strong());
                            ui.checkbox(&mut p.in_scope_only, "Show only in-scope items");
                            ui.checkbox(
                                &mut p.filter_hide_no_response,
                                "Hide items without responses",
                            );
                            ui.checkbox(
                                &mut p.params_only,
                                "Show only parameterized requests",
                            );
                        });
                        eframe::egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by MIME type").strong());
                            ui.columns(2, |mcols| {
                                mcols[0].checkbox(&mut p.mime_html, "HTML");
                                mcols[0].checkbox(&mut p.mime_script, "Script");
                                mcols[0].checkbox(&mut p.mime_xml, "XML");
                                mcols[0].checkbox(&mut p.mime_css, "CSS");
                                mcols[1].checkbox(&mut p.mime_other_text, "Other text");
                                mcols[1].checkbox(&mut p.mime_images, "Images");
                                mcols[1].checkbox(&mut p.mime_flash, "Flash");
                                mcols[1].checkbox(&mut p.mime_other_binary, "Other binary");
                            });
                        });
                        eframe::egui::Frame::group(cols[2].style()).show(&mut cols[2], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by status code").strong());
                            ui.checkbox(&mut p.status_2xx, "2xx [success]");
                            ui.checkbox(&mut p.status_3xx, "3xx [redirection]");
                            ui.checkbox(&mut p.status_4xx, "4xx [request error]");
                            ui.checkbox(&mut p.status_5xx, "5xx [server error]");
                        });
                    });
                    ui.add_space(6.0);

                    // Row 2: 4 side-by-side grouped boxes (`Filter by search term`, `Filter by file extension`, `Filter by annotation`, `Filter by listener`)
                    ui.columns(4, |cols| {
                        eframe::egui::Frame::group(cols[0].style()).show(&mut cols[0], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by search term").strong());
                            ui.text_edit_singleline(&mut p.filter);
                            ui.checkbox(&mut p.regex_search, "Regex");
                            ui.checkbox(&mut p.case_sensitive, "Case sensitive");
                            ui.checkbox(&mut p.negative_search, "Negative search");
                        });
                        eframe::egui::Frame::group(cols[1].style()).show(&mut cols[1], |ui| {
                            ui.label(
                                eframe::egui::RichText::new("Filter by file extension").strong(),
                            );
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut p.filter_show_extensions_enabled, "Show only:");
                                ui.text_edit_singleline(&mut p.show_extensions);
                            });
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut p.hide_extensions_enabled, "Hide:");
                                ui.text_edit_singleline(&mut p.hide_extensions);
                            });
                        });
                        eframe::egui::Frame::group(cols[2].style()).show(&mut cols[2], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by annotation").strong());
                            ui.checkbox(&mut p.only_notes, "Show only commented items");
                            ui.checkbox(&mut p.only_highlighted, "Show only highlighted items");
                        });
                        eframe::egui::Frame::group(cols[3].style()).show(&mut cols[3], |ui| {
                            ui.label(eframe::egui::RichText::new("Filter by listener").strong());
                            ui.horizontal(|ui| {
                                ui.label("Port");
                                ui.text_edit_singleline(&mut p.filter_listener_port);
                            });
                        });
                    });
                }

                ui.add_space(8.0);
                ui.separator();
                // Bottom action row (`Show all`, `Hide all`, `Revert changes`, `Convert to Bambda`, `Cancel`, `Apply`)
                ui.horizontal(|ui| {
                    if ui.button("Show all").clicked() {
                        p.in_scope_only = false;
                        p.params_only = false;
                        p.status_2xx = true;
                        p.status_3xx = true;
                        p.status_4xx = true;
                        p.status_5xx = true;
                        p.mime_html = true;
                        p.mime_script = true;
                        p.mime_xml = true;
                        p.mime_css = true;
                        p.mime_other_text = true;
                        p.mime_images = true;
                        p.mime_flash = true;
                        p.mime_other_binary = true;
                    }
                    if ui.button("Hide all").clicked() {
                        p.status_2xx = false;
                        p.status_3xx = false;
                        p.status_4xx = false;
                        p.status_5xx = false;
                    }
                    if ui.button("Revert changes").clicked() {
                        p.filter.clear();
                        p.in_scope_only = false;
                        p.params_only = false;
                        p.status_2xx = true;
                        p.status_3xx = true;
                        p.status_4xx = true;
                        p.status_5xx = true;
                    }
                    if ui.button("↔ Convert to Bambda").clicked() {
                        p.filter_mode_bambda = true;
                    }
                    ui.with_layout(
                        eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
                        |ui| {
                            if crate::ui::app::primary_button(ui, &theme, "Apply").clicked() {
                                p.show_filter_window = false;
                            }
                            if ui.button("Cancel").clicked() {
                                p.show_filter_window = false;
                            }
                        },
                    );
                });
            });
        if !open {
            app.panels.proxy_panel.show_filter_window = false;
        }
    }

    let filter_enabled = app.panels.proxy_panel.filter_enabled;
    let raw_needle = app.panels.proxy_panel.filter.trim().to_string();
    let in_scope_only = app.panels.proxy_panel.in_scope_only;
    let params_only = app.panels.proxy_panel.params_only;
    let errors_only = app.panels.proxy_panel.errors_only;
    let s2 = app.panels.proxy_panel.status_2xx;
    let s3 = app.panels.proxy_panel.status_3xx;
    let s4 = app.panels.proxy_panel.status_4xx;
    let s5 = app.panels.proxy_panel.status_5xx;
    let regex_search = app.panels.proxy_panel.regex_search;
    let case_sensitive = app.panels.proxy_panel.case_sensitive;
    let negative_search = app.panels.proxy_panel.negative_search;
    let hide_ext_on = app.panels.proxy_panel.hide_extensions_enabled;
    let hide_exts: Vec<String> = app
        .panels
        .proxy_panel
        .hide_extensions
        .split([',', ' '])
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let show_exts: Vec<String> = app
        .panels
        .proxy_panel
        .show_extensions
        .split([',', ' '])
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let only_notes = app.panels.proxy_panel.only_notes;
    let only_highlighted = app.panels.proxy_panel.only_highlighted;
    let mime_filter = app.panels.proxy_panel.mime_filter.clone();
    let compiled_re = if regex_search && !raw_needle.is_empty() {
        regex::RegexBuilder::new(&raw_needle)
            .case_insensitive(!case_sensitive)
            .build()
            .ok()
    } else {
        None
    };

    #[derive(Clone)]
    struct RowSummary {
        index: usize,
        host_url: String,
        method: String,
        target: String,
        path_query: String,
        has_params: bool,
        status: u16,
        bytes: u64,
        truncated: bool,
        mime: &'static str,
        ext: String,
        title: String,
        secure: bool,
        note: String,
        highlight: Option<u8>,
        cookies: String,
    }

    let cache_key = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        app.log_version.hash(&mut h);
        app.log.len().hash(&mut h);
        filter_enabled.hash(&mut h);
        errors_only.hash(&mut h);
        (s2, s3, s4, s5, params_only, in_scope_only).hash(&mut h);
        app.panels.target_panel.scope.hash(&mut h);
        app.panels.target_panel.scope_exclude.hash(&mut h);
        mime_filter.hash(&mut h);
        (only_notes, only_highlighted, hide_ext_on).hash(&mut h);
        show_exts.hash(&mut h);
        hide_exts.hash(&mut h);
        raw_needle.hash(&mut h);
        (regex_search, case_sensitive, negative_search).hash(&mut h);
        app.panels.proxy_panel.sort_column.hash(&mut h);
        app.panels.proxy_panel.sort_ascending.hash(&mut h);
        app.panels.proxy_panel.notes.len().hash(&mut h);
        for (k, v) in &app.panels.proxy_panel.notes {
            k.hash(&mut h);
            v.hash(&mut h);
        }
        app.panels.proxy_panel.highlights.len().hash(&mut h);
        for (k, v) in &app.panels.proxy_panel.highlights {
            k.hash(&mut h);
            v.hash(&mut h);
        }
        h.finish()
    };

    thread_local! {
        static HISTORY_ROWS_CACHE: std::cell::RefCell<Option<(u64, std::sync::Arc<Vec<RowSummary>>)>> =
            const { std::cell::RefCell::new(None) };
    }

    let visible: std::sync::Arc<Vec<RowSummary>> = if let Some(cached) =
        HISTORY_ROWS_CACHE.with(|c| {
            c.borrow()
                .as_ref()
                .filter(|(k, _)| *k == cache_key)
                .map(|(_, rows)| rows.clone())
        }) {
        cached
    } else {
        let rows = app.log.len();
        let lower_needle = if !case_sensitive && !raw_needle.is_empty() {
            raw_needle.to_lowercase()
        } else {
            String::new()
        };
        let mut built: Vec<RowSummary> = (0..rows)
            .filter_map(|index| {
                let tx = &app.log[index];
                let host_url = tx.host_url();
                let path_query = tx.path_and_query();
                let has_params = tx.has_params();
                let mime = tx.mime_type();
                let ext = tx.extension();
                let title = tx.page_title();
                let note = app
                    .panels
                    .proxy_panel
                    .notes
                    .get(&index)
                    .cloned()
                    .unwrap_or_default();
                let highlight = app.panels.proxy_panel.highlights.get(&index).copied();
                if filter_enabled {
                    if errors_only && tx.status < 400 {
                        return None;
                    }
                    let status_allowed = match tx.status {
                        200..=299 => s2,
                        300..=399 => s3,
                        400..=499 => s4,
                        500..=599 => s5,
                        _ => true,
                    };
                    if !status_allowed {
                        return None;
                    }
                    if params_only && !has_params {
                        return None;
                    }
                    if in_scope_only && !app.panels.target_panel.in_scope(&tx.target) {
                        return None;
                    }
                    if mime_filter != "All" && mime != mime_filter {
                        return None;
                    }
                    if only_notes && note.is_empty() {
                        return None;
                    }
                    if only_highlighted && highlight.is_none() {
                        return None;
                    }
                    if !show_exts.is_empty() && !show_exts.iter().any(|e| e == &ext) {
                        return None;
                    }
                    if hide_ext_on && !ext.is_empty() && hide_exts.iter().any(|e| e == &ext) {
                        return None;
                    }
                    if !raw_needle.is_empty() {
                        let matched = if let Some(re) = &compiled_re {
                            re.is_match(&tx.target)
                                || re.is_match(&host_url)
                                || re.is_match(&tx.method)
                                || re.is_match(&title)
                                || re.is_match(&note)
                                || re.is_match(&tx.request)
                                || re.is_match(&tx.response)
                        } else if case_sensitive {
                            tx.target.contains(&raw_needle)
                                || host_url.contains(&raw_needle)
                                || tx.method.contains(&raw_needle)
                                || mime.contains(&raw_needle)
                                || title.contains(&raw_needle)
                                || note.contains(&raw_needle)
                                || tx.status.to_string().contains(&raw_needle)
                                || tx.request.contains(&raw_needle)
                                || tx.response.contains(&raw_needle)
                        } else {
                            tx.target.to_lowercase().contains(&lower_needle)
                                || host_url.to_lowercase().contains(&lower_needle)
                                || tx.method.to_lowercase().contains(&lower_needle)
                                || mime.to_lowercase().contains(&lower_needle)
                                || title.to_lowercase().contains(&lower_needle)
                                || note.to_lowercase().contains(&lower_needle)
                                || tx.status.to_string().contains(&lower_needle)
                                || tx.request.to_lowercase().contains(&lower_needle)
                                || tx.response.to_lowercase().contains(&lower_needle)
                        };
                        if negative_search {
                            if matched {
                                return None;
                            }
                        } else if !matched {
                            return None;
                        }
                    }
                }
                Some(RowSummary {
                    index,
                    host_url,
                    method: tx.method.clone(),
                    target: tx.target.clone(),
                    path_query,
                    has_params,
                    status: tx.status,
                    bytes: tx.bytes,
                    truncated: tx.truncated,
                    mime,
                    ext,
                    title,
                    secure: tx.secure,
                    note,
                    highlight,
                    cookies: tx
                        .response
                        .split("\r\n\r\n")
                        .next()
                        .unwrap_or("")
                        .lines()
                        .filter_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("set-cookie").then(|| {
                                value.trim().split(';').next().unwrap_or("").to_string()
                            })
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                })
            })
            .collect();

        if let Some(col) = app.panels.proxy_panel.sort_column {
            let asc = app.panels.proxy_panel.sort_ascending;
            built.sort_by(|a, b| {
                let ord = match col {
                    0 => a.index.cmp(&b.index),
                    1 => a.host_url.cmp(&b.host_url),
                    2 => a.method.cmp(&b.method),
                    3 => a.path_query.cmp(&b.path_query),
                    4 => a.has_params.cmp(&b.has_params),
                    6 => a.status.cmp(&b.status),
                    7 => a.bytes.cmp(&b.bytes),
                    8 => a.mime.cmp(b.mime),
                    9 => a.ext.cmp(&b.ext),
                    10 => a.title.cmp(&b.title),
                    11 => a.note.cmp(&b.note),
                    12 => a.secure.cmp(&b.secure),
                    14 => a.cookies.cmp(&b.cookies),
                    _ => a.index.cmp(&b.index),
                };
                if asc {
                    ord
                } else {
                    ord.reverse()
                }
            });
        }
        let arc = std::sync::Arc::new(built);
        HISTORY_ROWS_CACHE.with(|c| {
            *c.borrow_mut() = Some((cache_key, arc.clone()));
        });
        arc
    };

    // One horizontal viewport keeps header and body aligned; only the body scrolls
    // vertically. Column widths never depend on URL/title/note length.
    let table_h = if app.panels.proxy_panel.selected.is_some() {
        app.panels
            .proxy_panel
            .table_height
            .min((ui.available_height() * 0.45).max(120.0))
    } else {
        (ui.available_height() - 48.0).max(app.panels.proxy_panel.table_height)
    };
    let columns = [
        "#",
        "Host",
        "Method",
        "URL",
        "Params",
        "Edited",
        "Status code",
        "Length",
        "MIME type",
        "Extension",
        "Title",
        "Notes",
        "TLS",
        "IP",
        "Cookies",
        "Time",
        "Listener port",
        "Start response timer",
        "End response timer",
    ];
    eframe::egui::ScrollArea::horizontal()
        .id_salt("proxy-history-horizontal")
        .max_height(table_h + 40.0)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            use eframe::egui::{self, Rect, Sense, Stroke, Vec2};
            let widths = app.panels.proxy_panel.history_column_widths;
            let width = widths.iter().sum::<f32>().max(ui.available_width());
            ui.set_min_width(width);
            ui.spacing_mut().item_spacing = Vec2::ZERO;
            let border = Stroke::new(1.0, theme.color("border.1"));
            let (header, _) = ui.allocate_exact_size(Vec2::new(width, 25.0), Sense::hover());
            ui.painter()
                .rect_filled(header, 0.0, theme.color("background.3"));
            ui.painter().rect_filled(
                Rect::from_min_size(header.left_bottom(), Vec2::new(width, table_h)),
                0.0,
                theme.color("background.1"),
            );
            let mut x = header.left();
            for (col, name) in columns.iter().enumerate() {
                let rect = Rect::from_min_size(
                    egui::pos2(x, header.top()),
                    Vec2::new(widths[col], header.height()),
                );
                let active = app.panels.proxy_panel.sort_column == Some(col);
                let label = if active {
                    format!(
                        "{name} {}",
                        if app.panels.proxy_panel.sort_ascending {
                            "▲"
                        } else {
                            "▼"
                        }
                    )
                } else {
                    (*name).into()
                };
                let response =
                    history_cell(ui, col + 100, rect, &label, theme.color("ui.text.body"), false);
                if response.clicked() && !matches!(col, 5 | 13 | 15..=18) {
                    let p = &mut app.panels.proxy_panel;
                    if active && !p.sort_ascending {
                        p.sort_column = None;
                        p.sort_ascending = true;
                    } else if active {
                        p.sort_ascending = false;
                    } else {
                        p.sort_column = Some(col);
                        p.sort_ascending = true;
                    }
                }
                ui.painter().vline(rect.right(), header.y_range(), border);
                let resize = ui
                    .interact(
                        Rect::from_center_size(
                            egui::pos2(rect.right(), header.center().y),
                            Vec2::new(6.0, header.height()),
                        ),
                        ui.id().with(("history-column-resize", col)),
                        Sense::drag(),
                    )
                    .on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
                let drag_id = resize.id.with("initial-width");
                if resize.drag_started() {
                    ui.data_mut(|data| data.insert_temp(drag_id, widths[col]));
                }
                if let Some(delta) = resize.total_drag_delta() {
                    let initial = ui
                        .data(|data| data.get_temp::<f32>(drag_id))
                        .unwrap_or(widths[col]);
                    app.panels.proxy_panel.history_column_widths[col] =
                        (initial + delta.x).clamp(30.0, 1000.0);
                }
                if resize.double_clicked() {
                    app.panels.proxy_panel.history_column_widths[col] =
                        ProxyPanel::default().history_column_widths[col];
                }
                x = rect.right();
            }
            ui.painter()
                .hline(header.x_range(), header.bottom(), border);
            egui::ScrollArea::vertical()
                .id_salt("proxy-history-scroll")
                .max_height(table_h)
                .auto_shrink([false, false])
                .show_rows(ui, 22.0, visible.len(), |ui, range| {
                    for row in &visible[range] {
                        let index = row.index;
                        ui.push_id(("history-row", index), |ui| {
                            let selected = app.panels.proxy_panel.selected == Some(index);
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::new(width, 22.0), Sense::hover());
                            let fill = if selected {
                                theme.color("background.5")
                            } else if let Some(code) = row.highlight {
                                highlight_colour(&theme, Some(code), false).gamma_multiply(0.22)
                            } else {
                                theme.color("background.1")
                            };
                            ui.painter().rect_filled(rect, 0.0, fill);
                            // Transaction currently has no edit/IP/timing/listener metadata.
                            // Leave those cells empty rather than inventing captured values.
                            let values = [
                                format!("{}", index + 1),
                                row.host_url.clone(),
                                row.method.clone(),
                                row.path_query.clone(),
                                if row.has_params { "✓" } else { "" }.into(),
                                String::new(),
                                if row.status == 0 {
                                    String::new()
                                } else {
                                    row.status.to_string()
                                },
                                format!("{}{}", row.bytes, if row.truncated { "+" } else { "" }),
                                row.mime.into(),
                                row.ext.clone(),
                                row.title.clone(),
                                row.note.clone(),
                                if row.secure { "✓" } else { "" }.into(),
                                String::new(),
                                row.cookies.clone(),
                                String::new(),
                                String::new(),
                                String::new(),
                                String::new(),
                            ];
                            let text_color = theme.color("ui.text.body");
                            let mut x = rect.left();
                            for (col, value) in values.iter().enumerate() {
                                let cell = Rect::from_min_size(
                                    egui::pos2(x, rect.top()),
                                    Vec2::new(widths[col], rect.height()),
                                );
                                let response =
                                    history_cell(ui, col, cell, value, text_color, selected);
                                if response.clicked() || response.secondary_clicked() {
                                    app.panels.proxy_panel.selected = Some(index);
                                }
                                if response.double_clicked() {
                                    app.panels.proxy_panel.detached_row = Some(index);
                                }
                                app.context_menu(&response, index);
                                if col == 3 {
                                    response.on_hover_text(&row.target);
                                } else if matches!(col, 5 | 13 | 15..=18) {
                                    response.on_hover_text(
                                        "This metadata was not recorded for this request",
                                    );
                                }
                                ui.painter().vline(
                                    cell.right(),
                                    rect.y_range(),
                                    Stroke::new(1.0, border.color.gamma_multiply(0.5)),
                                );
                                x = cell.right();
                            }
                        });
                    }
                });
        });

    horizontal_resize_handle(
        ui,
        &theme,
        "proxy-history-table-resize",
        &mut app.panels.proxy_panel.table_height,
        120.0,
        560.0,
        240.0,
    );

    if let Some(index) = app.panels.proxy_panel.selected {
        if let Some(tx) = app.log.get(index).cloned() {
            ui.horizontal_wrapped(|ui| {
                ui.label(eframe::egui::RichText::new(&tx.target).strong());
                ui.radio_value(&mut app.panels.proxy_panel.hex_view, false, "Pretty");
                ui.radio_value(&mut app.panels.proxy_panel.hex_view, true, "Hex");
                ui.separator();
                if ui.button("Open in window").clicked() {
                    app.panels.proxy_panel.detached_row = Some(index);
                }
                if ui.button("Scan").clicked() {
                    app.scan_url(&tx.target, true);
                }
                if ui.button("Passive scan").clicked() {
                    app.passive_scan_transaction(&tx.target, &tx.response);
                }
                if ui.button("To Repeater").clicked() {
                    app.panels.repeater.open(&tx.target, &tx.request);
                    app.tool = crate::ui::app::REPEATER;
                    app.status = "Request copied to Repeater".into();
                }
                if ui.button("To Intruder").clicked() {
                    app.send_to_intruder(&tx.target, &tx.request);
                }
                if ui.button("To Organizer").clicked() {
                    let next = app.organizer.len() + 1;
                    super::organizer::retain(
                        app,
                        super::organizer::OrganizerItem {
                            host: tx.host.clone(),
                            name: format!("item-{next}"),
                            request: tx.request.clone(),
                            response: tx.response.clone(),
                            notes: String::new(),
                        },
                    );
                    app.status = "Saved to Organizer".into();
                }
                if ui.button("Copy as curl").clicked() {
                    let curl = crate::ui::app::Transaction::to_curl_command(&tx.target, &tx.request);
                    ui.ctx().copy_text(curl);
                    app.status = "Copied as curl command".into();
                }
                if ui.button("Close").clicked() {
                    app.panels.proxy_panel.selected = None;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Notes:");
                let mut note = app
                    .panels
                    .proxy_panel
                    .notes
                    .get(&index)
                    .cloned()
                    .unwrap_or_default();
                if ui
                    .add(
                        eframe::egui::TextEdit::singleline(&mut note)
                            .hint_text("Add a note for this request…")
                            .desired_width(340.0),
                    )
                    .changed()
                {
                    if note.trim().is_empty() {
                        app.panels.proxy_panel.notes.remove(&index);
                    } else {
                        app.panels.proxy_panel.notes.insert(index, note);
                    }
                }
            });
            let (request, response) = (tx.request, tx.response);
            if app.panels.proxy_panel.hex_view {
                app.panels.proxy_panel.history_req_fmt_mode = 2;
                app.panels.proxy_panel.history_resp_fmt_mode = 2;
            }
            let detail_h = (ui.available_height() - 18.0)
                .max(app.panels.proxy_panel.detail_height.min(180.0));
            let mut ratio = app.panels.proxy_panel.split_ratio;
            vertical_split(
                ui,
                &theme,
                "proxy-history-req-resp-split",
                &mut ratio,
                detail_h,
                |side, ui| {
                    if side == 0 {
                        super::burp_message_formatter_bar(
                            ui,
                            &theme,
                            "proxy-hist-req-fmt",
                            "Request",
                            &mut app.panels.proxy_panel.history_req_fmt_mode,
                            false,
                            &mut app.panels.proxy_panel.history_req_wrap,
                            &mut app.panels.proxy_panel.history_req_np,
                        );
                        app.panels.proxy_panel.hex_view =
                            app.panels.proxy_panel.history_req_fmt_mode == 2;
                        let r = super::burp_numbered_message_view_wrapped(
                            ui,
                            &theme,
                            "proxy-hist-req-view",
                            detail_h - 48.0,
                            &request,
                            app.panels.proxy_panel.history_req_fmt_mode,
                            app.panels.proxy_panel.history_req_np,
                            app.panels.proxy_panel.history_req_wrap,
                        );
                        super::attach_message_context_menu(
                            app,
                            &r,
                            &tx.target,
                            &request,
                            &response,
                        );
                    } else {
                        super::burp_message_formatter_bar(
                            ui,
                            &theme,
                            "proxy-hist-resp-fmt",
                            "Response",
                            &mut app.panels.proxy_panel.history_resp_fmt_mode,
                            true,
                            &mut app.panels.proxy_panel.history_resp_wrap,
                            &mut app.panels.proxy_panel.history_resp_np,
                        );
                        let r = super::burp_numbered_message_view_wrapped(
                            ui,
                            &theme,
                            "proxy-hist-resp-view",
                            detail_h - 48.0,
                            &response,
                            app.panels.proxy_panel.history_resp_fmt_mode,
                            app.panels.proxy_panel.history_resp_np,
                            app.panels.proxy_panel.history_resp_wrap,
                        );
                        super::attach_message_context_menu(
                            app,
                            &r,
                            &tx.target,
                            &request,
                            &response,
                        );
                    }
                },
            );
            app.panels.proxy_panel.split_ratio = ratio;
            horizontal_resize_handle(
                ui,
                &theme,
                "proxy-history-detail-resize",
                &mut app.panels.proxy_panel.detail_height,
                120.0,
                640.0,
                280.0,
            );
            super::draw_inspector(ui, &theme, "proxy-history-insp", &request, &response);
        }
    }

    if let Some(detached_idx) = app.panels.proxy_panel.detached_row {
        if let Some(tx) = app.log.get(detached_idx).cloned() {
            let mut open = true;
            let mut ratio = app.panels.proxy_panel.detached_split_ratio;
            let message_bg = theme.color("ui.editor.message.background");
            eframe::egui::Window::new(format!("Request #{} — {}", detached_idx + 1, tx.target))
                .open(&mut open)
                .resizable(true)
                .default_size([860.0, 520.0])
                .show(ui.ctx(), |ui| {
                    let h = (ui.available_height() - 32.0).max(160.0);
                    vertical_split(
                        ui,
                        &theme,
                        "proxy-detached-split",
                        &mut ratio,
                        h,
                        |side, ui| {
                            if side == 0 {
                                ui.label(eframe::egui::RichText::new("Request").strong());
                                crate::ui::highlight::show_message_in(
                                    ui,
                                    "proxy-detached-req",
                                    h - 24.0,
                                    &tx.request,
                                    &theme,
                                    message_bg,
                                );
                            } else {
                                ui.label(eframe::egui::RichText::new("Response").strong());
                                crate::ui::highlight::show_message_in(
                                    ui,
                                    "proxy-detached-resp",
                                    h - 24.0,
                                    &tx.response,
                                    &theme,
                                    message_bg,
                                );
                            }
                        },
                    );
                });
            app.panels.proxy_panel.detached_split_ratio = ratio;
            if !open {
                app.panels.proxy_panel.detached_row = None;
            }
        }
    }

    cookie_jar(app, ui);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{HeldInfo, HeldKind};

    /// The text the frame drew, so a test can look for a label or a message.
    fn text_of(output: &eframe::egui::FullOutput) -> Vec<String> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                eframe::egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect()
    }

    /// The intercept view has to show the parked request in an editor, with the buttons that let
    /// it through. It is checked headless, because the window cannot be driven from a test.
    #[test]
    fn the_intercept_view_shows_the_parked_request() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.held.push(HeldInfo {
            id: 7,
            kind: HeldKind::Request,
            method: "GET".into(),
            target: "/held".into(),
            raw: "GET /held HTTP/1.1\r\nHost: example.test\r\n\r\n".into(),
        });

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                intercept(&mut app, ui);
            });
        });
        let texts = text_of(&output);

        let all = texts.join("\n");
        assert!(
            all.contains("GET /held HTTP/1.1"),
            "the parked request should be in the editor: {all}"
        );
        for button in ["Forward", "Drop", "To Repeater", "Reset"] {
            assert!(
                all.contains(button),
                "the {button} button should be there: {all}"
            );
        }
    }

    /// A parked response is shown with its own wording.
    #[test]
    fn the_intercept_view_shows_a_parked_response() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.held.push(HeldInfo {
            id: 8,
            kind: HeldKind::Response,
            method: "200".into(),
            target: String::new(),
            raw: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".into(),
        });

        let output = ctx.run(eframe::egui::RawInput::default(), |ctx| {
            eframe::egui::CentralPanel::default().show(ctx, |ui| {
                intercept(&mut app, ui);
            });
        });
        let texts = text_of(&output);

        let all = texts.join("\n");
        assert!(
            all.contains("HTTP/1.1 200 OK"),
            "the parked response should be in the editor: {all}"
        );
        assert!(
            all.contains("Cancel"),
            "a parked response is cancelled rather than dropped: {all}"
        );
    }
}
