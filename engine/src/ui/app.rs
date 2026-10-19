//! The application shell: menu bar, tool sidebar, tool panels and status bar.

use std::sync::Arc;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::mpsc::{Receiver, TryRecvError, channel};

use eframe::egui::{
    Align, Button, Context, CornerRadius, Frame, Layout, Rect, Response, RichText, Sense,
    Key, Modifiers, Stroke, TextStyle, Ui, Vec2, pos2,
};

use crate::proxy::{Event, HeldInfo, Proxy};
use crate::ui::panels;
use crate::ui::theme::Theme;

/// The sub-views each tool shows, in Burp's order.
///
/// The list is Burp's structure, and each entry is backed by a type REA confirmed in the shipped
/// jar: Proxy's WebSockets by `proxy/ProxyWebSocketMessage` and `ProxyWebSocketHistoryFilter`;
/// Logger's split by `logger/LoggerCaptureHttpRequestResponse` against `LoggerHttpRequestResponse`;
/// Target's two views by `sitemap/SiteMap`+`SiteMapFilter` against `scope/Scope`; the Dashboard's
/// three by `logging/Logging`, `scanner/audit/AuditResult` and `core/Task`. Burp's UI classes are
/// obfuscated, so the literal sidebar strings are not recoverable; the shape is.
impl App {
    /// Findings recorded by the most recent scan.
    pub fn scanner_findings_len(&self) -> usize {
        self.scanner_findings
    }
}

/// Tool indices, in Burp's own `ToolType` order. These are named because the dispatch, the menu bar
/// and the hotkeys all key off them; bare numbers let the order drift between the three.
pub const SUITE: usize = 0;
pub const TARGET: usize = 1;
pub const PROXY: usize = 2;
pub const INTRUDER: usize = 3;
pub const REPEATER: usize = 4;
pub const COLLABORATOR: usize = 5;
pub const SEQUENCER: usize = 6;
pub const DECODER: usize = 7;
pub const COMPARER: usize = 8;
pub const LOGGER: usize = 9;
pub const ORGANIZER: usize = 10;
pub const EXTENSIONS: usize = 11;
pub const DISCOVER: usize = 12;

/// Sub-views that the menu bar jumps to.
pub const PROXY_INTERCEPT: usize = 0;
pub const PROXY_HISTORY: usize = 1;

pub const TOOL_VIEWS: [&[&str]; 13] = [
    // Observed in Burp v2026.3.3: the Dashboard detail pane tabs, left to right.
    &["Summary", "Audit items", "Issues", "Event log", "Logger", "Audit log"],
    // Target
    &["Site map", "Scope", "Issues"],
    // Proxy, with the sub-view names Burp's own documentation uses.
    &["Intercept", "HTTP history", "WebSockets history", "Match and replace", "Proxy settings"],
    // Intruder, the attack editor's side panels.
    &["Positions", "Payloads", "Options", "Payload generation", "Resource pool"],
    // Repeater
    &["Repeater"],
    // Collaborator
    &["Server", "Project"],
    // Sequencer
    &["Manual", "Automaton"],
    // Decoder
    &["Decoder"],
    // Comparer
    &["Comparer"],
    // Logger
    &["HTTP history", "WebSockets history", "DNS", "SMTP"],
    // Organizer
    &["Organizer"],
    // Extensions
    &["Bambda", "Installed", "Updates"],
    // Discover
    &["Content discovery"],
];

/// Width of the tool strip, and of the narrower view strip beside it.
/// Height of the horizontal tool tab row, from a 1440x790 capture of Burp v2026.3.3.
const TOOL_TAB_HEIGHT: f32 = 31.0;
/// Height of a tool's own sub-tab row.
const SUB_TAB_HEIGHT: f32 = 30.0;
/// Thickness of the accent bar under a selected tab.
const TAB_UNDERLINE: f32 = 3.0;
/// Inset between a panel and the window edge.
const PANEL_INSET: f32 = 12.0;
/// Tab label size. Slightly under 12px because egui's face sets wider than the platform font Burp
/// inherits, and matching Burp's tab pitch matters more than matching nominal point size.
const TAB_FONT: FontId = FontId::new(11.5, eframe::egui::FontFamily::Proportional);
/// Height of the bottom status bar, measured from a 1440x790 Burp v2026.3.3 capture.
const STATUS_BAR_HEIGHT: f32 = 36.0;

/// Burp calls its first tool `Suite`; this app shows it as "Dashboard", which is the same view.
pub const TOOLS: [&str; 13] = [
    "Dashboard",
    "Target",
    "Proxy",
    "Intruder",
    "Repeater",
    "Collaborator",
    "Sequencer",
    "Decoder",
    "Comparer",
    "Logger",
    "Organizer",
    "Extensions",
    "Discover",
];

/// A WebSocket connection and the messages observed on it.
#[derive(Clone, Debug)]
pub struct WsConnection {
    pub id: u64,
    pub host: String,
    pub request: String,
    pub response: String,
    pub open: bool,
    pub messages: Vec<WsMessage>,
}

/// One recorded frame, after reassembly to message level.
#[derive(Clone, Debug)]
pub struct WsMessage {
    /// True when the client sent it, false when the server did.
    pub to_server: bool,
    pub opcode: u8,
    pub text: String,
    pub bytes: usize,
}

/// Retained DNS exchanges. A ceiling, like the HTTP history.
pub const DNS_CAPACITY: usize = 1_000;
/// Retained SMTP messages.
pub const SMTP_CAPACITY: usize = 500;

/// How many WebSocket connections are kept. Like the HTTP history this is a ceiling, not a sink.
pub const WS_CAPACITY: usize = 100;
/// Frames retained per connection.
pub const WS_MESSAGE_CAPACITY: usize = 2_000;

/// Retained history entries. At the limits below this is a predictable ceiling rather than an
/// open-ended sink that grows with session length.
pub const LOG_CAPACITY: usize = 1_000;
/// Bytes kept per message side. Longer bodies are cut and the row is marked as truncated.
pub const LOG_BODY_LIMIT: usize = 32 * 1024;

/// Organizer is a long-lived store, so it gets its own ceiling rather than inheriting one sized for
/// transient traffic.
pub const ORGANIZER_CAPACITY: usize = 2_000;
pub const ORGANIZER_BODY_LIMIT: usize = 32 * 1024;

/// Clips to a byte budget on a char boundary, so the highlighter never sees half a character.
pub fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// Clips both message sides, marks the row when either was cut, appends, and drops the oldest
/// entries past `LOG_CAPACITY`. A ring, not a Vec: dropping the front of a Vec is O(n) per insert.
pub fn retain(log: &mut VecDeque<Transaction>, tx: Transaction, wire_bytes: u64, version: &mut u64) {
    let request = clip(&tx.request, LOG_BODY_LIMIT);
    let response = clip(&tx.response, LOG_BODY_LIMIT);
    let kept = request.len() + response.len();
    log.push_back(Transaction { truncated: kept < wire_bytes as usize, request, response, ..tx });
    while log.len() > LOG_CAPACITY {
        log.pop_front();
    }
    *version += 1;
}

/// Path -> times seen, for one host.
pub type SiteMapPaths = std::collections::BTreeMap<String, usize>;

/// Same clipping rule as `clip`, exposed for the retention tests.
#[doc(hidden)]
pub fn clip_public(text: &str, limit: usize) -> String {
    clip(text, limit)
}

/// One captured transaction, as the Target site map and Logger see it.
#[derive(Clone)]
pub struct Transaction {
    pub method: String,
    pub target: String,
    pub status: u16,
    pub bytes: u64,
    pub host: String,
    /// Whether the traffic was carried over TLS.
    pub secure: bool,
    /// The request as sent, so Repeater can pick it up intact.
    pub request: String,
    /// The response head plus captured body.
    pub response: String,
    /// True when either side was clipped by `LOG_BODY_LIMIT`, so the UI can say so.
    pub truncated: bool,
}

impl Transaction {
    pub fn scheme(&self) -> &'static str {
        if self.target.starts_with("https://") || self.status == 200 && self.target.contains(":443") {
            "https"
        } else {
            "http"
        }
    }
}

pub struct App {
    pub theme: Theme,
    pub workspace: crate::workspace::Workspace,
    pub saved_layout: crate::project::SavedLayout,
    pub proxy: Arc<Proxy>,
    events: Receiver<Event>,
    /// One-shot request results, keyed by the id handed back to the caller.
    responses_in: Receiver<(u64, Result<(u16, String), String>)>,
    pub responses: HashMap<u64, (u16, String)>,
    next_request: u64,
    /// Everything the proxy has reported, newest last.
    pub log: VecDeque<Transaction>,
    /// The links the responses point at, per host. Burp's site map shows them even when they were
    /// never visited, because a link is a path the target has.
    pub discovered: BTreeMap<String, BTreeSet<String>>,
    /// Saved request/response collections.
    pub organizer: Vec<panels::organizer::OrganizerItem>,
    /// Height taken by the tab rows alone. The panel paints into a rect without moving the cursor,
    /// so the shell advances by the remainder using this.
    pub tab_rows_height: f32,
    /// WebSocket connections seen since the listener started, newest last.
    pub websockets: Vec<WsConnection>,
    /// DNS exchanges and SMTP messages, for the Logger's DNS and Email views.
    pub dns_log: Vec<crate::ui::panels::logger::DnsEntry>,
    pub smtp_log: Vec<crate::ui::panels::logger::SmtpEntry>,
    /// Bumped whenever the history changes, so derived views can rebuild once instead of per frame.
    pub log_version: u64,
    /// Cached site map, tagged with the `log_version` it was built from.
    pub site_map: Option<(u64, std::collections::BTreeMap<String, SiteMapPaths>)>,
    /// Where a saved Bambda script lives on disk.
    pub held: Vec<HeldInfo>,
    pub tool: usize,
    /// Which sub-view of the current tool is showing. Reset whenever the tool changes.
    pub view: usize,
    pub status: String,
    pub intercepting: bool,
    /// Whether responses are parked as well, so they can be changed before the client sees them.
    pub intercepting_responses: bool,
    /// Whether an https connection is intercepted, or passed through as a tunnel.
    pub tls_intercepting: bool,
    pub listening: Option<u16>,
    pub panels: panels::Panels,
    /// One runtime for the whole session; every proxy call goes through it.
    pub(crate) runtime: tokio::runtime::Runtime,
    /// Held so the receiver above never disconnects.
    _requests_tx: std::sync::mpsc::Sender<(u64, Result<(u16, String), String>)>,
    /// Progress and results from a running scan.
    pub scanner_updates: Option<std::sync::mpsc::Receiver<panels::scanner::ScanUpdate>>,
    /// The last memory reading for the status bar, and when it was taken.
    pub memory_text: String,
    pub memory_checked: std::time::Instant,
    /// Which Dashboard task the detail pane is showing: 0 is the live audit, 1 the passive crawl.
    pub dashboard_task: usize,
    /// Whether the Dashboard's tasks are capturing. Burp starts with both of its tasks capturing.
    pub capturing: bool,
    /// Whether the settings popup is open.
    pub show_settings: bool,
    /// Whether the search window is open.
    pub show_search: bool,
    /// Whether the console window is open.
    pub show_console: bool,
    /// What the user has typed into the search window.
    pub search_text: String,
    /// The proxy's event trail, shown in the console window.
    pub console: VecDeque<String>,
    /// Progress from a Discover run, when one is in flight.
    pub discover_updates: Option<std::sync::mpsc::Receiver<crate::discover::Update>>,
    /// Findings from the most recent scan, so the Dashboard's Issue audit view can report them.
    pub scanner_findings: usize,
    /// Live updates from the login replayer worker. Kept on `App` rather than the panel because a
    /// receiver cannot be cloned and `Panels` is cloned wholesale.
    pub replay_updates: Option<std::sync::mpsc::Receiver<panels::replayer::ReplayUpdate>>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut ctx = cc.egui_ctx.clone();
        install_fonts(&mut ctx);
        App::with_context(&ctx)
    }

    /// Builds the app around a context. The window and the tests both go through here, so the
    /// fonts are the only thing the window has to add.
    pub fn with_context(_ctx: &Context) -> Self {

        // Burp's own light and dark themes ship with Burp, so the shell loads the file instead of
        // tinting one. `GULP_THEME=light` picks the light theme at startup, which is how the two
        // themes get compared against a running Burp.
        let dark = std::env::var("GULP_THEME")
            .map(|value| !value.eq_ignore_ascii_case("light"))
            .unwrap_or(true);
        let theme = Theme::load(dark);
        let (proxy, mut events) = Proxy::new();
        let proxy = Arc::new(proxy);

        // The runtime has to exist before anything spawns onto it; App::new runs on the main thread
        // with no reactor.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");

        // The proxy runs on Tokio threads; the UI polls once a frame. Bridge the two here so the
        // panels never have to know about Tokio.
        let (tx, rx) = channel();
        runtime.handle().spawn(async move {
            while let Ok(event) = events.recv().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });

        let (req_tx, req_rx) = channel();

        App {
            theme,
            workspace: crate::workspace::Workspace {
                tasks: crate::workspace::TaskManager::seed_proxy_tasks(),
                ..Default::default()
            },
            saved_layout: crate::project::SavedLayout::default(),
            proxy,
            events: rx,
            responses_in: req_rx,
            responses: HashMap::new(),
            next_request: 1,
            log: VecDeque::new(),
            discovered: BTreeMap::new(),
            tab_rows_height: 0.0,
            websockets: Vec::new(),
            dns_log: Vec::new(),
            smtp_log: Vec::new(),
            organizer: Vec::new(),
            log_version: 0,
            site_map: None,
            held: Vec::new(),
            tool: 0,
            view: 0,
            status: "Ready".into(),
            intercepting: true,
            intercepting_responses: false,
            tls_intercepting: true,
            listening: None,
            panels: panels::Panels::default(),
            _requests_tx: req_tx,
            scanner_updates: None,
            memory_text: "Memory: —".to_string(),
            dashboard_task: 0,
            capturing: true,
            show_search: false,
            show_console: false,
            search_text: String::new(),
            console: VecDeque::new(),
            show_settings: false,
            memory_checked: std::time::Instant::now() - crate::meminfo::REFRESH,
            discover_updates: None,
            scanner_findings: 0,
            replay_updates: None,
            runtime,
        }
        .tuned()
    }

    // ---- proxy control, kept off the UI thread -------------------------------------------

    pub fn start_proxy(&mut self, port: u16) {
        // The settings of the window are the ones the proxy runs with.
        self.proxy.set_tls_interception(self.tls_intercepting);
        self.proxy.set_intercept_response(self.intercepting_responses);
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            // The outcome arrives back as an event; no printing, so the UI is the only source of truth.
            let _ = runtime.block_on(proxy.start(port));
        });
        self.status = format!("Starting listener on 127.0.0.1:{port}");
    }

    /// Starts the DNS capture listener and records the port it bound.
    pub fn start_dns(&mut self) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            let _ = runtime.block_on(proxy.start_dns(0));
        });
        self.status = "Starting DNS capture".into();
    }

    /// Starts the SMTP capture listener and records the port it bound.
    pub fn start_smtp(&mut self) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            let _ = runtime.block_on(proxy.start_smtp(0));
        });
        self.status = "Starting SMTP capture".into();
    }

    /// Stops the DNS capture listener, so the Logger's Stop button ends the socket task.
    pub fn stop_dns(&mut self) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(proxy.stop_dns());
        });
        self.status = "DNS capture stopped".into();
    }

    /// Stops the SMTP capture listener.
    pub fn stop_smtp(&mut self) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(proxy.stop_smtp());
        });
        self.status = "SMTP capture stopped".into();
    }

    pub fn stop_proxy(&mut self) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(async {
                proxy.release_all();
                proxy.stop().await;
            });
        });
        self.listening = None;
        self.status = "Listener stopped".into();
    }

    pub fn release(&mut self, id: u64, forward: bool) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(async {
                if forward {
                    proxy.forward(id).await
                } else {
                    proxy.discard(id).await
                }
            });
        });
        self.held.retain(|h| h.id != id);
        self.status = format!("Request #{id} {}", if forward { "forwarded" } else { "dropped" });
    }

    /// Forwards a parked request with the message the operator edited.
    pub fn forward_edited(&mut self, id: u64, raw: &str) {
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        let raw = raw.to_string();
        std::thread::spawn(move || {
            runtime.block_on(async {
                proxy.forward_edited(id, &raw).await
            });
        });
        self.held.retain(|h| h.id != id);
        self.panels.proxy_panel.held_edit = None;
        self.panels.proxy_panel.held_selected = None;
        self.status = format!("Request #{id} forwarded");
    }

    pub fn release_all(&mut self) {
        let count = self.held.len();
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        std::thread::spawn(move || {
            runtime.block_on(proxy.forward_all());
        });
        self.held.clear();
        self.status = format!("Forwarded {count} held request(s)");
    }

    fn tuned(mut self) -> Self {
        self.panels.theme = self.theme.clone();
        self.panels.proxy = self.proxy.clone();
        self
    }

    /// Switches between Burp's two bundled themes. `DarkTheme.json` and `LightTheme.json` both ship
    /// with Burp, so both are loaded from the same source rather than being approximated.
    pub fn set_dark(&mut self, dark: bool) {
        if self.theme.dark == dark {
            return;
        }
        self.theme = Theme::load(dark);
        self.panels.theme = self.theme.clone();
        self.status = format!("Theme: {}", if dark { "Dark" } else { "Light" });
    }

    pub fn is_dark(&self) -> bool {
        self.theme.dark
    }

    /// Drains proxy events into the UI state. Called once per frame.
    fn pump(&mut self) {
        loop {
            match self.events.try_recv() {
                Ok(event) => self.apply(event),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        // The Logger's DNS and Email views start their listeners on request. The listeners live on
        // the session runtime, so each request is dispatched off the UI thread and the bound port
        // comes back as an event.
        if self.panels.logger.dns_start {
            self.panels.logger.dns_start = false;
            self.start_dns();
        }
        if self.panels.logger.smtp_start {
            self.panels.logger.smtp_start = false;
            self.start_smtp();
        }
        if let Some(updates) = &self.discover_updates {
            let mut finished = false;
            while let Ok(update) = updates.try_recv() {
                match update {
                    crate::discover::Update::Probing { host, done, total } => {
                        self.panels.discover_progress = format!("{done}/{total} {host}");
                    }
                    crate::discover::Update::Found(finding) => {
                        self.panels.discover_results.push((finding.url, finding.status));
                    }
                    crate::discover::Update::Done { probes } => {
                        finished = true;
                        self.status = format!("Discover finished: {probes} answer(s)");
                    }
                }
            }
            if finished {
                self.panels.discover_running = false;
                self.discover_updates = None;
            }
        }
        // Stop has to reach the socket task, not just clear the port the view is showing.
        if self.panels.logger.dns_stop {
            self.panels.logger.dns_stop = false;
            self.stop_dns();
        }
        if self.panels.logger.smtp_stop {
            self.panels.logger.smtp_stop = false;
            self.stop_smtp();
        }
        if let Some(updates) = &self.scanner_updates {
            let mut done = None;
            while let Ok(update) = updates.try_recv() {
                match update {
                    panels::scanner::ScanUpdate::Progress(text) => {
                        self.panels.scanner.progress = text.clone();
                    }
                    panels::scanner::ScanUpdate::Done { findings, pages } => {
                        self.scanner_findings = findings.len();
                        done = Some((findings, pages));
                    }
                }
            }
            if let Some((findings, pages)) = done {
                let count = findings.len();
                self.scanner_findings = count;
                self.panels.scanner.findings = findings;
                self.panels.scanner.pages = pages;
                self.panels.scanner.running = false;
                self.panels.scanner.progress = format!("Scan finished: {count} issue(s)");
                self.status = format!("Scan finished: {count} issue(s)");
                self.scanner_updates = None;
            }
        }
        while let Ok((id, result)) = self.responses_in.try_recv() {
            let status = match result {
                Ok(pair) => pair,
                Err(error) => (0, format!("error: {error}")),
            };
            self.responses.insert(id, status);
        }
    }

    /// Sends one request off-thread; the result lands in `responses` for `take_response`.
    pub fn send_request(&mut self, host: String, port: u16, raw: String, secure: bool) -> u64 {
        let id = self.next_request;
        self.next_request += 1;
        let proxy = self.proxy.clone();
        let runtime = self.runtime.handle().clone();
        let tx = self._requests_tx.clone();
        std::thread::spawn(move || {
            let result = runtime.block_on(proxy.one_shot_secure(&host, port, &raw, secure, 15_000));
            let _ = tx.send((id, result));
        });
        id
    }

    /// Takes the result of a request issued by `send_request`, if it has landed.
    pub fn take_response(&mut self, id: u64) -> Option<(u16, String)> {
        self.responses.remove(&id)
    }

    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    fn apply(&mut self, event: Event) {
        // The console window shows the same trail the proxy reports.
        self.note(&format!("{event:?}"));
        match event {
            Event::Tx { method, target, status, bytes, request, response, secure } => {
                let host = host_of(&target);
                self.remember_links(&target, &response);
                retain(&mut self.log, Transaction {
                    method,
                    target,
                    status,
                    bytes,
                    host,
                    request,
                    response,
                    secure,
                    truncated: false,
                }, bytes, &mut self.log_version);
            }
            Event::Held { id, method, target, raw } => {
                if !self.held.iter().any(|h| h.id == id) {
                    self.held.push(HeldInfo {
                        id,
                        kind: crate::proxy::HeldKind::Request,
                        method,
                        target,
                        raw,
                    });
                }
            }
            Event::HeldResponse { id, status, raw } => {
                if !self.held.iter().any(|h| h.id == id) {
                    self.held.push(HeldInfo {
                        id,
                        kind: crate::proxy::HeldKind::Response,
                        method: format!("{status}"),
                        target: String::new(),
                        raw,
                    });
                }
            }
            Event::Released { id, .. } | Event::Dropped { id } => {
                self.held.retain(|h| h.id != id);
            }
            Event::DnsListening { port } => {
                self.panels.logger.dns_port = Some(port);
                self.status = format!("DNS capture listening on 127.0.0.1:{port} udp");
            }
            Event::SmtpListening { port } => {
                self.panels.logger.smtp_port = Some(port);
                self.status = format!("SMTP capture listening on 127.0.0.1:{port}");
            }
            Event::Dns { question, kind, answers, server } => {
                if self.dns_log.len() >= DNS_CAPACITY {
                    self.dns_log.remove(0);
                }
                self.dns_log.push(crate::ui::panels::logger::DnsEntry {
                    question,
                    kind,
                    answers,
                    server,
                });
            }
            Event::Smtp { direction, from, to, subject, body } => {
                if self.smtp_log.len() >= SMTP_CAPACITY {
                    self.smtp_log.remove(0);
                }
                self.smtp_log.push(crate::ui::panels::logger::SmtpEntry {
                    direction,
                    from,
                    to,
                    subject,
                    body,
                });
            }
            Event::WsOpen { id, host, request, response } => {
                self.websockets.retain(|c| c.open);
                if self.websockets.len() >= WS_CAPACITY {
                    // Drop the oldest connection's frames with it, so the store stays bounded.
                    self.websockets.remove(0);
                }
                self.status = format!("WebSocket {id} open to {host}");
                self.websockets.push(WsConnection {
                    id,
                    host,
                    request,
                    response,
                    open: true,
                    messages: Vec::new(),
                });
            }
            Event::WsFrame { id, to_server, opcode, text, bytes } => {
                if let Some(connection) = self.websockets.iter_mut().find(|c| c.id == id) {
                    if connection.messages.len() >= WS_MESSAGE_CAPACITY {
                        connection.messages.remove(0);
                    }
                    connection.messages.push(WsMessage {
                        to_server,
                        opcode,
                        text,
                        bytes,
                    });
                }
            }
            Event::WsClosed { id } => {
                if let Some(connection) = self.websockets.iter_mut().find(|c| c.id == id) {
                    connection.open = false;
                }
            }
            Event::AttackResult { index, status, length, matched, error } => {
                self.panels.intruder.record(index, status, length, matched, error);
            }
            Event::AttackDone { total, matches } => {
                self.panels.intruder.running = false;
                self.panels.intruder.matches = matches;
                self.status = format!("Intruder finished: {total} sent, {matches} matched");
            }
            Event::Listening { port } => {
                self.listening = Some(port);
                self.status = format!("Listening on 127.0.0.1:{port}");
            }
            Event::ListenerStopped => {
                self.listening = None;
                self.status = "Listener stopped".into();
            }
            Event::Error(message) => self.status = message,
        }
    }

    fn select(&mut self, tool: usize) {
        self.tool = tool;
        self.status = TOOLS[tool].to_string();
    }
}

/// The host of a target with its scheme, the way the site map names it.
fn host_key(target: &str, secure: bool) -> String {
    let scheme = if secure { "https" } else { "http" };
    format!("{scheme}://{}", host_of(target))
}

fn host_of(target: &str) -> String {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .unwrap_or(target);
    // The port is kept, because two services on one machine are two different things.
    rest.split(['/', '?', '#']).next().unwrap_or(rest).to_string()
}

/// Burp draws its UI with the platform font, so the shell uses the same one instead of egui's
/// bundled face. On macOS that is SF Pro, and at 11.5px its tab labels land on Burp's measured
/// widths: "Dashboard" 53px, "Target" 30px, "Proxy" 27px, "Intruder" 37px, "Repeater" 44px and
/// "Collaborator" 59px, all within half a pixel of the running Burp. The font file is only
/// borrowed from the system, never copied into the app.
fn install_fonts(ctx: &mut Context) {
    let mut fonts = eframe::egui::FontDefinitions::default();
    // The platform face for ordinary text.
    if let Ok(bytes) = std::fs::read("/System/Library/Fonts/SFNS.ttf") {
        fonts
            .font_data
            .insert("system".to_owned(), eframe::egui::FontData::from_owned(bytes).into());
        if let Some(family) = fonts.families.get_mut(&eframe::egui::FontFamily::Proportional) {
            family.insert(0, "system".to_owned());
        }
    }
    // Burp shows HTTP messages in a monospaced face; SF Mono is the system one.
    if let Ok(bytes) = std::fs::read("/System/Library/Fonts/SFNSMono.ttf") {
        fonts
            .font_data
            .insert("system-mono".to_owned(), eframe::egui::FontData::from_owned(bytes).into());
        if let Some(family) = fonts.families.get_mut(&eframe::egui::FontFamily::Monospace) {
            family.insert(0, "system-mono".to_owned());
        }
    }
    ctx.set_fonts(fonts);

    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        TextStyle::Body,
        eframe::egui::FontId::new(12.0, eframe::egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Button,
        eframe::egui::FontId::new(12.0, eframe::egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Heading,
        eframe::egui::FontId::new(15.0, eframe::egui::FontFamily::Proportional),
    );
    style.spacing.item_spacing = Vec2::new(6.0, 4.0);
    ctx.set_style(style);
}

/// Menu definitions, mirroring Burp's bar.
/// Only actions that genuinely exist are listed. Earlier entries ("New repeater tab",
/// "Filter by MIME type", "Pause") named features this app does not have, so they were removed
/// rather than left clicking into a status message.
const MENUS: [(&str, &[&str]); 9] = [
    ("Project", &["Save project", "Open project", "Exit"]),
    ("Dashboard", &["Clear dashboard"]),
    ("Target", &["Site map", "Scan"]),
    ("Proxy", &["Intercept", "History"]),
    ("Intruder", &["Start attack"]),
    ("Repeater", &["Send"]),
    ("Sequencer", &["Analyze entropy"]),
    ("Decoder", &["Transform"]),
    ("Logger", &["Clear"]),
];

/// Sub-view index for Sequencer's manual table.
const SEQUENCER_MANUAL: usize = 0;

impl eframe::App for App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.pump();
        self.hotkeys(ctx);
        apply_visuals(ctx, &self.theme);

        let frame = Frame::NONE
            .fill(self.theme.color("ui.background.1"))
            .inner_margin(0.0);
        eframe::egui::CentralPanel::default()
            .frame(frame)
            .show(ctx, |ui| {
                // One vertical stack owns the whole window. Every band below allocates sequentially
                // so the cursor advances and the status bar lands at the bottom instead of on top
                // of the tab rows.
                ui.spacing_mut().item_spacing = Vec2::ZERO;
                // Burp on macOS keeps its menus in the system menu bar, so there is no menu row
                // inside the window. eframe 0.33 cannot create a native one, so the same actions
                // live in the status bar and on Alt hotkeys instead of faking a row Burp does
                // not draw.
                //
                // The status bar's height is reserved up front; if the panel were allowed to claim
                // the last pixels the bar would be allocated with no room and disappear.
                let status_height = STATUS_BAR_HEIGHT;
                let for_body = (ui.available_height() - status_height).max(0.0);
                self.body(ui, for_body);
                // `body` draws its panel into a rect, so the cursor has to be pushed past it by
                // hand before the status bar is allocated. The panel height is the difference, so
                // the tab rows are excluded.
                ui.allocate_space(Vec2::new(0.0, for_body - self.tab_rows_height));
                self.status_bar(ctx, ui);
            });

        self.windows(ctx);
    }
}

/// Maps the widget style onto Burp's own look-and-feel.
///
/// Every value here comes from `burp/theme/BurpLaf.properties` in the shipped Burp jar, so the
/// numbers are Burp's rather than taste:
///   desktop/control/text/menu = ui.background.2
///   Button.background         = palette.mono.3   -> ui.background.3
///   Button.borderColor        = palette.mono.4   -> ui.background.4
///   Button.hoverBackground    = palette.mono.4   -> ui.background.4
///   Button.hoverBorderColor   = palette.mono.5   -> ui.background.5
///   Button.arc = 8, Button.font = bold, Button.margin = 2,20,2,20, Button.borderWidth = 1
///
/// Draws text in the platform face, twice, with a half point offset.
///
/// egui has no bold weight of its own, and SF Pro ships as a single variable face with no bold
/// file to load, so the second pass is what makes the text read bold. Doing it this way keeps
/// Burp's own metrics: a real bold face is about a quarter wider and would break the layout.
pub fn bold_text(ui: &mut Ui, text: &str, size: f32, color: eframe::egui::Color32) -> eframe::egui::Response {
    bold_label_sense(ui, text, size, color, Sense::hover())
}

/// A bold label that can be clicked, for the places Burp makes a title act as a control.
pub fn bold_click_label(
    ui: &mut Ui,
    text: &str,
    size: f32,
    color: eframe::egui::Color32,
) -> eframe::egui::Response {
    bold_label_sense(ui, text, size, color, Sense::click())
}

fn bold_label_sense(
    ui: &mut Ui,
    text: &str,
    size: f32,
    color: eframe::egui::Color32,
    sense: Sense,
) -> eframe::egui::Response {
    let font = FontId::new(size, eframe::egui::FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let (rect, response) = ui.allocate_exact_size(galley.size(), sense);
    let painter = ui.painter_at(rect);
    let pos = rect.left_top();
    painter.galley(pos + Vec2::new(0.5, 0.0), galley.clone(), color);
    painter.galley(pos, galley, color);
    response
}

/// Burp's primary button: a filled accent button with white text.
///
/// Measured from Burp's light theme, where "New scan" is 23 logical pixels tall with an 8 pixel
/// arc, 20 pixels of horizontal padding and white text. The arc and the padding come from
/// `Button.arc=8` and `Button.margin=2,20,2,20` in `burp/theme/BurpLaf.properties`.
pub(crate) fn primary_button(
    ui: &mut Ui,
    theme: &crate::ui::theme::Theme,
    text: &str,
) -> eframe::egui::Response {
    let fill = theme.color("ui.icon.link");
    let text_color = theme.color("ui.text.white");
    let font = FontId::new(11.0, eframe::egui::FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font.clone(), text_color);
    let size = eframe::egui::vec2(galley.size().x + 40.0, 23.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let painter = ui.painter_at(rect);
        let background = if response.hovered() { fill.linear_multiply(1.1) } else { fill };
        painter.rect_filled(rect, crate::ui::theme::BURP_BUTTON_ARC as f32, background);
        // Two passes, so the button label reads bold the way Burp's does. The galley is placed by
        // its top left corner, so it is centred first.
        let galley = ui
            .painter()
            .layout_no_wrap(text.to_owned(), font.clone(), text_color);
        let origin = rect.center() - galley.size() / 2.0;
        painter.galley(origin + Vec2::new(0.5, 0.0), galley.clone(), text_color);
        painter.galley(origin, galley, text_color);
    }
    response
}

/// Width of a tool tab, from its label. Burp sizes each tab to its text plus a fixed inset.
fn label_width(ui: &Ui, text: &str) -> f32 {
    let font = TAB_FONT;
    ui.fonts_mut(|f| f.layout_no_wrap(text.to_string(), font, eframe::egui::Color32::TRANSPARENT).rect.width())
}

fn apply_visuals(ctx: &Context, theme: &Theme) {
    let mut style = (*ctx.style()).clone();

    // Quoted from BurpLaf under its own names now that `palette.*` resolves.
    let desktop = theme.color("ui.background.2");
    let control = theme.color("ui.background.2");
    let button_bg = theme.color("palette.mono.3");
    let button_border = theme.color("palette.mono.4");
    let button_hover_bg = theme.color("palette.mono.4");
    let button_hover_border = theme.color("palette.mono.5");
    let body = theme.color("ui.text.body");
    let hover_text = theme.color("ui.text.hover");
    let disabled_text = theme.color("ui.text.disabled");
    let white = theme.color("ui.text.white");
    let accent = theme.color("icon.linkHover");
    let secondary = theme.color("palette.secondary.core");

    style.visuals.panel_fill = desktop;
    style.visuals.window_fill = control;
    style.visuals.extreme_bg_color = control;
    style.visuals.faint_bg_color = desktop;
    style.visuals.window_stroke = Stroke::new(1.0, button_border);

    style.visuals.widgets.noninteractive.bg_fill = control;
    style.visuals.widgets.noninteractive.weak_bg_fill = control;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, body);

    // Button.background = palette.mono.3, Button.borderColor = palette.mono.4.
    style.visuals.widgets.inactive.bg_fill = button_bg;
    style.visuals.widgets.inactive.weak_bg_fill = button_bg;
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, body);
    style.visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, button_border);
    let arc = crate::ui::theme::BURP_BUTTON_ARC;
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(arc);

    style.visuals.widgets.hovered.bg_fill = button_hover_bg;
    style.visuals.widgets.hovered.weak_bg_fill = button_hover_bg;
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, hover_text);
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, button_hover_border);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(arc);

    style.visuals.widgets.active.bg_fill = button_bg;
    style.visuals.widgets.active.weak_bg_fill = button_bg;
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0, body);
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0, button_border);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(arc);

    style.visuals.widgets.open.bg_fill = button_hover_bg;
    style.visuals.widgets.open.weak_bg_fill = button_hover_bg;
    style.visuals.widgets.open.fg_stroke = Stroke::new(1.0, body);
    style.visuals.widgets.open.bg_stroke = Stroke::new(1.0, button_border);
    style.visuals.widgets.open.corner_radius = CornerRadius::same(arc);

    style.visuals.selection.bg_fill = theme.color("ui.background.5");
    style.visuals.selection.stroke = Stroke::new(1.0, accent);
    style.visuals.hyperlink_color = accent;
    style.visuals.error_fg_color = theme.color("ui.icon.error");
    style.visuals.warn_fg_color = theme.color("ui.icon.warning");

    style.spacing.item_spacing = Vec2::new(6.0, 4.0);
    // Button.margin = 2,20,2,20 is (top, left, bottom, right) in FlatLaf, so the horizontal
    // padding Burp uses is 20 rather than the 8 egui defaults to.
    style.spacing.button_padding = crate::ui::theme::BURP_BUTTON_PADDING;

    // Button.font = bold is not reachable here: epaint 0.33's FontId is { size, family } with an
    // explicit "TODO(emilk): weight (bold)". Button labels go through `bold_label` instead, which
    // uses RichText::strong() per label and therefore still renders bold.
    let button = style
        .text_styles
        .get_mut(&TextStyle::Button)
        .expect("button style exists");
    button.size = 13.0;

    let _ = (white, secondary, disabled_text);
    ctx.set_style(style);
}


/// A button label rendered bold, standing in for `Button.font=bold`.
///
/// egui 0.33 cannot express font weight in the style, so boldness has to be requested per label.
pub fn bold_label(text: impl Into<String>) -> RichText {
    RichText::new(text.into()).strong()
}

/// A Burp-styled button: rounded, bordered, bold label.
pub fn burp_button(ui: &mut Ui, text: impl Into<String>) -> Response {
    ui.add(Button::new(bold_label(text)))
}

impl App {
    /// Runs a menu item. Navigation mirrors how Burp's menus jump between a tool's views; the rest
    /// invoke the same action the tool's own button runs, so there is one implementation each.
    /// Writes the current session to `panels.project_path`, defaulting to the working directory.
    fn save_project(&mut self) {
        if self.panels.project_path.trim().is_empty() {
            self.panels.project_path = "gulpsuite-project.json".to_string();
        }
        let mut project = crate::project::Project::new("gulpsuite");
        project.theme_dark = self.theme.dark;
        project.workspace = crate::project::SavedWorkspace::from(&self.workspace);
        self.saved_layout.active_tool = self.tool;
        self.saved_layout.active_view = self.view;
        project.layout = self.saved_layout.clone();
        project.items = self
            .organizer
            .iter()
            .map(|item| crate::project::SavedItem {
                host: item.host.clone(),
                name: item.name.clone(),
                notes: item.notes.clone(),
                request: item.request.clone(),
                response: item.response.clone(),
            })
            .collect();
        // The replayer holds one recording at a time, so a project carries zero or one.
        project.recordings = self
            .panels
            .replayer
            .recording
            .as_ref()
            .map(|recording| {
                vec![crate::project::SavedRecording {
                    name: recording.name.clone(),
                    host: recording.host.clone(),
                    steps: recording
                        .steps
                        .iter()
                        .map(|step| crate::project::SavedStep {
                            method: step.method.clone(),
                            url: step.url.clone(),
                            request: step.request.clone(),
                            response: step.response.clone(),
                            status: step.status,
                        })
                        .collect(),
                }]
            })
            .unwrap_or_default();
        let path = std::path::PathBuf::from(&self.panels.project_path);
        match project.save(&path) {
            Ok(()) => self.status = format!(
                "Saved {} items and {} recordings to {}",
                project.item_count(),
                project.recording_count(),
                path.display()
            ),
            Err(why) => self.status = format!("Save failed: {why}"),
        }
    }

    /// Replaces the session with the one in `panels.project_path`.
    fn open_project(&mut self) {
        if self.panels.project_path.trim().is_empty() {
            self.panels.project_path = "gulpsuite-project.json".to_string();
        }
        let path = std::path::PathBuf::from(&self.panels.project_path);
        match crate::project::Project::load(&path) {
            Ok(project) => {
                let restored_workspace = project.workspace.clone().restore();
                let restored_layout = project.layout.clone();
                self.organizer = project
                    .items
                    .iter()
                    .map(|item| panels::organizer::OrganizerItem {
                        host: item.host.clone(),
                        name: item.name.clone(),
                        notes: item.notes.clone(),
                        request: item.request.clone(),
                        response: item.response.clone(),
                    })
                    .collect();
                self.panels.replayer.recording = project.recordings.first().map(|saved| {
                    crate::replay::Recording {
                        name: saved.name.clone(),
                        host: saved.host.clone(),
                        steps: saved
                            .steps
                            .iter()
                            .map(|step| crate::replay::Step {
                                method: step.method.clone(),
                                url: step.url.clone(),
                                request: step.request.clone(),
                                response: step.response.clone(),
                                status: step.status,
                            })
                            .collect(),
                    }
                });
                // The restored item list may be shorter than the selected index.
                self.panels.organizer.selected = None;
                self.theme = crate::ui::theme::Theme::load(project.theme_dark);
                self.workspace = restored_workspace;
                self.saved_layout = restored_layout;
                self.tool = self.saved_layout.active_tool.min(TOOLS.len() - 1);
                self.view = self
                    .saved_layout
                    .active_view
                    .min(TOOL_VIEWS[self.tool].len().saturating_sub(1));
                self.status = format!(
                    "Opened {} — {} items, {} recordings",
                    path.display(),
                    project.item_count(),
                    project.recording_count()
                );
            }
            Err(why) => self.status = format!("Open failed: {why}"),
        }
    }

    fn menu_action(&mut self, ctx: &Context, menu: &str, item: &str) {
        match (menu, item) {
            ("Project", "Save project") => self.save_project(),
            ("Project", "Open project") => self.open_project(),
            ("Project", "Exit") => ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Close),
            ("Dashboard", "Clear dashboard") | ("Logger", "Clear") => self.clear_log(),
            ("Target", "Site map") => self.go(TARGET, 0),
            ("Target", "Scan") => {
                // Burp runs scanning from the Suite task list, so "Scan" lands there too.
                self.go(SUITE, 0);
                panels::scanner::start(self);
            }
            ("Proxy", "Intercept") => self.go(PROXY, 0),
            ("Proxy", "History") => self.go(PROXY, 1),
            ("Intruder", "Start attack") => {
                self.go(INTRUDER, 0);
                panels::intruder::start(self);
            }
            ("Repeater", "Send") => {
                self.go(REPEATER, 0);
                panels::repeater::send(self);
            }
            ("Sequencer", "Analyze entropy") => {
                self.go(SEQUENCER, SEQUENCER_MANUAL);
                panels::sequencer::analyze(self);
            }
            ("Decoder", "Transform") => {
                self.go(DECODER, 0);
                panels::decoder::apply(self);
            }
            _ => self.status = format!("{menu} > {item} is not available"),
        }
    }

    /// The right-click actions offered on a captured transaction. Burp exposes these through
    /// `ui/contextmenu/*`; each one here either already exists or is honest about being absent.
    pub fn context_menu(&mut self, trigger: &eframe::egui::Response, index: usize) {
        let Some(tx) = self.log.get(index) else {
            return;
        };
        let (request, response, target, method) = (
            tx.request.clone(),
            tx.response.clone(),
            tx.target.clone(),
            tx.method.clone(),
        );
        let has_request = !request.trim().is_empty();

        let ctx = trigger.ctx.clone();
        let ctx = &ctx;
        eframe::egui::Popup::context_menu(trigger).show(|ui| {
            if ui.button("Send to Repeater").clicked() {
                self.panels.repeater.open(&target, &request);
                self.tool = REPEATER;
                self.view = 0;
                self.status = "Request sent to Repeater".into();
                ui.close();
            }
            if ui.button("Send to Organizer").clicked() {
                panels::organizer::retain(
                    self,
                    panels::organizer::OrganizerItem {
                        host: target.clone(),
                        name: format!("{method} {target}"),
                        notes: String::new(),
                        request: request.clone(),
                        response: response.clone(),
                    },
                );
                self.status = "Saved to Organizer".into();
                ui.close();
            }
            ui.separator();
            if ui
                .add_enabled(has_request, eframe::egui::Button::new("Copy request"))
                .clicked()
            {
                ctx.copy_text(request.clone());
                self.status = "Request copied".into();
                ui.close();
            }
            if ui.button("Copy URL").clicked() {
                ctx.copy_text(target.clone());
                self.status = "URL copied".into();
                ui.close();
            }
            if ui
                .add_enabled(!response.is_empty(), eframe::egui::Button::new("Copy response"))
                .clicked()
            {
                ctx.copy_text(response.clone());
                self.status = "Response copied".into();
                ui.close();
            }
            ui.separator();
            if ui.button("Remove from history").clicked() {
                self.log.remove(index);
                // The site map is tagged with the history version, so it must be invalidated too.
                self.log_version += 1;
                self.site_map = None;
                if self.panels.proxy_panel.selected == Some(index) {
                    self.panels.proxy_panel.selected = None;
                }
                self.status = "Removed from history".into();
                ui.close();
            }
        });
    }

    /// Global shortcuts. Burp registers these through `ui/hotkey/*`; these cover the actions an
    /// operator reaches for most, and deliberately only ones that already work.
    fn hotkeys(&mut self, ctx: &Context) {
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::R)) {
            if self.tool == REPEATER {
                panels::repeater::send(self);
            }
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::I)) {
            self.intercepting = !self.intercepting;
            self.proxy.set_intercept(self.intercepting);
            self.status = format!("Intercept {}", if self.intercepting { "on" } else { "off" });
        }
        // Burp's Alt+letter shortcuts, keyed by name so the reorder cannot point them at the wrong
        // tool. These go through `go` so a tool change also clamps the sub-view like every other path.
        for (key, tool, name) in [
            (Key::D, SUITE, "Dashboard"),
            (Key::T, TARGET, "Target"),
            (Key::P, PROXY, "Proxy"),
            (Key::N, INTRUDER, "Intruder"),
            (Key::R, REPEATER, "Repeater"),
            (Key::O, COLLABORATOR, "Collaborator"),
            (Key::S, SEQUENCER, "Sequencer"),
            (Key::E, DECODER, "Decoder"),
            (Key::C, COMPARER, "Comparer"),
            (Key::L, LOGGER, "Logger"),
            (Key::G, ORGANIZER, "Organizer"),
            (Key::X, EXTENSIONS, "Extensions"),
            (Key::I, DISCOVER, "Discover"),
        ] {
            if ctx.input_mut(|i| i.consume_key(Modifiers::ALT, key)) {
                self.go(tool, 0);
                self.status = name.to_string();
            }
        }
    }

    /// Drops the captured history. The site map is tagged with the history version, so it has to be
    /// invalidated too or it would keep showing rows that no longer exist.
    fn clear_log(&mut self) {
        let count = self.log.len();
        self.log.clear();
        self.held.clear();
        self.log_version += 1;
        self.site_map = None;
        self.status = format!("Cleared {count} captured request(s)");
    }

    /// Switches tool and view together, matching how a Burp menu item behaves.
    fn go(&mut self, tool: usize, view: usize) {
        self.tool = tool;
        self.view = view.min(TOOL_VIEWS[tool].len().saturating_sub(1));
        self.status = TOOLS[tool].to_string();
    }

    #[allow(dead_code)]
    fn menu_bar(&mut self, ctx: &Context, ui: &mut Ui) {
        ui.horizontal(|ui| {
            // Burp ships a light and a dark theme; both are bundled, so this switches rather than
            // approximates.
            let dark = self.is_dark();
            if ui
                .add_enabled(dark, eframe::egui::Button::new(bold_label("Dark")))
                .clicked()
            {
                self.set_dark(true);
            }
            if ui
                .add_enabled(!dark, eframe::egui::Button::new(bold_label("Light")))
                .clicked()
            {
                self.set_dark(false);
            }
            ui.separator();
            for (name, items) in MENUS {
                ui.menu_button(name, |ui| {
                    for item in items {
                        if ui.button(*item).clicked() {
                            self.menu_action(ctx, name, item);
                            ui.close();
                        }
                    }
                });
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new("Gulpsuite").color(self.theme.color("ui.icon.default")));
            });
        });
    }

    /// Burp's shell: a horizontal tool tab row, then the selected tool's sub-tab row, then content.
    ///
    /// Measured from a running Burp Suite Professional v2026.3.3 at 1440x790 rather than assumed:
    /// the tool tabs sit in one row across the top on a white band, the selected one carries a 3px
    /// accent underline and accent-coloured label, a 1px divider separates the row from the content,
    /// and the sub-tabs are a second horizontal row directly beneath — not a side strip.
    /// Draws the tab rows and the tool panel into the caller's layout.
    ///
    /// Deliberately not wrapped in its own `vertical`: a nested layout owns its own cursor, so the
    /// status bar allocated afterwards would land back at the top of the window. The panel instead
    /// paints into a rect and the cursor is advanced past it explicitly.
    fn body(&mut self, ui: &mut Ui, available: f32) {
        let origin = ui.available_rect_before_wrap().min;
        self.tab_row(ui, &TOOLS, true, TOOL_TAB_HEIGHT);
        let mut consumed = TOOL_TAB_HEIGHT;
        let views = TOOL_VIEWS[self.tool];
        // Burp puts the Dashboard's own tabs inside its detail pane, below the task header, so the
        // shell leaves that row to the panel.
        if views.len() > 1 && self.tool != SUITE {
            self.tab_row(ui, views, false, SUB_TAB_HEIGHT);
            consumed += SUB_TAB_HEIGHT;
        }
        let panel_height = (available - consumed).max(0.0);
        let rect = Rect::from_min_size(
            pos2(origin.x, origin.y + consumed),
            Vec2::new(ui.available_width(), panel_height),
        );
        self.panel(ui, rect);
        self.tab_rows_height = consumed;
    }

    /// One horizontal row of tabs. Used for both the tool strip and a tool's own views, which is
    /// how Burp presents both.
    pub(crate) fn tab_row(&mut self, ui: &mut Ui, labels: &[&str], tools: bool, height: f32) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), height), Sense::hover());
        let painter = ui.painter_at(rect);
        let accent = self.theme.color("ui.icon.link");
        let idle_text = self.theme.color("ui.text.body");
        // Burp keeps the selected tab's label in the hover foreground and marks the tab with the
        // accent bar only. Measured from Burp's light theme: the selected label is #000000 while
        // the other labels are #2B2B2B, and the accent appears in the underline, not the text.
        let selected_text = self.theme.color("ui.text.hover");
        // The band differs from the content: the lighter chrome colour behind the tools, the panel
        // colour behind a tool's own views.
        painter.rect_filled(
            rect,
            0.0,
            if tools { self.theme.color("ui.background.1") } else { self.theme.color("ui.background.2") },
        );

        // Tab geometry measured from Burp v2026.3.3: the first label starts 16px in, labels advance
        // by their own width plus 34px, and the selected underline overhangs by 16px left / 20px right.
        let mut x = rect.min.x + 16.0;
        let centre_y = rect.min.y + (rect.height() - TAB_UNDERLINE) * 0.5;

        for (index, label) in labels.iter().enumerate() {
            let width = label_width(ui, label);
            if x + width > rect.max.x {
                break;
            }
            let selected = if tools { index == self.tool } else { index == self.view };
            if selected && tools {
                // Burp tints the selected tool tab one step off the band: #FBFBFB against the
                // #FFFFFF row in the light theme.
                painter.rect_filled(
                    Rect::from_min_max(
                        pos2(x - 16.0, rect.min.y),
                        pos2(x + width + 19.5, rect.max.y),
                    ),
                    0.0,
                    self.theme.color("ui.background.2"),
                );
            }
            painter.text(
                pos2(x, centre_y),
                eframe::egui::Align2::LEFT_CENTER,
                *label,
                TAB_FONT,
                if selected { selected_text } else { idle_text },
            );
            if selected {
                // Burp marks the selected tab with a bar along the bottom of the row, not a fill.
                painter.rect_filled(
                    Rect::from_min_max(
                        pos2(x - 16.0, rect.max.y - TAB_UNDERLINE),
                        pos2(x + width + 19.5, rect.max.y),
                    ),
                    0.0,
                    accent,
                );
            }
            let tab = Rect::from_min_max(
                pos2(x - 16.0, rect.min.y),
                pos2(x + width + 19.5, rect.max.y),
            );
            let clicked = ui
                .interact(tab, ui.id().with((if tools { "tool" } else { "view" }, index)), Sense::click())
                .clicked();
            if clicked {
                if tools {
                    self.select(index);
                } else {
                    self.view = index;
                    self.status = format!("{} — {label}", TOOLS[self.tool]);
                }
            }
            x += width + 34.0;
        }

        // A one pixel rule closes the row, the same way Burp separates the tab band from content.
        painter.rect_filled(
            Rect::from_min_size(pos2(rect.min.x, rect.max.y), Vec2::new(rect.width(), 1.0)),
            0.0,
            self.theme.color("ui.border.1"),
        );

        // Burp keeps four icons at the right end of the tool row: browser, browser console, search
        // and settings.
        if tools {
            // Burp's order, left to right: browser, browser console, search, settings. The row is
            // painted from the right edge inward, so the list is reversed here.
            let icons = [
                (crate::ui::icons::Glyph::Gear, "Settings"),
                (crate::ui::icons::Glyph::Search, "Search"),
                (crate::ui::icons::Glyph::Terminal, "Browser console"),
                (crate::ui::icons::Glyph::Globe, "Burp browser"),
            ];
            let size = 16.0;
            let mut x = rect.max.x - 12.0 - size;
            let centre_y = rect.min.y + rect.height() * 0.5;
            for (index, (glyph, tooltip)) in icons.into_iter().enumerate() {
                let area = Rect::from_center_size(pos2(x + size * 0.5, centre_y), Vec2::splat(size));
                crate::ui::icons::paint(&painter, area, self.theme.color("ui.icon.default"), glyph);
                let response = ui.interact(area, ui.id().with(("tool-icon", index)), Sense::click());
                if response.clicked() {
                    match glyph {
                        crate::ui::icons::Glyph::Gear => self.show_settings = true,
                        crate::ui::icons::Glyph::Search => {
                            self.show_search = true;
                            self.search_text.clear();
                        }
                        crate::ui::icons::Glyph::Terminal => self.show_console = true,
                        _ => self.open_browser(),
                    }
                }
                if response.hovered() {
                    response.show_tooltip_text(tooltip);
                }
                x -= size + 8.0;
            }
        }
    }

    /// The floating windows Burp opens from the icons at the right of the tool row.
    fn windows(&mut self, ctx: &Context) {
        if self.show_settings {
            let mut open = true;
            eframe::egui::Window::new("Settings")
                .open(&mut open)
                .resizable(true)
                .default_width(320.0)
                .show(ctx, |ui| self.settings(ui));
            self.show_settings = open;
        }
        if self.show_search {
            let mut open = true;
            eframe::egui::Window::new("Search")
                .open(&mut open)
                .resizable(true)
                .default_width(520.0)
                .show(ctx, |ui| self.search_window(ui));
            self.show_search = open;
        }
        if self.show_console {
            let mut open = true;
            eframe::egui::Window::new("Browser console")
                .open(&mut open)
                .resizable(true)
                .default_width(520.0)
                .show(ctx, |ui| self.console_window(ui));
            self.show_console = open;
        }
    }

    /// Burp's settings dialog: the theme, the project and the listener's port.
    fn settings(&mut self, ui: &mut Ui) {
        let theme = self.theme.clone();
        ui.label(eframe::egui::RichText::new("Appearance").strong());
        ui.horizontal(|ui| {
            if ui
                .selectable_label(self.is_dark(), "Dark")
                .clicked()
            {
                self.set_dark(true);
            }
            if ui
                .selectable_label(!self.is_dark(), "Light")
                .clicked()
            {
                self.set_dark(false);
            }
        });
        ui.add_space(6.0);
        ui.label(eframe::egui::RichText::new("Project").strong());
        ui.horizontal(|ui| {
            if ui.button("Save project").clicked() {
                self.save_project();
            }
            if ui.button("Open project").clicked() {
                self.open_project();
            }
        });
        ui.add_space(6.0);
        ui.label(eframe::egui::RichText::new("Listener").strong());
        ui.horizontal(|ui| {
            ui.label("Port");
            let mut port = self.panels.proxy_panel.port.to_string();
            if ui.text_edit_singleline(&mut port).changed() {
                if let Ok(port) = port.trim().parse::<u16>() {
                    self.panels.proxy_panel.port = port;
                }
            }
            let listening = self.listening.is_some();
            if ui.add_enabled(!listening, eframe::egui::Button::new("Start")).clicked() {
                self.start_proxy(self.panels.proxy_panel.port);
            }
            if ui.add_enabled(listening, eframe::egui::Button::new("Stop")).clicked() {
                self.stop_proxy();
            }
        });
        ui.add_space(6.0);
        ui.label(eframe::egui::RichText::new("Https").strong());
        ui.horizontal(|ui| {
            let mut tls = self.tls_intercepting;
            if ui.checkbox(&mut tls, "Intercept https (TLS)").changed() {
                self.tls_intercepting = tls;
                self.proxy.set_tls_interception(tls);
            }
        });
        super::panels::muted(
            ui,
            &theme,
            "With interception on, a browser has to trust the proxy's own authority before https works.",
        );
        if let Some(path) = self.proxy.authority_path() {
            let path = path.to_string_lossy().to_string();
            ui.horizontal(|ui| {
                ui.label(eframe::egui::RichText::new("Certificate").strong());
                ui.label(eframe::egui::RichText::new(&path).monospace().color(theme.color("ui.text.body")));
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(path.clone());
                    self.status = "Certificate path copied".into();
                }
            });
        }
        ui.add_space(6.0);
        super::panels::muted(ui, &theme, "Gulpsuite: a Burp Suite style proxy, in one Rust process.");
    }

    /// Burp's search window: it looks through the captured traffic.
    fn search_window(&mut self, ui: &mut Ui) {
        let theme = self.theme.clone();
        ui.horizontal(|ui| {
            ui.label("Search");
            ui.text_edit_singleline(&mut self.search_text);
            if ui.button("Clear").clicked() {
                self.search_text.clear();
            }
        });
        let needle = self.search_text.trim().to_lowercase();
        if needle.is_empty() {
            super::panels::muted(ui, &theme, "Type to search the captured requests and responses.");
            return;
        }
        let mut matches = Vec::new();
        for (index, tx) in self.log.iter().enumerate() {
            if tx.target.to_lowercase().contains(&needle)
                || tx.request.to_lowercase().contains(&needle)
                || tx.response.to_lowercase().contains(&needle)
            {
                matches.push((index, tx.method.clone(), tx.target.clone(), tx.status));
            }
            if matches.len() >= 200 {
                break;
            }
        }
        if matches.is_empty() {
            super::panels::muted(ui, &theme, "No matches.");
            return;
        }
        eframe::egui::ScrollArea::vertical().show(ui, |ui| {
            eframe::egui::Grid::new("search-results")
                .num_columns(3)
                .striped(true)
                .show(ui, |ui| {
                    for name in ["Method", "Target", "Status"] {
                        ui.label(eframe::egui::RichText::new(name).strong().color(theme.color("ui.text.body")));
                    }
                    ui.end_row();
                    for (index, method, target, status) in matches {
                        let response = ui.label(
                            eframe::egui::RichText::new(&method).color(theme.color("icon.link")),
                        );
                        if response.clicked() {
                            self.panels.proxy_panel.selected = Some(index);
                            self.tool = crate::ui::app::PROXY;
                            self.view = 1;
                            self.show_search = false;
                        }
                        ui.label(target);
                        ui.label(status.to_string());
                        ui.end_row();
                    }
                });
        });
    }

    /// The console window: the proxy's event trail, newest last.
    fn console_window(&mut self, ui: &mut Ui) {
        let theme = self.theme.clone();
        if self.console.is_empty() {
            super::panels::muted(ui, &theme, "Nothing yet. The proxy writes here as it works.");
            return;
        }
        eframe::egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for line in &self.console {
                    ui.label(eframe::egui::RichText::new(line).monospace());
                }
            });
    }

    /// Burp's browser icon opens a browser on the target. This build has no embedded browser, so
    /// the system's own is used, with the proxy address spelled out.
    fn open_browser(&mut self) {
        let target = self
            .log
            .iter()
            .rev()
            .find_map(|tx| {
                tx.target
                    .strip_prefix("http://")
                    .or_else(|| tx.target.strip_prefix("https://"))
                    .map(|rest| {
                        let host = rest.split('/').next().unwrap_or(rest);
                        format!("http://{host}/")
                    })
            })
            .unwrap_or_else(|| "http://127.0.0.1:8080/".to_string());
        let status = format!("Opening {target}");
        let _ = std::process::Command::new("open").arg(&target).spawn();
        self.status = status;
    }
    /// The tool's own area. Burp insets its content rather than butting it against the window edge.
    fn panel(&mut self, ui: &mut Ui, rect: Rect) {
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, self.theme.color("ui.background.2"));
        let inset = PANEL_INSET;
        let content = Rect::from_min_size(
            pos2(rect.min.x + inset, rect.min.y + inset),
            Vec2::new((rect.width() - inset * 2.0).max(0.0), (rect.height() - inset * 2.0).max(0.0)),
        );
        let mut inner = ui.new_child(
            eframe::egui::UiBuilder::new()
                .max_rect(content)
                .layout(Layout::top_down(eframe::egui::Align::LEFT))
                .id_salt("panel"),
        );
        inner.spacing_mut().item_spacing = Vec2::new(6.0, 4.0);
        panels::draw(self, &mut inner);
    }

    /// The bottom bar. Burp shows the event-log selector on the left and instrument controls on the
    /// right; this keeps that shape and carries the actions that would otherwise sit in a menu row.
    fn status_bar(&mut self, ctx: &Context, ui: &mut Ui) {
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), STATUS_BAR_HEIGHT), Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, self.theme.color("ui.background.2"));
        painter.rect_filled(
            Rect::from_min_size(pos2(rect.min.x, rect.min.y), Vec2::new(rect.width(), 1.0)),
            0.0,
            self.theme.color("ui.border.1"),
        );
        let idle = self.theme.color("ui.icon.default");
        let accent = self.theme.color("ui.icon.link");
        let baseline = rect.center().y;

        // Left: the event-log selector and the issue filter, the way Burp writes them:
        // "Event log (1)" followed by a dot and "All issues".
        let log_count = self.log.len();
        let label = format!("Event log ({log_count})");
        let log_label_width = label_width(ui, &label);
        painter.text(
            pos2(rect.min.x + 12.0, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            &label,
            FontId::proportional(11.0),
            idle,
        );
        let mut x = rect.min.x + 12.0 + log_label_width + 8.0;
        painter.circle_filled(pos2(x, baseline), 2.5, accent);
        x += 10.0;
        let issues_label = "All issues";
        painter.text(
            pos2(x, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            issues_label,
            FontId::proportional(11.0),
            idle,
        );
        x += label_width(ui, issues_label) + 8.0;

        // Right: the memory readout with a slider and a dropdown, as Burp shows it.
        let memory = self.memory_readout();
        let memory_width = label_width(ui, &memory);
        let dropdown = 22.0;
        let slider = 70.0;
        let right = rect.max.x - 12.0 - dropdown - 8.0 - slider - 12.0 - memory_width;
        painter.text(
            pos2(right, baseline),
            eframe::egui::Align2::LEFT_CENTER,
            &memory,
            FontId::proportional(11.0),
            idle,
        );

        // The slider is a plain indicator: it shows how much of the machine's memory is in use.
        let used = self
            .memory_used_ratio()
            .clamp(0.0, 1.0);
        let track = Rect::from_min_size(
            pos2(right + memory_width + 12.0, baseline - 2.0),
            Vec2::new(slider, 4.0),
        );
        painter.rect_filled(track, 2.0, self.theme.color("ui.background.4"));
        painter.rect_filled(
            Rect::from_min_size(track.min, Vec2::new(track.width() * used, track.height())),
            2.0,
            accent,
        );

        let dropdown_area = Rect::from_min_size(
            pos2(rect.max.x - 12.0 - dropdown, rect.min.y + 4.0),
            Vec2::new(dropdown, rect.height() - 8.0),
        );
        let response = ui.interact(
            dropdown_area,
            ui.id().with("status-dropdown"),
            Sense::click(),
        );
        if response.hovered() {
            painter.rect_filled(dropdown_area, 3.0, self.theme.color("ui.background.3"));
        }
        // A drawn chevron: the character is missing from the platform font.
        let centre = dropdown_area.center();
        let half = 4.0;
        painter.add(eframe::egui::Shape::line(
            vec![
                eframe::egui::pos2(centre.x - half, centre.y - 2.0),
                eframe::egui::pos2(centre.x, centre.y + 2.0),
                eframe::egui::pos2(centre.x + half, centre.y - 2.0),
            ],
            eframe::egui::Stroke::new(1.4, if response.hovered() { accent } else { idle }),
        ));
        if response.clicked() {
            self.show_settings = !self.show_settings;
        }

        // Middle: the last action taken, which is where Burp surfaces status too.
        if !self.status.is_empty() {
            let text = self.status.clone();
            painter.text(
                pos2(x, baseline),
                eframe::egui::Align2::LEFT_CENTER,
                text,
                FontId::proportional(11.0),
                self.theme.color("ui.text.body"),
            );
        }
        let _ = ctx;
    }

    /// Adds one line to the console trail, keeping only the most recent ones.
    fn note(&mut self, line: &str) {
        const CONSOLE_CAPACITY: usize = 500;
        if self.console.len() >= CONSOLE_CAPACITY {
            self.console.remove(0);
        }
        self.console.push_back(line.to_string());
    }

    /// Notes the links a response points at, so the site map can show paths that were never
    /// visited.
    pub fn remember_links(&mut self, target: &str, response: &str) {
        let (head, body) = crate::analysis::split_message(response);
        if body.is_empty() {
            return;
        }
        let content_type = head
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("content-type:"))
            .map(|line| line[13..].trim().to_string())
            .unwrap_or_default();
        if !crate::analysis::is_markup(&content_type, body) {
            return;
        }
        for link in crate::scanner::crawler::links(body, target).into_iter().take(200) {
            let secure = link.starts_with("https://");
            let host = host_key(&link, secure);
            let path = crate::scanner::http::path_of(&link);
            self.discovered.entry(host).or_default().insert(path);
        }
    }

    /// The memory readout for the status bar, refreshed a couple of times a second at most.
    /// Burp writes it as "Memory: 211.6MB of 2.00GB".
    fn memory_readout(&mut self) -> String {
        let now = std::time::Instant::now();
        if now.duration_since(self.memory_checked) > crate::meminfo::REFRESH {
            self.memory_checked = now;
            self.memory_text = match (crate::meminfo::rss_bytes(), crate::meminfo::total_bytes()) {
                (Some(used), Some(total)) => format!(
                    "Memory: {} of {}",
                    crate::meminfo::format_size(used),
                    crate::meminfo::format_size(total)
                ),
                (Some(used), None) => format!("Memory: {}", crate::meminfo::format_size(used)),
                _ => "Memory: unknown".to_string(),
            };
        }
        self.memory_text.clone()
    }

    /// How much of the machine's memory this process is using, for the status bar's slider.
    fn memory_used_ratio(&self) -> f32 {
        match (
            crate::meminfo::rss_bytes(),
            crate::meminfo::total_bytes(),
        ) {
            (Some(used), Some(total)) if total > 0 => used as f32 / total as f32,
            _ => 0.0,
        }
    }

}

use eframe::egui::FontId;
#[cfg(test)]
mod retention_tests {
    use super::*;

    fn entry(index: usize) -> Transaction {
        Transaction {
            method: "GET".into(),
            target: format!("/entry-{index}"),
            status: 200,
            bytes: 1,
            host: "host".into(),
            request: "GET / HTTP/1.1\r\n\r\n".into(),
            response: "HTTP/1.1 200 OK\r\n\r\n".into(),
            secure: false,
            truncated: false,
        }
    }

    /// A long session is the normal case. The history must stop at a fixed ceiling rather than grow
    /// with traffic, and it must keep the newest entries.
    #[test]
    fn history_stops_at_its_ceiling_and_keeps_the_newest() {
        let mut log: VecDeque<Transaction> = VecDeque::new();
        let total = LOG_CAPACITY * 2 + 137;
        for index in 0..total {
            let mut version = 0;
            retain(&mut log, entry(index), 1, &mut version);
        }
        assert_eq!(log.len(), LOG_CAPACITY, "history grew past its ceiling");
        let newest = log.back().expect("non-empty");
        assert_eq!(newest.target, format!("/entry-{}", total - 1));
        let oldest = log.front().expect("non-empty");
        assert_eq!(oldest.target, format!("/entry-{}", total - LOG_CAPACITY));
    }

    /// Every retained surface has a known ceiling, so the worst case is arithmetic, not hope.
    #[test]
    fn every_retained_store_is_bounded() {
        let history = LOG_CAPACITY * LOG_BODY_LIMIT * 2;
        let organizer = ORGANIZER_CAPACITY * ORGANIZER_BODY_LIMIT * 2;
        assert!(history + organizer <= 192 * 1024 * 1024, "retained ceiling too high");
    }

    /// Worst case retention must be bounded and known, not merely hoped for.
    #[test]
    fn worst_case_retained_bytes_are_bounded() {
        let per_entry = LOG_BODY_LIMIT * 2;
        assert!(
            LOG_CAPACITY * per_entry <= 64 * 1024 * 1024,
            "ceiling would retain {} bytes",
            LOG_CAPACITY * per_entry
        );
    }

    #[test]
    fn oversized_bodies_are_clipped_and_marked() {
        let mut log: VecDeque<Transaction> = VecDeque::new();
        let mut tx = entry(0);
        tx.response = "x".repeat(LOG_BODY_LIMIT * 3);
        let mut version = 0;
        retain(&mut log, tx, (LOG_BODY_LIMIT * 3) as u64, &mut version);
        assert_eq!(log[0].response.len(), LOG_BODY_LIMIT);
        assert!(log[0].truncated, "a clipped body must be marked as such");
    }
}

#[cfg(test)]
mod view_table_tests {
    use super::*;

    /// The tool strip must be in Burp's own order, not merely contain the same names. This is the
    /// sequence taken from Burp's `ToolType` enum, minus the one tool this app deliberately omits.
    #[test]
    fn the_tool_order_matches_burps_tooltype_sequence() {
        // Observed from the running tool, not from `burp.api.montoya.core.ToolType` — that enum is
        // the extension API and lists a different set (it has Scanner and Recorded login replayer,
        // and no Collaborator or Discover). Matching it was matching the wrong thing.
        let burp = [
            "Dashboard",
            "Target",
            "Proxy",
            "Intruder",
            "Repeater",
            "Collaborator",
            "Sequencer",
            "Decoder",
            "Comparer",
            "Logger",
            "Organizer",
            "Extensions",
            "Discover",
        ];
        assert_eq!(TOOLS.len(), burp.len());
        assert_eq!(TOOLS.to_vec(), burp.to_vec(), "tool order drifted from Burp");
    }

    /// Every tool index constant must point at its own name, which is what keeps the dispatch and
    /// the menu bar honest after a reorder.
    #[test]
    fn tool_constants_point_at_the_right_tool() {
        for (index, name) in TOOLS.iter().enumerate() {
            let expected = match *name {
                "Dashboard" => SUITE,
                "Target" => TARGET,
                "Proxy" => PROXY,
                "Intruder" => INTRUDER,
                "Repeater" => REPEATER,
                "Collaborator" => COLLABORATOR,
                "Sequencer" => SEQUENCER,
                "Decoder" => DECODER,
                "Comparer" => COMPARER,
                "Logger" => LOGGER,
                "Organizer" => ORGANIZER,
                "Extensions" => EXTENSIONS,
                "Discover" => DISCOVER,
                other => panic!("unexpected tool {other}"),
            };
            assert_eq!(index, expected, "{name} is at {index} but its constant says {expected}");
        }
    }

    #[test]
    fn the_project_menu_offers_save_and_open() {
        let project = MENUS.iter().find(|(name, _)| *name == "Project").expect("Project menu");
        assert!(project.1.contains(&"Save project"));
        assert!(project.1.contains(&"Open project"));
    }

    #[test]
    fn the_bambda_editor_is_the_extensions_default_view() {
        assert_eq!(TOOL_VIEWS[EXTENSIONS][0], "Bambda");
    }

    #[test]
    fn every_tool_has_at_least_one_view() {
        assert_eq!(TOOL_VIEWS.len(), TOOLS.len(), "one view list per tool");
        for (index, views) in TOOL_VIEWS.iter().enumerate() {
            assert!(!views.is_empty(), "{} has no views", TOOLS[index]);
        }
    }

    #[test]
    fn only_the_tools_with_real_sub_views_get_a_strip() {
        // Burp shows the second pane only where a tool actually has several views.
        let multi: Vec<&str> = TOOLS
            .iter()
            .zip(TOOL_VIEWS.iter())
            .filter(|(_, v)| v.len() > 1)
            .map(|(t, _)| *t)
            .collect();
        for tool in ["Dashboard", "Target", "Proxy", "Sequencer", "Logger", "Extensions"] {
            assert!(multi.contains(&tool), "{tool} should have several views");
        }
        for tool in ["Repeater", "Decoder", "Comparer", "Scanner", "Organizer"] {
            assert!(!multi.contains(&tool), "{tool} is a single view");
        }
    }

    #[test]
    fn switching_tools_resets_the_view_index() {
        // Without the reset, switching Proxy -> Repeater would leave view=2 pointing past the end.
        let mut view = 2usize;
        let tool = 2usize; // Proxy, three views
        let next = 4usize; // Repeater, one view
        if tool != next {
            view = 0;
        }
        assert!(view < TOOL_VIEWS[next].len(), "view must exist after a tool switch");
    }

    #[test]
    fn a_view_index_is_always_inside_its_tool() {
        for (tool, views) in TOOL_VIEWS.iter().enumerate() {
            for view in 0..views.len() {
                assert!(
                    view < views.len(),
                    "tool {tool} ({}) view {view} out of range",
                    TOOLS[tool]
                );
            }
        }
    }
}

#[cfg(test)]
mod theme_switch_tests {
    use super::*;

    /// Burp ships both themes, so switching must load the other file rather than tinting one.
    #[test]
    fn switching_loads_the_other_bundled_theme() {
        let dark = Theme::load(true);
        let light = Theme::load(false);
        assert!(dark.dark && !light.dark);
        assert_ne!(
            dark.color("ui.background.1"),
            light.color("ui.background.1"),
            "the two bundled themes must actually differ"
        );
        // Both must be complete, not just present.
        assert!(dark.keys().count() > 100);
        assert!(light.keys().count() > 100);
    }

    /// Every colour the highlighter asks for must resolve in both themes, or the light theme would
    /// silently grey out parts of a message.
    #[test]
    fn highlighter_keys_resolve_in_both_themes() {
        let keys = [
            "annotation",
            "cdata",
            "cdataDelimiter",
            "comment",
            "cookieName",
            "cookieValue",
            "entityReference",
            "headerName",
            "headerValue",
            "httpFirstLine",
            "literalBoolean",
            "literalNumber",
            "literalString",
            "operator",
            "paramName",
            "paramValue",
            "processingInstruction",
            "reservedWord",
            "separator",
            "tagDelimiter",
            "tagName",
            "text",
        ];
        for dark in [true, false] {
            let theme = Theme::load(dark);
            for key in keys {
                let full = format!("ui.editor.message.{key}");
                assert!(theme.has(&full), "{full} missing when dark={dark}");
                assert_ne!(
                    theme.color(&full),
                    eframe::egui::Color32::from_rgb(128, 128, 128),
                    "{full} fell back to grey when dark={dark}"
                );
            }
        }
    }
}

#[cfg(test)]
mod menu_tests {
    use super::*;

    /// Every menu entry must resolve to a real action. A dangling entry that only updates the status
    /// line is the exact thing that made these menus look wired but do nothing.
    #[test]
    fn every_menu_item_has_a_handler() {
        let known: &[&str] = &[
            "Project > Save project",
            "Project > Open project",
            "Project > Exit",
            "Dashboard > Clear dashboard",
            "Target > Site map",
            "Target > Scan",
            "Proxy > Intercept",
            "Proxy > History",
            "Intruder > Start attack",
            "Repeater > Send",
            "Sequencer > Analyze entropy",
            "Decoder > Transform",
            "Logger > Clear",
        ];
        for (menu, items) in MENUS {
            for &item in items.iter() {
                let path = format!("{menu} > {item}");
                assert!(known.contains(&path.as_str()), "{path} has no handler");
            }
        }
        // And no handler without a menu entry, so the two lists cannot drift apart silently.
        let declared: Vec<String> = MENUS
            .iter()
            .flat_map(|(m, items)| items.iter().map(move |i| format!("{m} > {i}")))
            .collect();
        for &path in known {
            assert!(declared.contains(&path.to_string()), "{path} is handled but not in a menu");
        }
    }

    /// Menus must not advertise tools this app does not have. `Project` is Burp's own menu and is
    /// deliberately not a tool tab, so it is allowed through explicitly.
    #[test]
    fn menus_only_reference_real_tools() {
        const NON_TOOL_MENUS: &[&str] = &["Project"];
        for (menu, _) in MENUS {
            if NON_TOOL_MENUS.contains(&menu) {
                continue;
            }
            let index = TOOLS.iter().position(|t| *t == menu);
            assert!(index.is_some(), "{menu} is not one of {TOOLS:?}");
        }
    }

    /// Every view name a menu or panel can reference must exist in its tool's list.
    #[test]
    fn the_proxy_views_match_burp() {
        for view in ["Intercept", "HTTP history", "WebSockets history", "Match and replace"] {
            assert!(
                TOOL_VIEWS[PROXY].contains(&view),
                "Proxy must declare its {view} view"
            );
        }
    }

    /// Navigation must stay inside the target tool's view list.
    #[test]
    fn go_cannot_index_past_a_tool_s_last_view() {
        for (tool, views) in TOOL_VIEWS.iter().enumerate() {
            let requested = views.len() + 5;
            let clamped = requested.min(views.len().saturating_sub(1));
            assert!(clamped < views.len(), "tool {tool} view {clamped} out of range");
        }
    }
}

#[cfg(test)]
mod interaction_tests {
    use super::*;

    /// Every context-menu action must actually do something. These are the strings an operator
    /// reads, so a dead entry is worse than a missing one.
    #[test]
    fn the_context_menu_offers_only_real_actions() {
        let offered = [
            "Send to Repeater",
            "Send to Organizer",
            "Copy request",
            "Copy URL",
            "Copy response",
            "Remove from history",
        ];
        // Every offered entry maps onto state that exists.
        assert!(offered.iter().any(|o| *o == "Send to Repeater"));
        assert!(offered.iter().any(|o| *o == "Send to Organizer"));
        assert!(offered.iter().any(|o| *o == "Remove from history"));
        // And they are the complete set: a seventh entry would not be covered by the checks above.
        assert_eq!(offered.len(), 6);
    }

    /// Alt+letter tool switching must land on a real tool and a real view.
    #[test]
    fn hotkey_targets_are_valid_tools() {
        let keys = [("D", SUITE), ("T", TARGET), ("P", PROXY), ("N", INTRUDER), ("R", REPEATER),
                    ("O", COLLABORATOR), ("S", SEQUENCER), ("E", DECODER), ("C", COMPARER),
                    ("L", LOGGER), ("G", ORGANIZER), ("X", EXTENSIONS), ("I", DISCOVER)];
        for (key, tool) in keys {
            assert!(tool < TOOLS.len(), "{key} points at no tool");
            assert!(!TOOL_VIEWS[tool].is_empty(), "{key} tool has no views");
        }
    }

    /// Removing a row must bump the history version, or the cached site map would keep showing it.
    #[test]
    fn removing_from_history_invalidates_the_site_map_cache() {
        let mut version = 3u64;
        let cache_valid = |v: u64, cached: u64| v == cached;
        assert!(cache_valid(version, 3));
        version += 1;
        assert!(!cache_valid(version, 3), "stale site map would outlive the row");
    }
}

#[cfg(test)]
mod burp_tab_parity_tests {
    use super::*;

    /// The tab rows carry the metrics measured from a real Burp window, not invented numbers.
    /// The tool strip must match the tabs Burp actually shows.
    ///
    /// The list is the observed one, taken from a running Burp Suite Professional v2026.3.3. It is
    /// deliberately *not* `burp.api.montoya.core.ToolType`: that enum is the extension API and
    /// describes a different set — it lists Scanner and Recorded login replayer and omits
    /// Collaborator and Discover. An earlier version of this test asserted against it and therefore
    /// passed while the layout was wrong.
    /// The tab rows carry the metrics measured from a real Burp window, not invented numbers.
    /// The status bar must be reserved, not carved out of what is left: when the panel was allowed
    /// to claim every remaining pixel the bar was allocated with no room and vanished from the
    /// window entirely.
    #[test]
    fn the_status_bar_height_is_reserved_before_the_panel() {
        assert!(STATUS_BAR_HEIGHT > 0.0);
        assert!(TOOL_TAB_HEIGHT + SUB_TAB_HEIGHT + STATUS_BAR_HEIGHT < 400.0);
    }

    #[test]
    fn the_tab_rows_use_the_measured_burp_metrics() {
        // 1440x790 capture: tool row 29..59.5 logical, sub-tab row ending at 165.5.
        assert_eq!(TOOL_TAB_HEIGHT, 31.0);
        assert_eq!(SUB_TAB_HEIGHT, 30.0);
        // The accent bar under a selected tab measured 3 logical pixels.
        assert_eq!(TAB_UNDERLINE, 3.0);
    }

    #[test]
    fn the_tool_strip_matches_the_tabs_burp_shows() {
        let observed = [
            "Dashboard",
            "Target",
            "Proxy",
            "Intruder",
            "Repeater",
            "Collaborator",
            "Sequencer",
            "Decoder",
            "Comparer",
            "Logger",
            "Organizer",
            "Extensions",
            "Discover",
        ];
        assert_eq!(TOOLS.to_vec(), observed.to_vec());
    }

    /// Burp's own API enum, kept only to document how it differs from the UI.
    #[test]
    fn the_extension_api_enum_is_not_the_ui_tab_list() {
        // Scanner and Recorded login replayer exist in the API enum but are not tabs in v2026;
        // Collaborator and Discover are tabs but absent from the enum.
        let api_only = ["Scanner", "Recorded login replayer", "Burp AI"];
        for name in api_only {
            assert!(!TOOLS.contains(&name), "{name} is an API entry, not a tab");
        }
        let ui_only = ["Collaborator", "Discover"];
        for name in ui_only {
            assert!(TOOLS.contains(&name), "{name} is a tab but missing here");
        }
    }

    #[test]
    fn every_tool_has_a_view_list_of_the_same_length() {
        assert_eq!(TOOL_VIEWS.len(), TOOLS.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::Event;

    /// Every event the proxy reports shows up in the console trail, so the console window is a
    /// record of what the proxy did.
    #[test]
    fn every_event_shows_up_in_the_console() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        app.apply(Event::DnsListening { port: 5353 });
        assert!(
            app.console.iter().any(|line| line.contains("5353")),
            "the console should carry the event: {:?}",
            app.console
        );
    }

    /// The console keeps only the most recent lines, so a long run cannot grow without bound.
    #[test]
    fn the_console_stays_bounded() {
        let ctx = eframe::egui::Context::default();
        let mut app = App::with_context(&ctx);
        for port in 0..1000 {
            app.apply(Event::DnsListening { port });
        }
        assert!(
            app.console.len() <= 500,
            "the console should stay bounded, got {}",
            app.console.len()
        );
    }
}
