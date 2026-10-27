//! The proxy and request machinery, as a library the GUI drives in-process.
//!
//! Everything here used to live inside the newline-delimited JSON binary. That binary is now a thin
//! adapter over this module, and the GUI talks to it directly instead of across a pipe.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, broadcast, oneshot};

/// A connection that can be read and written, whether it is a plain socket or a TLS one.
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

/// A whole connection, boxed.
type StreamBox = Box<dyn Stream>;
/// A stream the proxy reads from.
type ReadBox = Box<dyn tokio::io::AsyncRead + Unpin + Send>;
/// A stream the proxy writes to.
type WriteBox = Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
type Io = BufReader<ReadBox>;
type Out = WriteBox;

/// How much of a body the proxy keeps for display. Beyond this the operator still sees the correct
/// byte count, but the text is truncated, so memory stays bounded on a large transfer.
pub const BODY_CAPTURE_LIMIT: usize = 512 * 1024;
/// Manual tools return a full text response, so reject larger captures before allocating them.
pub const MANUAL_RESPONSE_LIMIT: usize = 32 * 1024 * 1024;

/// Everything the proxy tells its owner about.
#[derive(Clone, Debug)]
pub enum Event {
    /// The listener bound, or failed to. The UI learns the outcome this way rather than by polling.
    Listening { port: u16 },
    ListenerStopped,
    Tx {
        method: String,
        target: String,
        status: u16,
        bytes: u64,
        /// The request as sent, for Repeater and the history detail view.
        request: String,
        /// The response head and captured body.
        response: String,
        /// Whether the traffic was carried over TLS.
        secure: bool,
    },
    Held { id: u64, method: String, target: String, raw: String },
    /// A response parked for the operator to look at, change or let through.
    HeldResponse { id: u64, status: u16, raw: String },
    Released { id: u64, forwarded: bool },
    Dropped { id: u64 },
    /// A connection completed a WebSocket handshake and its frames are now being recorded.
    WsOpen {
        id: u64,
        host: String,
        request: String,
        response: String,
    },
    /// One decoded WebSocket frame. `to_server` is false for frames travelling toward the client.
    WsFrame { id: u64, to_server: bool, opcode: u8, text: String, bytes: usize },
    WsClosed { id: u64 },
    /// The DNS or SMTP capture listener bound.
    DnsListening { port: u16 },
    SmtpListening { port: u16 },
    /// One DNS exchange seen by the Logger's DNS view.
    Dns { question: String, kind: u16, answers: Vec<String>, server: String },
    /// One SMTP message seen by the Logger's Email view.
    Smtp { direction: String, from: String, to: Vec<String>, subject: String, body: String },
    AttackResult { index: usize, status: u16, length: usize, matched: bool, error: Option<String> },
    AttackDone { total: usize, matches: usize },
    Error(String),
}

/// What a parked message is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeldKind {
    Request,
    Response,
}

/// A message parked until the operator forwards or drops it.
///
/// The decision carries the message to send, so the operator can edit it before it is let
/// through. `None` means drop it.
struct Held {
    kind: HeldKind,
    method: String,
    target: String,
    raw: String,
    decision: oneshot::Sender<Option<String>>,
}

/// The most body bytes the proxy will hold for editing. A bigger body is streamed untouched.
pub const MAX_HELD_BODY: usize = 8 * 1024 * 1024;

/// A parked request as the UI sees it.
#[derive(Clone, Debug)]
pub struct HeldInfo {
    pub id: u64,
    pub kind: HeldKind,
    pub method: String,
    pub target: String,
    pub raw: String,
}

/// Match rules for an Intruder run.
#[derive(Default, Clone)]
pub struct MatchRules {
    pub status: Vec<u16>,
    pub negative_status: Vec<u16>,
    pub negative_regex: Option<regex::Regex>,
    pub length: bool,
}

impl MatchRules {
    pub fn new(
        status: Vec<u16>,
        negative_status: Vec<u16>,
        negative_regex: Option<String>,
        length: bool,
    ) -> Self {
        Self {
            status,
            negative_status,
            negative_regex: negative_regex
                .filter(|s| !s.is_empty())
                .and_then(|s| regex::Regex::new(&s).ok()),
            length,
        }
    }
}

struct Inner {
    lifecycle: Mutex<()>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The DNS capture listener, kept so the Logger panel's Stop actually ends it.
    dns_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The SMTP capture listener, same purpose.
    smtp_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The port the live listener is bound to, so a restart can report the same one.
    bound: tokio::sync::Mutex<Option<u16>>,
    held: std::sync::Mutex<HashMap<u64, Held>>,
    intercept: AtomicBool,
    /// Whether responses are parked as well.
    intercept_response: AtomicBool,
    /// Whether an https connection is intercepted, or passed through as a tunnel.
    intercept_tls: AtomicBool,
    next_held: AtomicU64,
    next_ws: AtomicU64,
    matches: AtomicUsize,
    events: broadcast::Sender<Event>,
    /// Session handling: cookies learned from `Set-Cookie` and replayed on later requests.
    cookies: crate::cookies::CookieJar,
    /// The match-and-replace script, applied to requests on their way out.
    rules: std::sync::RwLock<Option<Vec<crate::bambda::Statement>>>,
    /// The authority that signs the certificates the proxy hands to clients that ask for https.
    authority: Option<Arc<crate::tls::Authority>>,
    /// Authorities the proxy trusts on top of the system roots, for origins that serve a
    /// certificate from their own certificate authority.
    extra_roots: std::sync::Mutex<Vec<rustls::pki_types::CertificateDer<'static>>>,
    /// Host patterns that bypass TLS MITM interception and tunnel straight through.
    passthrough_hosts: std::sync::RwLock<Vec<String>>,
    /// Automatically add hosts to `passthrough_hosts` when client TLS handshake fails.
    auto_passthrough_on_error: AtomicBool,
    /// Live HTTP response modification rules (`Proxy -> Proxy settings`).
    response_mod: std::sync::RwLock<ResponseModRules>,
}

impl Inner {
    fn next_ws_id(&self) -> u64 {
        self.next_ws.fetch_add(1, Ordering::Relaxed)
    }

    /// Emits a decoded DNS exchange.
    fn record_dns(&self, question: String, kind: u16, answers: Vec<String>, server: String) {
        let _ = self.events.send(Event::Dns { question, kind, answers, server });
    }

    /// Emits a captured SMTP message.
    fn record_smtp(&self, direction: String, from: String, to: Vec<String>, subject: String, body: String) {
        let _ = self.events.send(Event::Smtp { direction, from, to, subject, body });
    }

    /// Emits one decoded WebSocket frame for the UI to record.
    fn record_frame(&self, id: u64, to_server: bool, frame: &crate::ws::Frame) {
        // Binary frames are shown as a summary rather than dumped, since a payload can be megabytes.
        const TEXT_LIMIT: usize = 8 * 1024;
        let text = if frame.payload.len() > TEXT_LIMIT {
            format!("<{} bytes>", frame.payload.len())
        } else {
            match frame.as_text() {
                Some(t) => t.to_string(),
                None => format!("<{} bytes>", frame.payload.len()),
            }
        };
        let _ = self.events.send(Event::WsFrame {
            id,
            to_server,
            opcode: frame.opcode,
            text,
            bytes: frame.payload.len(),
        });
    }
}

/// Built-in HTTP response modification rules configured in `Proxy -> Proxy settings`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResponseModRules {
    pub unhide_fields: bool,
    pub highlight_unhidden: bool,
    pub enable_disabled: bool,
    pub remove_maxlength: bool,
    pub remove_js_validation: bool,
    pub remove_all_js: bool,
    pub https_to_http: bool,
    pub strip_cookie_secure: bool,
}

impl ResponseModRules {
    pub fn is_active(&self) -> bool {
        self.unhide_fields
            || self.highlight_unhidden
            || self.enable_disabled
            || self.remove_maxlength
            || self.remove_js_validation
            || self.remove_all_js
            || self.https_to_http
            || self.strip_cookie_secure
    }

    pub fn apply(&self, response: &str) -> String {
        if !self.is_active() || response.is_empty() {
            return response.to_string();
        }
        let (head, body) = crate::analysis::split_message(response);
        let mut new_head = head.to_string();
        let mut new_body = body.to_string();

        if self.strip_cookie_secure {
            let mut lines = Vec::new();
            for line in new_head.lines() {
                if line
                    .split_once(':')
                    .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("set-cookie"))
                {
                    let cleaned = line
                        .replace("; Secure", "")
                        .replace("; secure", "")
                        .replace(";Secure", "")
                        .replace(";secure", "");
                    lines.push(cleaned);
                } else {
                    lines.push(line.to_string());
                }
            }
            new_head = lines.join("\r\n");
        }

        if self.unhide_fields {
            let replacement = if self.highlight_unhidden {
                "type=\"text\" style=\"border:2px solid #ff6633;background:#fff3cd\""
            } else {
                "type=\"text\""
            };
            new_body = new_body
                .replace("type=\"hidden\"", replacement)
                .replace("type='hidden'", replacement)
                .replace("TYPE=\"HIDDEN\"", replacement);
        }
        if self.enable_disabled {
            new_body = new_body
                .replace(" disabled=\"disabled\"", "")
                .replace(" disabled='disabled'", "")
                .replace(" disabled", "");
        }
        if self.remove_maxlength {
            new_body = new_body
                .replace("maxlength=", "data-removed-maxlength=")
                .replace("maxLength=", "data-removed-maxlength=");
        }
        if self.remove_js_validation {
            for attr in ["onsubmit=", "onchange=", "onblur=", "onkeyup=", "onkeydown="] {
                new_body = new_body.replace(attr, "data-removed-event=");
            }
        }
        if self.remove_all_js {
            new_body = new_body
                .replace("<script", "<!-- script removed ")
                .replace("</script>", " /script -->");
        }
        if self.https_to_http {
            new_body = new_body.replace("https://", "http://");
        }

        crate::intruder::sync_content_length(&format!("{new_head}\r\n\r\n{new_body}"))
    }
}
/// The running proxy. Cheap to clone; every clone drives the same listener.
#[derive(Clone)]
pub struct Proxy {
    inner: Arc<Inner>,
}

impl Proxy {
    pub fn new() -> (Self, broadcast::Receiver<Event>) {
        let (events, rx) = broadcast::channel(1024);
        // The authority is made up front, so the certificate a browser has to trust is on disk
        // before the first https request is made.
        let authority = crate::tls::Authority::generate().ok().map(Arc::new);
        (
            Proxy {
                inner: Arc::new(Inner {
                    lifecycle: Mutex::new(()),
                    task: Mutex::new(None),
                    dns_task: Mutex::new(None),
                    smtp_task: Mutex::new(None),
                    bound: tokio::sync::Mutex::new(None),
                    held: std::sync::Mutex::new(HashMap::new()),
                    intercept: AtomicBool::new(false),
                    intercept_response: AtomicBool::new(false),
                    intercept_tls: AtomicBool::new(true),
                    next_held: AtomicU64::new(1),
                    next_ws: AtomicU64::new(1),
                    matches: AtomicUsize::new(0),
                    events,
                    cookies: crate::cookies::CookieJar::new(),
                    rules: std::sync::RwLock::new(None),
                    authority,
                    extra_roots: std::sync::Mutex::new(Vec::new()),
                    passthrough_hosts: std::sync::RwLock::new(Vec::new()),
                    auto_passthrough_on_error: AtomicBool::new(false),
                    response_mod: std::sync::RwLock::new(ResponseModRules::default()),
                }),
            },
            rx,
        )
    }

    pub fn set_tls_passthrough(&self, hosts: Vec<String>, auto_on_error: bool) {
        if let Ok(mut guard) = self.inner.passthrough_hosts.write() {
            *guard = hosts;
        }
        self.inner
            .auto_passthrough_on_error
            .store(auto_on_error, Ordering::SeqCst);
    }

    pub fn is_tls_passthrough(&self, host: &str) -> bool {
        let host_lc = host.trim().to_ascii_lowercase();
        if host_lc.is_empty() {
            return false;
        }
        let Ok(guard) = self.inner.passthrough_hosts.read() else {
            return false;
        };
        guard.iter().any(|pattern| {
            let pat = pattern.trim().to_ascii_lowercase();
            if pat.is_empty() {
                return false;
            }
            if let Some(suffix) = pat.strip_prefix("*.") {
                host_lc == suffix || host_lc.ends_with(&format!(".{suffix}"))
            } else {
                host_lc == pat || host_lc.ends_with(&format!(".{pat}"))
            }
        })
    }

    pub fn set_response_mod_rules(&self, rules: ResponseModRules) {
        if let Ok(mut guard) = self.inner.response_mod.write() {
            *guard = rules;
        }
    }

    pub fn apply_response_mod_rules(&self, response: &str) -> String {
        let Ok(guard) = self.inner.response_mod.read() else {
            return response.to_string();
        };
        guard.apply(response)
    }

    fn emit(&self, event: Event) {
        // A send error only means nobody is listening yet, which is not a failure.
        let _ = self.inner.events.send(event);
    }

    /// Starts the DNS capture listener on its own port.
    ///
    /// DNS is a separate protocol on a separate socket, so it gets a listener of its own rather
    /// than a mode on the HTTP one. `port` 0 asks the OS for an ephemeral port.
    pub async fn start_dns(&self, port: u16) -> io::Result<u16> {
        let bind = tokio::net::UdpSocket::bind(("127.0.0.1", port)).await?;
        let actual = bind.local_addr()?.port();
        self.emit(Event::DnsListening { port: actual });
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = bind.recv_from(&mut buf).await else { continue };
                let Ok(request) = crate::dns::decode(&buf[..n]) else { continue };
                let Some(question) = request.questions.first() else { continue };
                let mut answer = crate::dns::query(question_id(&buf[..n]), &question.name, question.kind, question.class);
                // Mark it as a response so a resolver accepts it.
                if answer.len() >= 4 {
                    answer[2] |= 0x80;
                }
                let _ = bind.send_to(&answer, peer).await;
                let answers = request
                    .answers
                    .iter()
                    .map(|a| format!("{} {} ttl {}", a.name, crate::dns::kind_name(a.kind), a.ttl))
                    .collect();
                inner.record_dns(question.name.clone(), question.kind, answers, peer.to_string());
            }
        });
        *self.inner.dns_task.lock().await = Some(handle);
        Ok(actual)
    }

    /// Stops the DNS capture listener.
    pub async fn stop_dns(&self) {
        if let Some(handle) = self.inner.dns_task.lock().await.take() {
            handle.abort();
        }
    }

    /// True while the DNS capture listener is bound.
    pub async fn dns_running(&self) -> bool {
        self.inner.dns_task.lock().await.is_some()
    }

    /// Starts the SMTP capture listener.
    ///
    /// This is a passive observer: it speaks just enough SMTP to keep the conversation moving and
    /// records the headers and body of each message. It does not queue or relay.
    pub async fn start_smtp(&self, port: u16) -> io::Result<u16> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        let actual = listener.local_addr()?.port();
        self.emit(Event::SmtpListening { port: actual });
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let inner = inner.clone();
                tokio::spawn(async move { observe_smtp(stream, inner).await });
            }
        });
        *self.inner.smtp_task.lock().await = Some(handle);
        Ok(actual)
    }

    /// Stops the SMTP capture listener.
    pub async fn stop_smtp(&self) {
        if let Some(handle) = self.inner.smtp_task.lock().await.take() {
            handle.abort();
        }
    }

    /// True while the SMTP capture listener is bound.
    pub async fn smtp_running(&self) -> bool {
        self.inner.smtp_task.lock().await.is_some()
    }

    /// Binds and starts accepting. Port 0 asks the OS for an ephemeral one.
    pub async fn start(&self, port: u16) -> io::Result<u16> {
        let _guard = self.inner.lifecycle.lock().await;
        self.start_unlocked(port, false).await
    }

    /// Atomically starts or reuses the ready listener for the integrated browser.
    pub async fn ensure_started(&self, port: u16) -> io::Result<u16> {
        let _guard = self.inner.lifecycle.lock().await;
        self.start_unlocked(port, true).await
    }

    async fn start_unlocked(&self, port: u16, reuse: bool) -> io::Result<u16> {
        // Bound to a local so the guard is released before bound_port() locks it again.
        let already_running = self.inner.task.lock().await.is_some();
        if already_running {
            let existing = self.bound_port().await.unwrap_or(port);
            self.emit(Event::Listening { port: existing });
            if reuse { return Ok(existing); }
            return Err(io::Error::other("already listening"));
        }
        let listener = match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => listener,
            Err(error) => {
                self.emit(Event::Error(format!("Cannot listen on port {port}: {error}")));
                return Err(error);
            }
        };
        let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
        *self.inner.bound.lock().await = Some(bound);
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            loop {
                let accept = listener.accept().await;
                if inner.task.lock().await.is_none() {
                    return;
                }
                match accept {
                    Ok((stream, _)) => {
                        let proxy = Proxy { inner: inner.clone() };
                        tokio::spawn(async move { proxy.handle(stream).await });
                    }
                    Err(_) => return,
                }
            }
        });
        *self.inner.task.lock().await = Some(handle);
        self.emit(Event::Listening { port: bound });
        Ok(bound)
    }

    /// The port currently bound, if the listener is running.
    pub async fn bound_port(&self) -> Option<u16> {
        let running = self.inner.task.lock().await.is_some();
        if running {
            *self.inner.bound.lock().await
        } else {
            None
        }
    }

    /// Sets the match-and-replace script. A script that does not parse is refused, so a typo never
    /// silently disables the rules.
    pub fn set_rules(&self, source: &str) -> Result<(), String> {
        let script = crate::bambda::parse(source).map_err(|e| e.to_string())?;
        *self.inner.rules.write().unwrap_or_else(|e| e.into_inner()) = Some(script);
        Ok(())
    }

    /// Removes the match-and-replace script.
    pub fn clear_rules(&self) {
        *self.inner.rules.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// True when a match-and-replace script is active.
    pub fn has_rules(&self) -> bool {
        self.inner.rules.read().unwrap_or_else(|e| e.into_inner()).is_some()
    }

    /// Applies the match-and-replace rules to a request, when any are set.
    pub fn apply_rules(&self, head: &str) -> String {
        let guard = self.inner.rules.read().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(script) => crate::bambda::run(script, head),
            None => head.to_string(),
        }
    }

    /// Adds a `Cookie` header when the request lacks one and the jar has something to send.
    fn apply_cookies(&self, head: String, host: &str, port: u16) -> String {
        if head.to_lowercase().contains("\ncookie:") || head.to_lowercase().starts_with("cookie:") {
            return head;
        }
        let path = request_path(&head);
        let secure = port == 443;
        let Some(value) = self.inner.cookies.header(host, &path, secure) else {
            return head;
        };
        // Keep the head/body separator intact whatever line ending the request used.
        if let Some(at) = head.find("\r\n\r\n") {
            let mut out = String::with_capacity(head.len() + value.len() + 16);
            out.push_str(&head[..at]);
            out.push_str("\r\nCookie: ");
            out.push_str(&value);
            out.push_str(&head[at..]);
            return out;
        }
        format!("{head}\r\nCookie: {value}\r\n\r\n")
    }

    pub async fn stop(&self) {
        let _guard = self.inner.lifecycle.lock().await;
        self.release_all();
        let handle = self.inner.task.lock().await.take();
        if let Some(h) = handle {
            h.abort();
        }
        // The capture listeners belong to the same session, so stopping the proxy stops them.
        if let Some(h) = self.inner.dns_task.lock().await.take() {
            h.abort();
        }
        if let Some(h) = self.inner.smtp_task.lock().await.take() {
            h.abort();
        }
        *self.inner.bound.lock().await = None;
        self.emit(Event::ListenerStopped);
    }

    /// The cookie jar, for the Proxy panel's Cookies view.
    pub fn cookies(&self) -> &crate::cookies::CookieJar {
        &self.inner.cookies
    }

    pub fn set_intercept(&self, on: bool) {
        self.inner.intercept.store(on, Ordering::SeqCst);
        if !on {
            self.release_all();
        }
    }

    pub fn intercepting(&self) -> bool {
        self.inner.intercept.load(Ordering::SeqCst)
    }

    /// Trusts one more authority when the proxy dials an origin.
    ///
    /// An origin that serves a certificate from its own certificate authority is otherwise
    /// unreachable, because the proxy only trusts the system roots.
    pub fn add_trusted_root(&self, root: rustls::pki_types::CertificateDer<'static>) {
        if let Ok(mut roots) = self.inner.extra_roots.lock() {
            roots.push(root);
        }
    }

    /// The proxy's own certificate, for a client that has to trust the proxy.
    pub fn authority_certificate(&self) -> Option<rustls::pki_types::CertificateDer<'static>> {
        self.inner.authority.as_ref().map(|a| a.certificate_der())
    }

    /// Where the proxy's certificate was written, so a browser can be pointed at it.
    pub fn authority_path(&self) -> Option<std::path::PathBuf> {
        self.inner.authority.as_ref().map(|a| a.path.clone())
    }

    /// The proxy's CA certificate in PEM format.
    pub fn authority_pem(&self) -> Option<String> {
        self.inner.authority.as_ref().map(|a| a.pem())
    }

    /// Raw DER bytes of the proxy's CA certificate (`cacert.der`).
    pub fn authority_der(&self) -> Option<Vec<u8>> {
        self.inner.authority.as_ref().map(|a| a.der_bytes())
    }

    /// Raw PKCS#8 DER bytes of the proxy's CA private key (`cakey.pkcs8.der`).
    pub fn authority_private_key_der(&self) -> Option<Vec<u8>> {
        self.inner.authority.as_ref().map(|a| a.private_key_der())
    }

    /// PEM-encoded PKCS#8 private key of the proxy's CA (`cakey.pem`).
    pub fn authority_private_key_pem(&self) -> Option<String> {
        self.inner.authority.as_ref().map(|a| a.private_key_pem())
    }

    /// Regenerates a fresh CA keypair and certificate, clearing cached per-host leaf certs.
    pub fn regenerate_authority(&self) -> Result<(), String> {
        self.inner
            .authority
            .as_ref()
            .ok_or_else(|| String::from("Proxy certificate authority is not initialized"))?
            .regenerate()
    }

    /// Imports a custom CA private key (PEM or PKCS#8 DER) and binds the CA certificate.
    pub fn import_authority_key(&self, key_bytes: &[u8]) -> Result<(), String> {
        self.inner
            .authority
            .as_ref()
            .ok_or_else(|| String::from("Proxy certificate authority is not initialized"))?
            .import_key(key_bytes)
    }

    /// Sets the listener TLS certificate generation mode (`0 = per-host`, `1 = self-signed`, `2 = specific host`).
    pub fn set_cert_mode(&self, mode: usize, specific_host: String) {
        if let Some(auth) = &self.inner.authority {
            auth.set_cert_mode(mode, specific_host);
        }
    }

    pub fn browser_ca_pin(&self) -> Result<String, String> {
        self.inner.authority.as_ref().map(|a| a.spki_pin())
            .ok_or_else(|| "Proxy certificate authority could not be initialized".into())
    }

    /// Whether an https connection is intercepted. With it off the connection is passed through
    /// as a tunnel, so nothing inside it can be seen or changed.
    pub fn set_tls_interception(&self, on: bool) {
        self.inner.intercept_tls.store(on, Ordering::SeqCst);
    }

    pub fn tls_intercepting(&self) -> bool {
        self.inner.intercept_tls.load(Ordering::SeqCst)
    }

    /// Turns response interception on or off. It only matters while requests are intercepted.
    pub fn set_intercept_response(&self, on: bool) {
        self.inner.intercept_response.store(on, Ordering::SeqCst);
    }

    pub fn intercepting_response(&self) -> bool {
        self.inner.intercept_response.load(Ordering::SeqCst)
    }

    pub async fn held(&self) -> Vec<HeldInfo> {
        let held = self.inner.held.lock().unwrap_or_else(|error| error.into_inner());
        let mut items: Vec<HeldInfo> = held
            .iter()
            .map(|(id, h)| HeldInfo {
                id: *id,
                kind: h.kind,
                method: h.method.clone(),
                target: h.target.clone(),
                raw: h.raw.clone(),
            })
            .collect();
        items.sort_by_key(|h| h.id);
        items
    }

    /// Releases one parked request. Returns false when the id is unknown or already answered.
    pub async fn forward(&self, id: u64) -> bool {
        let item = self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
        let ok = item
            .map(|i| i.decision.send(Some(i.raw)).is_ok())
            .unwrap_or(false);
        self.emit(Event::Released { id, forwarded: ok });
        ok
    }

    /// Releases one parked request with the message the operator edited.
    pub async fn forward_edited(&self, id: u64, raw: &str) -> bool {
        let item = self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
        let ok = item
            .map(|i| i.decision.send(Some(raw.to_string())).is_ok())
            .unwrap_or(false);
        self.emit(Event::Released { id, forwarded: ok });
        ok
    }

    /// Discards one parked request instead of letting it through.
    pub async fn discard(&self, id: u64) -> bool {
        let item = self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
        let ok = item.map(|i| i.decision.send(None).is_ok()).unwrap_or(false);
        self.emit(Event::Released { id, forwarded: false });
        ok
    }

    pub async fn forward_all(&self) {
        self.release_all();
    }

    /// Releases every parked request. Used when interception is switched off.
    pub fn release_all(&self) {
        let items: Vec<_> = self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).drain().collect();
        for (id, item) in items {
            let forwarded = item.decision.send(Some(item.raw)).is_ok();
            self.emit(Event::Released { id, forwarded });
        }
    }

    /// Sends one raw request and returns the status and full response text.
    pub async fn one_shot(&self, host: &str, port: u16, raw: &str, timeout_ms: u64) -> Result<(u16, String), String> {
        self.one_shot_secure(host, port, raw, false, timeout_ms).await
    }

    /// The same, over TLS when the target is a secure one.
    pub async fn one_shot_secure(
        &self,
        host: &str,
        port: u16,
        raw: &str,
        secure: bool,
        timeout_ms: u64,
    ) -> Result<(u16, String), String> {
        // The rules apply to every request this build sends, not only the ones that pass through
        // the listener, so Repeater, the scanner and Discover see the same rewriting.
        let raw = self.apply_rules(raw);
        let roots = self.inner.extra_roots.lock().map(|roots| roots.clone()).unwrap_or_default();
        let call = one_shot(host, port, &raw, secure, &roots);
        match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), call).await {
            Ok(Ok((status, response))) => {
                let first_line = raw.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();
                let method = parts.next().unwrap_or("GET").to_string();
                let req_target = parts.next().unwrap_or("/");
                let scheme = if secure { "https" } else { "http" };
                let default_port = if secure { 443 } else { 80 };
                let authority = if port == default_port {
                    host.to_string()
                } else {
                    format!("{host}:{port}")
                };
                let target =
                    if req_target.starts_with("http://") || req_target.starts_with("https://") {
                        req_target.to_string()
                    } else if req_target.starts_with('/') {
                        format!("{scheme}://{authority}{req_target}")
                    } else {
                        format!("{scheme}://{authority}/{req_target}")
                    };
                self.emit(Event::Tx {
                    method,
                    target,
                    status,
                    bytes: response.len() as u64,
                    request: raw,
                    response: response.clone(),
                    secure,
                });
                Ok((status, response))
            }
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timed out".to_string()),
        }
    }

    /// Records a synthetic or failed tool transaction into the shared proxy/Logger stream.
    pub fn record_tx(
        &self,
        method: String,
        target: String,
        status: u16,
        request: String,
        response: String,
        secure: bool,
    ) {
        self.emit(Event::Tx {
            method,
            target,
            status,
            bytes: response.len() as u64,
            request,
            response,
            secure,
        });
    }

    /// Runs an Intruder grid with bounded concurrency, emitting one result per request.
    pub async fn attack(
        &self,
        host: String,
        port: u16,
        requests: Vec<String>,
        threads: usize,
        rules: MatchRules,
    ) {
        self.inner.matches.store(0, Ordering::SeqCst);
        let total = requests.len();
        let cursor = Arc::new(AtomicUsize::new(0));
        let baseline = Arc::new(AtomicUsize::new(usize::MAX));
        let workers = threads.clamp(1, 64).min(total.max(1));

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let cursor = cursor.clone();
            let host = host.clone();
            let requests = requests.clone();
            let rules = rules.clone();
            let proxy = self.clone();
            let baseline = baseline.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    let index = cursor.fetch_add(1, Ordering::SeqCst);
                    if index >= requests.len() {
                        return;
                    }
                    let raw = requests[index].clone();
                    let outcome = proxy.one_shot(&host, port, &raw, 15_000).await;
                    let event = match outcome {
                        Ok((status, body)) => {
                            let length = body.len();
                            let matched = apply_rules(&rules, &baseline, status, &body);
                            if matched {
                                proxy.inner.matches.fetch_add(1, Ordering::SeqCst);
                            }
                            Event::AttackResult { index, status, length, matched, error: None }
                        }
                        Err(error) => Event::AttackResult {
                            index,
                            status: 0,
                            length: 0,
                            matched: false,
                            error: Some(error),
                        },
                    };
                    proxy.emit(event);
                }
            }));
        }
        for handle in handles {
            let _ = handle.await;
        }
        let matches = self.inner.matches.load(Ordering::SeqCst);
        self.emit(Event::AttackDone { total, matches });
    }

    async fn handle(self, mut stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        // The first request is read a byte at a time, so nothing is taken off the wire that the
        // connection still needs. A `CONNECT` needs the whole socket, because the TLS handshake
        // runs on it afterwards.
        let head = match read_head_exact(&mut stream).await {
            Ok(h) => h,
            Err(_) => return,
        };
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();

        if method.eq_ignore_ascii_case("CONNECT") {
            let (connect_host, _) = split_authority(&target);
            if self.inner.intercept_tls.load(Ordering::SeqCst)
                && !self.is_tls_passthrough(&connect_host)
            {
                self.serve_tls(stream, head).await;
            } else {
                // Without interception (or for TLS pass-through hosts) the tunnel is passed through as-is.
                let (read, write) = stream.into_split();
                let reader = BufReader::new(Box::new(read) as ReadBox);
                self.tunnel(reader, Box::new(write) as Out, &method, &target).await;
            }
            return;
        }
        let (read, write) = stream.into_split();
        let reader = BufReader::new(Box::new(read) as ReadBox);
        self.forward_request(reader, Box::new(write) as Out, head, &method, &target, false)
            .await;
    }

    async fn forward_request(
        self,
        mut reader: Io,
        mut client: Out,
        head: String,
        method: &str,
        target: &str,
        secure: bool,
    ) {
        // While intercepting, the body is read in as well, so the whole message can be edited
        // before it goes out. A body too large to hold is streamed on untouched.
        let mut head = head;
        let capture_target = crate::http_target::request_url(&head, secure).unwrap_or_else(|_| target.to_owned());
        if self.serve_portal(&mut client, &capture_target).await {
            return;
        }
        let mut held_body: Option<Vec<u8>> = None;
        if self.inner.intercept.load(Ordering::SeqCst) {
            if let Some(length) = content_length(&head) {
                if length <= MAX_HELD_BODY {
                    let mut buffer = vec![0u8; length];
                    if reader.read_exact(&mut buffer).await.is_ok() {
                        held_body = Some(buffer);
                    }
                }
            }
            let raw = match &held_body {
                Some(body) => format!("{head}{}", String::from_utf8_lossy(body)),
                None => head.clone(),
            };
            let (decision, wait) = oneshot::channel();
            let id = self.inner.next_held.fetch_add(1, Ordering::SeqCst);
            let queued = {
            let mut held = self.inner.held.lock().unwrap_or_else(|error| error.into_inner());
            if self.inner.intercept.load(Ordering::SeqCst) {
            held.insert(
                id,
                Held {
                    kind: HeldKind::Request,
                    method: method.to_string(),
                    target: capture_target.clone(),
                    raw: raw.clone(),
                    decision,
                },
            );
            true
            } else { let _ = decision.send(Some(raw.clone())); false }
            };
            if queued {
            self.emit(Event::Held {
                id,
                method: method.to_string(),
                target: capture_target,
                raw,
            });
            }
            match wait.await {
                Ok(Some(edited)) => {
                    // The operator may have changed the request line, the headers or the body.
                    let (edited_head, edited_body) = split_message(&edited);
                    head = fix_content_length(&edited_head, edited_body.as_deref());
                    if let Some(body) = edited_body {
                        held_body = Some(body.into_bytes());
                    }
                }
                _ => {
                    self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
                    self.emit(Event::Dropped { id });
                    return;
                }
            }
        }

        let method = head.split_whitespace().next().unwrap_or(method).to_owned();
        let target_address = match crate::http_target::request_url(&head, secure) {
            Ok(address) => address,
            Err(error) => {
                let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
                self.emit(Event::Error(error));
                return;
            }
        };
        let service = match crate::http_target::HttpTarget::parse(&target_address) {
            Ok(service) => service,
            Err(error) => { self.emit(Event::Error(error)); return; }
        };
        let target = target_address.as_str();
        let method = method.as_str();
        let (host, port, secure) = (service.host, service.port, service.secure);
        let roots = self.inner.extra_roots.lock().map(|r| r.clone()).unwrap_or_default();
        let mut upstream = match connect_upstream(&host, port, secure, &roots).await {
            Ok(s) => s,
            Err(_) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                self.emit(Event::Tx {
                    method: method.to_string(),
                    target: target.to_string(),
                    status: 502,
                    bytes: 0,
                    request: head.clone(),
                    response: "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".into(),
                    secure,
                });
                return;
            }
        };
        // Session handling: replay cookies this jar already holds for the target, and learn new ones
        // from the response. A request that already carries a Cookie header is left alone, so an
        // explicit cookie always wins over the jar.
        // Match-and-replace runs first, so a rule can rewrite a header the cookie jar would add.
        let head = sanitize_upstream_request_headers(&self.apply_cookies(self.apply_rules(&head), &host, port));
        if upstream.write_all(head.as_bytes()).await.is_err() {
            self.emit(Event::Error(format!("write upstream: {target}")));
            return;
        }
        if let Some(body) = held_body.as_ref() {
            // The body was read in while intercepting, so it is sent from here and the client's
            // stream holds nothing more to copy.
            if upstream.write_all(body).await.is_err() {
                self.emit(Event::Error(format!("write upstream body: {target}")));
                return;
            }
        }

        let (up_read, up_write) = tokio::io::split(upstream);
        // A WebSocket upgrade is relay-only after the handshake, so the blind forwarder must not
        // start: it would consume the client half this handler needs to decode frames.
        // A WebSocket upgrade is relay-only after the handshake, so this path keeps both halves
        // here and returns before the ordinary forwarder below can take the client's read half.
        if crate::ws::is_upgrade(&head) {
            let mut up_reader = BufReader::new(Box::new(up_read) as ReadBox);
            let (status, status_line) = take_status_line(&mut up_reader).await;
            if client.write_all(&status_line).await.is_err() {
                return;
            }
            if status != 101 {
                self.emit(Event::Error(format!(
                    "upgrade to websocket refused with {status}"
                )));
                return;
            }
            // The 101 still carries headers, so the head has to be drained before frames start.
            let mut rest = String::new();
            loop {
                match up_reader.read_line(&mut rest).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if n == 0 || rest.ends_with("\r\n\r\n") || rest.ends_with("\n\n") {
                            break;
                        }
                        if rest.len() > 64 * 1024 {
                            break;
                        }
                    }
                }
            }
            let _ = client.write_all(rest.as_bytes()).await;
            let _ = client.flush().await;
            let response = format!("{}{rest}", String::from_utf8_lossy(&status_line));
            let id = self.inner.next_ws_id();
            self.emit(Event::WsOpen {
                id,
                // The resolved authority, not the request target: the target is just the path, and
                // a WebSocket list grouped by target would be useless.
                host: format!("{host}:{port}"),
                request: head.clone(),
                response,
            });
            self.relay_websocket(id, reader, client, up_reader, Box::new(up_write) as Out).await;
            self.emit(Event::WsClosed { id });
            return;
        }

        // Never wait for client EOF: a keep-alive client does not send one. When the body was
        // read in while intercepting it has already been sent, so there is nothing left to copy.
        if held_body.is_none() && (content_length(&head).is_some_and(|length| length > 0) || header_has_token(&head, "transfer-encoding", "chunked")) {
            let mut out: Out = Box::new(up_write);
            let body_head = head.clone();
            tokio::spawn(async move {
                let _ = copy_framed_body(&mut reader, &mut out, &body_head, "POST", 200).await;
            });
        }

        let mut up_reader = BufReader::new(Box::new(up_read) as ReadBox);

        if self.inner.intercept.load(Ordering::SeqCst) && self.inner.intercept_response.load(Ordering::SeqCst) {
            // The whole response head is read in, because the length of the body is only known
            // once the headers have been seen.
            let (head_status, head_text, head_bytes) = loop {
                let (status, head, bytes) = read_response_head(&mut up_reader).await;
                if status == 0 { self.emit(Event::Error("Invalid response headers".into())); return; }
                if (100..200).contains(&status) && status != 101 {
                    if client.write_all(&bytes).await.is_err() { return; }
                    continue;
                }
                break (status, head, bytes);
            };
            // A response without a known length is not held, because reading it to the end would
            // wait for the origin to close.
            if let Some(length) = content_length(&head_text).filter(|n| *n <= MAX_HELD_BODY && response_has_body(method, head_status)) {
                let mut body = vec![0u8; length];
                if up_reader.read_exact(&mut body).await.is_ok() {
                    let raw = decode_http_response_for_display(&head_text, &body, true);
                    let (decision, wait) = oneshot::channel();
                    let id = self.inner.next_held.fetch_add(1, Ordering::SeqCst);
                    let queued = {
                    let mut held = self.inner.held.lock().unwrap_or_else(|error| error.into_inner());
                    if self.inner.intercept.load(Ordering::SeqCst) && self.inner.intercept_response.load(Ordering::SeqCst) {
                    held.insert(
                        id,
                        Held {
                            kind: HeldKind::Response,
                            method: method.to_string(),
                            target: target.to_string(),
                            raw: raw.clone(),
                            decision,
                        },
                    );
                    true
                    } else { let _ = decision.send(Some(raw.clone())); false }
                    };
                    if queued {
                    self.emit(Event::HeldResponse {
                        id,
                        status: head_status,
                        raw,
                    });
                    }
                    match wait.await {
                        Ok(Some(edited)) => {
                            // The changed response is what the client gets, with the length kept
                            // in step with its body.
                            let (edited_head, edited_body) = split_message(&edited);
                            let edited_head = fix_content_length(&edited_head, edited_body.as_deref());
                            // The head and the body go out as one message.
                            let edited = match edited_body {
                                Some(body) => format!("{edited_head}{body}"),
                                None => edited_head,
                            };
                            let edited = self.apply_response_mod_rules(&edited);
                            if client.write_all(edited.as_bytes()).await.is_err() {
                                return;
                            }
                            let _ = client.flush().await;
                            // The response is over, so the connection is closed cleanly. Over TLS
                            // this is what sends the close notice the client is waiting for.
                            let _ = client.shutdown().await;
                            self.emit(Event::Tx {
                                method: method.to_string(),
                                target: target.to_string(),
                                status: head_status,
                                bytes: edited.len() as u64,
                                request: head.clone(),
                                response: edited,
                                secure,
                            });
                            return;
                        }
                        _ => {
                            self.inner.held.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
                            self.emit(Event::Dropped { id });
                            return;
                        }
                    }
                }
            }
            // Not held: what was read goes to the client, and the rest is streamed as it is.
            if client.write_all(&head_bytes).await.is_err() {
                return;
            }
            let (bytes, captured) = match copy_framed_body(&mut up_reader, &mut client, &head_text, method, head_status).await {
                Ok(body) => body,
                Err(error) => { self.emit(Event::Error(format!("Incomplete response: {error}"))); return; }
            };
            let _ = client.flush().await;
            let _ = client.shutdown().await;
            let response = self.apply_response_mod_rules(&decode_http_response_for_display(&head_text, &captured, false));
            for cookie in crate::cookies::parse_set_cookie_headers(&response) {
                self.inner.cookies.store(&host, &cookie);
            }
            self.inner.cookies.evict_expired();
            self.emit(Event::Tx {
                method: method.to_string(),
                target: target.to_string(),
                status: head_status,
                bytes,
                request: head.clone(),
                response,
                secure,
            });
            return;
        }

        let (status, response_head, head_bytes) = loop {
            let (status, head, bytes) = read_response_head(&mut up_reader).await;
            if status == 0 { self.emit(Event::Error("Invalid response headers".into())); return; }
            if (100..200).contains(&status) && status != 101 {
                if client.write_all(&bytes).await.is_err() { return; }
                continue;
            }
            break (status, head, bytes);
        };
        if client.write_all(&head_bytes).await.is_err() {
            return;
        }
        let (body, captured) = match copy_framed_body(&mut up_reader, &mut client, &response_head, method, status).await {
            Ok(body) => body,
            Err(error) => { self.emit(Event::Error(format!("Incomplete response: {error}"))); return; }
        };
        let _ = client.flush().await;
        let _ = client.shutdown().await;

        let response = self.apply_response_mod_rules(&decode_http_response_for_display(&response_head, &captured, false));
        for cookie in crate::cookies::parse_set_cookie_headers(&response) {
            self.inner.cookies.store(&host, &cookie);
        }
        self.inner.cookies.evict_expired();
        self.emit(Event::Tx {
            method: method.to_string(),
            target: target.to_string(),
            status,
            bytes: body,
            request: head,
            response,
            secure,
        });
    }


    /// Answers a `CONNECT` and then speaks TLS to the client, so the traffic inside the tunnel
    /// can be seen, changed and logged like any other request.
    ///
    /// The client is told to trust the proxy's own authority, which is why a browser has to be
    /// told about that certificate before https works through the proxy.
    /// Built-in Gulpsuite proxy portal (`http://gulp/`, `http://gulpsuite/`, `/cert`, `/cert.pem`).
    /// Served before the hold queue so browser certificate downloads never deadlock on Intercept.
    async fn serve_portal(&self, client: &mut Out, capture_target: &str) -> bool {
        let Ok(url) = url::Url::parse(capture_target) else {
            return false;
        };
        let Some(host) = url.host_str() else {
            return false;
        };
        let is_portal_host = host.eq_ignore_ascii_case("gulp")
            || host.eq_ignore_ascii_case("gulpsuite")
            || host.eq_ignore_ascii_case("gulp.local");
        if !is_portal_host {
            return false;
        }
        match url.path() {
            "/cert" | "/cacert.der" => {
                let Some(cert) = self.authority_certificate() else {
                    return false;
                };
                let bytes = cert.as_ref();
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/x-x509-ca-cert\r\n\
                     Content-Disposition: attachment; filename=\"cacert.der\"\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = client.write_all(header.as_bytes()).await;
                let _ = client.write_all(bytes).await;
                let _ = client.flush().await;
                let _ = client.shutdown().await;
                true
            }
            "/cert.pem" | "/gulpsuite-proxy-ca.pem" => {
                let Some(pem) = self.authority_pem() else {
                    return false;
                };
                let bytes = pem.as_bytes();
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/x-pem-file\r\n\
                     Content-Disposition: attachment; filename=\"gulpsuite-proxy-ca.pem\"\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = client.write_all(header.as_bytes()).await;
                let _ = client.write_all(bytes).await;
                let _ = client.flush().await;
                let _ = client.shutdown().await;
                true
            }
            _ => {
                let body = concat!(
                    "<!doctype html><html><head><meta charset=\"utf-8\">",
                    "<title>Gulpsuite Proxy</title>",
                    "<style>body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:48px auto;max-width:640px;color:#2b2b2b;line-height:1.5}",
                    ".bar{display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #ff6633;padding-bottom:12px;margin-bottom:24px}",
                    "a.btn{display:inline-block;background:#ff6633;color:#fff;text-decoration:none;padding:8px 16px;border-radius:6px;font-weight:600;margin-right:12px}",
                    "a.sec{display:inline-block;background:#eee;color:#2b2b2b;text-decoration:none;padding:8px 16px;border-radius:6px;font-weight:600}</style>",
                    "</head><body><div class=\"bar\"><h2>Gulpsuite Professional Proxy</h2>",
                    "<div><a class=\"btn\" href=\"/cert\">CA Certificate (DER)</a>",
                    "<a class=\"sec\" href=\"/cert.pem\">CA Certificate (PEM)</a></div></div>",
                    "<p>Welcome to Gulpsuite Proxy. Your browser is routing HTTP and HTTPS traffic through this listener.</p>",
                    "</body></html>"
                );
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = client.write_all(header.as_bytes()).await;
                let _ = client.flush().await;
                let _ = client.shutdown().await;
                true
            }
        }
    }

    async fn serve_tls(self, mut stream: TcpStream, head: String) {
        let authority = head
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string();
        let (host, _port) = split_authority(&authority);
        if host.is_empty() {
            self.emit(Event::Error("CONNECT without a host".into()));
            return;
        }

        let Some(signer) = self.inner.authority.clone() else {
            self.emit(Event::Error("no certificate authority available".into()));
            return;
        };
        let config = match signer.server_config_arc(&host) {
            Ok(c) => c,
            Err(e) => {
                self.emit(Event::Error(format!("certificate for {host}: {e}")));
                return;
            }
        };
        if stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let tls = match acceptor.accept(stream).await {
            Ok(t) => t,
            Err(e) => {
                if self.inner.auto_passthrough_on_error.load(Ordering::SeqCst) {
                    if let Ok(mut guard) = self.inner.passthrough_hosts.write() {
                        if !guard.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
                            guard.push(host.clone());
                        }
                    }
                }
                self.emit(Event::Error(format!("tls handshake with {host}: {e}")));
                return;
            }
        };
        let (read, write) = tokio::io::split(tls);
        let mut reader = BufReader::new(Box::new(read) as ReadBox);
        let client: Out = Box::new(write);

        // One request per connection, the same as the plain path.
        let head = match read_head(&mut reader).await {
            Ok(h) => h,
            Err(_) => return,
        };
        let mut parts = head.lines().next().unwrap_or("").split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let target = parts.next().unwrap_or("").to_string();
        self.forward_request(reader, client, head, &method, &target, true)
            .await;
    }

    async fn tunnel(self, mut reader: Io, mut client: Out, method: &str, authority: &str) {
        let (host, port) = split_authority(authority);
        let upstream = match TcpStream::connect((host.as_str(), port)).await {
            Ok(s) => s,
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                self.emit(Event::Error(format!("connect {authority}: {e}")));
                return;
            }
        };
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
            return;
        }
        let (up_read, mut up_write) = upstream.into_split();

        let up = tokio::spawn(async move {
            let mut r = BufReader::new(up_read);
            let mut buf = vec![0u8; 16384];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if client.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });

        let mut buf = vec![0u8; 16384];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        up.abort();
        self.emit(Event::Tx {
            method: method.to_string(),
            target: authority.to_string(),
            status: 200,
            bytes: 0,
            request: format!("CONNECT {authority} HTTP/1.1\r\n\r\n"),
            response: "HTTP/1.1 200 Connection Established\r\n\r\n".into(),
            secure: true,
        });
    }
}

impl Proxy {
    /// Relays WebSocket frames in both directions, recording each decoded one.
    ///
    /// Frames are forwarded byte-for-byte so the proxy cannot alter what the two peers negotiated;
    /// the decode is used only for the record. The loop ends as soon as *either* side closes,
    /// because a WebSocket conversation is over when one peer hangs up, not only when the client does.
    async fn relay_websocket(
        &self,
        id: u64,
        mut from_client: Io,
        mut to_client: Out,
        mut from_server: Io,
        mut to_server: Out,
    ) {
        // Bytes arriving mid-frame are carried into the next decode, so each direction keeps its own
        // buffer rather than decoding each read in isolation.
        let mut to_upstream: Vec<u8> = Vec::new();
        let mut to_downstream: Vec<u8> = Vec::new();
        let mut up_buf = vec![0u8; 16384];
        let mut down_buf = vec![0u8; 16384];
        loop {
            tokio::select! {
                read = from_client.read(&mut up_buf) => {
                    let n = match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if to_server.write_all(&up_buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = to_server.flush().await;
                    to_upstream.extend_from_slice(&up_buf[..n]);
                    drain_frames(&mut to_upstream, &mut |frame| self.inner.record_frame(id, true, frame));
                }
                read = from_server.read(&mut down_buf) => {
                    let n = match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if to_client.write_all(&down_buf[..n]).await.is_err() {
                        break;
                    }
                    let _ = to_client.flush().await;
                    to_downstream.extend_from_slice(&down_buf[..n]);
                    drain_frames(&mut to_downstream, &mut |frame| self.inner.record_frame(id, false, frame));
                }
            }
        }
    }
}

/// The most bytes a single frame header plus payload can occupy, given the codec's ceiling.
const CARRY_CEILING: usize = crate::ws::MAX_FRAME_PAYLOAD + 14;

/// Decodes and reports every whole frame at the front of `buffer`, then removes those bytes.
///
/// Whatever is left is an incomplete frame and stays buffered for the next read. A frame larger
/// than `CARRY_CEILING` cannot be legal, so a buffer that reaches it without producing a frame means
/// the stream is desynchronised and the remainder is dropped rather than grown without limit.
fn drain_frames(buffer: &mut Vec<u8>, on_frame: &mut dyn FnMut(&crate::ws::Frame)) {
    loop {
        if buffer.len() < 2 {
            return;
        }
        // If RSV1 (`0x40`, RFC 7692 `permessage-deflate`) is set on a data frame, clear RSV bits
        // before RFC 6455 framing decode and inflate the payload afterwards.
        let rsv1 = buffer[0] & 0x40 != 0;
        if buffer[0] & 0x70 != 0 {
            buffer[0] &= !0x70;
        }
        let Ok((mut frames, used)) = crate::ws::decode(buffer) else {
            // A malformed stream cannot resynchronise on a frame boundary.
            buffer.clear();
            return;
        };
        if frames.is_empty() || used == 0 {
            if rsv1 {
                buffer[0] |= 0x40;
            }
            if buffer.len() > CARRY_CEILING {
                buffer.clear();
            }
            return;
        }
        for (idx, frame) in frames.iter_mut().enumerate() {
            if idx == 0 && rsv1 && !crate::ws::is_control(frame.opcode) {
                let mut compressed = frame.payload.clone();
                compressed.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
                let mut inflated = Vec::new();
                if std::io::Read::read_to_end(
                    &mut flate2::read::DeflateDecoder::new(&compressed[..]),
                    &mut inflated,
                )
                .is_ok()
                    && !inflated.is_empty()
                {
                    frame.payload = inflated;
                }
            }
            on_frame(frame);
        }
        buffer.drain(..used);
    }
}

fn question_id(bytes: &[u8]) -> u16 {
    if bytes.len() >= 2 {
        u16::from_be_bytes([bytes[0], bytes[1]])
    } else {
        0
    }
}

/// Reads one SMTP message and records it. Errors are swallowed: a capture tool must not interrupt
/// whatever is on the other end of the socket.
async fn observe_smtp(stream: tokio::net::TcpStream, inner: Arc<Inner>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let _ = write_half.write_all(b"220 gulpsuite ESMTP\r\n").await;

    let mut from = String::new();
    let mut to: Vec<String> = Vec::new();
    let mut subject = String::new();
    let mut body = String::new();
    let mut in_data = false;

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if in_data {
            // Header lines still arrive inside DATA, so the subject has to be picked up here; by
            // the time this reaches the command section it has already been consumed.
            if subject.is_empty() && trimmed.to_ascii_uppercase().starts_with("SUBJECT:") {
                subject = trimmed["SUBJECT:".len()..].trim().to_string();
            }
            if trimmed == "." {
                in_data = false;
                inner.record_smtp("client to server".into(), from.clone(), to.clone(), subject.clone(), body.clone());
                from.clear();
                to.clear();
                subject.clear();
                body.clear();
                let _ = write_half.write_all(b"250 OK\r\n").await;
                continue;
            }
            // A leading dot is an escape for a literal one.
            body.push_str(trimmed.strip_prefix('.').unwrap_or(&trimmed));
            body.push('\n');
            // A message body is capped so a large upload cannot grow without bound.
            if body.len() > 1024 * 1024 {
                in_data = false;
            }
            continue;
        }
        let upper = trimmed.to_ascii_uppercase();
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let _ = write_half.write_all(b"250 gulpsuite\r\n").await;
        } else if upper.starts_with("MAIL FROM") {
            from = address_of(&trimmed);
            let _ = write_half.write_all(b"250 OK\r\n").await;
        } else if upper.starts_with("RCPT TO") {
            to.push(address_of(&trimmed));
            let _ = write_half.write_all(b"250 OK\r\n").await;
        } else if upper.starts_with("DATA") {
            in_data = true;
            let _ = write_half.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n").await;
        } else if upper.starts_with("QUIT") {
            let _ = write_half.write_all(b"221 Bye\r\n").await;
            return;
        } else {
            let _ = write_half.write_all(b"250 OK\r\n").await;
        }
    }
}

/// Pulls the address out of `MAIL FROM:<a@b>` or `RCPT TO:<c@d>`.
fn address_of(line: &str) -> String {
    let Some(start) = line.find('<') else { return line.trim().to_string() };
    let Some(end) = line[start..].find('>').map(|i| start + i) else {
        return line[start + 1..].trim().to_string();
    };
    line[start + 1..end].trim().to_string()
}

async fn read_head<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut head = String::new();
    loop {
        let n = reader.read_line(&mut head).await?;
        if n == 0 || head.ends_with("\r\n\r\n") || head.ends_with("\n\n") {
            return Ok(head);
        }
        if head.len() > 64 * 1024 {
            return Err(io::Error::other("request head too large"));
        }
    }
}


/// The `Content-Length` a request head carries, when it has one.
fn content_length(head: &str) -> Option<usize> {
    for line in head.lines() {
        // The request line has no colon, so a line without one is simply skipped.
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

/// Splits a raw message into its head and its body. The head keeps the blank line that ends it.
fn split_message(raw: &str) -> (String, Option<String>) {
    for separator in ["\r\n\r\n", "\n\n"] {
        if let Some(index) = raw.find(separator) {
            let head = raw[..index + separator.len()].to_string();
            let body = raw[index + separator.len()..].to_string();
            return (head, Some(body));
        }
    }
    (raw.to_string(), None)
}

/// Keeps the `Content-Length` in step with the body that is actually sent.
fn fix_content_length(head: &str, body: Option<&str>) -> String {
    let Some(body) = body else {
        return head.to_string();
    };
    if !head
        .lines()
        .any(|line| line.split_once(':').is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("content-length")))
    {
        return head.to_string();
    }
    let mut out = String::with_capacity(head.len() + 16);
    for line in head.split_inclusive('\n') {
        let replaced = line
            .split_once(':')
            .map(|(name, _value)| {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    format!("{name}: {}\r\n", body.len())
                } else {
                    line.to_string()
                }
            })
            .unwrap_or_else(|| line.to_string());
        out.push_str(&replaced);
    }
    out
}


async fn read_bounded_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, limit: usize) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() { return Ok(line); }
        let count = available.iter().position(|byte| *byte == b'\n').map_or(available.len(), |index| index + 1);
        if count > limit.saturating_sub(line.len()) { return Err(io::Error::other("HTTP metadata line exceeds its size limit")); }
        let ended = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if ended { return Ok(line); }
    }
}

async fn read_http_head(reader: &mut Io) -> io::Result<(u16, String, Vec<u8>)> {
    let mut raw = Vec::new();
    loop {
        let line = read_bounded_line(reader, 65536usize.saturating_sub(raw.len())).await?;
        if line.is_empty() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete response headers")); }
        let done = line == b"\r\n" || line == b"\n";
        raw.extend_from_slice(&line);
        if done { break; }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text.lines().next().filter(|line| line.starts_with("HTTP/"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok()).filter(|code| (100..600).contains(code))
        .ok_or_else(|| io::Error::other("invalid HTTP response status"))?;
    Ok((status, text, raw))
}

async fn read_response_head(reader: &mut Io) -> (u16, String, Vec<u8>) {
    read_http_head(reader).await.unwrap_or_default()
}


/// Dials an origin, over TLS when the request is secure.
async fn connect_upstream(
    host: &str,
    port: u16,
    secure: bool,
    extra_roots: &[rustls::pki_types::CertificateDer<'static>],
) -> io::Result<StreamBox> {
    let tcp = TcpStream::connect((host, port)).await?;
    if !secure {
        return Ok(Box::new(tcp));
    }
    let config = crate::tls::client_config_arc(extra_roots).map_err(io::Error::other)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| io::Error::other(format!("bad server name: {host}")))?;
    let tls = connector.connect(name, tcp).await?;
    Ok(Box::new(tls))
}

/// Reads a request head one byte at a time.
///
/// A buffered reader would take more off the wire than the head, and those bytes are lost when
/// the reader is dropped. The first request of a connection is read this way, because a `CONNECT`
/// has to leave the socket whole for the TLS handshake that follows it.
/// Reads a request head without consuming any bytes past the terminating blank line.
///
/// Uses `TcpStream::peek` so the entire header block is read in one kernel call instead of one
/// syscall per byte, while still leaving the socket positioned at the exact start of the TLS
/// handshake (for `CONNECT`) or request body.
async fn read_head_exact(stream: &mut TcpStream) -> io::Result<String> {
    let mut raw = Vec::with_capacity(1024);
    let mut peek_buf = [0u8; 8192];
    loop {
        let n = stream.peek(&mut peek_buf).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before request head completed",
            ));
        }
        let mut take = n;
        let mut found_end = false;
        for i in 0..n {
            raw.push(peek_buf[i]);
            if raw.ends_with(b"\r\n\r\n") || raw.ends_with(b"\n\n") {
                take = i + 1;
                found_end = true;
                break;
            }
            if raw.len() > 64 * 1024 {
                return Err(io::Error::other("request head too large"));
            }
        }
        let mut discard = vec![0u8; take];
        stream.read_exact(&mut discard).await?;
        if found_end {
            return Ok(String::from_utf8_lossy(&raw).into_owned());
        }
    }
}

/// Consumes the status line, handing back the code and the raw bytes to replay verbatim.
async fn take_status_line(reader: &mut Io) -> (u16, Vec<u8>) {
    let mut raw = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte).await {
            Ok(_) => {}
            Err(_) => break,
        }
        raw.push(byte[0]);
        if raw.len() >= 2 && raw[raw.len() - 2] == b'\r' && byte[0] == b'\n' {
            break;
        }
        if raw.len() >= 8192 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (code, raw)
}

/// Streams a body to the client while keeping the first `BODY_CAPTURE_LIMIT` bytes for display.
async fn copy_across(from: &mut Io, to: &mut Out) -> (u64, Vec<u8>) {
    let mut buf = vec![0u8; 16384];
    let mut total = 0u64;
    let mut kept: Vec<u8> = Vec::new();
    loop {
        match from.read(&mut buf).await {
            Ok(0) | Err(_) => return (total, kept),
            Ok(n) => {
                total += n as u64;
                if kept.len() < BODY_CAPTURE_LIMIT {
                    let room = BODY_CAPTURE_LIMIT - kept.len();
                    kept.extend_from_slice(&buf[..n.min(room)]);
                }
                if to.write_all(&buf[..n]).await.is_err() {
                    return (total, kept);
                }
            }
        }
    }
}

fn response_has_body(method: &str, status: u16) -> bool {
    !method.eq_ignore_ascii_case("HEAD") && !(100..200).contains(&status) && !matches!(status, 204 | 304)
}

fn capture_part(kept: &mut Vec<u8>, bytes: &[u8]) {
    let room = BODY_CAPTURE_LIMIT.saturating_sub(kept.len());
    kept.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

async fn copy_exact_body(from: &mut Io, to: &mut Out, mut length: u64, kept: &mut Vec<u8>) -> io::Result<u64> {
    let total = length;
    let mut buffer = [0u8; 16384];
    while length > 0 {
        let count = length.min(buffer.len() as u64) as usize;
        from.read_exact(&mut buffer[..count]).await?;
        to.write_all(&buffer[..count]).await?;
        capture_part(kept, &buffer[..count]);
        length -= count as u64;
    }
    Ok(total)
}

async fn copy_framed_body(from: &mut Io, to: &mut Out, head: &str, method: &str, status: u16) -> io::Result<(u64, Vec<u8>)> {
    if !response_has_body(method, status) { return Ok((0, Vec::new())); }
    let mut kept = Vec::new();
    if header_has_token(head, "transfer-encoding", "chunked") {
        let mut total = 0;
        loop {
            let line = read_bounded_line(from, 8192).await?;
            if line.is_empty() { return Err(io::Error::other("invalid chunk header")); }
            let size = u64::from_str_radix(String::from_utf8_lossy(&line).split(';').next().unwrap_or("").trim(), 16).map_err(|_| io::Error::other("invalid chunk size"))?;
            to.write_all(&line).await?; capture_part(&mut kept, &line); total += line.len() as u64;
            if size == 0 {
                let mut trailer_size = 0;
                loop {
                    let line = read_bounded_line(from, 65536usize.saturating_sub(trailer_size)).await?;
                    if line.is_empty() { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete chunk trailers")); }
                    trailer_size += line.len();
                    if trailer_size > 65536 { return Err(io::Error::other("chunk trailers too large")); }
                    let done = line == b"\r\n" || line == b"\n";
                    to.write_all(&line).await?; capture_part(&mut kept, &line); total += line.len() as u64;
                    if done { return Ok((total, kept)); }
                }
            }
            total += copy_exact_body(from, to, size, &mut kept).await?;
            let mut ending = [0; 2]; from.read_exact(&mut ending).await?;
            if ending != *b"\r\n" { return Err(io::Error::other("invalid chunk terminator")); }
            to.write_all(&ending).await?; capture_part(&mut kept, &ending); total += 2;
        }
    } else if let Some(length) = content_length(head) {
        let total = copy_exact_body(from, to, length as u64, &mut kept).await?;
        Ok((total, kept))
    } else {
        Ok(copy_across(from, to).await)
    }
}

async fn one_shot(host: &str, port: u16, raw: &str, secure: bool, roots: &[rustls::pki_types::CertificateDer<'static>]) -> io::Result<(u16, String)> {
    let mut stream = connect_upstream(host, port, secure, roots).await?;
    stream.write_all(normalise_newlines(raw).as_bytes()).await?;
    stream.flush().await?;
    let (read, _write) = tokio::io::split(stream);
    let mut reader = BufReader::new(Box::new(read) as ReadBox);
    let method = raw.split_whitespace().next().unwrap_or("");
    let mut interim = 0;
    let (status, head, mut full) = loop {
        let (status, head, bytes) = read_http_head(&mut reader).await?;
        if (100..200).contains(&status) && status != 101 {
            interim += 1;
            if interim > 16 { return Err(io::Error::other("too many interim responses")); }
            continue;
        }
        break (status, head, bytes);
    };
    let head_len = full.len();
    if method.eq_ignore_ascii_case("HEAD") || matches!(status, 101 | 204 | 304) {
        return Ok((status, head));
    }
    if header_has_token(&head, "transfer-encoding", "chunked") {
        loop {
            let line = read_bounded_line(&mut reader, 8192).await?;
            if line.is_empty() {
                return Err(io::Error::other("invalid chunk header"));
            }
            let text = String::from_utf8_lossy(&line);
            let size = usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                .map_err(|_| io::Error::other("invalid chunk size"))?;
            if size > MANUAL_RESPONSE_LIMIT.saturating_sub(full.len() + line.len() + 2) {
                return Err(io::Error::other("response exceeds the 32 MiB manual capture limit"));
            }
            full.extend_from_slice(&line);
            if size == 0 {
                let mut trailer_size = 0;
                loop {
                    let trailer = read_bounded_line(&mut reader, 65536usize.saturating_sub(trailer_size)).await?;
                    if trailer.is_empty() {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete chunk trailers"));
                    }
                    trailer_size += trailer.len();
                    if trailer_size > 65536 { return Err(io::Error::other("chunk trailers too large")); }
                    let done = trailer == b"\r\n" || trailer == b"\n";
                    full.extend_from_slice(&trailer);
                    if done { break; }
                }
                break;
            }
            let mut chunk = vec![0; size.checked_add(2).ok_or_else(|| io::Error::other("chunk too large"))?];
            reader.read_exact(&mut chunk).await?;
            if !chunk.ends_with(b"\r\n") { return Err(io::Error::other("invalid chunk terminator")); }
            full.extend_from_slice(&chunk);
        }
    } else if let Some(length) = content_length(&head) {
        if length > MANUAL_RESPONSE_LIMIT.saturating_sub(full.len()) {
            return Err(io::Error::other("response exceeds the 32 MiB manual capture limit"));
        }
        let start = full.len();
        full.resize(start.checked_add(length).ok_or_else(|| io::Error::other("response too large"))?, 0);
        reader.read_exact(&mut full[start..]).await?;
    } else {
        let remaining = MANUAL_RESPONSE_LIMIT.saturating_sub(full.len()) + 1;
        reader.take(remaining as u64).read_to_end(&mut full).await?;
        if full.len() > MANUAL_RESPONSE_LIMIT { return Err(io::Error::other("response exceeds the 32 MiB manual capture limit")); }
    }
    let body_raw = &full[head_len..];
    Ok((status, decode_http_response_for_display(&head, body_raw, false)))
}

/// Normalises outgoing request headers so:
/// 1. `Accept-Encoding` only advertises `gzip, deflate` (never `br`/`zstd`), ensuring compressed
///    responses can always be decompressed for inspection in Proxy/Repeater/Intruder/Scanner.
/// 2. WebSocket upgrade requests omit `Sec-WebSocket-Extensions` (`permessage-deflate`) so frames
///    arrive as readable RFC 6455 UTF-8/binary messages.
fn sanitize_upstream_request_headers(raw_head: &str) -> String {
    let is_ws = crate::ws::is_upgrade(raw_head);
    let mut out = String::with_capacity(raw_head.len());
    for (idx, line) in raw_head.split_inclusive('\n').enumerate() {
        if idx > 0 {
            if let Some((name, val)) = line.split_once(':') {
                let name_trim = name.trim();
                if is_ws && name_trim.eq_ignore_ascii_case("sec-websocket-extensions") {
                    continue;
                }
                if name_trim.eq_ignore_ascii_case("accept-encoding") {
                    let lower = val.to_ascii_lowercase();
                    if lower.contains("br") || lower.contains("zstd") {
                        out.push_str("Accept-Encoding: gzip, deflate\r\n");
                        continue;
                    }
                }
            }
        }
        out.push_str(line);
    }
    out
}

/// Extracts contiguous payload bytes from a `Transfer-Encoding: chunked` body buffer if chunked,
/// then transparently decompresses `Content-Encoding: gzip` / `deflate` so responses in Proxy,
/// Repeater, Intruder, Logger, and Target Site map never render as binary `0x1f 0x8b` garbage.
fn decode_http_response_for_display(head: &str, raw_body: &[u8], strip_encoding_header: bool) -> String {
    use std::io::Read;

    let unchunked: std::borrow::Cow<'_, [u8]> =
        if header_has_token(head, "transfer-encoding", "chunked") {
            let mut decoded = Vec::with_capacity(raw_body.len());
            let mut cursor = 0usize;
            let mut ok = false;
            while cursor < raw_body.len() {
                let rest = &raw_body[cursor..];
                let Some(nl) = rest.iter().position(|&b| b == b'\n') else {
                    break;
                };
                let size_line = String::from_utf8_lossy(&rest[..=nl]);
                let hex_part = size_line
                    .trim_end_matches(['\r', '\n'])
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                let Ok(chunk_size) = usize::from_str_radix(hex_part, 16) else {
                    break;
                };
                cursor += nl + 1;
                if chunk_size == 0 {
                    ok = true;
                    break;
                }
                if cursor + chunk_size > raw_body.len() {
                    decoded.extend_from_slice(&raw_body[cursor..]);
                    ok = true;
                    break;
                }
                decoded.extend_from_slice(&raw_body[cursor..cursor + chunk_size]);
                cursor += chunk_size;
                if raw_body[cursor..].starts_with(b"\r\n") {
                    cursor += 2;
                } else if raw_body[cursor..].starts_with(b"\n") {
                    cursor += 1;
                }
            }
            if ok && !decoded.is_empty() {
                std::borrow::Cow::Owned(decoded)
            } else {
                std::borrow::Cow::Borrowed(raw_body)
            }
        } else {
            std::borrow::Cow::Borrowed(raw_body)
        };

    let payload: &[u8] = &unchunked;
    let is_gzip = header_has_token(head, "content-encoding", "gzip")
        || header_has_token(head, "content-encoding", "x-gzip")
        || payload.starts_with(&[0x1f, 0x8b]);
    let is_deflate = header_has_token(head, "content-encoding", "deflate");

    let mut decompressed = Vec::new();
    let did_decompress = if is_gzip && payload.len() >= 10 {
        let mut decoder = flate2::read::GzDecoder::new(payload).take(16 * 1024 * 1024);
        decoder.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty()
    } else if is_deflate && !payload.is_empty() {
        let mut zlib = flate2::read::ZlibDecoder::new(payload).take(16 * 1024 * 1024);
        if zlib.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
            true
        } else {
            decompressed.clear();
            let mut def = flate2::read::DeflateDecoder::new(payload).take(16 * 1024 * 1024);
            def.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty()
        }
    } else {
        false
    };

    let final_head = if did_decompress && strip_encoding_header {
        let mut cleaned = String::with_capacity(head.len());
        for line in head.split_inclusive('\n') {
            if line
                .split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case("content-encoding"))
            {
                continue;
            }
            cleaned.push_str(line);
        }
        cleaned
    } else {
        head.to_string()
    };

    if did_decompress {
        format!("{final_head}{}", String::from_utf8_lossy(&decompressed))
    } else {
        format!("{final_head}{}", String::from_utf8_lossy(raw_body))
    }
}

fn header_has_token(head: &str, name: &str, token: &str) -> bool {
    head.lines().filter_map(|line| line.split_once(':'))
        .any(|(key, value)| key.trim().eq_ignore_ascii_case(name) && value.split(',').any(|part| part.trim().eq_ignore_ascii_case(token)))
}

/// CRLF-normalises a request and guarantees the terminating blank line.
fn normalise_newlines(raw: &str) -> String {
    let (head, body) = split_message(raw);
    let s = head.replace("\r\n", "\n").replace('\r', "\n").replace('\n', "\r\n");
    // The head already ends in at most one CRLF; the blank line needs exactly one more, so
    // appending a full CRLFCRLF emitted a stray empty line.
    let mut head = if s.ends_with("\r\n\r\n") {
        s
    } else if s.ends_with("\r\n") {
        format!("{s}\r\n")
    } else {
        format!("{s}\r\n\r\n")
    };
    if let Some(body) = body {
        if !header_has_token(&head, "transfer-encoding", "chunked") {
            head = fix_content_length(&head, Some(&body));
            if !body.is_empty() && content_length(&head).is_none() {
                head.truncate(head.len() - 2);
                head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
            }
        }
        head.push_str(&body);
    }
    head
}

/// Decides whether one response counts as a hit.
pub(crate) fn apply_rules(rules: &MatchRules, baseline: &AtomicUsize, status: u16, body: &str) -> bool {
    if !rules.negative_status.is_empty() && rules.negative_status.contains(&status) {
        return false;
    }
    if let Some(re) = &rules.negative_regex {
        if re.is_match(body) {
            return false;
        }
    }
    if !rules.status.is_empty() && !rules.status.contains(&status) {
        return false;
    }
    if rules.length {
        return match baseline.compare_exchange(usize::MAX, body.len(), Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => false,
            Err(previous) => body.len() != previous,
        };
    }
    true
}

fn split_authority(authority: &str) -> (String, u16) {
    split_authority_with_default(authority, 443)
}

/// `default_port` matters: an absolute `http://` URL without a port is 80, while a CONNECT
/// authority without a port is 443. Assuming 443 for both sent plain HTTP to the TLS port.
fn split_authority_with_default(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        // Only treat the tail as a port when it actually parses as one.
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => (authority.to_string(), default_port),
        },
        None => (authority.to_string(), default_port),
    }
}

pub fn host_port(head: &str, target: &str) -> Option<(String, u16)> {
    for (scheme, default_port) in [("http://", 80u16), ("https://", 443)] {
        if let Some(rest) = target.strip_prefix(scheme) {
            let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            return Some(split_authority_with_default(authority, default_port));
        }
    }
    for line in head.lines() {
        if let Some(value) = line
            .split_once(':')
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.trim())
        {
            return Some(split_authority(value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_defaults_to_https() {
        assert_eq!(split_authority("example.com"), ("example.com".into(), 443));
        assert_eq!(split_authority("example.com:8443"), ("example.com".into(), 8443));
    }

    #[test]
    fn target_host_beats_missing_header() {
        let head = "GET http://example.com/x HTTP/1.1\r\n";
        assert_eq!(host_port(head, "http://example.com/x"), Some(("example.com".into(), 80)));
        // A scheme decides the default port; HTTPS is not HTTP.
        assert_eq!(host_port(head, "https://example.com/x"), Some(("example.com".into(), 443)));
        assert_eq!(host_port(head, "http://example.com:8080/x"), Some(("example.com".into(), 8080)));
        // A query string must not end up inside the authority.
        assert_eq!(host_port(head, "http://example.com/x?a=b"), Some(("example.com".into(), 80)));
    }

    #[test]
    fn falls_back_to_host_header() {
        let head = "GET /x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(host_port(head, "/x"), Some(("example.com".into(), 8080)));
    }

    #[test]
    fn unresolvable_target_is_none() {
        assert_eq!(host_port("GET /x HTTP/1.1\r\n", "/x"), None);
    }

    #[test]
    fn status_filter_is_allow_list() {
        let baseline = AtomicUsize::new(usize::MAX);
        let rules = MatchRules::new(vec![200], vec![], None, false);
        assert!(apply_rules(&rules, &baseline, 200, "ok"));
        assert!(!apply_rules(&rules, &baseline, 404, "ok"));
    }

    #[test]
    fn negative_filters_win_over_positive() {
        let baseline = AtomicUsize::new(usize::MAX);
        let rules = MatchRules::new(vec![200], vec![200], Some("boom".into()), false);
        assert!(!apply_rules(&rules, &baseline, 200, "boom"));
    }

    #[test]
    fn length_rule_uses_first_response_as_baseline() {
        let baseline = AtomicUsize::new(usize::MAX);
        let rules = MatchRules::new(vec![], vec![], None, true);
        assert!(!apply_rules(&rules, &baseline, 200, "aaaa"), "baseline never matches");
        assert!(!apply_rules(&rules, &baseline, 200, "aaaa"), "same length never matches");
        assert!(apply_rules(&rules, &baseline, 200, "aaaaa"), "different length matches");
    }

    #[test]
    fn newlines_are_normalised_and_terminated() {
        assert_eq!(normalise_newlines("GET / HTTP/1.1\n"), "GET / HTTP/1.1\r\n\r\n");
        // Already terminated inputs must not gain an extra blank line.
        assert_eq!(normalise_newlines("GET / HTTP/1.1"), "GET / HTTP/1.1\r\n\r\n");
        assert_eq!(normalise_newlines("GET / HTTP/1.1\r\n\r\n"), "GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn one_shot_round_trips_verbatim() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let (status, body) = one_shot("127.0.0.1", port, "GET / HTTP/1.1\nHost: x\n\n", false, &[])
            .await
            .unwrap();
        assert_eq!(status, 204);
        assert!(body.starts_with("HTTP/1.1 204"));
    }

    #[tokio::test]
    async fn start_binds_a_port_and_records_a_transaction() {
        let (proxy, mut events) = Proxy::new();
        // Port 0 asks the OS for a free port, so the test never collides with anything.
        let port = proxy.start(0).await.unwrap();
        assert!(port > 0);
        assert!(proxy.start(0).await.is_err(), "a second start must be refused");

        // 127.0.0.1:1 refuses connections, so the proxy answers 502 and logs the transaction.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await;

        // Lifecycle events share the stream now, so the transaction is selected rather than assumed.
        let event = loop {
            let event = tokio::time::timeout(std::time::Duration::from_secs(2), events.recv())
                .await
                .expect("proxy logged no transaction")
                .unwrap();
            match event {
                Event::Listening { .. } | Event::ListenerStopped => continue,
                other => break other,
            }
        };
        assert!(
            matches!(event, Event::Tx { status: 502, .. } | Event::Error(_)),
            "expected a 502 or an error, got {event:?}"
        );
        proxy.stop().await;
        assert!(proxy.start(0).await.is_ok(), "stop must free the slot");
    }

    #[tokio::test]
    async fn start_announces_the_port_it_bound() {
        // The UI enables Stop from this event, so a silent bind leaves the panel stuck on
        // "Starting..." forever.
        let (proxy, mut events) = Proxy::new();
        let bound = proxy.start(0).await.expect("bind");
        let mut saw = false;
        for _ in 0..16 {
            match events.recv().await.expect("event") {
                Event::Listening { port } => {
                    assert_eq!(port, bound);
                    saw = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(saw, "start never announced its port");
        assert_eq!(proxy.bound_port().await, Some(bound));

        proxy.stop().await;
        let mut stopped = false;
        for _ in 0..16 {
            match events.recv().await.expect("event") {
                Event::ListenerStopped => {
                    stopped = true;
                    break;
                }
                _ => continue,
            }
        }
        assert!(stopped, "stop never announced itself");
        assert_eq!(proxy.bound_port().await, None);
    }

    #[tokio::test]
    async fn a_second_start_reports_the_running_port_instead_of_binding_again() {
        let (proxy, mut events) = Proxy::new();
        let bound = proxy.start(0).await.expect("bind");
        assert!(proxy.start(0).await.is_err(), "second start must fail");
        let announced = loop {
            match events.recv().await.expect("event") {
                Event::Listening { port } => break port,
                _ => continue,
            }
        };
        assert_eq!(announced, bound, "the still-running port should be reported");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn interception_parks_until_forwarded() {
        let (proxy, mut events) = Proxy::new();
        proxy.set_intercept(true);
        let port = proxy.start(0).await.unwrap();
        tokio::spawn(async move {
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let _ = client
                .write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
                .await;
            let mut buf = vec![0u8; 256];
            let _ = client.read(&mut buf).await;
        });

        let held = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let list = proxy.held().await;
                if let Some(first) = list.first() {
                    return first.clone();
                }
                let _ = events.recv().await;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("request was never parked");

        assert!(proxy.forward(held.id).await, "forward should release a held request");
        proxy.stop().await;
    }

    #[tokio::test]
    async fn dropping_an_unknown_id_reports_failure() {
        let (proxy, _rx) = Proxy::new();
        assert!(!proxy.forward(999).await);
        assert!(!proxy.discard(999).await);
    }
}

#[cfg(test)]
mod retention_tests {
    /// Clipping must cut on a char boundary, never mid-character.
    #[test]
    fn clipping_never_splits_a_character() {
        let text = "e\u{301}".repeat(64); // combining mark: multi-byte chars
        let clipped = crate::ui::app::clip_public(&text, 32);
        assert!(clipped.len() <= 32);
        assert!(clipped.chars().all(|c| c == 'e' || c == '\u{301}'));
        // Round-tripping must not panic and must be valid UTF-8.
        assert_eq!(clipped.chars().count(), text[..clipped.len()].chars().count());
    }
}

/// The request path for cookie scoping.
///
/// A proxied request uses the absolute form `GET http://host/path HTTP/1.1`, so the target token is
/// a full URL and its path is only the part after the authority. Taking the token verbatim made every
/// cookie fail its path match, which is why nothing was ever replayed.
pub fn request_path(head: &str) -> String {
    let target = head.lines().next().and_then(|line| line.split_whitespace().nth(1));
    let Some(target) = target else {
        return "/".into();
    };
    let without_query = target.split(['?', '#']).next().unwrap_or(target);
    if without_query.starts_with("http://") || without_query.starts_with("https://") {
        let Some((_, authority)) = without_query.split_once("://") else {
            return "/".into();
        };
        return match authority.find('/') {
            Some(at) => authority[at..].to_string(),
            None => "/".into(),
        };
    }
    if without_query.is_empty() {
        return "/".into();
    }
    without_query.to_string()
}

