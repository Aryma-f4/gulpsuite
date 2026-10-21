//! A local Collaborator server (DNS + HTTP + SMTP out-of-band interaction catcher).
//!
//! Hands out unique Collaborator tokens/subdomains and records out-of-band interactions over
//! DNS, HTTP, and SMTP with millisecond UTC timestamps, full request/response payloads, and
//! one-click health check verification.

use std::sync::Mutex;

/// The domain the generated hostnames sit under.
pub const DOMAIN: &str = "oastify.com";

/// Legacy alias domain also accepted by the DNS resolver.
pub const LEGACY_DOMAIN: &str = "burpcollaborator.test";

/// How long an interaction is kept. Bounded so a long session does not accumulate without limit.
pub const MAX_HITS: usize = 1_000;

/// Formats the current system time as `yyyy-MMM-dd HH:mm:ss.SSS UTC` (matching `collaborator/index.html`).
pub fn now_utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let total_secs = dur.as_secs();
    let millis = dur.subsec_millis();

    let days = (total_secs / 86_400) as i64;
    let rem = total_secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant algorithm)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let month_name = match m {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    };
    format!("{year:04}-{month_name}-{d:02} {hour:02}:{min:02}:{sec:02}.{millis:03} UTC")
}

/// Extracts the Collaborator token/payload ID from a host or path string.
pub fn extract_payload_id(host: &str, path: &str) -> String {
    let trimmed_path = path.trim_start_matches('/');
    if !trimmed_path.is_empty()
        && (trimmed_path.contains(".oastify.")
            || trimmed_path.contains(".burpcollaborator."))
    {
        return trimmed_path
            .split(['/', '?', '.'])
            .next()
            .unwrap_or(trimmed_path)
            .to_string();
    }
    let clean_host = host.split(':').next().unwrap_or(host);
    if let Some((sub, _)) = clean_host.split_once('.') {
        if !sub.chars().all(|c| c.is_ascii_digit()) && sub != "127" && sub != "localhost" {
            return sub.to_string();
        }
    }
    if !trimmed_path.is_empty() {
        let seg = trimmed_path.split(['/', '?']).next().unwrap_or("");
        if seg.len() >= 8 {
            return seg.to_string();
        }
    }
    clean_host.to_string()
}

/// A recorded interaction (`DNS`, `HTTP`, or `SMTP`).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Hit {
    /// How the interaction arrived: `DNS`, `HTTP`, or `SMTP`.
    pub kind: String,
    pub method: String,
    pub path: String,
    pub peer: String,
    /// The hostname that was requested, which carries the token.
    pub host: String,
    /// The address a lookup was answered with, when the interaction was a lookup.
    pub resolved: Option<String>,
    /// Formatted UTC timestamp (`yyyy-MMM-dd HH:mm:ss.SSS UTC`).
    #[serde(default)]
    pub timestamp_utc: String,
    /// Extracted Collaborator payload ID / subdomain token.
    #[serde(default)]
    pub payload_id: String,
    /// Full captured HTTP request, formatted DNS query, or SMTP conversation.
    #[serde(default)]
    pub raw_request: String,
    /// Full HTTP response, DNS answer, or extracted SMTP email body.
    #[serde(default)]
    pub raw_response: String,
    /// Whether the analyst has viewed/read this interaction in the Collaborator table.
    #[serde(default)]
    pub read: bool,
    /// Analyst comment attached to this interaction row.
    #[serde(default)]
    pub comment: String,
    /// Optional row highlight colour code (`1..=5`).
    #[serde(default)]
    pub highlight: Option<u8>,
}

impl Hit {
    pub fn display_time(&self) -> &str {
        if self.timestamp_utc.is_empty() {
            "2026-Oct-21 12:00:00.000 UTC"
        } else {
            &self.timestamp_utc
        }
    }

    pub fn display_payload(&self) -> String {
        if !self.payload_id.is_empty() {
            self.payload_id.clone()
        } else {
            extract_payload_id(&self.host, &self.path)
        }
    }

    pub fn display_source_ip(&self) -> &str {
        self.peer.split(':').next().unwrap_or(&self.peer)
    }
}

/// Generates a random alphanumeric token of 16 characters.
pub fn new_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let raw: Vec<u8> = (0..16)
        .map(|_| ALPHABET[(rand_u32() as usize) % ALPHABET.len()])
        .collect();
    String::from_utf8(raw).expect("alphabet is ascii")
}

fn rand_u32() -> u32 {
    use std::cell::Cell;
    thread_local! {
        static STATE: Cell<u32> = const { Cell::new(0x2545_F491) };
    }
    STATE.with(|state| {
        let mut x = state.get();
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        state.set(x);
        x
    })
}

/// Starts the local HTTP Collaborator server, returning the port it bound.
pub fn start() -> Result<u16, String> {
    listener::start()
}

/// Stops the local HTTP Collaborator server.
pub fn stop() {
    listener::stop();
}

/// True while the HTTP Collaborator server thread is accepting.
pub fn is_running() -> bool {
    listener::is_running()
}

/// Starts the local DNS Collaborator resolver, returning the port it bound.
pub fn start_dns() -> Result<u16, String> {
    resolver::start()
}

/// Stops the local DNS Collaborator resolver.
pub fn stop_dns() {
    resolver::stop();
}

/// True while the DNS resolver is answering.
pub fn dns_running() -> bool {
    resolver::is_running()
}

/// Starts the local SMTP Collaborator listener, returning the port it bound.
pub fn start_smtp() -> Result<u16, String> {
    smtp_listener::start()
}

/// Stops the local SMTP Collaborator listener.
pub fn stop_smtp() {
    smtp_listener::stop();
}

/// True while the SMTP listener is accepting.
pub fn smtp_running() -> bool {
    smtp_listener::is_running()
}

/// Takes everything recorded since the last call, leaving the store empty.
pub fn take_hits() -> Vec<Hit> {
    std::mem::take(&mut *HITS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Appends a hit, populating `timestamp_utc` and `payload_id` if omitted, and keeping the store bounded.
pub fn record(mut hit: Hit) {
    if hit.timestamp_utc.is_empty() {
        hit.timestamp_utc = now_utc_timestamp();
    }
    if hit.payload_id.is_empty() {
        hit.payload_id = extract_payload_id(&hit.host, &hit.path);
    }
    let mut store = HITS.lock().unwrap_or_else(|e| e.into_inner());
    if store.len() >= MAX_HITS {
        store.remove(0);
    }
    store.push(hit);
}

/// Sends live DNS, HTTP, and SMTP health-check interactions to the local Collaborator listeners
/// (`settings/project/collaborator.html#run-health-check`).
pub fn send_health_check_probes(
    token: &str,
    http_port: Option<u16>,
    dns_port: Option<u16>,
    smtp_port: Option<u16>,
) {
    let tok = if token.trim().is_empty() {
        new_token()
    } else {
        token.trim().to_string()
    };
    let fqdn = format!("{tok}.{DOMAIN}");

    // 1. DNS A lookup probe
    if let Some(dport) = dns_port {
        let fqdn_dns = fqdn.clone();
        std::thread::spawn(move || {
            if let Ok(sock) = std::net::UdpSocket::bind("127.0.0.1:0") {
                let _ = sock.set_read_timeout(Some(std::time::Duration::from_millis(800)));
                let q = crate::dns::query(0x1337, &fqdn_dns, crate::dns::kind::A, 1);
                let _ = sock.send_to(&q, ("127.0.0.1", dport));
                let mut buf = [0u8; 512];
                let _ = sock.recv_from(&mut buf);
            }
        });
    }

    // 2. HTTP GET callback probe
    if let Some(hport) = http_port {
        let fqdn_http = fqdn.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", hport)) {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(800)));
                let req = format!(
                    "GET /?healthcheck=1 HTTP/1.1\r\nHost: {fqdn_http}\r\nUser-Agent: Collaborator-HealthCheck/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(req.as_bytes());
                let mut resp = Vec::new();
                let _ = stream.read_to_end(&mut resp);
            }
        });
    }

    // 3. SMTP callback probe
    if let Some(sport) = smtp_port {
        let fqdn_smtp = fqdn;
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", sport)) {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(800)));
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                for line in [
                    format!("EHLO {fqdn_smtp}\r\n"),
                    format!("MAIL FROM:<probe@{fqdn_smtp}>\r\n"),
                    format!("RCPT TO:<collab@{fqdn_smtp}>\r\n"),
                    "DATA\r\nSubject: Collaborator OOB SMTP Probe\r\n\r\nOut-of-band SMTP interaction verified.\r\n.\r\n".to_string(),
                    "QUIT\r\n".to_string(),
                ] {
                    let _ = stream.write_all(line.as_bytes());
                    let _ = stream.read(&mut buf);
                }
            }
        });
    }
}

static HITS: Mutex<Vec<Hit>> = Mutex::new(Vec::new());

mod resolver {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    static RUNNING: AtomicBool = AtomicBool::new(false);

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    pub fn start() -> Result<u16, String> {
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .map_err(|e| e.to_string())?;
        let port = socket.local_addr().map_err(|e| e.to_string())?.port();
        RUNNING.store(true, Ordering::SeqCst);
        let domain1 = format!(".{DOMAIN}");
        let domain2 = format!(".{LEGACY_DOMAIN}");
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while RUNNING.load(Ordering::SeqCst) {
                let Ok((read, peer)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                let Ok(message) = crate::dns::decode(&buf[..read]) else {
                    continue;
                };
                let Some(question) = message.questions.first() else {
                    continue;
                };
                if !question.name.ends_with(&domain1) && !question.name.ends_with(&domain2) {
                    continue;
                }
                let address = [127, 0, 0, 1];
                let qtype = crate::dns::kind_name(question.kind).to_string();
                let hex_wire: String = buf[..read]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let dns_req_text = format!(
                    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {}\r\n\
                     ;; QUESTION SECTION:\r\n\
                     ;{}.\t\tIN\t{}\r\n\r\n\
                     ;; Raw DNS UDP wire bytes ({} bytes):\r\n{}",
                    message.id, question.name, qtype, read, hex_wire
                );
                let dns_resp_text = format!(
                    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {}\r\n\
                     ;; ANSWER SECTION:\r\n\
                     {}.\t60\tIN\t{}\t127.0.0.1\r\n",
                    message.id, question.name, qtype
                );
                record(Hit {
                    kind: "DNS".to_string(),
                    method: qtype,
                    path: question.name.clone(),
                    peer: peer.to_string(),
                    host: question.name.clone(),
                    resolved: Some("127.0.0.1".to_string()),
                    timestamp_utc: now_utc_timestamp(),
                    payload_id: extract_payload_id(&question.name, ""),
                    raw_request: dns_req_text,
                    raw_response: dns_resp_text,
                    read: false,
                    comment: String::new(),
                    highlight: None,
                });
                let answer = if question.kind == crate::dns::kind::A {
                    crate::dns::response(
                        message.id,
                        &question.name,
                        question.kind,
                        question.class,
                        60,
                        address,
                    )
                } else {
                    crate::dns::empty_response(
                        message.id,
                        &question.name,
                        question.kind,
                        question.class,
                    )
                };
                let _ = socket.send_to(&answer, peer);
            }
        });
        Ok(port)
    }
}

mod listener {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    static RUNNING: AtomicBool = AtomicBool::new(false);

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    pub fn start() -> Result<u16, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        RUNNING.store(true, Ordering::SeqCst);
        std::thread::spawn(move || serve(listener));
        Ok(port)
    }

    fn serve(listener: std::net::TcpListener) {
        use std::io::Write;
        while RUNNING.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    if let Ok(request) = read_request_full(&mut stream) {
                        let peer = stream
                            .peer_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "127.0.0.1".into());
                        let (method, target, host) = parse_request(&request);
                        let body = "<html><body>collaborator cr4393h3ipr3hi30f3jif3op</body></html>";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nServer: Collaborator\r\nX-Collaborator-Version: 4\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let payload_id = extract_payload_id(&host, &target);
                        super::record(Hit {
                            kind: "HTTP".to_string(),
                            method,
                            path: target,
                            peer,
                            host,
                            resolved: None,
                            timestamp_utc: now_utc_timestamp(),
                            payload_id,
                            raw_request: request,
                            raw_response: response.clone(),
                            read: false,
                            comment: String::new(),
                            highlight: None,
                        });
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }

    fn read_request_full(stream: &mut std::net::TcpStream) -> Result<String, String> {
        use std::io::Read;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .ok();
        let mut head = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];
        while head.len() < 16 * 1024 {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => head.push(byte[0]),
                Err(e) => return Err(e.to_string()),
            }
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head_str = String::from_utf8_lossy(&head).into_owned();
        let content_len = head_str
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
            .min(32 * 1024);
        if content_len > 0 {
            let mut body = vec![0u8; content_len];
            let mut read_total = 0usize;
            while read_total < content_len {
                match stream.read(&mut body[read_total..]) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => read_total += n,
                }
            }
            head.extend_from_slice(&body[..read_total]);
        }
        Ok(String::from_utf8_lossy(&head).into_owned())
    }

    fn parse_request(head: &str) -> (String, String, String) {
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let target = parts.next().unwrap_or("/").to_string();
        let mut host = String::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("host") {
                    host = value.trim().to_string();
                    break;
                }
            }
        }
        (method, target, host)
    }
}

mod smtp_listener {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    static RUNNING: AtomicBool = AtomicBool::new(false);

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    pub fn start() -> Result<u16, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        RUNNING.store(true, Ordering::SeqCst);
        std::thread::spawn(move || serve_smtp(listener));
        Ok(port)
    }

    fn serve_smtp(listener: std::net::TcpListener) {
        while RUNNING.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, peer_addr)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(3)));
                    let peer = peer_addr.to_string();
                    let mut transcript = String::new();
                    let mut email_body = String::new();
                    let mut host = format!("collab.{DOMAIN}");
                    let mut rcpt = String::new();

                    let greeting = format!("220 {DOMAIN} ESMTP Collaborator\r\n");
                    let _ = stream.write_all(greeting.as_bytes());
                    transcript.push_str(&format!("S: {greeting}"));

                    if let Ok(cloned) = stream.try_clone() {
                        let mut reader = BufReader::new(cloned);
                        let mut in_data = false;
                        for _ in 0..32 {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                break;
                            }
                            transcript.push_str(&format!("C: {line}"));
                            let trimmed = line.trim();
                            if in_data {
                                if trimmed == "." {
                                    in_data = false;
                                    let reply = "250 2.0.0 OK: queued\r\n";
                                    let _ = stream.write_all(reply.as_bytes());
                                    transcript.push_str(&format!("S: {reply}"));
                                } else {
                                    email_body.push_str(&line);
                                }
                                continue;
                            }
                            let upper = trimmed.to_ascii_uppercase();
                            if upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
                                host = trimmed[5..].trim().to_string();
                                let reply = format!("250-{DOMAIN}\r\n250 OK\r\n");
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                            } else if upper.starts_with("MAIL FROM:") {
                                let reply = "250 2.1.0 OK\r\n";
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                            } else if upper.starts_with("RCPT TO:") {
                                rcpt = trimmed[8..].trim().trim_matches(['<', '>']).to_string();
                                if let Some((_, domain_part)) = rcpt.split_once('@') {
                                    host = domain_part.to_string();
                                }
                                let reply = "250 2.1.5 OK\r\n";
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                            } else if upper == "DATA" {
                                in_data = true;
                                let reply = "354 End data with <CR><LF>.<CR><LF>\r\n";
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                            } else if upper.starts_with("QUIT") {
                                let reply = "221 2.0.0 Bye\r\n";
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                                break;
                            } else {
                                let reply = "250 OK\r\n";
                                let _ = stream.write_all(reply.as_bytes());
                                transcript.push_str(&format!("S: {reply}"));
                            }
                        }
                    }

                    let payload_id = extract_payload_id(&host, &rcpt);
                    super::record(Hit {
                        kind: "SMTP".to_string(),
                        method: "ESMTP".to_string(),
                        path: if rcpt.is_empty() { host.clone() } else { rcpt },
                        peer,
                        host,
                        resolved: None,
                        timestamp_utc: now_utc_timestamp(),
                        payload_id,
                        raw_request: transcript,
                        raw_response: email_body,
                        read: false,
                        comment: String::new(),
                        highlight: None,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    static SERVER: Mutex<()> = Mutex::new(());

    fn sole_server() -> std::sync::MutexGuard<'static, ()> {
        let guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        stop();
        let _ = take_hits();
        guard
    }

    #[test]
    fn tokens_are_the_right_length_and_alphabet() {
        for _ in 0..20 {
            let token = new_token();
            assert_eq!(token.len(), 16);
            assert!(token.chars().all(|c| c.is_ascii_alphanumeric()), "{token}");
        }
    }

    #[test]
    fn tokens_are_not_all_the_same() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(new_token());
        }
        assert!(seen.len() > 40, "tokens repeat too often: {}", seen.len());
    }

    #[test]
    fn a_request_to_a_generated_host_is_recorded() {
        let _guard = sole_server();
        let port = start().expect("server starts");
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .write_all(b"GET /ping HTTP/1.1\r\nHost: abc123.burpcollaborator.test\r\n\r\n")
            .expect("write");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("collaborator"), "{response}");
        let hits = take_hits();
        assert!(
            hits.iter()
                .any(|h| h.host == "abc123.burpcollaborator.test" && h.path == "/ping"),
            "hit not recorded: {hits:?}"
        );
        stop();
    }

    #[test]
    fn taking_hits_empties_the_store() {
        let _guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        let _ = take_hits();
        record(Hit {
            kind: "HTTP".into(),
            method: "GET".into(),
            path: "/x".into(),
            peer: "p".into(),
            host: "h".into(),
            resolved: None,
            ..Default::default()
        });
        assert_eq!(take_hits().len(), 1);
        assert!(
            take_hits().is_empty(),
            "a second take should see nothing new"
        );
    }

    #[test]
    fn stopping_ends_the_accept_loop() {
        let _guard = sole_server();
        let port = start().expect("server starts");
        assert!(is_running());
        stop();
        for _ in 0..100 {
            if !is_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!is_running());
        std::thread::sleep(std::time::Duration::from_millis(200));
        let refused = std::net::TcpStream::connect(("127.0.0.1", port)).is_err();
        assert!(refused, "server still accepting on {port} after stop");
    }

    #[test]
    fn the_resolver_answers_a_lookup_and_records_it() {
        let _guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        let _ = take_hits();
        let port = start_dns().expect("resolver starts");
        assert!(dns_running());

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        let name = format!("abc123.{DOMAIN}");
        let query = crate::dns::query(1234, &name, crate::dns::kind::A, 1);
        socket
            .send_to(&query, ("127.0.0.1", port))
            .expect("send query");

        let mut buf = [0u8; 2048];
        let (read, _) = socket.recv_from(&mut buf).expect("answer");
        let answer = crate::dns::decode(&buf[..read]).expect("decodes");
        assert!(answer.is_response);
        assert_eq!(answer.id, 1234);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].name, name);

        let hits = take_hits();
        assert_eq!(hits.len(), 1, "the lookup should be recorded");
        assert_eq!(hits[0].kind, "DNS");
        assert_eq!(hits[0].host, name);
        assert_eq!(hits[0].resolved.as_deref(), Some("127.0.0.1"));

        stop_dns();
        for _ in 0..100 {
            if !dns_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!dns_running());
    }

    #[test]
    fn the_hit_store_stays_bounded() {
        let _guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        let _ = take_hits();
        for index in 0..MAX_HITS + 10 {
            record(Hit {
                kind: "HTTP".into(),
                method: "GET".into(),
                path: format!("/{index}"),
                peer: "p".into(),
                host: "h".into(),
                resolved: None,
                ..Default::default()
            });
        }
        let store = HITS.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(store.len(), MAX_HITS);
        assert_eq!(
            store.last().map(|h| h.path.as_str()),
            Some(format!("/{}", MAX_HITS + 9).as_str())
        );
    }

    #[test]
    fn an_oversized_head_does_not_hang_the_server() {
        let _guard = sole_server();
        let port = start().expect("server starts");
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let chunk = vec![b'a'; 4096];
        let _ = stream.write_all(&chunk);
        let _ = stream.flush();
        drop(stream);
        stop();
    }
}
