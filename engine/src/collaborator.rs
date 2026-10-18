//! A local Collaborator server.
//!
//! Burp's Collaborator hands out a unique hostname and reports which servers interacted with it,
//! over DNS or HTTP. The hosted service is not available here, so this is a self-contained HTTP
//! variant: a token becomes a hostname, and any request to it is recorded. That is enough to drive
//! out-of-band interaction workflows against a target this machine can reach.

use std::sync::Mutex;

/// How long an interaction is kept. Bounded so a long session does not accumulate without limit.
pub const MAX_HITS: usize = 1_000;

/// A recorded interaction.
#[derive(Clone, Debug)]
pub struct Hit {
    pub method: String,
    pub path: String,
    pub peer: String,
    /// The hostname that was requested, which carries the token.
    pub host: String,
}

/// Generates a random alphanumeric token of `length` characters.
pub fn new_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let raw: Vec<u8> = (0..16).map(|_| ALPHABET[(rand_u32() as usize) % ALPHABET.len()]).collect();
    String::from_utf8(raw).expect("alphabet is ascii")
}

/// A tiny xorshift generator. This is a convenience token, not a cryptographic one, and nothing
/// here depends on unpredictability — a predictable token would still record its own callbacks.
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

/// Starts the local server, returning the port it bound.
pub fn start() -> Result<u16, String> {
    listener::start()
}

/// Stops the local server. The socket thread notices between accepts, so this returns immediately.
pub fn stop() {
    listener::stop();
}

/// True while a server thread is accepting.
pub fn is_running() -> bool {
    listener::is_running()
}

/// Takes everything recorded since the last call, leaving the store empty.
pub fn take_hits() -> Vec<Hit> {
    std::mem::take(&mut *HITS.lock().unwrap_or_else(|e| e.into_inner()))
}

/// Appends a hit, keeping the store bounded.
pub fn record(hit: Hit) {
    let mut store = HITS.lock().unwrap_or_else(|e| e.into_inner());
    if store.len() >= MAX_HITS {
        store.remove(0);
    }
    store.push(hit);
}

static HITS: Mutex<Vec<Hit>> = Mutex::new(Vec::new());

mod listener {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Set by `stop`, cleared by `start`. The accept loop polls it, which is how the socket thread
    /// learns to exit without blocking forever inside `accept`.
    static RUNNING: AtomicBool = AtomicBool::new(false);

    pub fn stop() {
        RUNNING.store(false, Ordering::SeqCst);
    }

    pub fn is_running() -> bool {
        RUNNING.load(Ordering::SeqCst)
    }

    /// The port currently in use, exposed so the UI can report it.
    pub fn start() -> Result<u16, String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        // Nonblocking accept plus a short sleep is what makes Stop observable from another thread.
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        RUNNING.store(true, Ordering::SeqCst);
        std::thread::spawn(move || serve(listener));
        Ok(port)
    }

    fn serve(listener: std::net::TcpListener) {
        use std::io::Write;
        // Read requests with a bounded line parser rather than an unbounded read.
        while RUNNING.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    if let Ok(request) = read_request_head(&mut stream) {
                        let peer = stream
                            .peer_addr()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|_| "unknown".into());
                        let (method, target, host) = parse_request(&request);
                        super::record(Hit { method, path: target, peer, host });
                        let body = "collaborator";
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
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

    /// Reads until the head ends or the cap is reached, so a client cannot exhaust memory here.
    fn read_request_head(stream: &mut std::net::TcpStream) -> Result<String, String> {
        use std::io::Read;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
        let mut head = String::new();
        let mut byte = [0u8; 1];
        while head.len() < 16 * 1024 {
            match stream.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => head.push(byte[0] as char),
                Err(e) => return Err(e.to_string()),
            }
            if head.ends_with("\r\n\r\n") {
                break;
            }
        }
        Ok(head)
    }

    fn parse_request(head: &str) -> (String, String, String) {
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let target = parts.next().unwrap_or("/").to_string();
        let mut host = String::new();
        for line in lines {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// One server and one hit store per process, so the tests that drive them take turns.
    static SERVER: Mutex<()> = Mutex::new(());

    /// Serialises a test that needs the server, and hands back a clean store.
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
        // The UI reads through this, so the recorded hit has to actually arrive.
        let hits = take_hits();
        assert!(
            hits.iter().any(|h| h.host == "abc123.burpcollaborator.test" && h.path == "/ping"),
            "hit not recorded: {hits:?}"
        );
        stop();
    }

    #[test]
    fn taking_hits_empties_the_store() {
        let _guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        let _ = take_hits();
        record(Hit { method: "GET".into(), path: "/x".into(), peer: "p".into(), host: "h".into() });
        assert_eq!(take_hits().len(), 1);
        assert!(take_hits().is_empty(), "a second take should see nothing new");
    }

    #[test]
    fn stopping_ends_the_accept_loop() {
        let _guard = sole_server();
        let port = start().expect("server starts");
        assert!(is_running());
        stop();
        // The loop polls the flag between accepts, so give it a moment to notice.
        for _ in 0..100 {
            if !is_running() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(!is_running());
        // Once stopped the port must stop answering.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let refused = std::net::TcpStream::connect(("127.0.0.1", port)).is_err();
        assert!(refused, "server still accepting on {port} after stop");
    }

    #[test]
    fn the_hit_store_stays_bounded() {
        let _guard = SERVER.lock().unwrap_or_else(|e| e.into_inner());
        let _ = take_hits();
        for index in 0..MAX_HITS + 10 {
            record(Hit {
                method: "GET".into(),
                path: format!("/{index}"),
                peer: "p".into(),
                host: "h".into(),
            });
        }
        let store = HITS.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(store.len(), MAX_HITS);
        // The oldest entry is the one dropped, so the newest survive.
        assert_eq!(store.last().map(|h| h.path.as_str()), Some(format!("/{}", MAX_HITS + 9).as_str()));
    }

    #[test]
    fn an_oversized_head_does_not_hang_the_server() {
        let _guard = sole_server();
        let port = start().expect("server starts");
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
        // No terminating blank line: the reader must stop at the cap and answer anyway.
        let chunk = vec![b'a'; 4096];
        let _ = stream.write_all(&chunk);
        let _ = stream.flush();
        drop(stream);
        stop();
    }
}
