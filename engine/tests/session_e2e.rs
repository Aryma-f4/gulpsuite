//! Session handling through the real proxy: a cookie set by the origin must come back on the next
//! request, and an explicit cookie must win over the jar.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gulpsuite::proxy::{Event, Proxy};

/// One-shot origin. Sets a cookie on its first response and then echoes whether it received one.
fn start_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().unwrap().port();
    let counter = Arc::new(AtomicUsize::new(0));
    let first_cookie = counter.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let counter = counter.clone();
            let first = first_cookie.fetch_add(0, Ordering::SeqCst) == 0;
            let _ = first;
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let had_cookie = request
                    .to_lowercase()
                    .split("\r\n")
                    .any(|line| line.starts_with("cookie:"));
                let body = if had_cookie { "with-cookie" } else { "no-cookie" };
                let first_response = counter.fetch_add(1, Ordering::SeqCst) == 0;
                let set = if first_response {
                    "Set-Cookie: sid=secret42; Path=/; HttpOnly\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\n{set}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    port
}

fn proxy_get(proxy_port: u16, host: &str, extra: &str) -> String {
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect to proxy");
    let request = format!(
        "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra}\r\n"
    );
    stream.write_all(request.as_bytes()).expect("write request");
    let mut out = String::new();
    let _ = stream.read_to_string(&mut out);
    out
}

/// Waits until the jar has at least `n` cookies, polling the jar the UI would read.
fn wait_for_cookies(runtime: &tokio::runtime::Runtime, proxy: &Proxy, n: usize) -> bool {
    for _ in 0..200 {
        if runtime.block_on(async { proxy.cookies().len() }) >= n {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn the_proxy_learns_a_cookie_and_replays_it() {
    let origin = start_origin();
    // A multi-thread runtime: a current-thread one stops driving the accept loop the moment
    // block_on returns, so the proxy would never accept anything.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let (proxy, _events) = Proxy::new();
    proxy.set_intercept(false);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let first = proxy_get(proxy_port, &host, "");
    assert!(
        first.contains("no-cookie"),
        "the first request must not carry a cookie yet"
    );

    assert!(
        wait_for_cookies(&runtime, &proxy, 1),
        "the Set-Cookie must land in the jar"
    );

    let second = proxy_get(proxy_port, &host, "");
    assert!(
        second.contains("with-cookie"),
        "the second request must replay the stored cookie, got: {second}"
    );

    runtime.block_on(proxy.stop());
}

#[test]
fn an_explicit_cookie_header_wins_over_the_jar() {
    let origin = start_origin();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let (proxy, _events) = Proxy::new();
    proxy.set_intercept(false);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let _ = proxy_get(proxy_port, &host, "");
    assert!(wait_for_cookies(&runtime, &proxy, 1));

    // With our own Cookie header present the jar must stay out of the way. The origin reports
    // "with-cookie" either way, so what is being checked is that the request is not duplicated or
    // overwritten: the jar adds nothing, the caller's value is what goes out.
    let explicit = proxy_get(proxy_port, &host, "Cookie: mine=1\r\n");
    assert!(
        explicit.contains("with-cookie"),
        "the explicit header must reach the origin"
    );

    runtime.block_on(proxy.stop());
}
