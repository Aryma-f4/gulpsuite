//! Interception through the real proxy: a request is parked, the operator edits it, and the
//! edited message is what reaches the origin.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gulpsuite::proxy::{Event, Proxy};

/// An origin that records the request it was sent and answers with it.
fn start_origin() -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind origin");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let record = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let record = record.clone();
            std::thread::spawn(move || {
                // The request can arrive in more than one segment, so it is read until the head and
                // the body it announces are both in.
                let mut request = String::new();
                let mut buf = [0u8; 8192];
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.push_str(&String::from_utf8_lossy(&buf[..n]));
                    let complete = match request.find("\r\n\r\n") {
                        Some(index) => {
                            let length = request[..index]
                                .lines()
                                .find_map(|line| {
                                    line.split_once(':').and_then(|(name, value)| {
                                        name.trim()
                                            .eq_ignore_ascii_case("content-length")
                                            .then(|| value.trim().parse::<usize>().ok())
                                            .flatten()
                                    })
                                })
                                .unwrap_or(0);
                            request.len() - (index + 4) >= length
                        }
                        None => false,
                    };
                    if complete || std::time::Instant::now() > deadline {
                        break;
                    }
                }
                *record.lock().expect("record") = request.clone();
                let body = request.lines().next().unwrap_or("").to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            });
        }
    });
    (port, seen)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// Waits for the proxy to report a parked request.
fn wait_for_held(runtime: &tokio::runtime::Runtime, proxy: &Proxy) -> Option<u64> {
    for _ in 0..200 {
        let held = runtime.block_on(async { proxy.held().await });
        if let Some(item) = held.first() {
            return Some(item.id);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn an_edited_request_is_what_reaches_the_origin() {
    let (origin, seen) = start_origin();
    let runtime = runtime();
    let (proxy, events) = Proxy::new();
    proxy.set_intercept(true);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    // The client sends its request and waits; the proxy parks it instead of forwarding it.
    let client = {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
            let request =
                format!("GET http://{host}/original HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
            out
        })
    };

    let id = wait_for_held(&runtime, &proxy).expect("the request should be parked");
    let held = runtime.block_on(async { proxy.held().await });
    let parked = held.iter().find(|item| item.id == id).expect("parked");
    assert!(
        parked.raw.contains("/original"),
        "the parked request should be the one the client sent: {}",
        parked.raw
    );

    // The operator changes the path and lets it through.
    let edited = parked.raw.replace("/original", "/edited");
    assert!(
        runtime.block_on(async { proxy.forward_edited(id, &edited).await }),
        "the edited request should be released"
    );

    let answer = client.join().expect("client thread");
    assert!(
        answer.contains("/edited"),
        "the origin should have seen the edited request, got: {answer}"
    );

    let sent = seen.lock().expect("seen").clone();
    assert!(
        sent.contains("/edited"),
        "the origin should have received the edited path, got: {sent}"
    );
    assert!(
        !sent.contains("/original"),
        "the original path should not have gone out: {sent}"
    );

    runtime.block_on(proxy.stop());
}

#[test]
fn a_dropped_request_never_reaches_the_origin() {
    let (origin, seen) = start_origin();
    let runtime = runtime();
    let (proxy, _events) = Proxy::new();
    proxy.set_intercept(true);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let client = {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
            let request =
                format!("GET http://{host}/dropped HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
            out
        })
    };

    let id = wait_for_held(&runtime, &proxy).expect("the request should be parked");
    assert!(runtime.block_on(async { proxy.discard(id).await }));

    let _ = client.join().expect("client thread");
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        seen.lock().expect("seen").is_empty(),
        "a dropped request must not reach the origin"
    );

    runtime.block_on(proxy.stop());
}

#[test]
fn an_edited_body_keeps_the_content_length_in_step() {
    let (origin, seen) = start_origin();
    let runtime = runtime();
    let (proxy, _events) = Proxy::new();
    proxy.set_intercept(true);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let client = {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
            let request = format!(
                "POST http://{host}/submit HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd"
            );
            stream.write_all(request.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
            out
        })
    };

    let id = wait_for_held(&runtime, &proxy).expect("the request should be parked");
    let held = runtime.block_on(async { proxy.held().await });
    let parked = held.iter().find(|item| item.id == id).expect("parked");
    assert!(
        parked.raw.ends_with("abcd"),
        "the parked request should carry the body: {}",
        parked.raw
    );

    // The body is replaced with a longer one, so the length has to be corrected.
    let edited = parked.raw.replace("abcd", "abcdefgh");
    assert!(runtime.block_on(async { proxy.forward_edited(id, &edited).await }));

    let _ = client.join().expect("client thread");
    let sent = seen.lock().expect("seen").clone();
    assert!(sent.contains("abcdefgh"), "the new body should be sent: {sent}");
    assert!(
        sent.contains("Content-Length: 8"),
        "the content length should match the new body: {sent}"
    );

    runtime.block_on(proxy.stop());
}

#[test]
fn the_event_stream_reports_the_parked_request() {
    let (origin, _seen) = start_origin();
    let runtime = runtime();
    let (proxy, mut events) = Proxy::new();
    proxy.set_intercept(true);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let client = {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
            let request =
                format!("GET http://{host}/x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(request.as_bytes());
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
        })
    };

    let mut saw_held = false;
    let mut saw_released = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline && !(saw_held && saw_released) {
        let event = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(200), events.recv()).await
        });
        match event {
            Ok(Ok(Event::Held { id, .. })) => {
                saw_held = true;
                // Letting it through is what produces the release event.
                assert!(runtime.block_on(async { proxy.forward(id).await }));
            }
            Ok(Ok(Event::Released { forwarded: true, .. })) => saw_released = true,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }
    assert!(saw_held, "the proxy should report that it parked a request");
    assert!(saw_released, "the proxy should report that it let the request through");

    let _ = client.join().expect("client thread");
    runtime.block_on(proxy.stop());
}

#[test]
fn an_edited_response_is_what_the_client_gets() {
    let (origin, _seen) = start_origin();
    let runtime = runtime();
    let (proxy, _events) = Proxy::new();
    proxy.set_intercept(true);
    proxy.set_intercept_response(true);
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let host = format!("127.0.0.1:{origin}");

    let client = {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut stream =
                std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect");
            let request =
                format!("GET http://{host}/x HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            stream.write_all(request.as_bytes()).expect("write");
            let mut out = String::new();
            let _ = stream.read_to_string(&mut out);
            out
        })
    };

    // The request is let through, and the response is parked in its place.
    let id = wait_for_held(&runtime, &proxy).expect("the request should be parked");
    assert!(runtime.block_on(async { proxy.forward(id).await }));

    // The response is parked next.
    let mut response_id = None;
    for _ in 0..200 {
        let held = runtime.block_on(async { proxy.held().await });
        if let Some(item) = held
            .iter()
            .find(|item| item.kind == gulpsuite::proxy::HeldKind::Response)
        {
            response_id = Some(item.id);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let response_id = response_id.expect("the response should be parked");
    let held = runtime.block_on(async { proxy.held().await });
    let parked = held
        .iter()
        .find(|item| item.id == response_id)
        .expect("parked response");
    assert!(
        parked.raw.starts_with("HTTP/1.1 200"),
        "the parked response should be the answer: {}",
        parked.raw
    );

    // The operator changes the body of the response.
    let edited = parked.raw.replace("GET http://", "EDITED http://");
    assert!(
        runtime.block_on(async { proxy.forward_edited(response_id, &edited).await }),
        "the edited response should be released"
    );

    let answer = client.join().expect("client thread");
    assert!(
        answer.contains("EDITED http://"),
        "the client should have seen the edited response, got: {answer}"
    );

    runtime.block_on(proxy.stop());
}
