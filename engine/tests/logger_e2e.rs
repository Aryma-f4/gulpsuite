//! Live DNS and SMTP capture through the Logger's listeners.

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::Duration;

use gulpsuite::proxy::Event;

fn runtime() -> tokio::runtime::Runtime {
    // Multi-thread, for the same reason the other proxy tests use one.
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn a_dns_query_is_recorded_by_the_logger() {
    let rt = runtime();
    let (proxy, mut events) = gulpsuite::proxy::Proxy::new();
    let dns_port = rt.block_on(proxy.start_dns(0)).expect("dns starts");

    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let query = gulpsuite::dns::query(0x4242, "capture.test", gulpsuite::dns::kind::A, 1);
    socket.send_to(&query, ("127.0.0.1", dns_port)).expect("send");

    let mut buffer = vec![0u8; 4096];
    let (n, _) = socket.recv_from(&mut buffer).expect("answer");
    assert!(n > 12, "short answer: {n}");
    // The listener must set the response bit, or a resolver rejects it.
    assert_eq!(buffer[0..2], [0x42, 0x42], "transaction id must match");
    assert!(buffer[2] & 0x80 != 0, "response bit must be set");

    // The decoded query must also reach the UI.
    let found = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Ok(Event::Dns { question, kind, .. })) => return Some((question, kind)),
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        None
    });
    let (question, kind) = found.expect("dns event");
    assert_eq!(question, "capture.test");
    assert_eq!(kind, gulpsuite::dns::kind::A);
}

#[test]
fn an_smtp_message_is_recorded_by_the_logger() {
    let rt = runtime();
    let (proxy, mut events) = gulpsuite::proxy::Proxy::new();
    let smtp_port = rt.block_on(proxy.start_smtp(0)).expect("smtp starts");

    let mut client = std::net::TcpStream::connect(("127.0.0.1", smtp_port)).expect("connect");
    client.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let read_line = |c: &mut std::net::TcpStream| {
        let mut line = String::new();
        let mut byte = [0u8; 1];
        while !line.ends_with("\r\n") {
            match c.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => line.push(byte[0] as char),
            }
        }
        line
    };

    assert!(read_line(&mut client).starts_with("220"), "banner");
    client.write_all(b"EHLO tester\r\n").expect("ehlo");
    assert!(read_line(&mut client).starts_with("250"));
    client.write_all(b"MAIL FROM:<a@example.test>\r\n").expect("mail from");
    assert!(read_line(&mut client).starts_with("250"));
    client.write_all(b"RCPT TO:<b@example.test>\r\n").expect("rcpt to");
    assert!(read_line(&mut client).starts_with("250"));
    client.write_all(b"DATA\r\n").expect("data");
    assert!(read_line(&mut client).starts_with("354"));
    client
        .write_all(b"SUBJECT: hello\r\n\r\nbody line one\r\nbody line two\r\n.\r\n")
        .expect("payload");
    assert!(read_line(&mut client).starts_with("250"));

    let found = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Ok(Event::Smtp { from, to, subject, body, .. })) => {
                    return Some((from, to, subject, body))
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        None
    });
    let (from, to, subject, body) = found.expect("smtp event");
    assert_eq!(from, "a@example.test");
    assert_eq!(to, vec!["b@example.test".to_string()]);
    assert_eq!(subject, "hello");
    assert!(body.contains("body line one"), "{body}");
    assert!(body.contains("body line two"), "{body}");
}

/// Stop has to release the port, not just clear the label in the view.
#[test]
fn stopping_dns_capture_releases_the_port() {
    let rt = runtime();
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    let port = rt.block_on(proxy.start_dns(0)).expect("dns starts");
    assert!(rt.block_on(proxy.dns_running()), "should report running");

    rt.block_on(proxy.stop_dns());
    assert!(!rt.block_on(proxy.dns_running()), "should report stopped");

    // A UDP socket cannot be "connected to", so rebinding the port is the check that matters.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match std::net::UdpSocket::bind(("127.0.0.1", port)) {
            Ok(socket) => {
                drop(socket);
                return;
            }
            Err(e) if std::time::Instant::now() < deadline => {
                assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "unexpected bind error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("port {port} still held after stop: {e}"),
        }
    }
}

/// Same for SMTP, where a TCP connect is the natural check.
#[test]
fn stopping_smtp_capture_releases_the_port() {
    let rt = runtime();
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    let port = rt.block_on(proxy.start_smtp(0)).expect("smtp starts");
    assert!(rt.block_on(proxy.smtp_running()));

    rt.block_on(proxy.stop_smtp());
    assert!(!rt.block_on(proxy.smtp_running()));

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                drop(listener);
                return;
            }
            Err(e) if std::time::Instant::now() < deadline => {
                assert_eq!(e.kind(), std::io::ErrorKind::AddrInUse, "unexpected bind error: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("port {port} still held after stop: {e}"),
        }
    }
}

/// Stopping the proxy takes the capture listeners down with it.
#[test]
fn stopping_the_proxy_also_stops_the_capture_listeners() {
    let rt = runtime();
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    rt.block_on(proxy.start_dns(0)).expect("dns starts");
    rt.block_on(proxy.start_smtp(0)).expect("smtp starts");

    rt.block_on(proxy.stop());
    assert!(!rt.block_on(proxy.dns_running()), "dns survived the proxy stop");
    assert!(!rt.block_on(proxy.smtp_running()), "smtp survived the proxy stop");
}
