use egui_kittest::{kittest::Queryable, Harness};
use gulpsuite::http_target::HttpTarget;
use gulpsuite::proxy::Proxy;
use gulpsuite::ui::app::{App, REPEATER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn origin(response: &[u8], keep_open: bool) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let response = response.to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&request);
        let length = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await.unwrap();
        request.extend(body);
        let _ = stream.write_all(&response).await;
        if keep_open {
            let _ = stream.read(&mut byte).await;
        }
        request
    });
    (port, task)
}

#[test]
fn targets_route_http_https_explicit_ports_and_ipv6() {
    for (input, host, port, secure) in [
        ("http://example.test/path?q=1", "example.test", 80, false),
        ("https://example.test/", "example.test", 443, true),
        ("https://example.test:8443/", "example.test", 8443, true),
        ("127.0.0.1:8080", "127.0.0.1", 8080, false),
        ("http://[::1]:8080/", "::1", 8080, false),
        ("HTTPS://example.test/", "example.test", 443, true),
    ] {
        let target = HttpTarget::parse(input).unwrap();
        assert_eq!(
            (target.host.as_str(), target.port, target.secure),
            (host, port, secure)
        );
    }
    for input in [
        "",
        "https://",
        "ftp://example.test",
        "http://host:invalid",
        "http://host:0",
        "http://user:pass@host/",
        "/path-without-a-host",
    ] {
        assert!(HttpTarget::parse(input).is_err(), "accepted {input}");
    }
}

#[tokio::test]
async fn response_headers_accept_non_utf8_http_bytes() {
    let (port, task) = origin(
        b"HTTP/1.1 200 OK\r\nX-Filename: caf\xe9.txt\r\nContent-Length: 2\r\n\r\nok",
        true,
    )
    .await;
    let (proxy, _) = Proxy::new();
    let (status, response) = proxy
        .one_shot(
            "127.0.0.1",
            port,
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            1000,
        )
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert!(response.ends_with("ok"));
    task.await.unwrap();
}

#[tokio::test]
async fn chunk_metadata_is_bounded_before_a_newline_arrives() {
    for trailer in [false, true] {
        let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        if trailer {
            response.extend_from_slice(b"0\r\n");
        }
        response.extend(vec![b'a'; if trailer { 65537 } else { 8193 }]);
        let (port, task) = origin(&response, true).await;
        let (proxy, _) = Proxy::new();
        let result = proxy
            .one_shot(
                "127.0.0.1",
                port,
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                1000,
            )
            .await;
        assert!(result.unwrap_err().contains("limit"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn manual_requests_finish_at_http_message_boundaries_on_keepalive_connections() {
    for (method, response, status) in [
        ("GET", &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..], 200),
        ("GET", &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=1\r\nok\r\n0\r\nX-Trailer: value\r\n\r\n"[..], 200),
        ("HEAD", &b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"[..], 200),
        ("GET", &b"HTTP/1.1 204 No Content\r\n\r\n"[..], 204),
        ("GET", &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n"[..], 304),
        ("GET", &b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..], 200),
    ] {
        let (port, task) = origin(response, true).await;
        let (proxy, _) = Proxy::new();
        let result = proxy.one_shot("127.0.0.1", port, &format!("{method} / HTTP/1.1\r\nHost: localhost\r\n\r\n"), 1000).await;
        assert!(result.is_ok(), "{method} response stalled: {result:?}");
        assert_eq!(result.unwrap().0, status);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn edited_request_bodies_keep_literal_bytes_and_correct_content_length() {
    let (port, task) = origin(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false).await;
    let (proxy, _) = Proxy::new();
    proxy
        .one_shot(
            "127.0.0.1",
            port,
            "POST / HTTP/1.1\nHost: localhost\nContent-Length: 999\n\na\nbé",
            1000,
        )
        .await
        .unwrap();
    let sent = task.await.unwrap();
    assert!(sent.ends_with("a\nbé".as_bytes()));
    assert!(String::from_utf8(sent)
        .unwrap()
        .contains("Content-Length: 5\r\n"));
}

#[tokio::test]
async fn truncated_response_is_an_error_instead_of_successful_partial_data() {
    let (port, task) = origin(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort", false).await;
    let (proxy, _) = Proxy::new();
    assert!(proxy
        .one_shot(
            "127.0.0.1",
            port,
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            1000
        )
        .await
        .is_err());
    task.await.unwrap();
}

#[tokio::test]
async fn oversized_declared_bodies_are_rejected_without_allocating_the_declared_size() {
    for response in [
        &b"HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n"[..],
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFF\r\n"[..],
    ] {
        let (port, task) = origin(response, true).await;
        let (proxy, _) = Proxy::new();
        let result = proxy
            .one_shot(
                "127.0.0.1",
                port,
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                1000,
            )
            .await;
        assert!(result.unwrap_err().contains("limit"));
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn proxy_logs_framed_responses_without_waiting_for_upstream_keepalive_to_close() {
    let (origin_port, task) = origin(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true).await;
    let (proxy, mut events) = Proxy::new();
    let proxy_port = proxy.start(0).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    stream
        .write_all(
            format!("GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.read_to_end(&mut response),
    )
    .await
    .expect("proxy must complete a framed response")
    .unwrap();
    assert!(response.ends_with(b"ok"));
    let mut logged = false;
    while let Ok(event) = events.try_recv() {
        if matches!(event, gulpsuite::proxy::Event::Tx { status: 200, .. }) {
            logged = true;
        }
    }
    assert!(logged);
    proxy.stop().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .expect("upstream socket must close")
        .unwrap();
}

#[tokio::test]
async fn response_interception_skips_interim_heads_and_holds_the_final_response() {
    let (origin_port, task) = origin(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        true,
    )
    .await;
    let (proxy, mut events) = Proxy::new();
    proxy.set_intercept(true);
    proxy.set_intercept_response(true);
    let port = proxy.start(0).await.unwrap();
    let client = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(
                format!("GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.read_to_string(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        response
    });
    let forward = async {
        loop {
            if let gulpsuite::proxy::Event::Held { id, .. } = events.recv().await.unwrap() {
                proxy.forward(id).await;
                break;
            }
        }
        loop {
            if let gulpsuite::proxy::Event::HeldResponse { id, status, .. } =
                events.recv().await.unwrap()
            {
                assert_eq!(status, 200);
                proxy.forward(id).await;
                break;
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), forward)
        .await
        .expect("final response should be intercepted");
    assert!(client.await.unwrap().ends_with("ok"));
    proxy.stop().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn repeater_background_tabs_complete_while_another_tool_is_visible() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            workers.push(std::thread::spawn(move || {
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                if path == "/first" {
                    std::thread::sleep(std::time::Duration::from_millis(40));
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    path.len(),
                    path
                )
                .unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let host = format!("http://127.0.0.1:{port}");
    let mut harness = Harness::builder()
        .with_size(eframe::egui::vec2(1440.0, 790.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = REPEATER;
            app.panels.repeater.active_mut().host = host.clone();
            app.panels.repeater.active_mut().raw =
                "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n".into();
            app
        });
    harness.get_by_label("Send").click();
    harness.run();
    harness
        .state_mut()
        .panels
        .repeater
        .open(&host, "GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n");
    harness.run();
    harness.get_by_label("Send").click();
    harness.run();
    harness.get_by_label("Dashboard").click();
    harness.run();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while harness
        .state()
        .panels
        .repeater
        .tabs
        .iter()
        .any(|tab| tab.sending)
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
        harness.run();
    }
    let tabs = &harness.state().panels.repeater.tabs;
    assert!(!tabs[0].sending && !tabs[1].sending);
    assert!(tabs[0].response.ends_with("/first"));
    assert!(tabs[1].response.ends_with("/second"));
    assert_eq!(tabs[0].history.len(), 1);
    assert_eq!(tabs[1].history.len(), 1);
    server.join().unwrap();
}

#[test]
fn repeater_cancel_closes_the_connection_and_does_not_record_a_stale_response() {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        accepted_tx.send(()).unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        request
    });
    let mut harness = Harness::builder()
        .with_size(eframe::egui::vec2(1440.0, 790.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = REPEATER;
            app.panels.repeater.active_mut().host = format!("http://127.0.0.1:{port}");
            app
        });
    harness.get_by_label("Send").click();
    harness.run();
    accepted_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    harness.get_by_label("Cancel").click();
    harness.run();
    assert!(!harness.state().panels.repeater.active().sending);
    assert!(harness.state().panels.repeater.active().history.is_empty());
    assert!(!server.join().unwrap().is_empty());
    harness.run();
    assert_eq!(
        harness.state().panels.repeater.active().response,
        "Request cancelled"
    );
}
