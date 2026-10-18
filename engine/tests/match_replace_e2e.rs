//! Match and replace: the rules must rewrite traffic on its way through the proxy.

use std::time::Duration;

use gulpsuite::proxy::Event;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A origin server that echoes the request head back, so a rewritten header is visible.
async fn start_echo_origin() -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 16384];
                let Ok(n) = socket.read(&mut buf).await else { return };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = format!("{request}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

#[test]
fn a_rule_rewrites_the_request_that_reaches_the_server() {
    let rt = runtime();
    let port = rt.block_on(start_echo_origin());
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    let bound = rt.block_on(proxy.start(0)).expect("proxy starts");

    proxy
        .set_rules("set_header \"X-Test\" \"rewritten\"\nremove_header \"X-Drop\"")
        .expect("rules parse");

    // Send a request through the proxy; the echo comes back with the rewritten head.
    let response = rt.block_on(async {
        proxy
            .one_shot(
                "127.0.0.1",
                port,
                "GET / HTTP/1.1\r\nHost: example.test\r\nX-Drop: gone\r\n\r\n",
                8000,
            )
            .await
    });
    let (status, text) = response.expect("response");
    assert_eq!(status, 200);
    assert!(text.contains("X-Test: rewritten"), "rule did not apply: {text}");
    assert!(!text.contains("X-Drop"), "removal rule did not apply: {text}");

    rt.block_on(proxy.stop());
    let _ = bound;
}

#[test]
fn rules_off_leaves_the_request_alone() {
    let rt = runtime();
    let port = rt.block_on(start_echo_origin());
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    rt.block_on(proxy.start(0)).expect("proxy starts");

    let (_, text) = rt
        .block_on(async {
            proxy
                .one_shot(
                    "127.0.0.1",
                    port,
                    "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: original\r\n\r\n",
                    8000,
                )
                .await
        })
        .expect("response");
    assert!(text.contains("X-Test: original"), "no rules should mean no change: {text}");

    rt.block_on(proxy.stop());
}

#[test]
fn a_broken_script_is_refused_and_leaves_the_rules_off() {
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    assert!(proxy.set_rules("set_header \"X-Test\"").is_err());
    assert!(!proxy.has_rules(), "a refused script must not be installed");
    proxy.set_rules("set_header \"X-Test\" \"1\"").expect("valid script");
    assert!(proxy.has_rules());
    proxy.clear_rules();
    assert!(!proxy.has_rules());
}

#[test]
fn the_rules_reach_the_listener_not_only_one_shot() {
    let rt = runtime();
    let port = rt.block_on(start_echo_origin());
    let (proxy, mut events) = gulpsuite::proxy::Proxy::new();
    let bound = rt.block_on(proxy.start(0)).expect("proxy starts");
    proxy.set_rules("set_header \"X-Live\" \"yes\"").expect("rules parse");

    // Talk to the proxy itself, so the request goes through the full listener path.
    let buf = rt.block_on(async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", bound))
            .await
            .expect("connect");
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{port}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut buf = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), client.read_to_string(&mut buf)).await;
        buf
    });
    assert!(buf.contains("X-Live: yes"), "the listener path did not apply the rules: {buf}");

    // And the proxy saw the traffic.
    let seen = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Ok(Event::Tx { .. })) => return true,
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        false
    });
    assert!(seen, "the proxy should have recorded the request");
    rt.block_on(proxy.stop());
}
