//! Live WebSocket capture through the proxy.
//!
//! This stands up a real RFC 6455 server, upgrades a real client through the proxy, exchanges
//! frames, and asserts the proxy recorded them. The codec has unit tests; this proves the wiring.

use std::io::{Read, Write};
use std::time::Duration;

use gulpsuite::proxy::Event;
use gulpsuite::ws;

/// Reads a single HTTP head (up to the blank line) from a blocking stream.
fn read_head(stream: &mut std::net::TcpStream) -> String {
    let mut head = String::new();
    let mut byte = [0u8; 1];
    while !head.ends_with("\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0] as char),
        }
    }
    head
}

/// A WebSocket server that performs the handshake and echoes text frames back.
fn serve(listener: std::net::TcpListener, key: &'static str) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let head = read_head(&mut stream);
        assert!(head.to_lowercase().contains("upgrade: websocket"), "handshake head was {head}");
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws::accept_for(key)
        );
        stream.write_all(response.as_bytes()).expect("write handshake");
        // Echo one masked text frame, then send an unmasked one back.
        let mut incoming = vec![0u8; 64];
        let n = stream.read(&mut incoming).expect("read frame");
        let (frames, _) = ws::decode(&incoming[..n]).expect("client frame decodes");
        assert!(frames[0].masked, "a client-to-server frame must be masked");
        assert_eq!(frames[0].as_text(), Some("ping from client"));
        let _ = stream.write_all(&ws::encode(&ws::Frame::text("pong from server"), None));
        let _ = stream.flush();
        // Hold the connection open long enough for the proxy to relay the reply.
        std::thread::sleep(Duration::from_millis(300));
    })
}

#[test]
fn an_upgraded_connection_is_recorded_frame_by_frame() {
    // A multi-thread runtime, for the same reason the other proxy tests use one: a current-thread
    // runtime stops driving the accept loop the moment block_on returns.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind server");
    let server_port = listener.local_addr().expect("addr").port();
    let server = serve(listener, key);

    let (proxy, mut events) = gulpsuite::proxy::Proxy::new();
    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy starts");
    let collector = runtime.spawn(async move {
        let mut opened = Vec::new();
        let mut frames = Vec::new();
        let mut closed = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Ok(Event::WsOpen { id, host, request, response })) => {
                    assert!(host.contains(&server_port.to_string()), "host was {host}");
                    assert!(request.to_lowercase().contains("sec-websocket-key"), "{request}");
                    assert!(response.starts_with("HTTP/1.1 101"), "{response}");
                    assert!(response.contains(ws::accept_for(key).as_str()), "accept mismatch");
                    opened.push(id);
                }
                Ok(Ok(Event::WsFrame { id, to_server, opcode, text, bytes })) => {
                    frames.push((id, to_server, opcode, text, bytes));
                }
                Ok(Ok(Event::WsClosed { id })) => {
                    closed = opened.contains(&id);
                    break;
                }
                Ok(Ok(_)) => {}
                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }
        (opened, frames, closed)
    });

    // The client speaks to the proxy, not the server, which is what makes this a proxy test.
    let mut client = std::net::TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect via proxy");
    client
        .write_all(
            format!(
                "GET /chat HTTP/1.1\r\nHost: 127.0.0.1:{server_port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("send handshake");
    client
        .write_all(&ws::encode(&ws::Frame::text("ping from client"), Some([0x11, 0x22, 0x33, 0x44])))
        .expect("send frame");

    let (opened, frames, closed) = runtime.block_on(collector).expect("collector");
    drop(client);
    runtime.block_on(proxy.stop());
    let _ = server.join();

    assert_eq!(opened.len(), 1, "exactly one upgrade should be recorded");
    assert!(closed, "the connection should be reported closed");

    let id = opened[0];
    let to_server: Vec<_> = frames.iter().filter(|f| f.0 == id && f.1).collect();
    let to_client: Vec<_> = frames.iter().filter(|f| f.0 == id && !f.1).collect();
    assert!(
        to_server.iter().any(|f| f.3 == "ping from client"),
        "client frame missing from {frames:?}"
    );
    assert!(
        to_client.iter().any(|f| f.3 == "pong from server"),
        "server frame missing from {frames:?}"
    );
    for (_, _, opcode, _, _) in &to_server {
        assert_eq!(*opcode, ws::opcode::TEXT);
    }
}
