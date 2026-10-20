//! Https through the proxy: the client speaks TLS to the proxy, the proxy speaks TLS to the
//! origin, and the request in between is seen, logged and able to be changed.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use gulpsuite::proxy::Proxy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A client that trusts the given authorities.
fn client_config(roots: &[CertificateDer<'static>]) -> Result<rustls::ClientConfig, String> {
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).map_err(|e| e.to_string())?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(store)
        .with_no_client_auth())
}

/// Starts an https origin whose certificate comes from the given authority, and records what it
/// was sent.
async fn start_tls_origin(authority: &gulpsuite::tls::Authority) -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind origin");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(String::new()));
    let record = seen.clone();
    let config = authority
        .server_config("127.0.0.1")
        .expect("origin certificate");
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let Ok(n) = tls.read(&mut buf).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                *record.lock().expect("seen") = request.clone();
                let body = request.lines().next().unwrap_or("").to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.flush().await;
            });
        }
    });
    (port, seen)
}

#[test]
fn manual_https_requests_use_the_same_trusted_roots_as_the_proxy() {
    let runtime = runtime();
    let (proxy, _) = Proxy::new();
    let authority = gulpsuite::tls::Authority::generate().unwrap();
    proxy.add_trusted_root(authority.certificate_der());
    let (port, seen) = runtime.block_on(start_tls_origin(&authority));
    let (status, response) = runtime
        .block_on(proxy.one_shot_secure(
            "127.0.0.1",
            port,
            "GET /manual-tls HTTP/1.1\r\nHost: localhost\r\n\r\n",
            true,
            2000,
        ))
        .unwrap();
    assert_eq!(status, 200);
    assert!(response.contains("/manual-tls"));
    assert!(seen.lock().unwrap().contains("/manual-tls"));
}

#[test]
fn an_https_request_goes_through_the_proxy_and_is_seen() {
    let runtime = runtime();
    let (proxy, mut events) = Proxy::new();
    // The origin serves a certificate from an authority of its own, so the proxy is told to
    // trust that authority as well.
    let origin_authority = gulpsuite::tls::Authority::generate().expect("authority");
    proxy.add_trusted_root(origin_authority.certificate_der());

    let (origin_port, origin_seen) = runtime.block_on(start_tls_origin(&origin_authority));

    let proxy_port = runtime.block_on(proxy.start(0)).expect("proxy bind");
    let client_roots: Vec<CertificateDer<'static>> =
        proxy.authority_certificate().into_iter().collect();
    assert!(
        !client_roots.is_empty(),
        "the proxy should have an authority of its own"
    );

    // The client connects to the proxy, asks for a tunnel, and then speaks TLS through it.
    let client = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let mut tcp = TcpStream::connect(("127.0.0.1", proxy_port))
                .await
                .expect("connect to proxy");
            let connect = format!(
                "CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\n\r\n"
            );
            tcp.write_all(connect.as_bytes())
                .await
                .expect("write connect");

            // The proxy answers the tunnel before the TLS handshake starts.
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                let n = match tokio::time::timeout(Duration::from_secs(10), tcp.read(&mut byte))
                    .await
                {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return format!("read failed: {e}"),
                    Err(_) => return "no answer from the proxy".to_string(),
                };
                if n == 0 {
                    return "the proxy closed the connection".to_string();
                }
                head.push(byte[0]);
            }
            let answer = String::from_utf8_lossy(&head).to_string();
            if !answer.starts_with("HTTP/1.1 200") {
                return answer;
            }

            // Now the TLS handshake, with the proxy's authority as the root.
            let config = client_config(&client_roots).expect("client config");
            let connector = TlsConnector::from(Arc::new(config));
            let name = ServerName::try_from("127.0.0.1").expect("server name");
            let Ok(mut tls) = connector.connect(name, tcp).await else {
                return "handshake failed".to_string();
            };
            let _ = &mut tls;
            let request = format!(
                "GET /secret HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
            );
            let _ = tls.write_all(request.as_bytes()).await;
            let _ = tls.flush().await;
            let mut out = String::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(10), tls.read_to_string(&mut out)).await;
            out
        })
    });

    // The proxy reports the transaction it saw inside the tunnel.
    let mut saw = false;
    let mut seen: Vec<String> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline && !saw {
        let event = runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(200), events.recv()).await
        });
        match event {
            Ok(Ok(gulpsuite::proxy::Event::Tx { request, .. })) => {
                if request.contains("/secret") {
                    saw = true;
                }
                seen.push(format!("tx: {request}"));
            }
            Ok(Ok(gulpsuite::proxy::Event::Error(message))) => {
                seen.push(format!("error: {message}"))
            }
            Ok(Ok(other)) => seen.push(format!("event: {other:?}")),
            Ok(Err(_)) => break,
            Err(_) => {}
        }
    }

    let answer = client.join().expect("client thread");
    assert!(
        answer.contains("/secret"),
        "the client should have got the answer through the proxy, got: {answer}\nproxy said: {seen:?}"
    );
    assert!(
        saw,
        "the proxy should have logged the request inside the tunnel, proxy said: {seen:?}"
    );

    let sent = origin_seen.lock().expect("seen").clone();
    assert!(
        sent.contains("/secret"),
        "the origin should have received the request, got: {sent}"
    );

    runtime.block_on(proxy.stop());
}
