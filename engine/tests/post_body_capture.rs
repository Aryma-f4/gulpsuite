//! Synthetic localhost login fixtures; never uses real credentials or remote servers.
use gulpsuite::proxy::{Event, Proxy};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
const BODY: &str = "_token=fixture&username=test-user&password=test-pass";

async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> (String, Vec<u8>) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
        assert!(head.len() < 65536);
    }
    let head = String::from_utf8(head).unwrap();
    let mut body = Vec::new();
    if head.to_lowercase().contains("transfer-encoding: chunked") {
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                line.push(stream.read_u8().await.unwrap());
            }
            let n = usize::from_str_radix(String::from_utf8(line).unwrap().trim(), 16).unwrap();
            let mut chunk = vec![0; n];
            stream.read_exact(&mut chunk).await.unwrap();
            body.extend(chunk);
            let mut end = [0; 2];
            stream.read_exact(&mut end).await.unwrap();
            assert_eq!(end, *b"\r\n");
            if n == 0 {
                break;
            }
        }
    } else {
        let len = head
            .lines()
            .find_map(|l| {
                l.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        body.resize(len, 0);
        stream.read_exact(&mut body).await.unwrap();
    }
    (head, body)
}

async fn check_capture(
    intercept: bool,
    intercept_response: bool,
    chunked: bool,
    chunked_response: bool,
) {
    timeout(Duration::from_secs(8), async {
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let (_, body) = read_request(&mut stream).await;
            assert_eq!(body, BODY.as_bytes(), "origin must receive complete form body");
            let response = if chunked_response {
                "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n2\r\nok\r\n0\r\n\r\n"
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok"
            };
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let (proxy, mut events) = Proxy::new();
        proxy.set_intercept(intercept); proxy.set_intercept_response(intercept_response);
        let proxy_port = proxy.start(0).await.unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            let framing = if chunked { "Transfer-Encoding: chunked".into() } else { format!("Content-Length: {}", BODY.len()) };
            let head = format!("POST http://127.0.0.1:{port}/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/x-www-form-urlencoded\r\n{framing}\r\nConnection: keep-alive\r\n\r\n");
            stream.write_all(head.as_bytes()).await.unwrap();
            // Chromium may deliver headers and body in separate socket reads.
            tokio::time::sleep(Duration::from_millis(15)).await;
            let wire = if chunked { format!("{:x}\r\n{BODY}\r\n0\r\n\r\n", BODY.len()) } else { BODY.into() };
            for piece in wire.as_bytes().chunks(7) { stream.write_all(piece).await.unwrap(); }
            let mut response = Vec::new(); stream.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 302"));
        });
        let request = loop {
            match events.recv().await.unwrap() {
                Event::Held { id, raw, .. } => {
                    if !chunked { assert!(raw.ends_with(BODY)); }
                    assert!(proxy.forward(id).await);
                },
                Event::HeldResponse { id, .. } => { assert!(proxy.forward(id).await); },
                Event::Tx { request, status, .. } => { assert_eq!(status, 302); break request; },
                _ => {},
            }
        };
        client.await.unwrap(); server.await.unwrap(); proxy.stop().await;
        let captured = request.split_once("\r\n\r\n").unwrap().1;
        assert!(captured.contains(BODY), "history lost POST body (intercept={intercept}, response={intercept_response}, chunked={chunked}): {request}");
        if !chunked { assert_eq!(captured, BODY); }
    }).await.expect("POST capture must finish without waiting for client EOF");
}

#[tokio::test]
async fn post_body_without_intercept() {
    check_capture(false, false, false, true).await;
}
#[tokio::test]
async fn post_body_with_request_intercept() {
    check_capture(true, false, false, true).await;
}
#[tokio::test]
async fn post_body_with_held_response() {
    check_capture(true, true, false, false).await;
}
#[tokio::test]
async fn post_body_with_streamed_chunked_response() {
    check_capture(true, true, false, true).await;
}
#[tokio::test]
async fn chunked_post_body_without_intercept() {
    check_capture(false, false, true, true).await;
}
#[tokio::test]
async fn chunked_post_body_with_intercept() {
    check_capture(true, true, true, true).await;
}

async fn login_fixture<S: AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: S) {
    let (head, body) = read_request(&mut stream).await;
    let response = if head.starts_with("POST ") {
        assert_eq!(body, BODY.as_bytes());
        "HTTP/1.1 302 Found\r\nLocation: /dashboard\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nok\r\n0\r\n\r\n".into()
    } else {
        let html = if head.lines().next().unwrap().contains("/dashboard ") {
            "<html><body>login-post-capture-proof</body></html>"
        } else {
            "<html><body><form method='post' action='/login'><input name='_token' value='fixture'><input name='username' value='test-user'><input name='password' value='test-pass'></form><script>document.forms[0].submit()</script></body></html>"
        };
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}", html.len())
    };
    stream.write_all(response.as_bytes()).await.unwrap();
    let _ = stream.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires installed bundled Chromium; set GULPSUITE_TEST_CHROMIUM"]
async fn bundled_chromium_login_post_body_is_in_history() {
    use gulpsuite::browser::{BrowserInstall, LaunchConfig};
    let install = BrowserInstall {
        executable: std::env::var_os("GULPSUITE_TEST_CHROMIUM")
            .expect("set GULPSUITE_TEST_CHROMIUM")
            .into(),
        revision: "local-post-regression".into(),
    };
    for secure in [false, true] {
        let (proxy, mut events) = Proxy::new();
        proxy.set_intercept(false);
        proxy.set_tls_interception(true);
        let authority = gulpsuite::tls::Authority::generate().unwrap();
        proxy.add_trusted_root(authority.certificate_der());
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            authority.server_config("127.0.0.1").unwrap(),
        ));
        let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            while let Ok((stream, _)) = origin.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if secure {
                        login_fixture(acceptor.accept(stream).await.unwrap()).await;
                    } else {
                        login_fixture(stream).await;
                    }
                });
            }
        });
        let profile = std::env::temp_dir().join(format!(
            "gulp-post-capture-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&profile).unwrap();
        let scheme = if secure { "https" } else { "http" };
        let config = LaunchConfig {
            proxy_port: proxy.start(0).await.unwrap(),
            ca_spki: proxy.browser_ca_pin().unwrap(),
            profile_dir: profile.clone(),
            target: format!("{scheme}://127.0.0.1:{port}/"),
        };
        let browser = install.clone();
        let dom = tokio::task::spawn_blocking(move || {
            use std::process::Stdio;
            let output = config.profile_dir.join("dom.html");
            let errors = config.profile_dir.join("browser.log");
            let mut command = browser.command(&config).unwrap();
            command
                .args([
                    "--headless",
                    "--disable-gpu",
                    "--dump-dom",
                    "--timeout=10000",
                    "--virtual-time-budget=3000",
                ])
                .stdout(Stdio::from(std::fs::File::create(&output).unwrap()))
                .stderr(Stdio::from(std::fs::File::create(&errors).unwrap()));
            let mut child = command.spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(25);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(
                        status.success(),
                        "Chromium failed: {}",
                        std::fs::read_to_string(errors).unwrap()
                    );
                    break;
                }
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("Chromium login fixture timed out");
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            std::fs::read_to_string(output).unwrap()
        })
        .await
        .unwrap();
        assert!(
            dom.contains("login-post-capture-proof"),
            "browser must follow login 302: {dom}"
        );
        let request = timeout(Duration::from_secs(3), async {
            loop {
                if let Event::Tx {
                    method,
                    target,
                    request,
                    status,
                    secure: recorded_secure,
                    ..
                } = events.recv().await.unwrap()
                {
                    if method == "POST" && target.ends_with("/login") {
                        assert_eq!(status, 302);
                        assert_eq!(recorded_secure, secure);
                        break request;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            request.split_once("\r\n\r\n").unwrap().1,
            BODY,
            "{scheme} Chromium POST body missing from history"
        );
        eprintln!("{scheme}: Chromium login POST -> 302 -> dashboard; complete form body recorded");
        proxy.stop().await;
        server.abort();
        std::fs::remove_dir_all(&profile).unwrap();
    }
}
