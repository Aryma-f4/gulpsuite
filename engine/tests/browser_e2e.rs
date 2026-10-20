use gulpsuite::proxy::Proxy;
use std::{path::PathBuf, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn concurrent_browser_starts_share_one_ready_listener() {
    let (proxy, _) = Proxy::new();
    let (a, b, c) = tokio::join!(
        proxy.ensure_started(0),
        proxy.ensure_started(0),
        proxy.ensure_started(0)
    );
    let port = a.unwrap();
    assert_ne!(port, 0);
    assert_eq!(b.unwrap(), port);
    assert_eq!(c.unwrap(), port);
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok());
    proxy.stop().await;
    assert_eq!(proxy.bound_port().await, None);
}

#[tokio::test]
async fn occupied_port_is_reported_without_claiming_readiness() {
    let socket = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let (proxy, _) = Proxy::new();
    assert!(proxy
        .ensure_started(socket.local_addr().unwrap().port())
        .await
        .is_err());
    assert_eq!(proxy.bound_port().await, None);
    assert!(!proxy.browser_ca_pin().unwrap().is_empty());
}

fn browser_dom(
    install: &gulpsuite::browser::BrowserInstall,
    config: gulpsuite::browser::LaunchConfig,
) -> String {
    use std::process::Stdio;
    std::fs::create_dir_all(&config.profile_dir).unwrap();
    let output = config.profile_dir.join("dom.html");
    let errors = config.profile_dir.join("browser.log");
    let mut command = install.command(&config).unwrap();
    command
        .args(["--headless", "--disable-gpu", "--dump-dom", "--timeout=10000"])
        .stdout(Stdio::from(std::fs::File::create(&output).unwrap()))
        .stderr(Stdio::from(std::fs::File::create(&errors).unwrap()));
    let mut child = command.spawn().unwrap();
    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "Chromium failed: {}",
                std::fs::read_to_string(errors).unwrap()
            );
            return std::fs::read_to_string(output).unwrap();
        }
        if start.elapsed().as_secs() > 25 {
            let _ = child.kill();
            let _ = child.wait();
            panic!("Chromium smoke timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the pinned bundled Chromium; set GULPSUITE_TEST_CHROMIUM"]
async fn bundled_chromium_http_https_and_upstream_validation() {
    use gulpsuite::browser::{BrowserInstall, LaunchConfig};
    let executable = PathBuf::from(
        std::env::var("GULPSUITE_TEST_CHROMIUM").expect("set GULPSUITE_TEST_CHROMIUM"),
    );
    assert!(executable.is_absolute() && executable.is_file());
    let install = BrowserInstall {
        executable,
        revision: "test".into(),
    };
    let (proxy, mut events) = Proxy::new();
    proxy.set_intercept(false);
    proxy.set_tls_interception(true);
    let authority = gulpsuite::tls::Authority::generate().unwrap();
    proxy.add_trusted_root(authority.certificate_der());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let plain = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0; 8192];
                let _ = stream.read(&mut bytes).await;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\ngulp-browser-proof").await;
            });
        }
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let secure = listener.local_addr().unwrap().port();
    let acceptor =
        tokio_rustls::TlsAcceptor::from(Arc::new(authority.server_config("127.0.0.1").unwrap()));
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    let mut bytes = [0; 8192];
                    let _ = stream.read(&mut bytes).await;
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nConnection: close\r\n\r\ngulp-browser-proof").await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    let proxy_port = proxy.ensure_started(0).await.unwrap();
    let root = std::env::temp_dir().join(format!(
        "gulp-browser-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for (scheme, port) in [("http", plain), ("https", secure)] {
        eprintln!("Browser smoke navigating {scheme} loopback port {port}");
        let config = LaunchConfig {
            proxy_port,
            ca_spki: proxy.browser_ca_pin().unwrap(),
            profile_dir: root.join(scheme),
            target: format!("{scheme}://127.0.0.1:{port}/browser-proof"),
        };
        let install = install.clone();
        let dom = tokio::task::spawn_blocking(move || browser_dom(&install, config))
            .await
            .unwrap();
        if !dom.contains("gulp-browser-proof") {
            while let Ok(event) = events.try_recv() {
                match event {
                    gulpsuite::proxy::Event::Error(error) => {
                        eprintln!("browser smoke proxy error: {error}")
                    }
                    gulpsuite::proxy::Event::Tx {
                        target,
                        status,
                        secure,
                        ..
                    } => eprintln!("browser smoke transaction: {target} {status} TLS={secure}"),
                    _ => {}
                }
            }
        }
        assert!(
            dom.contains("gulp-browser-proof"),
            "{scheme} browser did not render fixture: {}",
            &dom[..dom.len().min(400)]
        );
    }
    let mut found_http = false;
    let mut found_https = false;
    while let Ok(event) = events.try_recv() {
        if let gulpsuite::proxy::Event::Tx {
            secure, response, ..
        } = event
        {
            if response.contains("gulp-browser-proof") {
                if secure {
                    found_https = true;
                } else {
                    found_http = true;
                }
            }
        }
    }
    assert!(found_http && found_https, "browser bypassed Proxy history");
    // A new proxy that does not trust the fixture origin must still reject it,
    // despite the browser trusting only that proxy's pin.
    let (untrusted, _) = Proxy::new();
    let bad_port = untrusted.ensure_started(0).await.unwrap();
    let config = LaunchConfig {
        proxy_port: bad_port,
        ca_spki: untrusted.browser_ca_pin().unwrap(),
        profile_dir: root.join("untrusted-origin"),
        target: format!("https://127.0.0.1:{secure}/browser-proof"),
    };
    let dom = tokio::task::spawn_blocking(move || browser_dom(&install, config))
        .await
        .unwrap();
    assert!(
        !dom.contains("gulp-browser-proof"),
        "untrusted origin certificate was bypassed"
    );
    proxy.stop().await;
    untrusted.stop().await;
    assert!(
        root.starts_with(std::env::temp_dir())
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("gulp-browser-e2e-")
    );
    std::fs::remove_dir_all(root).unwrap(); // only this test's owned profile fixture
}
