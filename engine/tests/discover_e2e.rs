//! Discover probing a real origin: only paths that answer should be reported.

use std::sync::Arc;

use gulpsuite::discover::{self, Update};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

fn http(status: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Serves /robots.txt, /.env, and a 404 for everything else.
async fn start_origin() -> u16 {
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
                let first = request.lines().next().unwrap_or("").to_string();
                let target = first.split_whitespace().nth(1).unwrap_or("/").to_string();
                let response = match target.as_str() {
                    "/robots.txt" => http(200, "text/plain", "User-agent: *\nDisallow: /admin\n"),
                    "/.env" => http(200, "text/plain", "SECRET=hunter2\n"),
                    "/admin" => http(403, "text/plain", "forbidden"),
                    _ => http(404, "text/plain", "not found"),
                };
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

#[test]
fn discovery_reports_the_paths_that_answer() {
    let rt = runtime();
    let port = rt.block_on(start_origin());
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();

    let host = format!("127.0.0.1:{port}");
    // The host comes from proxy history, exactly as the panel reads it.
    let history = vec![format!("http://{host}/seed")];
    let hosts = discover::hosts_from(history.into_iter());
    assert_eq!(hosts, vec![host.clone()]);

    let paths = discover::paths_from("/robots.txt\n/.env\n/admin\n/nothing-here");
    let urls = discover::plan(&hosts, &paths);
    assert_eq!(urls.len(), 4);

    let found = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = found.clone();
    let finished = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let done_flag = finished.clone();

    rt.block_on(async {
        let report = |update: Update| match update {
            Update::Found(finding) => sink.lock().unwrap().push(finding),
            Update::Done { .. } => {
                done_flag.store(1, std::sync::atomic::Ordering::SeqCst);
            }
            Update::Probing { .. } => {}
        };
        discover::probe(Arc::new(proxy.clone()), urls, &report).await;
    });

    let hits = found.lock().unwrap().clone();
    assert_eq!(finished.load(std::sync::atomic::Ordering::SeqCst), 1, "run never reported Done");
    assert_eq!(hits.len(), 4, "every probed path should answer: {hits:?}");

    let status = |path: &str| {
        hits.iter()
            .find(|h| h.url.ends_with(path))
            .unwrap_or_else(|| panic!("no finding for {path}"))
            .status
    };
    assert_eq!(status("/robots.txt"), 200);
    assert_eq!(status("/.env"), 200);
    assert_eq!(status("/admin"), 403, "a 403 is still an answer worth reporting");
    assert_eq!(status("/nothing-here"), 404);

    let robots = hits.iter().find(|h| h.url.ends_with("/robots.txt")).unwrap();
    assert!(robots.length > 0, "body length should be recorded");
}

#[test]
fn an_unreachable_host_produces_no_findings_and_still_finishes() {
    let rt = runtime();
    let (proxy, _events) = gulpsuite::proxy::Proxy::new();
    // Port 1 on loopback refuses, so the run has to report Done rather than hang.
    let urls = vec!["http://127.0.0.1:1/robots.txt".to_string()];
    let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = finished.clone();

    rt.block_on(async {
        let report = |update: Update| {
            if let Update::Done { .. } = update {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        };
        discover::probe(Arc::new(proxy.clone()), urls, &report).await;
    });
    assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
}

// Note: Discover uses `one_shot`, which dials out directly rather than through the listener, so
// probes do not appear in proxy history. That matches how the scanner's own requests behave here.
