//! Drives the proxy hard and reports resident memory, so "it does not leak" is measured rather
//! than assumed. Run with: cargo run --release --example proxy_load -- <requests>

use gulpsuite::proxy::{Event, Proxy};
use gulpsuite::ui::app::{retain, Transaction};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Resident set size in MB. macOS has no /proc, so ask `ps`.
fn rss_mb() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    out as f64 / 1024.0
}

#[tokio::main]
async fn main() {
    let total: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(20_000);

    // A local origin to forward to.
    let origin = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("origin");
    let origin_port = origin.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = origin.accept().await else { break };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                // A deliberately chunky body, so retention limits are actually exercised.
                let body = "x".repeat(120 * 1024);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
                let _ = socket.flush().await;
                // Close, otherwise the proxy never sees EOF and every request leaks a connection.
                let _ = socket.shutdown().await;
            });
        }
    });

    let (proxy, mut events) = Proxy::new();
    // Interception parks requests until the UI releases them, so a headless load run must not
    // intercept or it would measure a queue of parked sockets instead of steady-state traffic.
    proxy.set_intercept(false);
    let port = proxy.start(0).await.expect("bind");
    println!("proxy on 127.0.0.1:{port}, origin on {origin_port}");

    // Retain through the very same function the UI uses, so this measures production behaviour
    // rather than a look-alike. An uncapped log here would grow by the full body of every response.
    let log: Arc<std::sync::Mutex<VecDeque<Transaction>>> =
        Arc::new(std::sync::Mutex::new(VecDeque::new()));
    let consumer = log.clone();
    let mut version = 0u64;
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            if let Event::Tx { method, target, status, bytes, request, response, secure } = event {
                let host = target
                    .split_once("://")
                    .map(|(_, rest)| rest.split('/').next().unwrap_or("").to_string())
                    .unwrap_or_else(|| target.clone());
                let wire = bytes;
                retain(
                    &mut consumer.lock().unwrap(),
                    Transaction {
                        method,
                        target,
                        status,
                        bytes,
                        host,
                        request,
                        response,
                        secure,
                        truncated: false,
                    },
                    wire,
                    &mut version,
                );
            }
        }
    });

    let baseline = rss_mb();
    println!("baseline RSS: {baseline:.1} MB");

    let started = std::time::Instant::now();
    // One connection per request, matching `Connection: close`. Reusing a single socket while
    // announcing close leaves the proxy holding each request's read half until the client goes away.
    let mut sink = vec![0u8; 256 * 1024];
    for index in 0..total {
        let request = format!(
            "GET http://127.0.0.1:{origin_port}/item-{index} HTTP/1.1\r\nHost: 127.0.0.1:{origin_port}\r\nConnection: close\r\n\r\n"
        );
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        client.write_all(request.as_bytes()).await.expect("write");
        // Read until the proxy closes, which is what `Connection: close` asks for.
        loop {
            match client.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        drop(client);
        if index % 250 == 0 {
            println!(
                "  {index:>6} requests  RSS {:.1} MB  {:.0} ms",
                rss_mb(),
                started.elapsed().as_secs_f64() * 1000.0
            );
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    let peak = rss_mb();
    println!("\n{total} requests through the proxy");
    println!("peak RSS: {peak:.1} MB  (baseline {baseline:.1} MB, growth {:.1} MB)", peak - baseline);
    proxy.stop().await;
}
