//! End-to-end scanner test against a deliberately vulnerable local server.
//!
//! Unit tests prove each check fires on a canned response. This proves the whole chain — build a
//! request, send it through the proxy, parse the response, detect, report — works against a
//! socket.

use std::sync::Arc;

use gulpsuite::proxy::Proxy;
use gulpsuite::scanner::active::{self, InjectionPoint};
use gulpsuite::scanner::crawler;
use gulpsuite::scanner::http::parse_response;
use gulpsuite::scanner::{Coverage, Scope, Severity, passive};

/// A tiny origin server that is vulnerable in several specific, predictable ways.
async fn start_vulnerable_origin() -> u16 {
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

                let response = if target.starts_with("/search") {
                    // Reflects the q parameter, and errors when it looks like SQL.
                    if target.contains("%27") || target.contains("OR") {
                        http(500, "text/html",
                            "<b>You have an error in your SQL syntax</b> near your input")
                    } else {
                        let q = target.split("q=").nth(1).unwrap_or("hello");
                        http(200, "text/html", &format!("<p>results for {q}</p>"))
                    }
                } else if target.starts_with("/xss") {
                    // Echoes the raw, still-encoded query value.
                    let v = target.split("q=").nth(1).unwrap_or("");
                    http(200, "text/html", &format!("<div>you said {v}</div>"))
                } else if target.starts_with("/echo") {
                    // Decodes first, so the payload comes back verbatim and executable.
                    let v = percent_decode(target.split("q=").nth(1).unwrap_or(""));
                    http(200, "text/html", &format!("<div>you said {v}</div>"))
                } else if target.starts_with("/traversal") {
                    if target.contains("etc%2Fpasswd") || target.contains("etc/passwd") {
                        http(200, "text/plain", "root:x:0:0:root:/root:/bin/bash")
                    } else {
                        http(200, "text/plain", "ok")
                    }
                } else {
                    http(404, "text/html", "<h1>404</h1>")
                };
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    port
}

/// Minimal percent-decoding, enough for the payloads these tests use.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn http(status: u16, content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         X-Powered-By: PHP/5.4.1\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn sql_injection_is_confirmed_against_a_live_server() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    let url = format!("http://127.0.0.1:{port}/search");
    let point = InjectionPoint::query(&url, "q");
    let check = active::sql_injection();

    // The baseline is clean; the payload is not.
    let (_, _, _, baseline) = point.request("hello").unwrap();
    let (host, dport, _, _) = point.request("hello").unwrap();
    let baseline = proxy.one_shot(&host, dport, &baseline, 5_000).await.unwrap();
    assert_eq!(baseline.0, 200);
    assert!(active::evaluate(&check, &url, "q", "hello", &parse_response(&baseline.1)).is_none());

    let payload = "'";
    let (_, _, _, raw) = point.request(payload).unwrap();
    let (host, dport, _, _) = point.request(payload).unwrap();
    let injected = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();
    assert_eq!(injected.0, 500, "the server should error on a quote");

    let finding = active::evaluate(&check, &url, "q", payload, &parse_response(&injected.1))
        .expect("SQL injection was not reported");
    assert_eq!(finding.name, "SQL injection");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.contains('\''));
}

#[tokio::test]
async fn path_traversal_is_confirmed_against_a_live_server() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    let url = format!("http://127.0.0.1:{port}/traversal");
    let point = InjectionPoint::query(&url, "file");
    let check = active::path_traversal();
    let payload = "../../../../../../etc/passwd";

    let (_, _, _, raw) = point.request(payload).unwrap();
    let (host, dport, _, _) = point.request(payload).unwrap();
    let response = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();

    let finding = active::evaluate(&check, &url, "file", payload, &parse_response(&response.1))
        .expect("path traversal was not reported");
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.evidence.contains("etc/passwd"));
}

#[tokio::test]
async fn a_verbatim_xss_reflection_is_reported_at_medium() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    let url = format!("http://127.0.0.1:{port}/echo");
    let point = InjectionPoint::query(&url, "q");
    let check = active::cross_site_scripting();
    let payload = "<script>alert(1)</script>";

    let (_, _, _, raw) = point.request(payload).unwrap();
    let (host, dport, _, _) = point.request(payload).unwrap();
    let response = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();
    assert!(
        response.1.contains(payload),
        "the test server should echo the payload verbatim"
    );

    let finding = active::evaluate(&check, &url, "q", payload, &parse_response(&response.1))
        .expect("verbatim reflection was not reported");
    assert_eq!(finding.name, "Cross-site scripting (reflected)");
    assert_eq!(finding.severity, Severity::Medium);
}

#[tokio::test]
async fn an_encoded_only_reflection_is_only_informational() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    let url = format!("http://127.0.0.1:{port}/xss");
    let point = InjectionPoint::query(&url, "q");
    let check = active::cross_site_scripting();
    let payload = "<script>alert(1)</script>";

    let (_, _, _, raw) = point.request(payload).unwrap();
    let (host, dport, _, _) = point.request(payload).unwrap();
    let response = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();
    assert!(
        !response.1.contains(payload),
        "the test server should only echo the encoded form"
    );

    let finding = active::evaluate(&check, &url, "q", payload, &parse_response(&response.1))
        .expect("the encoded reflection should still be recorded");
    // Encoded output will not execute, so this cannot be called a medium.
    assert_eq!(finding.severity, Severity::Info);
    assert!(!finding.confidence.contains("unchanged"));
}

#[tokio::test]
async fn passive_analysis_finds_real_issues_in_a_live_response() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    let url = format!("http://127.0.0.1:{port}/search?q=hello");
    let point = InjectionPoint::query(&url, "q");
    let (_, _, _, raw) = point.request("hello").unwrap();
    let (host, dport, _, _) = point.request("hello").unwrap();
    let response = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();

    let findings = passive::inspect(&url, &parse_response(&response.1));
    let names: Vec<&str> = findings.iter().map(|f| f.name.as_str()).collect();

    assert!(
        names.iter().any(|n| n.contains("Version disclosure")),
        "X-Powered-By: PHP/5.4.1 should be flagged, got {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("Content-Security-Policy")),
        "missing CSP should be flagged, got {names:?}"
    );
}

#[tokio::test]
async fn a_clean_response_is_not_padded_with_false_positives() {
    let port = start_vulnerable_origin().await;
    let (proxy, _events) = Proxy::new();

    // /traversal?file=x returns a clean body with no version banner, so only header findings.
    let url = format!("http://127.0.0.1:{port}/traversal");
    let point = InjectionPoint::query(&url, "file");
    let (_, _, _, raw) = point.request("x").unwrap();
    let (host, dport, _, _) = point.request("x").unwrap();
    let response = proxy.one_shot(&host, dport, &raw, 5_000).await.unwrap();
    let parsed = parse_response(&response.1);

    // X-Powered-By is still there, so expect exactly that class of finding and nothing worse.
    let findings = passive::inspect(&url, &parsed);
    assert!(
        !findings.iter().any(|f| f.severity >= Severity::High),
        "nothing high should be reported on a benign page: {findings:?}"
    );
    assert!(
        !findings.iter().any(|f| f.name.contains("Stack trace")),
        "no stack trace expected"
    );
    assert!(!findings.iter().any(|f| f.name.contains("Filesystem path")));
}

#[tokio::test]
async fn the_crawler_walks_links_and_stays_in_scope() {
    // A site with an in-scope index, an in-scope page, and an off-site link that must be refused.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let Ok(n) = socket.read(&mut buf).await else { return };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let target = request.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("/").to_string();
                let body = if target.starts_with("/page") {
                    "<p>page</p>".to_string()
                } else {
                    format!("<a href=\"/page\">in</a><a href=\"http://offsite.invalid/x\">out</a>")
                };
                let _ = socket.write_all(http(200, "text/html", &body).as_bytes()).await;
            });
        }
    });

    let (proxy, _events) = Proxy::new();
    let scope = Scope::for_host("127.0.0.1");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let watcher = seen.clone();
    let coverage: Coverage = crawler::crawl(
        &format!("http://127.0.0.1:{port}/"),
        &scope,
        &proxy,
        &move |event| {
            if let crawler::Progress::Skipped { url, .. } = event {
                watcher.lock().unwrap().push(url);
            }
        },
    )
    .await;

    let urls: Vec<&str> = coverage.pages.iter().map(|(u, _)| u.as_str()).collect();
    assert_eq!(urls.len(), 2, "expected the index and its in-scope link, got {urls:?}");
    assert!(urls.iter().any(|u| u.ends_with("/page")));
    assert!(
        !urls.iter().any(|u| u.contains("offsite.invalid")),
        "an off-site link must never be fetched: {urls:?}"
    );
    assert!(coverage.requests_made >= 2);
}