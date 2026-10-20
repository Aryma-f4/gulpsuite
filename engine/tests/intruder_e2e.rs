use gulpsuite::http_target::HttpTarget;
use gulpsuite::intruder::{generate_requests, AttackType};
use gulpsuite::intruder::{run_attack, AttackControl, AttackOptions, AttackUpdate};
use gulpsuite::proxy::{MatchRules, Proxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn sets(values: &[&[&str]]) -> Vec<Vec<String>> {
    values
        .iter()
        .map(|set| set.iter().map(|value| (*value).into()).collect())
        .collect()
}

#[test]
fn attack_modes_replace_whole_positions_and_use_the_correct_payload_sets() {
    let template = "u=§user§&p=§pass§";
    for (mode, payload_sets, expected) in [
        (
            AttackType::Sniper,
            sets(&[&["alice", "bob"]]),
            vec![
                "u=alice&p=pass",
                "u=bob&p=pass",
                "u=user&p=alice",
                "u=user&p=bob",
            ],
        ),
        (
            AttackType::BatteringRam,
            sets(&[&["alice", "bob"]]),
            vec!["u=alice&p=alice", "u=bob&p=bob"],
        ),
        (
            AttackType::Pitchfork,
            sets(&[&["alice", "bob"], &["one", "two", "extra"]]),
            vec!["u=alice&p=one", "u=bob&p=two"],
        ),
        (
            AttackType::ClusterBomb,
            sets(&[&["alice", "bob"], &["one", "two"]]),
            vec![
                "u=alice&p=one",
                "u=alice&p=two",
                "u=bob&p=one",
                "u=bob&p=two",
            ],
        ),
    ] {
        let requests = generate_requests(template, mode, &payload_sets, 100).unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|row| row.request.as_str())
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn payloads_preserve_whitespace_empty_values_duplicates_and_unicode() {
    let requests = generate_requests(
        "q=§§&原=§旧§",
        AttackType::Sniper,
        &sets(&[&[" a ", "", "é", "é"]]),
        20,
    )
    .unwrap();
    assert_eq!(requests.len(), 8);
    assert_eq!(requests[0].request, "q= a &原=旧");
    assert_eq!(requests[1].request, "q=&原=旧");
    assert_eq!(requests[6].request, "q=&原=é");
    assert_eq!(requests[7].request, "q=&原=é");
}

#[test]
fn invalid_attack_configurations_fail_before_sending_any_requests() {
    assert!(generate_requests("q=§broken", AttackType::Sniper, &sets(&[&["x"]]), 10).is_err());
    assert!(generate_requests("q=none", AttackType::Sniper, &sets(&[&["x"]]), 10).is_err());
    assert!(generate_requests("q=§a§&p=§b§", AttackType::Pitchfork, &sets(&[&["x"]]), 10).is_err());
    assert!(generate_requests("q=§a§", AttackType::Sniper, &sets(&[&[]]), 10).is_err());
    assert!(generate_requests(
        "q=§a§&p=§b§",
        AttackType::ClusterBomb,
        &sets(&[&["a", "b"], &["1", "2"]]),
        3
    )
    .is_err());
}

#[test]
fn automatic_positions_cover_query_form_cookie_and_json_values_without_losing_bytes() {
    use gulpsuite::intruder::auto_mark_positions;
    let raw = "POST /?q=hello%20world&empty= HTTP/1.1\r\nHost: test\r\nCookie: sid=abc; token=xyz\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=one&b=two";
    assert_eq!(auto_mark_positions(raw), "POST /?q=§hello%20world§&empty=§§ HTTP/1.1\r\nHost: test\r\nCookie: sid=§abc§; token=§xyz§\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=§one§&b=§two§");
    let json = "POST / HTTP/1.1\r\nHost: test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"é\",\"count\":12}";
    assert!(auto_mark_positions(json).ends_with("{\"name\":\"§é§\",\"count\":§12§}"));
}

#[test]
fn numeric_and_date_payloads_honor_ranges_steps_and_generation_limits() {
    use gulpsuite::intruder::{date_payloads, number_payloads};
    assert_eq!(number_payloads(-2, 2, 2, 10).unwrap(), ["-2", "0", "2"]);
    assert_eq!(number_payloads(3, 1, -1, 10).unwrap(), ["3", "2", "1"]);
    assert!(number_payloads(1, 10, 0, 10).is_err());
    assert!(number_payloads(1, 10, 1, 5).is_err());
    assert_eq!(
        date_payloads("2024-02-28", "2024-03-01", 1, 10).unwrap(),
        ["2024-02-28", "2024-02-29", "2024-03-01"]
    );
    assert_eq!(
        date_payloads("2026-01-01 23:59:59", "2026-01-02 00:00:01", 1, 10).unwrap(),
        [
            "2026-01-01 23:59:59",
            "2026-01-02 00:00:00",
            "2026-01-02 00:00:01"
        ]
    );
    assert!(date_payloads("2025-02-29", "2025-03-01", 1, 10).is_err());
}

#[tokio::test]
async fn attack_sends_real_payloads_updates_host_and_shares_matching_across_workers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            workers.push(tokio::spawn(async move {
                let mut request = Vec::new();
                let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).await.unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap();
                let body = if request.contains("/different") {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    "different"
                } else {
                    "a"
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                request
            }));
        }
        let mut requests = Vec::new();
        for worker in workers {
            requests.push(worker.await.unwrap());
        }
        requests
    });
    let requests = generate_requests(
        "GET /§base§ HTTP/1.1\r\nHost: old.test\r\n\r\n",
        AttackType::Sniper,
        &sets(&[&["same", "different"]]),
        10,
    )
    .unwrap();
    let (proxy, _) = Proxy::new();
    let (tx, rx) = std::sync::mpsc::channel();
    let options = AttackOptions {
        concurrency: 2,
        rules: MatchRules::new(vec![], vec![], None, true),
        ..Default::default()
    };
    run_attack(
        proxy,
        HttpTarget::parse(&format!("http://127.0.0.1:{port}")).unwrap(),
        requests,
        options,
        AttackControl::default(),
        tx,
    )
    .await;
    let updates: Vec<_> = rx.try_iter().collect();
    let results: Vec<_> = updates
        .iter()
        .filter_map(|update| {
            if let AttackUpdate::Result(result) = update {
                Some(result)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(results.len(), 2);
    assert_eq!(results.iter().filter(|result| result.matched).count(), 1);
    assert!(results
        .iter()
        .all(|result| result.status == 200 && !result.response.is_empty()));
    let seen = server.await.unwrap();
    assert!(seen
        .iter()
        .all(|request| request.contains(&format!("Host: 127.0.0.1:{port}\r\n"))));
    assert!(seen
        .iter()
        .any(|request| request.starts_with("GET /different ")));
}

#[tokio::test]
async fn paused_attack_waits_and_cancel_interrupts_an_in_flight_request() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (proxy, _) = Proxy::new();
    let requests = generate_requests(
        "GET /§a§ HTTP/1.1\r\nHost: old.test\r\n\r\n",
        AttackType::Sniper,
        &sets(&[&["one", "two"]]),
        10,
    )
    .unwrap();
    let control = AttackControl::default();
    control.pause();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker_control = control.clone();
    let task = tokio::spawn(run_attack(
        proxy,
        HttpTarget::parse(&format!("127.0.0.1:{port}")).unwrap(),
        requests,
        AttackOptions {
            concurrency: 1,
            ..Default::default()
        },
        worker_control,
        tx,
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), listener.accept())
            .await
            .is_err()
    );
    control.resume();
    let (mut stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
            .await
            .unwrap()
            .unwrap();
    let mut byte = [0];
    assert!(stream.read(&mut byte).await.unwrap() > 0);
    control.cancel();
    tokio::time::timeout(std::time::Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    let done = rx
        .try_iter()
        .find_map(|update| {
            if let AttackUpdate::Done(done) = update {
                Some(done)
            } else {
                None
            }
        })
        .unwrap();
    assert!(done.cancelled);
    assert_eq!(done.completed, 0);
    assert_eq!(done.total, 2);
}

#[test]
fn native_intruder_runs_pitchfork_and_keeps_results_while_dashboard_is_visible() {
    use egui_kittest::{kittest::Queryable, Harness};
    use gulpsuite::ui::app::{App, INTRUDER};
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            seen.push(String::from_utf8(request).unwrap());
            stream
                .write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        }
        seen
    });
    let mut harness = Harness::builder()
        .with_size(eframe::egui::vec2(1440.0, 790.0))
        .build_eframe(|cc| {
            let mut app = App::with_context(&cc.egui_ctx);
            app.tool = INTRUDER;
            let panel = &mut app.panels.intruder;
            panel.host = format!("http://127.0.0.1:{port}");
            panel.template = "GET /?u=§u§&p=§p§ HTTP/1.1\r\nHost: old.test\r\n\r\n".into();
            panel.attack_type = AttackType::Pitchfork;
            panel.payload_sets[0].values = "alice\nbob".into();
            let mut second = panel.payload_sets[0].clone();
            second.values = "one\ntwo".into();
            panel.payload_sets.push(second);
            app
        });
    harness.get_by_label("Start attack").click();
    harness.run();
    harness.get_by_label("Dashboard").click();
    harness.run();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while harness.state().panels.intruder.running && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
        harness.run();
    }
    let panel = &harness.state().panels.intruder;
    assert!(!panel.running);
    assert_eq!(panel.results.len(), 2);
    assert!(panel
        .results
        .iter()
        .all(|row| row.status == 201 && row.response.ends_with("ok")));
    assert_eq!(
        harness
            .state()
            .workspace
            .tasks
            .get(panel.task_id.unwrap())
            .unwrap()
            .state,
        gulpsuite::workspace::TaskState::Completed
    );
    let seen = server.join().unwrap();
    assert!(seen
        .iter()
        .any(|raw| raw.starts_with("GET /?u=alice&p=one ")));
    assert!(seen.iter().any(|raw| raw.starts_with("GET /?u=bob&p=two ")));
    harness.state_mut().tool = INTRUDER;
    harness.state_mut().panels.intruder.host = "http://different-target.invalid".into();
    harness.state_mut().panels.intruder.selected = Some(0);
    harness.run();
    harness.get_by_label("Send result to Repeater").click();
    harness.run();
    assert_eq!(
        harness.state().panels.repeater.active().host,
        format!("http://127.0.0.1:{port}")
    );
}
