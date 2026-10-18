//! Gulpsuite engine: the proxy and analysis primitives speaking newline-delimited JSON.
//!
//! This binary exists for scripting and tests. The GUI drives `gulpsuite::proxy` in-process instead
//! and never spawns this.
//!
//! stdin  -> engine: {"cmd":"start","port":8080,"id":7}
//! engine -> stdout: {"type":"listening","port":8080,"id":7}
//!                       {"type":"tx","method":"GET","target":"...","status":204,"bytes":123}
//!                       {"type":"error","message":"..."}
//!
//! Port 0 asks the OS for an ephemeral port; the chosen one comes back in "listening".

use std::io::{self, Write};
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::AsyncBufReadExt;
use tokio::sync::Mutex;

use gulpsuite::logic;
use gulpsuite::proxy::{Event, MatchRules, Proxy};

fn emit(v: Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn fail(message: impl Into<String>) {
    emit(json!({ "type": "error", "message": message.into() }));
}

/// Emits `value` with the caller's correlation id attached, so the caller can match reply to call.
fn reply(cmd: &Value, mut value: Value) {
    if let (Value::Object(map), Some(id)) = (&mut value, cmd.get("id")) {
        map.insert("id".to_string(), id.clone());
    }
    emit(value);
}

fn string(cmd: &Value, key: &str) -> String {
    cmd.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

fn strings(cmd: &Value, key: &str) -> Vec<String> {
    cmd.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default()
}

fn event_to_json(event: &Event) -> Value {
    match event {
        Event::Listening { port } => json!({ "type": "listening", "port": port }),
        Event::ListenerStopped => json!({ "type": "listener-stopped" }),
        Event::Tx { method, target, status, bytes, request, response } => {
            json!({ "type": "tx", "method": method, "target": target, "status": status,
                    "bytes": bytes, "request": request, "response": response })
        }
        Event::DnsListening { port } => json!({ "type": "dns-listening", "port": port }),
        Event::SmtpListening { port } => json!({ "type": "smtp-listening", "port": port }),
        Event::Dns { question, kind, answers, server } => json!({
            "type": "dns", "question": question, "kind": kind,
            "answers": answers, "server": server
        }),
        Event::Smtp { direction, from, to, subject, body } => json!({
            "type": "smtp", "direction": direction, "from": from,
            "to": to, "subject": subject, "body": body
        }),
        Event::WsOpen { id, host, .. } => json!({ "type": "ws-open", "id": id, "host": host }),
        Event::WsFrame { id, to_server, opcode, text, bytes } => json!({
            "type": "ws-frame", "id": id, "to_server": to_server,
            "opcode": opcode, "text": text, "bytes": bytes
        }),
        Event::WsClosed { id } => json!({ "type": "ws-closed", "id": id }),
        Event::Held { id, method, target, raw } => {
            json!({ "type": "held", "id": id, "method": method, "target": target, "raw": raw })
        }
        Event::Released { id, forwarded } => {
            json!({ "type": "released", "id": id, "forwarded": forwarded })
        }
        Event::Dropped { id } => json!({ "type": "dropped", "id": id }),
        Event::AttackResult { index, status, length, matched, error } => json!({
            "type": "attack_result", "index": index, "status": status,
            "length": length, "matched": matched,
            "error": error.clone().map(Value::String).unwrap_or(Value::Null)
        }),
        Event::AttackDone { total, matches } => {
            json!({ "type": "attack_done", "total": total, "matches": matches })
        }
        Event::Error(message) => json!({ "type": "error", "message": message }),
    }
}

#[tokio::main]
async fn main() {
    emit(json!({ "type": "ready" }));

    let (proxy, mut events) = Proxy::new();
    let proxy = Arc::new(proxy);
    // Events are forwarded as they happen, carrying the id of whatever command is outstanding.
    let pending: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let pump_id = pending.clone();
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            let id = pump_id.lock().await.clone();
            match id {
                Some(cmd) => reply(&cmd, event_to_json(&event)),
                None => emit(event_to_json(&event)),
            }
        }
    });

    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(cmd) = serde_json::from_str::<Value>(&line) else {
            fail("malformed command");
            continue;
        };
        let kind = string(&cmd, "cmd");
        *pending.lock().await = Some(cmd.clone());

        match kind.as_str() {
            "ping" => reply(&cmd, json!({ "type": "pong" })),

            "ops" => {
                let names: Vec<&str> = logic::decoder_ops().iter().map(|o| o.name).collect();
                reply(&cmd, json!({ "type": "ops", "ops": names }));
            }
            "transform" => {
                let op_name = string(&cmd, "op");
                let input = string(&cmd, "input");
                match logic::find_op(&op_name) {
                    None => reply(&cmd, json!({ "type": "result", "ok": false,
                                                "error": format!("unknown op: {op_name}") })),
                    Some(op) => match (op.run)(&input) {
                        Ok(value) => reply(&cmd, json!({ "type": "result", "ok": true, "value": value })),
                        Err(error) => reply(&cmd, json!({ "type": "result", "ok": false, "error": error })),
                    },
                }
            }
            "magic" => {
                let input = string(&cmd, "input");
                reply(&cmd, json!({ "type": "result", "ok": true, "value": logic::magic_decode(&input) }));
            }
            "diff" => {
                let left = string(&cmd, "left");
                let right = string(&cmd, "right");
                let rows: Vec<Value> = logic::diff_lines(&left, &right)
                    .iter()
                    .map(|r| json!([r.kind.as_str(), r.left, r.right]))
                    .collect();
                reply(&cmd, json!({ "type": "diff", "rows": rows }));
            }
            "markers" => {
                let template = string(&cmd, "template");
                let found: Vec<Value> = logic::markers(&template)
                    .iter()
                    .map(|m| json!({ "positions": m.positions, "start": m.start, "end": m.end,
                                      "cluster": m.positions.len() > 1 }))
                    .collect();
                reply(&cmd, json!({ "type": "markers", "markers": found }));
            }
            "enumerate" => {
                let template = string(&cmd, "template");
                let payloads = strings(&cmd, "payloads");
                let cap = cmd.get("cap").and_then(Value::as_u64).unwrap_or(50_000) as usize;
                let requests = logic::enumerate(&template, &payloads, cap);
                reply(&cmd, json!({ "type": "enumerate", "requests": requests }));
            }
            "entropy" => {
                let text = string(&cmd, "text");
                let token = string(&cmd, "token");
                match logic::analyse_token(&text, &token) {
                    None => reply(&cmd, json!({ "type": "entropy", "found": false })),
                    Some(report) => {
                        let chars: Vec<Value> = report
                            .chars
                            .iter()
                            .map(|c| json!({ "char": c.ch.to_string(), "code": c.code,
                                              "count": c.count, "freq": c.freq }))
                            .collect();
                        reply(&cmd, json!({ "type": "entropy", "found": true, "length": report.length,
                                     "distinct": report.distinct, "entropy": report.entropy,
                                     "max_entropy": report.max_entropy, "chars": chars }));
                    }
                }
            }

            "start" => {
                let port = cmd.get("port").and_then(Value::as_u64).unwrap_or(8080) as u16;
                match proxy.start(port).await {
                    Ok(bound) => reply(&cmd, json!({ "type": "listening", "port": bound })),
                    Err(e) => fail(e.to_string()),
                }
            }
            "stop" => {
                proxy.stop().await;
                reply(&cmd, json!({ "type": "stopped" }));
            }

            "request" => {
                let host = string(&cmd, "host");
                let port = cmd.get("port").and_then(Value::as_u64).unwrap_or(80) as u16;
                let raw = string(&cmd, "raw");
                let timeout = cmd.get("timeout_ms").and_then(Value::as_u64).unwrap_or(15000);
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    match proxy.one_shot(&host, port, &raw, timeout).await {
                        Ok((status, body)) => emit(json!({
                            "type": "response", "status": status,
                            "length": body.len(), "raw": body, "error": Value::Null
                        })),
                        Err(error) => emit(json!({ "type": "response", "error": error })),
                    }
                });
            }

            "attack" => {
                let host = string(&cmd, "host");
                let port = cmd.get("port").and_then(Value::as_u64).unwrap_or(80) as u16;
                let requests = strings(&cmd, "requests");
                let threads = cmd.get("threads").and_then(Value::as_u64).unwrap_or(4).max(1) as usize;
                let rules = MatchRules::new(
                    numbers(&cmd, "status"),
                    numbers(&cmd, "negative_status"),
                    cmd.get("negative_regex").and_then(Value::as_str).map(str::to_string),
                    cmd.get("length").and_then(Value::as_bool).unwrap_or(false),
                );
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    proxy.attack(host, port, requests, threads, rules).await;
                });
            }

            "intercept" => {
                let on = cmd.get("enabled").and_then(Value::as_bool).unwrap_or(false);
                proxy.set_intercept(on);
                reply(&cmd, json!({ "type": "intercept", "enabled": on }));
            }
            "forward" => {
                // held_id, not the correlation id, selects the parked request.
                let id = cmd.get("held_id").and_then(Value::as_u64).unwrap_or(0);
                let ok = proxy.forward(id).await;
                reply(&cmd, json!({ "type": "released", "id": id, "forwarded": ok }));
            }
            "drop" => {
                let id = cmd.get("held_id").and_then(Value::as_u64).unwrap_or(0);
                let ok = proxy.discard(id).await;
                reply(&cmd, json!({ "type": "released", "id": id, "forwarded": false, "known": ok }));
            }
            "held_list" => {
                let items: Vec<Value> = proxy
                    .held()
                    .await
                    .iter()
                    .map(|h| json!({ "id": h.id, "method": h.method, "target": h.target }))
                    .collect();
                reply(&cmd, json!({ "type": "held_list", "items": items }));
            }

            other => fail(format!("unknown command: {other}")),
        }
        *pending.lock().await = None;
    }
}

fn numbers(cmd: &Value, key: &str) -> Vec<u16> {
    cmd.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).map(|v| v as u16).collect())
        .unwrap_or_default()
}