# Local tools functional parity implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement the tasks in this session. The user has authorized native implementation and verification.

**Goal:** Make the local Proxy → Repeater → Intruder workflow reliable and bring observable behavior closer to installed Burp Suite Professional v2026.3.3.

**Architecture:** Reuse the existing Rust/Tokio proxy transport, task workspace, and native egui panels. Introduce a shared HTTP target parser and a separate Intruder request generator; keep legacy marker primitives compatible for existing callers. Verify traffic against loopback HTTP/TLS origins, not external targets.

**Tech Stack:** Rust, Tokio, rustls, egui/eframe, egui_kittest.

**Spec:** User requirements in this chat: native UI and equivalent local functionality; prioritize Proxy, Repeater, Intruder and connected tools; defer cloud/second-service functionality, AI/BApp Store WIP, no licensing.

## Global constraints

- Preserve existing engine features and user files.
- Burp v2026.3.3 is the reference. REA archive evidence proves shipped API presence, not complete runtime equivalence.
- No cloud services, remote accounts, licensing, or new service dependencies.
- Do not claim 100% equivalence without feature-by-feature evidence.

## Review focus

- HTTPS targets, explicit ports, IPv6, and malformed targets must route correctly or fail clearly.
- Edited bodies must preserve bytes and Content-Length; framed keep-alive responses must finish promptly.
- Background Repeater tabs must receive their own responses; cancel/close must not attach stale responses to another tab.
- Intruder modes must preserve untouched base values, use the correct payload sets, and respect concurrency and cancellation.
- Proxy interception and send-to-tool operations must preserve request/target identity.

### Task 1: Finish Dashboard review corrections

Files: `engine/src/ui/panels/dashboard.rs`, `engine/tests/ui_parity.rs`, snapshots and evidence document.

- [x] Correct selected-task configuration, unknown metrics, issue severity ordering/time, and queued-task controls.
- [x] Make a narrow Dashboard scrollable; keep source regression snapshots clearly named.
- [x] Verify existing UI interactions and light/dark snapshots.

### Task 2: Shared HTTP transport and Proxy checks

Files: `engine/src/http_target.rs`, `engine/src/lib.rs`, `engine/src/proxy.rs`, `engine/tests/repeater_e2e.rs`, existing intercept/TLS tests.

- [x] Add `HttpTarget::parse(&str) -> Result<HttpTarget, String>` with HTTP/HTTPS defaults and bracketed IPv6.
- [x] Fix one-shot body/newline handling and response framing; honor configured trusted roots.
- [x] Verify Content-Length, chunked, HEAD/no-body statuses, interim responses, keep-alive, malformed/truncated response, and TLS.
- [x] Verify intercept edit/forward/drop and release-on-disable using real loopback traffic.

### Task 3: Repeater state and actions

Files: `engine/src/ui/panels/repeater.rs`, `engine/src/ui/app.rs`, focused unit/UI tests.

- [x] Consume results for every tab in the common app poll, independent of current tool.
- [x] Correct tab identity on close/reuse; add per-tab exchange history and previous/next navigation.
- [x] Add cancel using request task handles and prevent duplicate sends.
- [x] Verify HTTPS routing and concurrent tabs with local origins; preserve send-to-Repeater without automatic transmission.

### Task 4: Intruder generation and execution

Files: `engine/src/intruder.rs`, `engine/src/ui/panels/intruder.rs`, `engine/src/proxy.rs`, `engine/src/ui/app.rs`, `engine/tests/intruder_e2e.rs`.

- [x] Implement `AttackType` and bounded request generation for Sniper, Battering ram, Pitchfork, Cluster bomb.
- [x] Replace each complete §value§ region with a whole payload, preserve whitespace/empty payloads, validate markers and payload sets.
- [x] Connect HTTPS, Host-update option, numeric payload generation, bounded workers, shared matching baseline, pause/resume/cancel, request/response results.
- [x] Verify each mode's literal requests, matching across workers, lifecycle and real origin traffic.

### Task 5: Integration, review and release

- [x] Run the complete tests and native release build after the final changes.
- [x] Review the working diff, fix material findings, and document verified features and remaining gaps.
- [x] Produce a runnable native build without silently replacing the existing app bundle.

## Execution result

Completed this bounded local-tools slice on 2026-10-19. Final suite: 430 passing tests; release build and preview signature/plist checks passed. Native smoke verified Repeater loopback 200, target transfer without auto-send, and Intruder 3/3 successful loopback results. Two reviews completed and material findings corrected. Evidence and explicit remaining parity gaps are recorded in `docs/reverse-engineering/burp-v2026.3.3-local-tools-evidence.md`. Completing this plan does not mean all Burp features are equivalent.
