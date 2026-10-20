# Local tools: implementation and evidence

Verified on macOS arm64, 2026-10-19. Scope: native local Proxy, Repeater, Intruder and their shared workflow. No cloud/second service was added. AI and BApp Store remain WIP; licensing is absent by product requirement.

## Reference and limits

The installed Burp runtime reported v2026.3.3. Its JAR has SHA-256 `2d7ed0c16b87bbd45e539f02494e843a40d22401d2490592167389709670f820` despite the stale `burpsuite_pro_v2025.jar` filename. REA archive inventories retained as `ev_cd380653b98d0d56dd3f20aaf03de9812c408900b14c1f25ce97d65c94c8686e`, `ev_38fe9a1e458d96cb786342eac0213bde35276dc123157ed9804122d45650eae4`, and focused API inventory `ev_91471e35abf4b331c036ebd46d8b59942ab7f3540372a033f9c377ed3a8a3b4d` identify shipped tool surfaces. Focused API sources inspected: Montoya `proxy/Proxy.java`, `repeater/Repeater.java`, `intruder/Intruder.java`, and `intruder/HttpRequestTemplate.java`.

These establish API presence and exposed concepts such as insertion offsets, interception/history, and sending requests to Repeater without sending them to the network. Inventory alone does not establish hidden implementation, full runtime equivalence, or pixel-perfect UI parity. Gulpsuite uses its own Rust implementation.

## Delivered and tested

| Area | Behavior implemented | Verification |
| --- | --- | --- |
| HTTP targets | HTTP/HTTPS defaults, explicit ports, bracketed IPv6, invalid-target rejection; retained TLS/service identity | `repeater_e2e`, `tls_e2e`, `ui_parity` |
| Proxy | Edited request routing; forward/drop; disabling master intercept releases held traffic; framed response completion on keep-alive; interim responses; bounded headers/chunk metadata | `intercept_e2e`, `repeater_e2e`, existing proxy tests |
| Transport | Preserve body bytes while normalizing header newlines; update Content-Length; CL/chunked/HEAD/no-body responses; configured TLS roots; reject truncated and oversized responses | `repeater_e2e`, `tls_e2e` |
| Repeater | Background-tab response delivery, per-tab bounded exchange history, previous/next, cancellation and stale-result protection, send to Intruder without automatic transmission | `repeater_e2e`, `ui_parity`; native loopback smoke below |
| Intruder generation | Sniper, Battering ram, Pitchfork, Cluster bomb; replace complete marked regions; Unicode, duplicate, whitespace and empty payloads; Simple list, Numbers, Dates & times, Custom modification | `intruder_e2e` literal request and generator checks |
| Intruder execution | Bounded concurrent workers, HTTPS, Host update option, timeout/pacing, shared matching baseline, pause/resume/cancel, actual completion counts, captured request/response and original target per result | `intruder_e2e`; native loopback smoke below |
| Connected UI | Auto/Add/Clear positions; payload files; resource controls; result filtering/detail; send result to Repeater; Dashboard task progress; AI/BApp WIP navigation | `intruder_e2e`, `ui_parity`, Dashboard unit tests |

Generation is bounded to 50,000 requests and 64 MiB generated request data. Intruder response capture is bounded to 512 KiB per result and a shared 64 MiB budget; full length/matching is computed before truncation, and truncation is shown. Repeater retains up to 100 exchanges within 64 MiB. Manual one-shot responses are limited to 32 MiB. These are intentional resource limits, not unlimited Burp-equivalence claims.

## Verification record

From `engine/`:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --quiet
cargo build --release --quiet
```

Final suite passed: **360 unit + 70 integration/UI = 430 tests**, zero failures. Integration groups: discover 2, intercept 7, Intruder 8, logger 5, match/replace 4, Repeater 11, scanner 7, session 2, TLS 2, UI parity 17, websocket 1, workspace 4. Existing unused-import/variable warnings remain. The full suite predates only documentation and bundle assembly, not any later engine changes. Final release build succeeded after cleaning regenerable debug artifacts to reclaim disk space.

Two focused reviews were completed. Five material local-tool findings were corrected and regression-tested: held HTTPS/edited destination identity, per-result target retention, interim response interception, non-UTF-8 HTTP headers, and allocation-bounded metadata readers. Follow-up review cleared those findings; it was not a full Burp parity audit.

Native bundle assembly and checks from repository root:

```sh
GULPSUITE_BUNDLE_ID=net.gulpsuite.preview GULPSUITE_BUNDLE_NAME='Gulpsuite Preview' ./bundle.sh Gulpsuite-preview.app
codesign --verify --deep --strict Gulpsuite-preview.app
plutil -lint Gulpsuite-preview.app/Contents/Info.plist
```

All succeeded. The preview launched as a separate native app. Manual native smoke: Repeater sent to a temporary `127.0.0.1` origin and displayed `200 OK` with `Gulpsuite native loopback OK`. Send to Intruder preserved that target and did not auto-start. A marked query parameter with default payloads `a`, `b`, `c` completed **3/3**, all status 200, with visible result rows. Dashboard, Repeater and Intruder accessibility/rendered states were inspected. This complements rather than replaces the loopback integration tests. The original `Gulpsuite.app` remains untouched.

## Remaining gaps

This is not 100% Burp parity. UI typography, icons, editor structure and advanced workflows still differ. HTTP/2, HTTP/3, full persistent/pipelined HTTP behavior, the complete Burp payload catalogue, advanced Repeater configuration/groups/redirect behavior, and full scanner parity are not established. Chunked Proxy responses stream but are not fully editable through response interception. Automatic Content-Length updates lack a deliberate-malformation toggle. Other local tools retain their existing implementations and tests; they were not exhaustively compared feature by feature in this slice. No cross-platform native manual pass or cross-application pixel score was performed. Cloud-dependent capabilities remain deferred as requested.
