# Integrated Chromium and Installers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task, inline in the current chat. Preserve the existing local-tools changes. No implementation has started under this plan.

**Goal:** Install and launch a bundled Chromium through Gulpsuite's local proxy on Windows x64, Linux x64, and macOS x64/arm64.

**Architecture:** Keep the native Rust application; add an owned external-browser launcher and a verified, version-pinned Chromium resource bundle. A release-preparation tool resolves upstream revisions into a lock manifest; native packaging consumes only that manifest. Browser launch waits for the real proxy listener and restricts browser TLS exceptions to the session CA pin.

**Tech Stack:** Rust/Tokio/egui, Chromium official snapshots, Python standard-library build tooling, NSIS, Debian packaging tools, macOS hdiutil/codesign, native CI runners. Python and packaging tools are build dependencies only.

**Spec:** `docs/superpowers/specs/2026-10-19-integrated-chromium-installers-design.md` (approved in chat).

## Global Constraints

- Target Windows x64, Linux x64, macOS Intel/Apple Silicon; initial Linux baseline Ubuntu 24.04 x64 and compatible Debian-family systems, not every Linux distribution.
- Chromium is bundled in the installer, never downloaded on first app launch. No runtime npm/Python dependency or new cloud account/service.
- Resolve latest official snapshots during release preparation, pin revisions and archive SHA-256, then test those exact artifacts. No silent fallback to installed Chrome or older browser builds.
- Do not change system proxy, system trust, personal browser profiles, or disable Chromium sandbox. Do not add global `--ignore-certificate-errors` or `--no-sandbox`.
- AI/BApp Store remain WIP; no licensing implementation. Preserve existing engine features and original app bundles.
- Browser updates arrive through Gulpsuite releases, not a background updater. Keep Chromium licenses and third-party notices in packages.
- Do not claim Windows/Linux/macOS Intel verification until native checks execute. No remote publishing implied. Publisher signing credentials are external inputs, never source files.
- Stop before browser download/extraction if the free-space budget is insufficient; reclaim only explicitly identified generated build artifacts, never user data.

## Review Focus

- Multiple clicks or simultaneous proxy starts must not launch Chromium against an unbound or wrong listener (Task 3).
- A stale Chromium profile must not keep the previous process's CA pin/proxy port or attach to personal Chrome (Tasks 2–3).
- Missing/corrupted archive, symlink/path-traversal entries, missing notices, or architecture mismatch must fail packaging before executing downloaded code (Task 1).
- Spaces/non-ASCII in installation/profile paths and a different current directory must not alter resource lookup or command argument boundaries (Tasks 2, 4).
- Uninstall/upgrade and app shutdown must not kill unrelated browsers or delete profile/user project data (Tasks 2, 4–5).

## Task 1: Reproducible Chromium resource staging

**Files:** Create `packaging/chromium.py`, `packaging/chromium-lock.json`, `packaging/tests/test_chromium.py`, `packaging/README.md`; modify `.gitignore` for generated staging/download/installers.

**Interfaces:**

- CLI `python3 packaging/chromium.py resolve --platform PLATFORM --output LOCK` prepares a platform manifest entry from the official snapshot `LAST_CHANGE` and the exact selected archive; hashes downloaded bytes. Platforms: `windows-x64`, `linux-x64`, `macos-x64`, `macos-arm64`.
- CLI `python3 packaging/chromium.py stage --platform PLATFORM --lock LOCK --destination DIR` verifies the pinned archive hash and stages `DIR/resources/chromium/` plus `DIR/resources/chromium-manifest.json`. Refuse an occupied destination rather than deleting it.
- Entry fields: `platform`, `revision`, `url`, `sha256`, `executable` (resource-relative), `notices` (resource-relative list). Upstream bucket/platform/archive mappings are explicitly allowlisted and verified before resolving. No arbitrary URL supplied by an archive.

- [ ] Write standard-library `unittest` fixtures using tiny local archives. Assert exact SHA mismatch rejection; missing browser/notices rejection; path traversal, symlink and oversized expanded archive rejection; existing-destination preservation; platform mapping and spaced paths.
- [ ] Run `python3 -m unittest discover -s packaging/tests -v`; establish the failing baseline before implementation.
- [ ] Implement official-source resolution, bounded streaming downloads, disk-space checks, safe extraction and manifest validation. Use HTTPS allowlisted official storage URLs; a locally computed checksum pins retrieved bytes but is not falsely described as an upstream signature.
- [ ] Run the unit suite; prepare and stage the latest macOS arm64 snapshot, record its revision/hash/version and upstream notices. Resolve other architectures only when native release preparation needs them; do not invent lock values.
- [ ] Verify the staged browser's architecture and executable presence without launching it. Missing platform entries must make packaging fail clearly, not use a different architecture.

## Task 2: Browser launcher and platform-owned paths

**Files:** Create `engine/src/browser.rs`, `engine/src/platform_paths.rs`, `engine/tests/browser_launch.rs`; modify `engine/src/lib.rs`, `engine/src/tls.rs`, `engine/Cargo.toml`, `engine/Cargo.lock`.

**Interfaces:**

- `platform_paths::data_dir() -> Result<PathBuf, String>`: macOS Application Support/Gulpsuite, Windows LOCALAPPDATA/Gulpsuite, Linux XDG_DATA_HOME/gulpsuite or HOME/.local/share/gulpsuite. No `/tmp` fallback for persistent personal data. Pure path-resolution helper accepts explicit environment values for tests without mutating process environment.
- `browser::BrowserInstall::from_app_executable(app: &Path) -> Result<BrowserInstall, String>` locates resources relative to the app, never the working directory. `BrowserInstall` retains browser executable and pinned manifest metadata.
- Resource layout: macOS `Gulpsuite.app/Contents/Resources/chromium/Chromium.app/Contents/MacOS/Chromium`; Windows/Linux `APPDIR/resources/chromium/chrome.exe` or `chrome`. Linux app lives in `/opt/gulpsuite/`.
- `tls::Authority::spki_pin(&self) -> String` computes SHA-256/base64 over the authority key's DER SubjectPublicKeyInfo. Expose through `Proxy::browser_ca_pin() -> Result<String, String>` (Task 3). Add direct Rust hashing/base64 dependencies instead of calling shell OpenSSL at runtime.
- `browser::LaunchConfig { proxy_port: u16, ca_spki: String, profile_dir: PathBuf, target: String }` and `BrowserInstall::launch(&self, config: &LaunchConfig) -> Result<BrowserSession, String>`. `BrowserSession` owns process cleanup and reuse; no global process-name kill.

- [ ] Write failing tests for all four installed layouts, paths with spaces/Unicode, missing resources, non-HTTP targets, HTTP/HTTPS scheme preservation, and default `about:blank`. Test exact argument boundaries rather than shell command strings.
- [ ] Write failing tests asserting loopback proxy, explicit loopback bypass override, QUIC disabled, scoped SPKI flag and isolated profile; reject port zero/invalid pin; assert forbidden broad bypass/sandbox flags are absent.
- [ ] Implement path resolution, CA pin and launch arguments; move CA export to the platform data path while leaving the old public certificate file untouched. Do not persist CA private keys as part of this change.
- [ ] Implement per-app-session profile directories with private permissions where supported. Reuse the session only while its listener/pin are unchanged; otherwise fail clearly or replace only the owned browser session. Preserve old profile directories on exit/upgrade.
- [ ] Implement Unix process-group / Windows Job Object ownership and shutdown. Retain a live primary session, reap secondary launches, and test spawn failure and already-exited processes with a fake executable. No mutation of personal browser settings.
- [ ] Run `cargo test --test browser_launch` and focused TLS/unit tests with debug info/incremental disabled on this disk-constrained host. Confirm no unrelated GUI snapshot changes.

## Task 3: Connect Browser UI to listener readiness and real traffic

**Files:** Modify `engine/src/ui/app.rs`, `engine/src/proxy.rs`, `engine/src/ui/panels/proxy.rs`; create `engine/tests/browser_e2e.rs`; extend `engine/tests/ui_parity.rs`.

**Interfaces:**

- `Proxy::ensure_started(&self, requested_port: u16) -> io::Result<u16>` atomically starts/reuses the listener and returns the actual bound port. Preserve existing `start` callers' behavior; serialize listener state transitions rather than checking `bound_port` then racing another start. Coordinate stop through the same lifecycle ownership.
- UI holds pending browser-open/result state and optional owned `BrowserSession`. Replace the existing system `open` fallback. Resolve target from existing captured traffic with its exact HTTP/HTTPS scheme, or `about:blank`.
- Add an accessible `Open browser` action to Proxy Intercept as well as the existing shell Browser action. Both invoke the same implementation; failures appear in status/event UI, not just stderr.

- [ ] Write failing tests: concurrent ensure/start requests choose one listener; occupied requested port surfaces an error; stopped listener is not reused; repeated clicks while startup is pending do not spawn competing browser sessions.
- [ ] Write UI tests using injectable launcher results: missing bundle error, listener failure, successful launch after readiness, correct HTTPS target retention, and no launch on binding failure. Keep real browser launch out of normal unit tests.
- [ ] Implement the asynchronous UI path, listener lifecycle seam and CA pin accessor. Leave the UI responsive and preserve current interception settings; intercept-on may intentionally hold browser traffic for Forward/Drop.
- [ ] Add opt-in `browser_e2e` tests requiring the staged executable: actual Chromium HTTP and HTTPS to controlled loopback origins, expected body and Proxy history, intercept/Forward behavior, repeated window launch, shutdown. Trust a fixture origin CA only inside the test proxy. Verify unrelated invalid origin certificates remain rejected.
- [ ] Run focused tests, then real headless Chromium tests with its sandbox enabled and an isolated writable profile. If the bundled build does not honor scoped CA pin behavior, stop and diagnose; do not substitute a blanket TLS bypass.
- [ ] Build a new native macOS preview with staged Chromium and exercise the visible Browser button, navigation, HTTP history and HTTPS interception manually. Leave the original app untouched.

## Task 4: Build offline installers with browser resources

**Files:** Create `packaging/package.py`, `packaging/windows/gulpsuite.nsi`, `packaging/linux/gulpsuite.desktop`, `packaging/tests/test_package.py`; modify `bundle.sh`, `build.sh`, `.gitignore`, and `packaging/README.md`.

**Interfaces:**

- `python3 packaging/package.py --platform PLATFORM --binary PATH --stage DIR --output DIR [--development]` validates matching browser manifest and builds the platform installer from one explicit staging root.
- Outputs: `Gulpsuite-VERSION-macos-arm64.dmg`, `Gulpsuite-VERSION-macos-x64.dmg`, `Gulpsuite-VERSION-windows-x64-setup.exe`, `gulpsuite_VERSION_amd64.deb` plus SHA256SUMS and browser manifest/notices.
- Developer mode is explicitly unsigned/ad-hoc. Production mode requires configured signing credentials and fails closed if they are absent; do not present unsigned artifacts as publisher-signed.

- [ ] Write failing content/layout tests: missing Chromium or lock/platform mismatch fails; notices are included; no current-directory dependency; version comes from Cargo.toml; existing output is preserved; unsafe package destinations rejected.
- [ ] Implement macOS bundle resource inclusion and DMG Applications shortcut; retain nested Chromium resources/frameworks. Verify ad-hoc signatures in developer mode. Add explicit optional publisher signing/notarization stages without embedding secrets or executing them without credentials.
- [ ] Implement per-user NSIS installer, Start menu shortcut, install registry/uninstaller metadata, exact installed-file removal and profile preservation. Keep optional signing credentials outside source and logs.
- [ ] Implement DEB package layout under `/opt/gulpsuite`, desktop entry, executable permissions, and declared Ubuntu 24.04 runtime dependencies. Verify Chromium sandbox support; never compensate with `--no-sandbox`. Do not ship a setuid helper with unreviewed ownership/permissions.
- [ ] Fix `build.sh` so the cargo build exit status cannot be masked by its output-filtering pipeline; preserve its existing tests and executable output.
- [ ] Run packaging unit tests, inspect artifact contents and install a macOS arm64 development DMG into a separate temporary app location. Launch from a different working directory. No overwrite/uninstall of the user's original app.

## Task 5: Native CI matrix, release evidence and handoff

**Files:** Create `.github/workflows/installers.yml`, `packaging/smoke.py`, `docs/reverse-engineering/integrated-browser-release-evidence.md`; update `packaging/README.md`.

**Interfaces:**

- Separate manually invoked release preparation (resolve latest and output a candidate lock for review) from package builds (consume approved pinned manifest). No scheduled background automation or automatic publishing.
- Native matrix: macOS arm64, macOS x64, Windows x64, Ubuntu 24.04 x64. Runner availability/architecture must be checked explicitly; missing native runner is pending validation, not a successful cross-build.
- `python3 packaging/smoke.py --install-root PATH --platform PLATFORM` verifies installed binary/browser/notices/version and launches a dedicated Rust loopback browser smoke harness. GUI Linux tests run under Xvfb with sandbox-supporting runner configuration; no sandbox-disabling flags.

- [ ] Add native jobs for locked Rust build/tests, Chromium hash-verified staging, opt-in real browser HTTP/TLS smoke, package assembly and installed-layout smoke. Run existing GUI parity snapshots only on the matching approved baseline; separate engine/browser coverage from OS font-rendering differences.
- [ ] Windows: silent install/uninstall in disposable runner; assert browser works after install and profile sentinel remains after uninstall. Linux: DEB install/remove and same preservation checks. macOS: mount/copy/launch from temporary installation and verify signatures/resource paths; preserve profile sentinel after app removal.
- [ ] Add developer artifacts as job outputs only; no GitHub release/publication. Production signing remains an explicit credentials-dependent job, not a bypass.
- [ ] Execute the full existing Rust suite, browser tests, packaging unit tests, local release build and macOS arm64 installer smoke. Review the diff and correct material findings; update evidence with actual commands, exit codes, Chromium revision/hash and tested platforms.
- [ ] Report artifacts and exact gaps. Windows/Linux/macOS x64 remain unverified until jobs actually run; missing signing credentials and unavailable runners must be stated. Do not claim overall cross-platform completion on the strength of configuration files alone.

## Execution order and stop conditions

Work inline in task order; no new chat, publication, or autonomous scheduling. Task 1 produces the exact browser input used by the runtime and packaging tasks; Tasks 2–3 deliver the integrated browser; Task 4 delivers installers; Task 5 proves the supported matrix. Use focused tests at each boundary and final regression evidence. Stop for a real dependency/credential/disk/runner blocker after safe alternatives, preserving partial work and reporting what is runnable. This plan is ready for user review; code changes begin only after that review.
