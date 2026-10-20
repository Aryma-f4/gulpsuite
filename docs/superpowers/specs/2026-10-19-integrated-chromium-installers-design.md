# Integrated Chromium and cross-platform installers

Status: design approved by the user in chat on 2026-10-19; implementation plan pending review. Supersedes the earlier installed-Chrome-only browser design. No browser bundling or installer implementation has been completed yet.

## Intent and acceptance

Installing Gulpsuite must also install its own Chromium browser. The native Browser action launches that browser, with a separate Gulpsuite profile and HTTP/HTTPS traffic routed through Gulpsuite's local proxy, without requiring Chrome or manual system proxy/CA installation. Preserve the existing native Rust UI, existing local-tool features, and the user's normal browser profile. No licensing, cloud account, or runtime second service is required.

Deliver native installers for Windows x64, Linux x64, and macOS Intel/Apple Silicon. This is an initial architecture matrix, not a claim of support for every CPU or Linux distribution. Linux support must name and test its dependency baseline. Additional architectures need their own Chromium artifact availability and native validation.

## Approach and alternatives

Recommended: keep the Rust native application and ship a separately launched, bundled upstream Chromium. The browser window is external, as a tool-controlled browser rather than an embedded webview. This reuses the existing Browser command and proxy rather than replacing the UI framework.

An installed Chrome fallback would make installers smaller but does not meet the requirement that Chromium be included. An embedded CEF browser would require a new browser UI/lifecycle subsystem without improving the requested proxy workflow. Playwright-managed Chromium offers tested pinned revisions, but does not necessarily equal the latest upstream Chromium snapshot and should not silently substitute for that requirement.

## Chromium release policy

Resolve the latest available official Chromium snapshot separately for each supported build platform when preparing a release. Freeze the resolved revision and archive SHA-256 in a reviewed manifest, then build/test the installers from those exact artifacts. A failed download or smoke test fails the release; it must not silently ship an older or missing browser. Upstream snapshots are development builds, not a stable-channel promise, and platform revisions may differ.

Normal installer builds consume the pinned manifest, not an unrecorded moving latest URL. Preserve upstream license and third-party notices. Browser updates ship with new Gulpsuite releases initially; no background browser downloader, runtime npm/Python dependency, or self-update service is introduced. Installed Chromium will therefore not remain automatically latest indefinitely.

## Runtime integration

Add a small platform-aware browser module for bundled executable/resource discovery, per-user writable profile paths, launch arguments, process ownership, and actionable launch errors. Use platform data directories rather than the current macOS-only Library assumption. The browser must be found relative to the installed app, not the current working directory or a global Chrome installation.

The Browser action starts or reuses the actual Gulpsuite listener and waits for successful binding before launch. Propagate bind/browser errors to the UI instead of reporting success after a failed spawn. Preserve HTTP versus HTTPS on the target; use a local welcome page or blank page when there is no target. Do not navigate the browser directly to a proxy listening socket as if it were a website.

Configure an explicit loopback proxy, prevent localhost bypass for test traffic, and disable QUIC paths that bypass HTTP proxy interception. Keep the Chromium sandbox enabled. Do not use global certificate-error bypasses or change system trust. Limit HTTPS trust configuration to Gulpsuite's own current CA public-key pin in the isolated browser launch. Validate this mechanism against the actual bundled build; if unsupported, report a clear error rather than weakening verification for every certificate. Keep upstream TLS validation in the proxy intact.

The profile is isolated from personal browser data and scoped to this Gulpsuite installation/session policy. Avoid concurrent processes sharing one profile with conflicting proxy ports or CA pins. Repeated Browser actions must have an explicit reuse/open-new-window policy. Shut down only processes owned by this application; do not kill unrelated Chrome/Chromium. Preserve profile data on normal app exit and upgrades.

## Packaging and installation

- macOS: Chromium resources inside Gulpsuite.app, distributed in a DMG with Applications shortcut. Native builds for arm64 and x64.
- Windows: per-user installer EXE with app shortcuts and uninstaller, including Chromium resources. Prefer no administrator requirement.
- Linux: DEB installation package with desktop entry and bundled Chromium resources. Declare required system libraries; start with a documented Ubuntu/Debian baseline, not an unverified all-distributions promise.

Add build jobs on native macOS, Windows and Linux runners, plus reproducible browser-fetch/package scripts. Installer tests verify that the bundled browser is present and executable, the installed app can locate resources from a different working directory, and upgrade/uninstall does not delete personal browser data. Existing app bundles must not be overwritten during development packaging.

Public macOS signing/notarization and Windows signing require publisher credentials. Provide unsigned development artifacts without claiming they bypass Gatekeeper or SmartScreen; signing stages must accept secrets without storing them in source. No remote publish/upload is implied by this task.

## Verification

Unit tests cover platform resource/profile paths, launch arguments, target scheme retention, CA pin scoping, missing browser and process failures. Integration tests cover listener readiness/conflicts, real browser HTTP and HTTPS through a loopback origin, visible Proxy history/interception, repeated launch, app shutdown, and unchanged personal browser settings. Packaging checks inspect browser revision/checksum/notices, installer contents, and install/launch/uninstall on each native runner.

The current machine can manually validate only macOS arm64. Windows, Linux and Intel macOS are not declared verified until native jobs actually run. The current disk has approximately 3.3 GiB free; browser extraction and packaging require a free-space check and may need build-cache cleanup or additional disk space. Do not delete user files to make room.

## Out of scope

Embedding Chromium inside the egui window, cloud services, runtime download-on-first-launch instead of bundling, automatic self-updates, browser account sync, every Linux distribution, and additional CPU architectures. No claim of exact Burp browser implementation or full Burp feature parity.
