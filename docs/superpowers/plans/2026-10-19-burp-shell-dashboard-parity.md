# Burp v2026.3.3 Shell and Dashboard Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Gulpsuite's static Dashboard and partial shell with a persisted, functional v2026.3.3-style shell backed by real tasks, events, and issues.

**Architecture:** Add a serializable workspace domain model beneath the egui layer, adapt existing engine events into it, and make the shell and Dashboard render that single source of truth. Keep existing tool engines and panels intact behind the new shell, then verify structure and interactions with headless egui tests and fixed-size image snapshots.

**Tech Stack:** Rust 2021, eframe/egui 0.33.3, serde/serde_json, tokio, egui_kittest 0.33.3 for interaction and snapshot tests.

**Spec:** `docs/superpowers/specs/2026-10-19-burp-parity-shell-dashboard-design.md`

## Global Constraints

- Burp Suite Professional v2026.3.3 is the canonical observable reference.
- Reproduce observable UI and local behavior with independent Rust code; do not copy proprietary source or private services.
- AI and BApp Store entry points show explicit WIP states; licensing is absent.
- Existing functional tool panels remain available throughout this slice.
- Network and long-running work stays off the egui update thread and supports cancellation where the backing engine supports it.
- Histories remain explicitly bounded; no new unbounded task, event, issue, or body stores.
- Existing project files continue to load through serde defaults; reject newer unsupported project versions.
- The full existing test suite must stay green.

## Review Focus

- A project saved while work is running must reload that task as interrupted, never falsely running; Task 3 pins this behavior.
- A search or filter yielding zero tasks/issues/events must show a stable empty state without losing the user's selection; Tasks 2, 5, and 6 pin this behavior.
- Repeated engine completion/error events must not duplicate terminal transitions or issue records; Task 4 pins idempotence.
- Small windows must keep the selected tool and utility actions reachable instead of clipping them silently; Tasks 5 and 8 pin overflow behavior.
- Closing or failing a detached task viewport must reattach its detail and preserve the task; Task 7 pins fallback behavior.

---

### Task 1: Versioned Burp reference specification

**Files:**
- Create: `engine/assets/reference/burp-v2026.3.3.json`
- Create: `engine/src/ui/reference.rs`
- Modify: `engine/src/ui/mod.rs`
- Test: `engine/src/ui/reference.rs`

**Interfaces:**
- Consumes: approved design spec and REA evidence IDs.
- Produces: `pub fn burp_2026_3_3() -> &'static ReferenceSpec`, plus typed tab, dashboard, drawer, and evidence measurements used by later UI tasks.

- [ ] **Step 1: Write failing reference tests**

Add tests named `reference_identifies_exact_version_and_evidence`, `reference_preserves_observed_tool_order`, and `reference_dashboard_geometry_matches_capture`. Assert version `2026.3.3`, the 13 observed tool labels in order, tool-row height `31.0`, sub-row height `30.0`, Dashboard split `500.0 / 1440.0`, status height `36.0`, and both retained REA evidence IDs.

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `cargo test ui::reference::tests --lib`

Expected: FAIL because `ui::reference` and the reference JSON do not exist.

- [ ] **Step 3: Implement the reference loader**

Define `ReferenceSpec`, `ShellReference`, `DashboardReference`, `DrawerReference`, and `EvidenceReference` with serde deserialization. Load the checked-in JSON through `include_str!`; expose one `OnceLock<ReferenceSpec>` via `burp_2026_3_3()` and fail fast with a version-specific parse message.

- [ ] **Step 4: Run reference and theme tests**

Run: `cargo test ui::reference::tests ui::theme::tests --lib`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/assets/reference engine/src/ui/reference.rs engine/src/ui/mod.rs
git commit -m "test: codify Burp 2026 shell reference"
```

### Task 2: Serializable workspace task, event, and issue models

**Files:**
- Create: `engine/src/workspace/mod.rs`
- Create: `engine/src/workspace/task.rs`
- Create: `engine/src/workspace/event.rs`
- Create: `engine/src/workspace/issue.rs`
- Modify: `engine/src/lib.rs`
- Test: the four new workspace modules

**Interfaces:**
- Consumes: no UI types and no engine receivers.
- Produces: `Workspace`, `TaskManager`, `TaskId`, `TaskKind`, `TaskState`, `TaskProgress`, `EventStore`, `EventRecord`, `EventLevel`, `IssueStore`, `IssueRecord`, `IssueSeverity`, and bounded filter/query APIs.

- [ ] **Step 1: Write failing domain tests**

Cover these exact behaviors:

- `TaskManager::seed_proxy_tasks()` creates passive crawl then live audit with stable IDs 1 and 2 while display sorting places live audit first.
- `create`, `rename`, `pause`, `resume`, `complete`, `fail`, and `cancel` reject invalid transitions with `Result<(), WorkspaceError>`.
- `query(&TaskQuery)` combines state/kind filters and case-insensitive name/configuration search; a zero-result query leaves `selected()` unchanged.
- `EventStore::with_capacity(3)` and `IssueStore::with_capacity(3)` discard the oldest item on the fourth insert.
- `IssueStore::upsert` deduplicates by `(task_id, name, url, parameter, evidence)`.
- [ ] **Step 2: Run workspace tests and confirm failure**

Run: `cargo test workspace --lib`

Expected: FAIL because the workspace modules do not exist.

- [ ] **Step 3: Implement the domain types and transitions**

Use monotonically increasing `u64` newtypes for IDs, `VecDeque` for bounded stores, and serde derives for all persisted values. Use `TaskManager::DEFAULT_CAPACITY = 1_000`, `EventStore::DEFAULT_CAPACITY = 2_000`, and `IssueStore::DEFAULT_CAPACITY = 2_000`. Keep timestamps as caller-supplied Unix milliseconds so tests remain deterministic.

- [ ] **Step 4: Run workspace tests**

Run: `cargo test workspace --lib`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/src/workspace engine/src/lib.rs
git commit -m "feat: add workspace task event and issue models"
```

### Task 3: Backward-compatible project persistence

**Files:**
- Modify: `engine/src/project.rs`
- Modify: `engine/src/ui/app.rs`
- Test: `engine/src/project.rs`

**Interfaces:**
- Consumes: `Workspace` from Task 2.
- Produces: `SavedWorkspace`, `SavedLayout`, `DrawerLayout`, `impl From<&Workspace> for SavedWorkspace`, `SavedWorkspace::restore() -> Workspace`, and App save/load adapters.

- [ ] **Step 1: Write failing persistence tests**

Add `old_v1_project_loads_with_default_workspace`, `workspace_and_layout_round_trip`, `running_tasks_restore_as_interrupted`, `drawer_heights_are_clamped_on_restore`, and `unknown_newer_project_version_is_rejected`. Use a minimum drawer height of `120.0`, maximum of `600.0`, and default of `280.0`.

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `cargo test project::tests --lib`

Expected: FAIL on missing workspace/layout fields and adapters.

- [ ] **Step 3: Extend the project schema**

Keep `PROJECT_VERSION = 1` because new fields are additive. Add `#[serde(default)]` workspace and layout fields. On restore, map `Queued`, `Running`, and `Paused` tasks to `Interrupted` and append one warning event per interrupted task; preserve completed, cancelled, failed, and existing v1 content.

- [ ] **Step 4: Wire App save/load**

Have `App::save_project` persist `self.workspace` and `self.shell.layout()`. Have `App::open_project` replace those values only after `Project::load` and restoration succeed; keep current session state on any error.

- [ ] **Step 5: Run project and full library tests**

Run: `cargo test project::tests --lib && cargo test --lib`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/src/project.rs engine/src/ui/app.rs
git commit -m "feat: persist workspace and shell layout"
```

### Task 4: Adapt existing engine activity into the workspace

**Files:**
- Create: `engine/src/ui/workspace_adapter.rs`
- Modify: `engine/src/ui/mod.rs`
- Modify: `engine/src/ui/app.rs`
- Modify: `engine/src/ui/panels/scanner.rs`
- Modify: `engine/src/ui/panels/intruder.rs`
- Test: `engine/tests/workspace_integration.rs`

**Interfaces:**
- Consumes: `Workspace` and current `proxy::Event`, `scanner::ScanUpdate`, Discover updates, and Intruder events.
- Produces: `WorkspaceAdapter::apply_proxy`, `apply_scan`, `apply_discover`, and `apply_attack`; App owns `pub workspace: Workspace` and task IDs for active workers.

- [ ] **Step 1: Write failing integration tests**

Test that proxy transactions increment passive-crawl responses and live-audit processed counts; scanner start/progress/completion produces one scan task and normalized issues; Intruder completion updates one attack task; repeated completion is idempotent; and `Event::Error` records an error against the active task without discarding existing progress.

- [ ] **Step 2: Run the integration test and confirm failure**

Run: `cargo test --test workspace_integration`

Expected: FAIL because `WorkspaceAdapter` and App workspace state do not exist.

- [ ] **Step 3: Implement adapters at the existing pump/apply boundary**

Create tasks when operations start, retain their IDs on the corresponding panel/App state, and route updates before legacy panel fields are updated. Preserve legacy fields until later tool slices remove them. Convert scanner `Finding` values into `IssueRecord` without changing scanner detection logic.

- [ ] **Step 4: Run integration and existing engine tests**

Run: `cargo test --test workspace_integration --test scanner_e2e --test intercept_e2e --test session_e2e`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/src/ui/workspace_adapter.rs engine/src/ui/mod.rs engine/src/ui/app.rs engine/src/ui/panels/scanner.rs engine/src/ui/panels/intruder.rs engine/tests/workspace_integration.rs
git commit -m "feat: connect engine activity to dashboard workspace"
```

### Task 5: Shared shell state and functional bottom drawers

**Files:**
- Create: `engine/src/ui/shell.rs`
- Create: `engine/src/ui/drawers.rs`
- Modify: `engine/src/ui/mod.rs`
- Modify: `engine/src/ui/app.rs`
- Test: `engine/src/ui/shell.rs`
- Test: `engine/src/ui/drawers.rs`

**Interfaces:**
- Consumes: `Workspace`, `ReferenceSpec`, and `Theme`.
- Produces: `SuiteShell`, `DrawerKind::{EventLog, AllIssues}`, `DrawerState`, `ShellCommand`, `SuiteShell::draw_top`, `draw_bottom`, `draw_drawer`, `layout`, and `restore_layout`.

- [ ] **Step 1: Write failing shell-state tests**

Test independent drawer open/close state, height clamping, persisted selection, zero-result filters, clearing a filter without losing the selected record, and tool overflow calculation that always includes the selected tool and four utility buttons at widths `1440`, `900`, and `640`.

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `cargo test ui::shell::tests ui::drawers::tests --lib`

Expected: FAIL because shell modules do not exist.

- [ ] **Step 3: Implement state and rendering**

Move top-row and status-bar ownership from `App` into `SuiteShell`. Make Event Log and All Issues labels clickable. Render every open drawer in a vertical stack above the status bar, each with its own draggable separator, list/detail panes, filters, search, close control, selection, and explicit empty state. Return `ShellCommand` values rather than directly mutating engines.

- [ ] **Step 4: Integrate shell commands in App**

Replace `App::body`/`status_bar` state ownership with `SuiteShell` calls while keeping panel dispatch unchanged. Route tool selection, settings, search, console, and drawer commands through one `App::apply_shell_command` match.

- [ ] **Step 5: Run shell and App interaction tests**

Run: `cargo test ui::shell::tests ui::drawers::tests ui::app::interaction_tests --lib`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/src/ui/shell.rs engine/src/ui/drawers.rs engine/src/ui/mod.rs engine/src/ui/app.rs
git commit -m "feat: add Burp-style shell drawers"
```

### Task 6: Rebuild Dashboard on real workspace state

**Files:**
- Rewrite: `engine/src/ui/panels/dashboard.rs`
- Modify: `engine/src/ui/app.rs`
- Test: `engine/src/ui/panels/dashboard.rs`

**Interfaces:**
- Consumes: `Workspace`, `TaskQuery`, and `ShellCommand` from Tasks 2 and 5.
- Produces: task-list and detail rendering plus `DashboardCommand::{NewScan, NewLiveTask, Select, Rename, Pause, Resume, Cancel, Detach, ShowSettings, ShowHelp}`.

- [ ] **Step 1: Write failing Dashboard state tests**

Add tests for seeded ordering, search/filter behavior, selected-task details, live issue counters, rename validation, pause/resume availability, completed-task controls, and the no-task/zero-result empty states. Assert the search field stores text across frames instead of allocating a new empty `String` each frame.

- [ ] **Step 2: Run Dashboard tests and confirm failure**

Run: `cargo test ui::panels::dashboard::tests --lib`

Expected: FAIL against the static two-card Dashboard.

- [ ] **Step 3: Implement the task list and commands**

Render tasks from `workspace.tasks.query`, preserve Burp's live-audit-first display, bind filters/search to persistent Dashboard state, and expose real per-task pause/resume/rename/cancel menus. New scan navigates to the existing scanner configuration; New live task creates or focuses the existing proxy live task.

- [ ] **Step 4: Implement task detail**

Render task name, state, configuration, progress, counters, linked issues, and bounded task log. Keep the observed Summary/Audit items/Issues/Event log/Logger/Audit log subviews, but derive their contents from the selected task instead of global placeholders.

- [ ] **Step 5: Run Dashboard and scanner tests**

Run: `cargo test ui::panels::dashboard::tests --lib && cargo test --test scanner_e2e --test workspace_integration`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/src/ui/panels/dashboard.rs engine/src/ui/app.rs
git commit -m "feat: drive dashboard from real tasks"
```

### Task 7: Detachable task details and explicit WIP routes

**Files:**
- Create: `engine/src/ui/wip.rs`
- Modify: `engine/src/ui/shell.rs`
- Modify: `engine/src/ui/app.rs`
- Modify: `engine/src/ui/panels/extender.rs`
- Test: `engine/src/ui/shell.rs`
- Test: `engine/src/ui/wip.rs`

**Interfaces:**
- Consumes: selected `TaskId`, `SuiteShell`, and App viewport context.
- Produces: `DetailLocation::{Attached, Detached, Reattaching}`, `WipFeature::{Ai, BappStore}`, viewport IDs derived from task IDs, and fallback commands.

- [ ] **Step 1: Write failing detach/WIP tests**

Test that detach preserves selection, closing a viewport changes the task to attached, viewport creation failure logs a warning and attaches, and AI/BApp Store actions route to labeled WIP views. Assert no menu or view label contains `License`, `Licensing`, or `Activate`.

- [ ] **Step 2: Run focused tests and confirm failure**

Run: `cargo test ui::shell::tests ui::wip::tests --lib`

Expected: FAIL because detach state and WIP routes do not exist.

- [ ] **Step 3: Implement detach/reattach**

Use `Context::show_viewport_deferred` with `ViewportId::from_hash_of(("task-detail", task_id))`. Render the same selected-task detail component in either location. Treat close requests and viewport errors as reattach commands; never delete or duplicate a task.

- [ ] **Step 4: Implement WIP views and menu routing**

Add polished AI and BApp Store WIP states with purpose, current status, and a return action. Route existing Extensions Installed/Updates placeholders to the BApp Store WIP state. Remove licensing-related actions if any are encountered during menu reconstruction.

- [ ] **Step 5: Run focused and menu tests**

Run: `cargo test ui::shell::tests ui::wip::tests ui::app::menu_tests --lib`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add engine/src/ui/wip.rs engine/src/ui/shell.rs engine/src/ui/app.rs engine/src/ui/panels/extender.rs
git commit -m "feat: add detachable details and WIP routes"
```

### Task 8: Interaction and visual parity harness

**Files:**
- Modify: `engine/Cargo.toml`
- Modify: `engine/Cargo.lock`
- Modify: `.gitignore`
- Create: `engine/tests/ui_parity.rs`
- Create: `engine/kittest.toml`
- Create: `engine/tests/snapshots/shell-dashboard-light.png`
- Create: `engine/tests/snapshots/shell-dashboard-dark.png`

**Interfaces:**
- Consumes: complete shell/Dashboard rendering and deterministic fixture `Workspace`.
- Produces: headless interaction coverage and fixed-size 1440x790 light/dark snapshots.

- [ ] **Step 1: Add the compatible test dependency and ignore generated diffs**

Add `egui_kittest = { version = "=0.33.3", features = ["eframe", "snapshot", "wgpu"] }` under `[dev-dependencies]`. Ignore `**/tests/snapshots/**/*.new.png` and `**/tests/snapshots/**/*.diff.png`, but keep approved PNGs tracked.

- [ ] **Step 2: Write failing interaction tests**

Use a deterministic fixture with the two seeded live tasks, one completed scan, four issue severities, and event levels. Test top-tool selection, New scan, search, filter/no-results/clear, task selection, pause/resume, Event Log opening, All Issues opening, drawer close, and narrow-window access to the selected tool.

- [ ] **Step 3: Run interaction tests and confirm failures**

Run: `cargo test --test ui_parity --no-default-features`

Expected: FAIL until all controls expose stable accessibility labels and commands.

- [ ] **Step 4: Add missing accessibility labels and fix interactions**

Give icon-only controls explicit widget labels/descriptions and ensure every visible enabled control changes state or emits a command. Keep visual glyph rendering unchanged.

- [ ] **Step 5: Generate and review snapshots**

Run: `UPDATE_SNAPSHOTS=true cargo test --test ui_parity shell_dashboard_snapshot -- --nocapture`

Expected: two 1440x790 baseline PNGs. Compare them side by side with the approved Burp v2026.3.3 reference capture; correct structural differences before accepting. Configure threshold `0.6` and `max_failed_pixels = 10` per platform in `kittest.toml`.

- [ ] **Step 6: Run snapshots without update mode**

Run: `cargo test --test ui_parity`

Expected: PASS with no `.new.png` or `.diff.png` files.

- [ ] **Step 7: Commit**

```bash
git add .gitignore engine/Cargo.toml engine/Cargo.lock engine/kittest.toml engine/tests/ui_parity.rs engine/tests/snapshots
git commit -m "test: lock shell and dashboard visual parity"
```

### Task 9: Final slice verification and evidence ledger

**Files:**
- Create: `docs/reverse-engineering/burp-v2026.3.3-shell-dashboard-evidence.md`
- Modify: `docs/superpowers/specs/2026-10-19-burp-parity-shell-dashboard-design.md`

**Interfaces:**
- Consumes: completed implementation, REA evidence, runtime observations, and test results.
- Produces: a concise observed/inferred/unknown ledger and checked acceptance criteria.

- [ ] **Step 1: Run formatting and static checks**

Run: `cargo fmt --check && cargo clippy --all-targets`

Expected: both commands exit successfully; do not introduce new warnings in files added by this slice. Existing repository-wide Clippy findings are recorded separately rather than expanding this parity slice into unrelated cleanup.

- [ ] **Step 2: Run the complete suite**

Run: `cargo test --all-targets`

Expected: PASS, including existing tests, workspace integration, UI interactions, and visual snapshots.

- [ ] **Step 3: Build the release application**

Run: `cargo build --release --bin gulpsuite`

Expected: PASS and produce `engine/target/release/gulpsuite`.

- [ ] **Step 4: Perform focused live comparison**

At 1440x790 in light and dark themes, verify tool ordering, Dashboard empty and populated states, task controls, drawers, narrow-window overflow, detach/reattach, AI WIP, BApp Store WIP, and absence of licensing. Record deviations as platform limitations or fix them before completion.

- [ ] **Step 5: Write the evidence ledger and check acceptance criteria**

For each claim, record source type, evidence ID or runtime state, Gulpsuite test/snapshot, limitation, and remaining unknown. Mark each first-slice acceptance criterion pass, partial, or unresolved; do not call the slice complete with required unresolved items.

- [ ] **Step 6: Commit**

```bash
git add docs/reverse-engineering/burp-v2026.3.3-shell-dashboard-evidence.md docs/superpowers/specs/2026-10-19-burp-parity-shell-dashboard-design.md
git commit -m "docs: record shell dashboard parity evidence"
```
