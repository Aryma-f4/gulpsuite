# Burp v2026.3.3 Shell and Dashboard Parity Design

Date: 2026-10-19

## Objective

Rework Gulpsuite's shared application shell and Dashboard so their observable UI and local behavior closely match Burp Suite Professional v2026.3.3 while preserving Gulpsuite as an independent, free Rust implementation.

This is the first slice of a broader tool-by-tool parity effort. It establishes the shared navigation, task, event, issue, layout, and verification foundations that later Target, Proxy, Intruder, Repeater, and other tool slices will reuse.

## Reference and evidence boundary

The canonical behavioral and visual reference is the locally installed and running Burp Suite Professional v2026.3.3 application. Runtime observations are used for visible structure and interactions. REA shipped-artifact evidence is used for bounded structural claims about the installed JAR.

The inspected JAR has SHA-256 `2d7ed0c16b87bbd45e539f02494e843a40d22401d2490592167389709670f820`. Its complete archive inventory is retained as REA evidence `ev_cd380653b98d0d56dd3f20aaf03de9812c408900b14c1f25ce97d65c94c8686e`. Focused class inventory evidence for Burp tool, site map, scope, logger, WebSocket, logging, and scanner audit surfaces is retained as `ev_38fe9a1e458d96cb786342eac0213bde35276dc123157ed9804122d45650eae4`.

Static artifact evidence does not establish runtime behavior. Runtime observations do not establish Burp's internal implementation. Gulpsuite will reproduce observable behavior through its own architecture and code.

## Product constraints

- Match the Burp v2026.3.3 UI as closely as egui and the supported desktop platforms permit.
- Implement equivalent local functionality rather than inert visual copies.
- Preserve and migrate Gulpsuite's existing functional engines and panels.
- Show polished work-in-progress states for AI and the BApp Store until those features are designed separately.
- Do not implement licensing, license checks, license menus, or license dialogs.
- Do not copy proprietary source code, private services, credentials, or branding assets that are not appropriate for redistribution.
- Keep all long-running or network work off the UI thread.
- Preserve bounded histories and body-size limits.

## Chosen delivery strategy

Use measured vertical parity slices. Each slice includes reference capture, layout, interactions, persistence, functional behavior, automated tests, and a final comparison. The order begins with the shared shell and Dashboard, then proceeds tool by tool.

The first slice stops when the shell and Dashboard meet their acceptance criteria. Existing non-Dashboard tools remain accessible behind the new shell and retain their current behavior until their own parity slices.

## Architecture

### Reference specification

Introduce a versioned `ReferenceSpec` representation for Burp v2026.3.3 observations. It records:

- tool and menu ordering;
- visible labels and control states;
- measured dimensions and layout relationships;
- theme tokens and typography observations;
- dialogs, drawers, empty states, and interaction outcomes;
- provenance that distinguishes REA artifact evidence, runtime observation, and Gulpsuite design decisions.

The reference specification is test input and documentation, not a runtime dependency on Burp.

### Suite shell

`SuiteShell` owns shared desktop chrome and cross-tool behavior:

- top-level tool navigation;
- application and tool menus;
- bottom Event Log and All Issues drawers;
- status and memory indicators;
- global utility actions and settings entry points;
- detachable and reattachable detail views;
- theme application;
- persisted layout state.

Tool panels do not render or mutate global navigation directly.

### Tool panel contract

Each tool exposes a bounded interface describing:

- its display name and local views;
- commands and menu contributions;
- settings and serializable UI state;
- task and issue integrations;
- panel rendering against shared services.

Existing panels will migrate incrementally. Compatibility adapters are acceptable during the transition, but global shell state must have one owner.

### Task manager

`TaskManager` becomes the authoritative model for scans, live tasks, Intruder attacks, and future long-running operations. It owns:

- stable task identity;
- kind, name, configuration summary, and scope summary;
- queued, running, paused, completed, cancelled, and failed states;
- progress counters and timestamps;
- bounded per-task log entries;
- links to findings and relevant tool views;
- pause, resume, cancel, rename, detach, reattach, and focus commands.

Existing scanner, crawler, proxy, and Intruder events are adapted into this model instead of being duplicated as Dashboard-only state.

### Event and issue stores

A bounded event store receives typed application and task events. It powers the Event Log drawer, filters, detail display, and failure reporting.

A bounded issue store normalizes scanner and manually created findings. It powers the All Issues drawer, severity/confidence filters, issue detail, and navigation back to the originating task or request.

## UI design

### Top-level shell

Reproduce the observed v2026.3.3 top tool strip order, selection underline, typography, spacing, overflow behavior, and utility controls. The shell must remain usable at smaller window sizes without silently hiding the selected tool.

Menus contain only implemented or explicitly WIP actions. AI and BApp Store actions navigate to WIP views. Licensing actions are absent.

### Dashboard

The Dashboard uses the observed two-pane structure:

- a left task list with New scan, New live task, pause/resume controls, settings, help, filters, and search;
- a right task detail workspace with an empty state when no task is selected;
- task-specific summary, configuration, progress, logs, findings, and relevant subviews;
- explicit detached-view state with Bring to front and Re-attach actions.

Dashboard controls must operate on real `TaskManager` state. A visible control may be disabled with an explanation when its backing operation is unavailable, but it may not silently do nothing.

### Bottom drawers

Event Log and All Issues are independent bottom drawers. Each supports:

- open and close;
- resize with persisted height;
- filtering and search;
- list/detail split layout;
- empty states;
- selection persistence;
- keyboard and pointer interaction.

Opening a drawer must not destroy the active tool's state. Drawer state is part of the saved layout.

### Detachable views

Use egui viewports where supported for task-detail detachment. The model retains a single task-detail owner and records whether it is attached, detached, or awaiting restoration. Closing a detached viewport reattaches the detail rather than deleting the task.

On platforms without supported viewports, the same command presents a clearly labeled in-window detached mode so behavior remains testable.

### Theme and typography

Continue using the existing light and dark theme JSON files. Add tokens only where reference measurements reveal a missing semantic color or metric. System fonts remain preferred where they match observed platform rendering.

Reference screenshots use fixed window size, scale factor, theme, and deterministic fixture data. Screenshot tolerances must account for platform font rasterization without accepting structural drift.

## Data flow

Engine operations emit typed events through the existing application event path. Adapters translate them into task, event, and issue mutations. The UI reads immutable snapshots and sends typed commands back through explicit service methods.

The intended flow is:

1. A UI action creates or controls a task through `TaskManager`.
2. The task starts an existing engine operation or records a local state transition.
3. Engine events update task progress and append bounded event records.
4. Findings enter the issue store and update task severity counters.
5. The shell requests repaint and renders the resulting state.

Panels must not directly edit task internals, append arbitrary issue rows, or keep competing copies of shared state.

## Persistence and restoration

Project saves include:

- tasks and their terminal or restorable state;
- issues and event history within configured bounds;
- active tool and local view;
- filters, searches, selections, split ratios, and drawer heights;
- detached-view metadata;
- theme and relevant shell preferences.

Live sockets, workers, and in-flight network operations are never serialized as if still running. On load, such tasks become stopped or interrupted with an explanatory event and may be restarted explicitly when supported.

Persistence remains backward compatible with existing Gulpsuite projects where practical. New fields use serde defaults. If an incompatible transition becomes necessary, it requires a separate migration design before implementation.

## Error handling and resource limits

- Recoverable failures update the relevant task and Event Log instead of terminating the application.
- User-visible errors include the failed operation and actionable context without exposing secrets.
- Long-running work supports cancellation and never blocks egui's update loop.
- Task, event, issue, request, response, WebSocket, DNS, SMTP, and Organizer stores retain explicit ceilings.
- Rendering large tables uses filtered snapshots and virtualized or clipped rows where available.
- A failed detached viewport falls back to the attached workspace and logs the reason.

## Verification

Each parity slice must pass:

- unit tests for state transitions, filtering, bounds, and restoration;
- integration tests from engine events through tasks, events, issues, and Dashboard rendering state;
- interaction tests proving every visible control changes state, invokes a command, opens a documented WIP view, or is deliberately disabled;
- deterministic screenshot comparisons at fixed dimensions in light and dark themes;
- focused manual comparison with Burp v2026.3.3 for behavior not established by static evidence or accessibility output;
- the complete existing test suite.

The baseline before this design is 350 passing tests: 323 library tests and 27 integration tests across the remaining test binaries.

## First-slice acceptance criteria

The shell and Dashboard slice is complete when:

1. Top-level navigation, menus, utility controls, status area, and Dashboard structure match the approved v2026.3.3 reference states within documented platform limitations.
2. Dashboard task creation, selection, filtering, search, pause/resume, rename, cancellation where supported, details, and empty states are functional.
3. Existing scanner, crawler, proxy live tasks, and Intruder activity appear through the shared task model where those operations already exist.
4. Event Log and All Issues drawers are functional, resizable, filterable, and persisted.
5. Detach/reattach behavior works or uses the documented in-window fallback.
6. Project persistence restores layout and non-running task state safely.
7. AI and BApp Store entry points render explicit WIP states; licensing is absent.
8. No visible control silently does nothing.
9. New tests and existing tests pass.
10. Light and dark screenshot fixtures are reviewed against the canonical reference captures.

## Deferred work

The following are outside this first slice:

- full parity work inside Target, Proxy, Intruder, Repeater, Collaborator, Sequencer, Decoder, Comparer, Logger, Organizer, Extensions, and Discover;
- AI implementation;
- BApp Store implementation and remote catalog integration;
- any licensing system;
- PortSwigger-hosted service compatibility;
- unrelated engine rewrites.

Each remaining tool receives its own measured parity slice after the shell and Dashboard foundation is accepted.
