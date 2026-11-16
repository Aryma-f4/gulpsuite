# macOS layout correction — issue #1

Reference: [Mac M4 macOS UI Issues](https://github.com/Aryma-f4/gulpsuite/issues/1).

The report's screenshots show Logger headers detached from their data columns,
Scope action labels wrapping, and nested workspaces with poorly bounded content.
Existing local corrections to Logger geometry, Scope button sizes, and native
window chrome were preserved and tested alongside this change.

Two remaining layout defects were reproduced and corrected:

- The shared `vertical_split` used `allocate_ui_with_layout`, which expands to fit
  child content. A single unbroken line pushed the sibling pane more than 16,000
  logical pixels outside a 600-pixel window. The helper now reserves one fixed
  split rectangle and gives each pane its own bounded, clipped child UI. Divider
  dragging and double-click reset behavior are retained.
- Scope table frames inherited their enclosing horizontal layout. The header and
  body consequently appeared side by side, placing rule checkboxes and selected
  rows outside the window. Include and Exclude tables now explicitly use a
  vertical layout. Existing Enable/Disable and selected-row Remove tests pass.

## Verification

- Full `cargo test -- --skip generate_documentation_screenshots`: 490 passed,
  zero failures. Documentation screenshot export is excluded because it rewrites
  existing screenshots unrelated to this issue.
- Six targeted `macos_layout` regressions pass: pane isolation, divider dragging,
  editor/status-bar clipping, Retina Scope button geometry and visible rules,
  Logger header/data alignment, and Intruder sidebar visibility with long payloads.
- Layout tests cover 1× and 2× pixels per point; rendered 2× Logger, Scope and
  Intruder screenshots were visually inspected.
- `cargo run --example native_layout_smoke` passes on native arm64 macOS with
  actual `pixels_per_point = 2`. It switches between Logger, Scope, Intruder,
  Target Site map and populated Target Issues, changes window sizes and themes,
  and closes cleanly after at least 72 frames. It sends no network requests.
- Both release executables (`gulpsuite` and `gulpsuite-setup`) build with `--locked`.
- All 13 packaging tests pass.
- Baseline and rollback each reproduce the same three layout failures; the changed
  release passes all six regressions. Rollback restores original source hashes.
- v0.1.1 updates the three dashboard snapshots only for the displayed version;
  the setup wizard test derives its expected version from Cargo metadata.
- The release is isolated from unrelated uncommitted browser/proxy changes.

The available native host is Mac14,7 (Apple Silicon), not an M4. The reporter's
exact hardware was not directly tested. These results establish native macOS
and Retina layout regression coverage, not pixel-identical Burp parity or an
exhaustive check of every UI workflow.
