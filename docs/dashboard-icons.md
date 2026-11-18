# Local dashboard artwork

Gulpsuite uses its built-in illustrations by default. To use optional artwork you have permission to use, put PNG files in the application's per-user `dashboard-icons` directory, then restart Gulpsuite.

- macOS: `~/Library/Application Support/Gulpsuite/dashboard-icons`
- Windows: `%LOCALAPPDATA%\Gulpsuite\dashboard-icons`
- Linux: `${XDG_DATA_HOME:-$HOME/.local/share}/gulpsuite/dashboard-icons`

Use `no-search-results-light.png`, `no-search-results-dark.png`, `logger-light.png`, or `logger-dark.png`. Files must be RGB or RGBA PNGs no larger than 512 × 512 pixels or 512 KiB. Missing or invalid files fall back to Gulpsuite's own artwork. Third-party assets are not packaged with the release.

Dashboard → Issues and Event log show only records linked to the selected task. Search and filters change the visible list without changing scanning or capture behavior.
