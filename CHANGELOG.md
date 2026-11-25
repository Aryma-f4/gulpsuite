# Changelog

## 0.2.3

### Proxy
- Updated the Match and replace layout with separate HTTP and WebSocket rule tables, fixed-width columns, compact rows, and aligned editing controls.
- Added editable draft rules and disabled HTTP examples. Drafts do not modify traffic; existing Advanced Bambda controls are unchanged.

## 0.2.2

### WebSockets
- Reworked the Proxy and Logger WebSockets history with sortable columns, filter and search controls, and Up/Down navigation in the visible sort order.
- Added a read-only Message viewer with Pretty, Raw, and Hex views where captured data is available, plus Notes and an upgrade-handshake Inspector.
- Added a right-click menu for copying, formatting, and exporting text or sending captures to Repeater, Comparer, and Decoder.
- Repeater separates the original captured message from the upgrade request and shows the connection history beside it. Live WebSocket replay is not supported by this capture view.
- Kept closed connections in the bounded history and added connection and message metadata: TLS, listener port when known, and receive time in UTC.

### Merged pull requests
- **Merged pull request of @unlikeneptunev** — [#2: fix: set explicit Wayland application ID](https://github.com/Aryma-f4/gulpsuite/pull/2). The `gulpsuite` app ID matches `gulpsuite.desktop` so Wayland can associate the window with the correct launcher icon.
