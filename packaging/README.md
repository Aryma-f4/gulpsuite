# Gulpsuite Native Packaging & Setup Installers

Gulpsuite ships with a pinned, SHA-256-verified official Chromium build so clicking **Open browser** in the Proxy tab or top toolbar launches an isolated browser pre-routed through Gulpsuite's local proxy and session CA SPKI pin.

## Quick Auto-Install (macOS, Linux, Windows)

- **macOS / Linux**:
  ```sh
  ./install.sh --yes
  ```
- **Windows (Command Prompt / PowerShell)**:
  ```bat
  install.bat --yes
  ```

## Building Native Setup Installer Packages (`dist/`)

1. Stage the pinned Chromium archive from `packaging/chromium-lock.json` and render third-party credits:
   ```sh
   python3 packaging/chromium.py stage --platform macos-arm64 --destination .build/browser-stage
   python3 packaging/chromium.py credits --platform macos-arm64 --destination .build/browser-stage
   ```
2. Build the native setup installers:
   ```sh
   python3 packaging/package.py --platform macos-arm64 --binary engine/target/release/gulpsuite --stage .build/browser-stage --output dist --development
   ```

### Produced Setup Installers by Platform

- **macOS (`macos-arm64`, `macos-x64`)**:
  - `dist/Gulpsuite-VERSION-macos-arm64-setup.pkg` — Native macOS `Installer.app` GUI Setup Wizard (Welcome → Destination → Install → Summary).
  - `dist/Gulpsuite-VERSION-macos-arm64.dmg` — Drag-and-drop Disk Image with `Gulpsuite.app` and `/Applications` link.
- **Linux (`linux-x64`)**:
  - `dist/Gulpsuite-VERSION-linux-x64-setup.run` — Self-extracting Linux Setup Wizard (GUI via `zenity` or terminal wizard; supports `--prefix`, `--yes`, `--uninstall`).
  - `dist/gulpsuite_VERSION_amd64.deb` — Debian/Ubuntu package installing `/opt/gulpsuite`, `/usr/bin/gulpsuite`, and `/usr/share/applications/gulpsuite.desktop`.
- **Windows (`windows-x64`)**:
  - `dist/Gulpsuite-VERSION-windows-x64-setup.exe` — NSIS Modern UI 2 Setup Wizard (Welcome → Directory → Install → Finish & Launch, Start Menu + Desktop shortcuts, and `Uninstall.exe`).
