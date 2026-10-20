#!/bin/sh
# Assembles Gulpsuite.app. The executable is the app itself: no runtime, no helper binaries.
set -e
cd "$(dirname "$0")"

APP="${1:-Gulpsuite.app}"
BUNDLE_ID="${GULPSUITE_BUNDLE_ID:-net.gulpsuite.app}"
BUNDLE_NAME="${GULPSUITE_BUNDLE_NAME:-Gulpsuite}"
VERSION="$(grep -m1 '^version' engine/Cargo.toml | cut -d'"' -f2)"

if [ ! -x engine/target/release/gulpsuite ]; then
  echo "run ./build.sh first" >&2
  exit 1
fi

case "$APP" in
  *.app) ;;
  *) echo "error: output must be an .app bundle" >&2; exit 1 ;;
esac
if [ -e "$APP" ]; then
  BACKUP="$APP.backup.$(date +%Y%m%d-%H%M%S).$$"
  mv "$APP" "$BACKUP"
  echo "previous bundle preserved at $BACKUP"
fi
mkdir -p "$APP/Contents/MacOS"
cp engine/target/release/gulpsuite "$APP/Contents/MacOS/Gulpsuite"

# Local development may include a staged browser even when its upstream notices
# fail the distribution gate. Real installers use packaging/package.py instead.
if [ -z "${GULPSUITE_CHROMIUM_STAGE:-}" ] && [ -f ".build/browser-stage/resources/chromium-manifest.json" ]; then
  GULPSUITE_CHROMIUM_STAGE=".build/browser-stage"
fi
if [ -n "${GULPSUITE_CHROMIUM_STAGE:-}" ]; then
  if [ ! -f "$GULPSUITE_CHROMIUM_STAGE/resources/chromium-manifest.json" ]; then
    echo "error: Chromium stage manifest is missing" >&2
    exit 1
  fi
  mkdir -p "$APP/Contents/Resources"
  cp -R "$GULPSUITE_CHROMIUM_STAGE/resources/." "$APP/Contents/Resources/"
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$BUNDLE_NAME</string>
  <key>CFBundleDisplayName</key><string>$BUNDLE_NAME</string>
  <key>CFBundleExecutable</key><string>Gulpsuite</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST

printf 'APPL????' > "$APP/Contents/PkgInfo"

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP" >/dev/null 2>&1 \
    && echo "ad-hoc signed" \
    || echo "warning: ad-hoc signing failed" >&2
fi

echo "built $APP"
