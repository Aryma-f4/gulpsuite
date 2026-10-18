#!/bin/sh
# Assembles Gulpsuite.app. The executable is the app itself: no runtime, no helper binaries.
set -e
cd "$(dirname "$0")"

APP="Gulpsuite.app"
BUNDLE_ID="net.gulpsuite.app"
VERSION="$(grep -m1 '^version' engine/Cargo.toml | cut -d'"' -f2)"

if [ ! -x engine/target/release/gulpsuite ]; then
  echo "run ./build.sh first" >&2
  exit 1
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp engine/target/release/gulpsuite "$APP/Contents/MacOS/Gulpsuite"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Gulpsuite</string>
  <key>CFBundleDisplayName</key><string>Gulpsuite</string>
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
  codesign --force --sign - "$APP" >/dev/null 2>&1 \
    && echo "ad-hoc signed" \
    || echo "warning: ad-hoc signing failed" >&2
fi

echo "built $APP"
