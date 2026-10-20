#!/bin/sh
# Gulpsuite + Integrated Chromium Setup Launcher (macOS & Linux)
set -e
cd "$(dirname "$0")"
exec python3 ./install.py "$@"
