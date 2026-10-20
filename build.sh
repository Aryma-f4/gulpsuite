#!/bin/sh
# Builds the Gulpsuite app. Everything is Rust: the GUI and the proxy are one process.
set -e
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found; install a Rust toolchain" >&2
  exit 1
fi

# Two jobs keeps peak memory low; an unbounded fan-out is what made this machine swap before.
JOBS="${GULPSUITE_JOBS:-2}"
export CARGO_BUILD_JOBS="$JOBS"

cd engine
cargo build --release -j "$JOBS"

# Test output is filtered for readability but the exit status is kept, so a failure still fails.
if cargo test --release -j "$JOBS" > /tmp/gulpsuite-tests.log 2>&1; then
    grep -E "^test result" /tmp/gulpsuite-tests.log | sed 's/^/  /'
else
    grep -E "^test result|^failures:|^---- " /tmp/gulpsuite-tests.log | head -40
    echo "error: tests failed; see /tmp/gulpsuite-tests.log" >&2
    exit 1
fi
cd ..

cp engine/target/release/gulpsuite ./gulpsuite
echo "built: ./gulpsuite"
if [ -f engine/target/release/gulpsuite-setup ]; then
  cp engine/target/release/gulpsuite-setup ./gulpsuite-setup
  echo "built: ./gulpsuite-setup"
fi
