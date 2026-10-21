# Contributing to Gulpsuite

Thank you for your interest in contributing to **Gulpsuite**! We welcome bug reports, feature requests, scanner detection rules, and performance improvements.

## Development Workflow

1. **Prerequisites**:
   - Rust `1.78+` (`rustup` / `cargo`)
   - Python `3.10+` (for cross-platform installer packaging)

2. **Build & Run the Full Test Suite**:
   ```bash
   ./build.sh
   ```
   This compiles optimized release binaries (`./gulpsuite` and `./gulpsuite-setup`) and runs 460+ unit, integration, and headless `egui_kittest` UI tests.

3. **Pull Request Guidelines**:
   - Keep changes focused, fast, and memory-bounded.
   - Ensure `./build.sh` passes with zero test failures.
   - Follow our [Code of Conduct](CODE_OF_CONDUCT.md).
