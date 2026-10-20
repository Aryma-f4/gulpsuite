#!/usr/bin/env python3
"""Inspect an installed package and exercise its actual Chromium with Rust loopback tests."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gulp_package', HERE / 'package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def inspect_install(root, platform):
    root = Path(root).resolve()
    if platform.startswith('macos-'):
        binary = root / 'Gulpsuite.app/Contents/MacOS/Gulpsuite'
        resources = root / 'Gulpsuite.app/Contents/Resources'
    else:
        binary = root / ('gulpsuite.exe' if platform == 'windows-x64' else 'gulpsuite')
        resources = root / 'resources'
    entry = json.loads((resources / 'chromium-manifest.json').read_text())
    if entry['platform'] != platform or not binary.is_file():
        raise ValueError('installed app/platform mismatch')
    package.chromium.validate_entry(entry)
    browser = resources / 'chromium' / entry['executable']
    if not browser.is_file():
        raise ValueError('installed browser missing')
    for notice in entry['notices']:
        if not (resources / 'chromium' / notice).is_file():
            raise ValueError('installed notice missing')
    package.chromium.validate_credits((resources / 'chromium/THIRD-PARTY-CREDITS.html').read_text())
    return binary, browser


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-root', type=Path, required=True)
    parser.add_argument('--platform', choices=package.chromium.PLATFORMS, required=True)
    parser.add_argument('--engine-tests', action='store_true')
    args = parser.parse_args()
    binary, browser = inspect_install(args.install_root, args.platform)
    print(f'Installed app: {binary}\nInstalled browser: {browser}', flush=True)
    if args.engine_tests:
        env = {**os.environ, 'GULPSUITE_TEST_CHROMIUM': str(browser)}
        subprocess.run(['cargo', 'test', '--release', '--manifest-path', str(HERE.parent / 'engine/Cargo.toml'),
            '--test', 'browser_e2e', 'bundled_chromium', '--', '--ignored', '--nocapture'],
            env=env, cwd=HERE.parent, check=True)


if __name__ == '__main__':
    main()
