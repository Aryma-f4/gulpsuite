#!/usr/bin/env python3
"""Cross-platform Setup Installer for Gulpsuite + Integrated Chromium (macOS, Linux, Windows)."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform as host_platform
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chromium = load_module('gulp_chromium', ROOT / 'packaging/chromium.py')
package = load_module('gulp_package', ROOT / 'packaging/package.py')


def detect_platform():
    sys_name = host_platform.system().lower()
    machine = host_platform.machine().lower()
    if sys_name == 'darwin':
        return 'macos-arm64' if machine in ('arm64', 'aarch64') else 'macos-x64'
    if sys_name == 'linux' and machine in ('x86_64', 'amd64'):
        return 'linux-x64'
    if sys_name == 'windows' and machine in ('amd64', 'x86_64'):
        return 'windows-x64'
    raise ValueError(f'Unsupported host platform: {sys_name}/{machine}')


def default_prefix(platform_id):
    if platform_id.startswith('macos-'):
        return Path.home() / 'Applications'
    if platform_id == 'linux-x64':
        return Path('/opt/gulpsuite') if os.geteuid() == 0 else (Path.home() / '.local/opt/gulpsuite')
    local_app_data = os.environ.get('LOCALAPPDATA')
    if not local_app_data:
        raise ValueError('LOCALAPPDATA is not set on Windows')
    return Path(local_app_data) / 'Programs/Gulpsuite'


def app_version():
    cargo = (ROOT / 'engine/Cargo.toml').read_text()
    return re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)[1]


def ensure_chromium_staged(platform_id, stage_dir, lock_path, cache_dir, log=print):
    manifest = stage_dir / 'resources/chromium-manifest.json'
    if not manifest.is_file():
        log(f'[1/4] Downloading & staging pinned Chromium ({platform_id})...')
        entry = json.loads(lock_path.read_text())['platforms'][platform_id]
        chromium.validate_entry(entry)
        cache_dir.mkdir(parents=True, exist_ok=True)
        archive = cache_dir / f"{platform_id}-{entry['revision']}.zip"
        if not archive.is_file():
            chromium.download(entry['url'], archive)
        chromium.stage_archive(archive, entry, stage_dir)
    else:
        log(f'[1/4] Reusing verified staged Chromium at {stage_dir}')
    credits_file = stage_dir / 'resources/chromium/THIRD-PARTY-CREDITS.html'
    needs_render = not credits_file.is_file()
    if not needs_render:
        try:
            chromium.validate_credits(credits_file.read_text())
        except ValueError:
            needs_render = True
    if needs_render:
        log('[2/4] Rendering & verifying Chromium third-party credits...')
        chromium.render_credits(stage_dir, platform_id)
    else:
        log('[2/4] Chromium third-party credits verified.')


def ensure_binary_built(platform_id, log=print):
    exe_name = 'gulpsuite.exe' if platform_id == 'windows-x64' else 'gulpsuite'
    binary = ROOT / 'engine/target/release' / exe_name
    if not binary.is_file():
        log('[3/4] Building Gulpsuite release binary...')
        subprocess.run([
            'cargo', 'build', '--release', '--manifest-path',
            str(ROOT / 'engine/Cargo.toml'), '--bin', 'gulpsuite',
        ], check=True)
    else:
        log(f'[3/4] Using release binary at {binary}')
    return binary


def install_to_prefix(platform_id, binary, stage_dir, prefix, version, log=print):
    prefix = Path(prefix).expanduser().resolve()
    log(f'[4/4] Installing Gulpsuite {version} + Integrated Chromium to {prefix}...')
    if platform_id.startswith('macos-'):
        app_dest = prefix if prefix.name.endswith('.app') else (prefix / 'Gulpsuite.app')
        if app_dest.exists():
            backup = app_dest.with_name(f'{app_dest.name}.backup.{os.getpid()}')
            shutil.move(str(app_dest), str(backup))
            log(f'      Preserved existing bundle at {backup}')
        parent_out = app_dest.parent / f'.gulp-install-{os.getpid()}'
        try:
            package.assemble_layout(platform_id, binary, stage_dir, parent_out, version)
            built_app = parent_out / 'Gulpsuite.app'
            if shutil.which('codesign'):
                subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(built_app)], check=True)
            app_dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(built_app), str(app_dest))
        finally:
            if parent_out.exists():
                shutil.rmtree(parent_out)
        log(f'Installed: {app_dest}')
        return app_dest
    elif platform_id == 'linux-x64':
        if prefix.exists():
            raise ValueError(f'Destination already exists: {prefix}')
        scratch = prefix.parent / f'.gulp-install-{os.getpid()}'
        try:
            package.assemble_layout(platform_id, binary, stage_dir, scratch, version)
            prefix.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(scratch / 'opt/gulpsuite'), str(prefix))
            bin_dir = Path('/usr/local/bin') if os.geteuid() == 0 else (Path.home() / '.local/bin')
            desktop_dir = Path('/usr/share/applications') if os.geteuid() == 0 else (Path.home() / '.local/share/applications')
            bin_dir.mkdir(parents=True, exist_ok=True)
            desktop_dir.mkdir(parents=True, exist_ok=True)
            link = bin_dir / 'gulpsuite'
            if link.is_symlink() or link.exists():
                link.unlink()
            link.symlink_to(prefix / 'gulpsuite')
            desktop_text = (ROOT / 'packaging/linux/gulpsuite.desktop').read_text().replace(
                '/opt/gulpsuite/gulpsuite', str(prefix / 'gulpsuite')
            )
            (desktop_dir / 'gulpsuite.desktop').write_text(desktop_text)
        finally:
            if scratch.exists():
                shutil.rmtree(scratch)
        log(f'Installed: {prefix} (launcher: {bin_dir / "gulpsuite"})')
        return prefix
    else:
        package.assemble_layout(platform_id, binary, stage_dir, prefix, version)
        log(f'Installed: {prefix}')
        return prefix


def uninstall_from_prefix(platform_id, prefix, log=print):
    prefix = Path(prefix).expanduser().resolve()
    if platform_id.startswith('macos-'):
        app_dest = prefix if prefix.name.endswith('.app') else (prefix / 'Gulpsuite.app')
        if app_dest.is_dir():
            shutil.rmtree(app_dest)
            log(f'Removed {app_dest} (user profiles preserved).')
    else:
        for rel in ['resources/chromium', 'resources/chromium-manifest.json', 'gulpsuite', 'gulpsuite.exe']:
            target = prefix / rel
            if target.is_dir():
                shutil.rmtree(target)
            elif target.is_file():
                target.unlink()
        if (prefix / 'resources').is_dir():
            try:
                (prefix / 'resources').rmdir()
            except OSError:
                pass
        if prefix.is_dir():
            try:
                prefix.rmdir()
            except OSError:
                pass
        log(f'Removed Gulpsuite from {prefix} (user profiles preserved).')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=chromium.PLATFORMS, default=None)
    parser.add_argument('--prefix', type=Path, default=None, help='Installation directory')
    parser.add_argument('--stage', type=Path, default=ROOT / '.build/browser-stage')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist', help='Directory for setup installer artifacts')
    parser.add_argument('--build-installer', action='store_true', help='Also emit native OS setup installer into --output')
    parser.add_argument('--uninstall', action='store_true', help='Remove installed application files while preserving profiles')
    parser.add_argument('--yes', '-y', action='store_true', help='Non-interactive setup')
    args = parser.parse_args()

    platform_id = args.platform or detect_platform()
    prefix = args.prefix or default_prefix(platform_id)
    version = app_version()

    if args.uninstall:
        uninstall_from_prefix(platform_id, prefix)
        return

    print(f'=== Gulpsuite {version} Setup Wizard ({platform_id}) ===')
    print(f'Target install location: {prefix}')
    if not args.yes and sys.stdin.isatty():
        reply = input('Proceed with installation of Gulpsuite + Integrated Chromium? [Y/n] ').strip().lower()
        if reply.startswith('n'):
            print('Installation cancelled.')
            sys.exit(1)

    ensure_chromium_staged(platform_id, args.stage, ROOT / 'packaging/chromium-lock.json', ROOT / '.build/chromium-cache')
    binary = ensure_binary_built(platform_id)
    installed = install_to_prefix(platform_id, binary, args.stage, prefix, version)

    if args.build_installer:
        print(f'Building native setup installer package in {args.output}...')
        package.create_installer(platform_id, binary, args.stage, args.output, version, development=True)

    print(f'=== Setup Complete: {installed} ===')


if __name__ == '__main__':
    main()
