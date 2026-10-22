#!/usr/bin/env python3
"""Create offline native installers from an explicit pinned Chromium stage."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import platform as host_platform
import re
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('gulp_chromium', HERE / 'chromium.py')
chromium = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chromium)


def validate_stage(stage, platform):
    entry = json.loads((stage / 'resources/chromium-manifest.json').read_text())
    if entry['platform'] != platform:
        raise ValueError('browser platform does not match installer platform')
    chromium.validate_entry(entry)
    root = stage / 'resources/chromium'
    for name in [entry['executable'], *entry['notices']]:
        if not (root / name).is_file():
            raise ValueError(f'browser resource missing: {name}')
    credits = root / 'THIRD-PARTY-CREDITS.html'
    if not credits.is_file():
        raise ValueError('rendered third-party credits are missing')
    chromium.validate_credits(credits.read_text())
    return entry


def assemble_layout(platform, binary, stage, output, version):
    output, binary, stage = Path(output), Path(binary), Path(stage)
    if output.exists():
        raise ValueError('output already exists')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('invalid application version')
    if not binary.is_file():
        raise ValueError('application binary missing')
    validate_stage(stage, platform)
    if platform.startswith('macos-'):
        app = output / 'Gulpsuite.app/Contents'
        app.joinpath('MacOS').mkdir(parents=True)
        shutil.copy2(binary, app / 'MacOS/Gulpsuite')
        (app / 'MacOS/Gulpsuite').chmod(0o755)
        shutil.copytree(stage / 'resources', app / 'Resources', symlinks=True)
        icns_src = HERE / 'macos/Gulpsuite.icns'
        if icns_src.is_file():
            shutil.copy2(icns_src, app / 'Resources/Gulpsuite.icns')
        with (app / 'Info.plist').open('wb') as stream:
            plistlib.dump(dict(CFBundleName='Gulpsuite', CFBundleDisplayName='Gulpsuite',
                               CFBundleExecutable='Gulpsuite', CFBundleIconFile='Gulpsuite',
                               CFBundleIdentifier='net.gulpsuite.app',
                               CFBundlePackageType='APPL', CFBundleShortVersionString=version,
                               CFBundleVersion=version, NSHumanReadableCopyright='Copyright (c) Aryma-f4',
                               NSHighResolutionCapable=True,
                               LSMinimumSystemVersion='11.0'), stream)
    elif platform == 'windows-x64':
        output.mkdir(parents=True)
        shutil.copy2(binary, output / 'gulpsuite.exe')
        ico_src = HERE / 'windows/gulpsuite.ico'
        if ico_src.is_file():
            shutil.copy2(ico_src, output / 'gulpsuite.ico')
        shutil.copytree(stage / 'resources', output / 'resources', symlinks=True)
    elif platform == 'linux-x64':
        app = output / 'opt/gulpsuite'
        app.mkdir(parents=True)
        shutil.copy2(binary, app / 'gulpsuite')
        (app / 'gulpsuite').chmod(0o755)
        shutil.copytree(stage / 'resources', app / 'resources', symlinks=True)
        png_src = HERE.parent / 'assets/logo.png'
        if png_src.is_file():
            pixmaps = output / 'usr/share/pixmaps'
            pixmaps.mkdir(parents=True, exist_ok=True)
            shutil.copy2(png_src, pixmaps / 'gulpsuite.png')
            shutil.copy2(png_src, app / 'resources/gulpsuite.png')
        desktop = output / 'usr/share/applications'
        desktop.mkdir(parents=True)
        shutil.copy2(HERE / 'linux/gulpsuite.desktop', desktop)
        (output / 'usr/bin').mkdir(parents=True)
        (output / 'usr/bin/gulpsuite').symlink_to('/opt/gulpsuite/gulpsuite')
        control = output / 'DEBIAN'
        control.mkdir()
        (control / 'control').write_text(
            f'Package: gulpsuite\nVersion: {version}\nArchitecture: amd64\n'
            'Maintainer: Aryma-f4 <https://github.com/Aryma-f4/gulpsuite>\nSection: net\nPriority: optional\n'
            'Depends: libasound2t64, libatk-bridge2.0-0t64, libatk1.0-0t64, libatspi2.0-0t64, '
            'libc6 (>= 2.39), libcairo2, libcups2t64, libdbus-1-3, libdrm2, libexpat1, '
            'libgbm1, libglib2.0-0t64, libgtk-3-0t64, libnspr4, libnss3, libpango-1.0-0, '
            'libudev1, libvulkan1, libx11-6, libxcb1, libxcomposite1, libxdamage1, '
            'libxext6, libxfixes3, libxkbcommon0, libxrandr2, xdg-utils\n'
            'Description: Native HTTP testing suite with integrated Chromium\n')
    else:
        raise ValueError('unsupported installer platform')
    return output


def build_linux_setup_run(layout, artifact, version):
    layout = Path(layout)
    artifact = Path(artifact)
    if artifact.exists():
        raise ValueError(f'installer already exists: {artifact}')
    header = f"""#!/bin/sh
# Gulpsuite {version} Self-Extracting Setup Installer (Linux x64)
set -e
PREFIX="/opt/gulpsuite"
BIN_DIR="/usr/local/bin"
DESKTOP_DIR="/usr/share/applications"
INTERACTIVE=1
UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --prefix=*) PREFIX="${{1#*=}}"; shift ;;
    --yes|-y|--silent|-S) INTERACTIVE=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "Usage: $0 [--prefix DIR] [--yes] [--uninstall]" >&2; exit 1 ;;
  esac
done

if [ "$(id -u)" != "0" ]; then
  [ "$PREFIX" = "/opt/gulpsuite" ] && PREFIX="$HOME/.local/opt/gulpsuite"
  BIN_DIR="$HOME/.local/bin"
  DESKTOP_DIR="$HOME/.local/share/applications"
fi

if [ "$UNINSTALL" = "1" ]; then
  rm -rf "$PREFIX/resources/chromium" "$PREFIX/resources/chromium-manifest.json"
  rmdir "$PREFIX/resources" 2>/dev/null || true
  rm -f "$PREFIX/gulpsuite" "$BIN_DIR/gulpsuite" "$DESKTOP_DIR/gulpsuite.desktop"
  rmdir "$PREFIX" 2>/dev/null || true
  echo "Uninstalled Gulpsuite from $PREFIX (user profiles preserved)."
  exit 0
fi

if [ "$INTERACTIVE" = "1" ]; then
  if command -v zenity >/dev/null 2>&1 && [ -n "${{DISPLAY:-}}${{WAYLAND_DISPLAY:-}}" ]; then
    zenity --question --title="Gulpsuite {version} Setup" \\
      --text="Install Gulpsuite {version} and integrated Chromium to:\\n$PREFIX ?" || exit 1
  elif [ -t 0 ]; then
    printf "Gulpsuite %s Setup Wizard\\nInstall Gulpsuite + integrated Chromium to %s? [Y/n] " "{version}" "$PREFIX"
    read ans
    case "$ans" in [nN]*) echo "Cancelled."; exit 1 ;; esac
  fi
fi

mkdir -p "$PREFIX" "$BIN_DIR" "$DESKTOP_DIR"
ARCHIVE_LINE=$(awk '/^__GULPSUITE_ARCHIVE_BELOW__$/ {{print NR + 1; exit 0;}}' "$0")
tail -n +"$ARCHIVE_LINE" "$0" | tar -xzf - -C "$PREFIX"
chmod 0755 "$PREFIX/gulpsuite"
ln -sf "$PREFIX/gulpsuite" "$BIN_DIR/gulpsuite"
sed "s|/opt/gulpsuite/gulpsuite|$PREFIX/gulpsuite|g" <<'DESKTOP' > "$DESKTOP_DIR/gulpsuite.desktop"
[Desktop Entry]
Type=Application
Name=Gulpsuite
Comment=HTTP testing suite with integrated Chromium
Exec=/opt/gulpsuite/gulpsuite
Terminal=false
Categories=Development;Network;
StartupNotify=true
DESKTOP
echo "Installed Gulpsuite {version} + integrated Chromium to $PREFIX"
echo "Run: $BIN_DIR/gulpsuite"
exit 0
__GULPSUITE_ARCHIVE_BELOW__
""".encode('utf-8')
    with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False, dir=artifact.parent) as tmp_tar:
        tar_path = Path(tmp_tar.name)
    try:
        with tarfile.open(tar_path, 'w:gz') as archive:
            app_dir = layout / 'opt/gulpsuite'
            for item in sorted(app_dir.iterdir()):
                archive.add(item, arcname=item.name)
        with artifact.open('xb') as out:
            out.write(header)
            out.write(tar_path.read_bytes())
        artifact.chmod(0o755)
    finally:
        tar_path.unlink(missing_ok=True)
    return artifact


def build_linux_appimage(layout, artifact, version):
    """Builds `Gulpsuite-<version>-x86_64.AppImage` with a FUSE-free portable runtime
    that works out of the box on CachyOS, Arch Linux, Ubuntu, Fedora, and Debian without
    requiring legacy `libfuse.so.2`. Supports `--appimage-extract`, `--appimage-extract-and-run`,
    `--appimage-version`, `--appimage-help`, and `--install`.
    """
    layout = Path(layout)
    artifact = Path(artifact)
    if artifact.exists():
        raise ValueError(f'AppImage already exists: {artifact}')

    with tempfile.TemporaryDirectory(prefix='gulpsuite-appdir-', dir=artifact.parent) as tmp_dir:
        appdir = Path(tmp_dir) / 'Gulpsuite.AppDir'
        (appdir / 'usr/opt').mkdir(parents=True)
        (appdir / 'usr/bin').mkdir(parents=True)
        shutil.copytree(layout / 'opt/gulpsuite', appdir / 'usr/opt/gulpsuite', symlinks=True)
        (appdir / 'usr/bin/gulpsuite').symlink_to('../opt/gulpsuite/gulpsuite')

        shutil.copy2(HERE / 'linux/gulpsuite.desktop', appdir / 'gulpsuite.desktop')
        png_src = HERE.parent / 'assets/logo.png'
        if png_src.is_file():
            shutil.copy2(png_src, appdir / 'gulpsuite.png')
            shutil.copy2(png_src, appdir / '.DirIcon')

        apprun = appdir / 'AppRun'
        apprun.write_text(
            '#!/bin/sh\n'
            'HERE="$(dirname "$(readlink -f "$0")")"\n'
            'export APPDIR="$HERE"\n'
            'exec "$HERE/usr/opt/gulpsuite/gulpsuite" "$@"\n'
        )
        apprun.chmod(0o755)

        header = f"""#!/bin/sh
# Gulpsuite {version} Portable AppImage (FUSE-free — CachyOS / Arch / Linux x86_64)
# "Gulp it before burp" — Publisher: Aryma-f4
set -e

SELF="$(readlink -f "$0")"
CACHE_ROOT="${{XDG_CACHE_HOME:-$HOME/.cache}}/gulpsuite"
APPDIR="$CACHE_ROOT/AppDir-{version}"

extract_appdir() {{
  DEST="$1"
  rm -rf "$DEST"
  mkdir -p "$DEST"
  ARCHIVE_LINE=$(awk '/^__GULPSUITE_APPIMAGE_BELOW__$/ {{print NR + 1; exit 0;}}' "$SELF")
  tail -n +"$ARCHIVE_LINE" "$SELF" | tar -xzf - -C "$DEST"
  chmod 0755 "$DEST/AppRun" "$DEST/usr/opt/gulpsuite/gulpsuite"
}}

case "${{1:-}}" in
  --appimage-version)
    echo "Gulpsuite AppImage {version} (FUSE-free portable runtime by Aryma-f4)"
    exit 0
    ;;
  --appimage-help)
    echo "Gulpsuite {version} AppImage options:"
    echo "  --appimage-extract          Extract AppDir into ./squashfs-root"
    echo "  --appimage-extract-and-run  Extract and run Gulpsuite"
    echo "  --appimage-version          Print AppImage version"
    echo "  --install                   Integrate Gulpsuite into desktop menu & ~/.local/bin"
    exit 0
    ;;
  --appimage-extract)
    extract_appdir "./squashfs-root"
    echo "Extracted to ./squashfs-root"
    exit 0
    ;;
  --appimage-extract-and-run)
    shift
    extract_appdir "$APPDIR"
    exec "$APPDIR/AppRun" "$@"
    ;;
  --install)
    extract_appdir "$APPDIR"
    mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/512x512/apps"
    cp -f "$SELF" "$HOME/.local/bin/gulpsuite"
    chmod 0755 "$HOME/.local/bin/gulpsuite"
    if [ -f "$APPDIR/gulpsuite.png" ]; then
      cp -f "$APPDIR/gulpsuite.png" "$HOME/.local/share/icons/hicolor/512x512/apps/gulpsuite.png"
    fi
    cat > "$HOME/.local/share/applications/gulpsuite.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Gulpsuite
Comment=Gulp it before burp — Native Rust web security testing suite
Exec=$HOME/.local/bin/gulpsuite
Icon=gulpsuite
Terminal=false
Categories=Development;Network;Security;
StartupNotify=true
DESKTOP
    echo "Installed Gulpsuite {version} to ~/.local/bin/gulpsuite and desktop menu."
    exit 0
    ;;
esac

if [ ! -x "$APPDIR/AppRun" ]; then
  extract_appdir "$APPDIR"
fi
exec "$APPDIR/AppRun" "$@"
__GULPSUITE_APPIMAGE_BELOW__
""".encode('utf-8')

        tar_path = Path(tmp_dir) / 'appdir.tar.gz'
        with tarfile.open(tar_path, 'w:gz') as archive:
            for item in sorted(appdir.iterdir()):
                archive.add(item, arcname=item.name)
        with artifact.open('xb') as out:
            out.write(header)
            out.write(tar_path.read_bytes())
        artifact.chmod(0o755)
    return artifact


def build_arch_pkg(layout, artifact, version):
    """Builds a native CachyOS / Arch Linux pacman package (`gulpsuite-<version>-1-x86_64.pkg.tar.gz`)."""
    layout = Path(layout)
    artifact = Path(artifact)
    if artifact.exists():
        raise ValueError(f'Arch package already exists: {artifact}')

    with tempfile.TemporaryDirectory(prefix='gulpsuite-archpkg-', dir=artifact.parent) as tmp_dir:
        pkg_root = Path(tmp_dir) / 'pkg'
        pkg_root.mkdir()
        shutil.copytree(layout / 'opt', pkg_root / 'opt', symlinks=True)
        shutil.copytree(layout / 'usr', pkg_root / 'usr', symlinks=True)
        size_bytes = sum(f.stat().st_size for f in pkg_root.rglob('*') if f.is_file() and not f.is_symlink())
        pkginfo = (
            f'# Generated by Gulpsuite packaging (Aryma-f4)\n'
            f'pkgname = gulpsuite\n'
            f'pkgbase = gulpsuite\n'
            f'pkgver = {version}-1\n'
            f'pkgdesc = Gulp it before burp - Native Rust web security testing, DAST scanner & proxy suite\n'
            f'url = https://github.com/Aryma-f4/gulpsuite\n'
            f'builddate = 1776816000\n'
            f'packager = Aryma-f4 <https://github.com/Aryma-f4/gulpsuite>\n'
            f'size = {size_bytes}\n'
            f'arch = x86_64\n'
            f'license = MIT\n'
            f'depend = gtk3\n'
            f'depend = nss\n'
            f'depend = alsa-lib\n'
            f'depend = libxss\n'
        )
        (pkg_root / '.PKGINFO').write_text(pkginfo)
        with tarfile.open(artifact, 'w:gz') as archive:
            archive.add(pkg_root / '.PKGINFO', arcname='.PKGINFO')
            for sub in ['opt', 'usr']:
                archive.add(pkg_root / sub, arcname=sub)
    return artifact


def build_macos_pkg(layout, artifact, version, scratch):
    layout = Path(layout)
    artifact = Path(artifact)
    scratch = Path(scratch)
    if artifact.exists():
        raise ValueError(f'installer already exists: {artifact}')
    pkg_root = scratch / 'pkg-root/Applications'
    pkg_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(layout / 'Gulpsuite.app', pkg_root / 'Gulpsuite.app', symlinks=True)
    res_dir = scratch / 'pkg-resources'
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / 'welcome.html').write_text(
        '<!doctype html><html><body style="font-family:-apple-system,sans-serif">'
        f'<h2>Welcome to Gulpsuite {version} Setup</h2>'
        '<p>This installer installs <b>Gulpsuite.app</b> together with its preconfigured '
        '<b>integrated Chromium browser</b> and session CA support.</p>'
        '<p>No global proxy settings or personal browser profiles are modified.</p>'
        '</body></html>\n'
    )
    (res_dir / 'conclusion.html').write_text(
        '<!doctype html><html><body style="font-family:-apple-system,sans-serif">'
        f'<h2>Gulpsuite {version} Installed Successfully</h2>'
        '<p>Open <b>Gulpsuite</b> from Applications and click <b>Open browser</b> in the '
        'Proxy tab or top toolbar to launch the integrated Chromium browser.</p>'
        '</body></html>\n'
    )
    component_pkg = scratch / 'gulpsuite-component.pkg'
    subprocess.run([
        'pkgbuild', '--root', str(scratch / 'pkg-root'),
        '--identifier', 'net.gulpsuite.app.pkg',
        '--version', version,
        '--install-location', '/',
        str(component_pkg),
    ], check=True)
    dist_xml = scratch / 'Distribution.xml'
    dist_xml.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<installer-gui-script minSpecVersion="2">\n'
        f'  <title>Gulpsuite {version}</title>\n'
        '  <welcome file="welcome.html" mime-type="text/html"/>\n'
        '  <conclusion file="conclusion.html" mime-type="text/html"/>\n'
        '  <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>\n'
        '  <domains enable_anyone="true" enable_currentUserHome="true" enable_localSystem="true"/>\n'
        '  <choices-outline><line choice="default"><line choice="net.gulpsuite.app.pkg"/></line></choices-outline>\n'
        '  <choice id="default"/>\n'
        '  <choice id="net.gulpsuite.app.pkg" visible="false">\n'
        '    <pkg-ref id="net.gulpsuite.app.pkg"/>\n'
        '  </choice>\n'
        '  <pkg-ref id="net.gulpsuite.app.pkg" version="' + version + '" onConclusion="none">gulpsuite-component.pkg</pkg-ref>\n'
        '</installer-gui-script>\n'
    )
    subprocess.run([
        'productbuild', '--distribution', str(dist_xml),
        '--resources', str(res_dir),
        '--package-path', str(scratch),
        str(artifact),
    ], check=True)
    checksum = chromium.digest(artifact)
    artifact.with_suffix(artifact.suffix + '.sha256').write_text(f'{checksum}  {artifact.name}\n')
    return artifact


def build_windows_sfx_setup(setup_bin, resources_dir, artifact):
    """Builds a self-extracting Windows GUI Setup Wizard executable (`Gulpsuite-*-windows-x64-setup.exe`)
    by appending a ZIP archive of `resources/` (`chromium-manifest.json` + `chromium/chrome.exe` + DLLs)
    and the 24-byte trailer `[u64 zip_len_le][b'GULPCHROMIUMZIP1']` onto `gulpsuite-setup.exe`.
    """
    import os
    import struct
    import zipfile

    with tempfile.NamedTemporaryFile(prefix='gulp-win-res-', suffix='.zip', delete=False) as tmp_zf:
        tmp_zip_path = Path(tmp_zf.name)
    try:
        with zipfile.ZipFile(tmp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(resources_dir):
                for file in sorted(files):
                    full = Path(root) / file
                    rel = full.relative_to(resources_dir).as_posix()
                    zf.write(full, rel)
        zip_bytes = tmp_zip_path.read_bytes()
        exe_bytes = Path(setup_bin).read_bytes()
        trailer = struct.pack('<Q', len(zip_bytes)) + b'GULPCHROMIUMZIP1'
        artifact.write_bytes(exe_bytes + zip_bytes + trailer)
    finally:
        if tmp_zip_path.exists():
            tmp_zip_path.unlink()
    return artifact


def create_installer(platform, binary, stage, output, version, development):
    expected_os = 'Darwin' if platform.startswith('macos-') else ('Windows' if platform == 'windows-x64' else 'Linux')
    if host_platform.system() != expected_os:
        raise ValueError('native installer must be built on the target operating system')
    if not development:
        raise ValueError('publisher signing/notarization is not configured; use --development for unsigned artifacts')
    output.mkdir(parents=True, exist_ok=True)
    name = (f'gulpsuite_{version}_amd64.deb' if platform == 'linux-x64' else
            f'Gulpsuite-{version}-{platform}' + ('-setup.exe' if platform == 'windows-x64' else '.dmg'))
    artifact = (output / name).resolve()
    if artifact.exists():
        raise ValueError(f'installer already exists: {artifact}')
    with tempfile.TemporaryDirectory(prefix='gulpsuite-package-', dir=output) as scratch:
        layout = Path(scratch) / 'layout'
        assemble_layout(platform, binary, stage, layout, version)
        if platform.startswith('macos-'):
            subprocess.run(['codesign', '--force', '--deep', '--sign', '-', str(layout / 'Gulpsuite.app')], check=True)
            subprocess.run(['codesign', '--verify', '--deep', '--strict', str(layout / 'Gulpsuite.app')], check=True)
            if shutil.which('pkgbuild') and shutil.which('productbuild'):
                pkg_artifact = (output / f'Gulpsuite-{version}-{platform}-setup.pkg').resolve()
                if not pkg_artifact.exists():
                    build_macos_pkg(layout, pkg_artifact, version, scratch)
            (layout / 'Applications').symlink_to('/Applications')
            subprocess.run(['hdiutil', 'create', '-volname', 'Gulpsuite', '-srcfolder', str(layout),
                            '-format', 'UDZO', str(artifact)], check=True)
        elif platform == 'linux-x64':
            run_artifact = (output / f'Gulpsuite-{version}-linux-x64-setup.run').resolve()
            if not run_artifact.exists():
                build_linux_setup_run(layout, run_artifact, version)
                run_sum = chromium.digest(run_artifact)
                run_artifact.with_suffix('.run.sha256').write_text(f'{run_sum}  {run_artifact.name}\n')
            appimage_artifact = (output / f'Gulpsuite-{version}-x86_64.AppImage').resolve()
            if not appimage_artifact.exists():
                build_linux_appimage(layout, appimage_artifact, version)
                ai_sum = chromium.digest(appimage_artifact)
                appimage_artifact.with_suffix('.AppImage.sha256').write_text(f'{ai_sum}  {appimage_artifact.name}\n')
            arch_artifact = (output / f'gulpsuite-{version}-1-x86_64.pkg.tar.gz').resolve()
            if not arch_artifact.exists():
                build_arch_pkg(layout, arch_artifact, version)
                arch_sum = chromium.digest(arch_artifact)
                arch_artifact.with_suffix('.gz.sha256').write_text(f'{arch_sum}  {arch_artifact.name}\n')
            subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(layout), str(artifact)], check=True)
        else:
            setup_bin = binary.parent / 'gulpsuite-setup.exe'
            if setup_bin.is_file():
                build_windows_sfx_setup(setup_bin, stage / 'resources', artifact)
            else:
                subprocess.run(['makensis', f'/DAPPDIR={layout.resolve()}', f'/DOUTPUT={artifact}',
                                f'/DVERSION={version}', str(HERE / 'windows/gulpsuite.nsi')], check=True)
    checksum = chromium.digest(artifact)
    artifact.with_suffix(artifact.suffix + '.sha256').write_text(f'{checksum}  {artifact.name}\n')
    shutil.copy2(stage / 'resources/chromium-manifest.json', output / f'{name}.chromium.json')
    print(artifact)
    return artifact


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', required=True, choices=chromium.PLATFORMS)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--stage', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--development', action='store_true')
    args = parser.parse_args()
    cargo = (HERE.parent / 'engine/Cargo.toml').read_text()
    version = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M)[1]
    create_installer(args.platform, args.binary.resolve(), args.stage.resolve(), args.output.resolve(), version, args.development)


if __name__ == '__main__':
    main()
