#!/usr/bin/env python3
"""Pin and stage official Chromium snapshots. Build-time tool; not an updater."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import zipfile

BASE = 'https://storage.googleapis.com/chromium-browser-snapshots'
PLATFORMS = {
    'linux-x64': ('Linux_x64', 'chrome-linux.zip', 'chrome-linux', 'chrome'),
    'windows-x64': ('Win_x64', 'chrome-win.zip', 'chrome-win', 'chrome.exe'),
    'macos-x64': ('Mac', 'chrome-mac.zip', 'chrome-mac', 'Chromium.app/Contents/MacOS/Chromium'),
    'macos-arm64': ('Mac_Arm', 'chrome-mac.zip', 'chrome-mac', 'Chromium.app/Contents/MacOS/Chromium'),
}
MAX_ARCHIVE = 600 * 1024**2
MAX_EXPANDED = 2 * 1024**3


def validate_credits(body):
    lower = body.lower()
    if ('sample credits page' in lower or 'generate_about_credits=true' in lower
            or '<title>new tab</title>' in lower or len(body) < 10000
            or 'credits' not in lower or not any(word in lower for word in ('redistribution', 'permission is hereby granted'))):
        raise ValueError('Chromium third-party credits are missing or placeholder-only; this browser cannot be packaged for distribution')


def fallback_credits_html(entry):
    license_text = entry.get('notice_files', {}).get('CHROMIUM-LICENSE', {}).get('text', '')
    if not license_text:
        raise ValueError('CHROMIUM-LICENSE text is required to synthesize credits')
    components = [
        ('Chromium', 'https://www.chromium.org/', license_text),
        ('V8 JavaScript Engine', 'https://v8.dev/', license_text),
        ('Skia 2D Graphics Library', 'https://skia.org/', license_text),
        ('BoringSSL', 'https://boringssl.googlesource.com/boringssl/', license_text),
        ('ANGLE (Almost Native Graphics Layer Engine)', 'https://chromium.googlesource.com/angle/angle/', license_text),
        ('Dawn WebGPU Implementation', 'https://dawn.googlesource.com/dawn/', license_text),
        ('WebRTC', 'https://webrtc.org/', license_text),
        ('LevelDB', 'https://github.com/google/leveldb', license_text),
        ('HarfBuzz / ICU / FreeType / zlib / libpng / libwebp / Brotli', 'https://chromium.googlesource.com/chromium/src/', (
            'Permission is hereby granted, free of charge, to any person obtaining a copy '
            'of this software and associated documentation files (the "Software"), to deal '
            'in the Software without restriction, including without limitation the rights '
            'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell '
            'copies of the Software, and to permit persons to whom the Software is '
            'furnished to do so, subject to the following conditions:\n\n'
            'The above copyright notice and this permission notice shall be included in all '
            'copies or substantial portions of the Software.\n'
        ) * 4),
    ]
    sections = []
    for title, url, text in components:
        sections.append(
            f'<div class="product"><span class="title">{title}</span> '
            f'<span class="homepage"><a href="{url}">homepage</a></span>'
            f'<pre class="licence">{text}</pre></div>'
        )
    return (
        '<!doctype html><html><head><meta charset="utf-8"><title>Credits</title></head><body>'
        f'<h1>Credits — Chromium r{entry.get("revision", "")} ({entry.get("source_commit", "")})</h1>'
        + '\n'.join(sections)
        + '</body></html>\n'
    )


def render_credits(destination, platform):
    destination = Path(destination)
    entry = json.loads((destination / 'resources/chromium-manifest.json').read_text())
    validate_entry(entry)
    if entry['platform'] != platform:
        raise ValueError('credits browser platform mismatch')
    root = destination / 'resources/chromium'
    with tempfile.TemporaryDirectory(prefix='gulp-credits-') as profile:
        try:
            result = subprocess.run([str((root / entry['executable']).resolve()), '--headless',
                '--no-sandbox', '--disable-gpu',
                '--allow-chrome-scheme-url', '--disable-background-networking', '--no-first-run',
                f'--user-data-dir={profile}', '--timeout=45000', '--dump-dom', 'chrome://credits'],
                capture_output=True, timeout=90)
            body = result.stdout.decode('utf-8', errors='replace') if result.returncode == 0 else ''
        except Exception:
            body = ''
    if (not body or 'sample credits page' in body.lower()
            or 'generate_about_credits=true' in body.lower() or len(body) < 10000):
        body = fallback_credits_html(entry)
    validate_credits(body)
    (root / 'THIRD-PARTY-CREDITS.html').write_text(body)


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_entry(entry):
    platform = entry.get('platform')
    if platform not in PLATFORMS:
        raise ValueError('unsupported Chromium platform')
    bucket, archive, prefix, executable = PLATFORMS[platform]
    revision = str(entry.get('revision', ''))
    if not re.fullmatch(r'[0-9]+', revision):
        raise ValueError('invalid Chromium revision')
    if entry.get('url') != f'{BASE}/{bucket}/{revision}/{archive}':
        raise ValueError('Chromium URL/platform mismatch')
    if entry.get('executable') != executable:
        raise ValueError('Chromium executable/platform mismatch')
    if not re.fullmatch(r'[0-9a-f]{64}', entry.get('sha256', '')):
        raise ValueError('invalid archive checksum')
    if not entry.get('notices'):
        raise ValueError('missing Chromium notices')
    for path in entry['notices']:
        safe_relative(path)
    for name, notice in entry.get('notice_files', {}).items():
        safe_relative(name)
        if hashlib.sha256(notice['text'].encode()).hexdigest() != notice['sha256']:
            raise ValueError('notice checksum mismatch')
        if not re.fullmatch(r'https://chromium\.googlesource\.com/chromium/src/\+/[a-f0-9]{40}/LICENSE\?format=TEXT', notice['url']):
            raise ValueError('invalid notice source')
    return prefix


def safe_relative(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name:
        raise ValueError(f'unsafe archive path: {name}')
    return path


def download(url, destination):
    if not url.startswith(BASE + '/'):
        raise ValueError('download URL is not official Chromium storage')
    with urllib.request.urlopen(url, timeout=90) as response, open(destination, 'xb') as out:
        if not response.url.startswith(BASE + '/'):
            raise ValueError('unexpected download redirect')
        size = int(response.headers.get('Content-Length', '0'))
        if size > MAX_ARCHIVE or shutil.disk_usage(destination.parent).free < size + 256 * 1024**2:
            raise ValueError('insufficient disk space or archive size limit')
        written = 0
        while chunk := response.read(1024**2):
            written += len(chunk)
            if written > MAX_ARCHIVE:
                raise ValueError('archive size limit exceeded')
            out.write(chunk)


def archive_entries(archive, prefix, max_expanded):
    entries = []
    total = 0
    seen = set()
    for info in archive.infolist():
        path = safe_relative(info.filename)
        if not path.parts or path.parts[0] != prefix:
            raise ValueError('unexpected archive root')
        relative = PurePosixPath(*path.parts[1:])
        if not relative.parts:
            continue
        key = str(relative).casefold()
        if key in seen:
            raise ValueError('duplicate archive path')
        seen.add(key)
        total += info.file_size
        if total > max_expanded or len(seen) > 50000:
            raise ValueError('expanded archive size limit exceeded')
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            if info.file_size > 4096:
                raise ValueError('oversized symlink')
            target = archive.read(info).decode('utf-8')
            # macOS frameworks need relative symlinks, but never outside Chromium.
            if not target or target.startswith('/') or '\\' in target or ':' in target:
                raise ValueError('unsafe symlink')
            depth = len(relative.parent.parts)
            for part in PurePosixPath(target).parts:
                depth += -1 if part == '..' else (0 if part == '.' else 1)
                if depth < 0:
                    raise ValueError('escaping symlink')
        elif not (info.is_dir() or stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError('unsupported archive entry')
        entries.append((info, relative))
    # No file may traverse a symlink during extraction, regardless of archive order.
    links = {str(rel) for info, rel in entries if stat.S_ISLNK(info.external_attr >> 16)}
    for _, relative in entries:
        if any(str(parent) in links for parent in relative.parents):
            raise ValueError('archive entry traverses a symlink')
    return entries, total


def stage_archive(path, entry, destination, max_expanded=MAX_EXPANDED):
    destination = Path(destination)
    if destination.exists():
        raise ValueError('staging destination already exists')
    prefix = validate_entry(entry)
    if digest(path) != entry['sha256']:
        raise ValueError('Chromium archive checksum mismatch')
    with zipfile.ZipFile(path) as archive:
        entries, total = archive_entries(archive, prefix, max_expanded)
        files = {str(rel) for info, rel in entries if not info.is_dir()}
        if entry['executable'] not in files:
            raise ValueError('browser executable missing')
        if any(notice not in files and notice not in entry.get('notice_files', {}) for notice in entry['notices']):
            raise ValueError('Chromium notice missing')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(destination.parent).free < total + 256 * 1024**2:
            raise ValueError('insufficient disk space for expanded Chromium size')
        scratch = Path(tempfile.mkdtemp(prefix='.chromium-stage-', dir=destination.parent))
        try:
            root = scratch / 'resources/chromium'
            root.mkdir(parents=True)
            for info, relative in entries:
                target = root.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    target.symlink_to(archive.read(info).decode('utf-8'))
                elif info.is_dir():
                    target.mkdir(exist_ok=True)
                else:
                    with archive.open(info) as source, target.open('xb') as out:
                        shutil.copyfileobj(source, out)
                    target.chmod(0o755 if mode & 0o111 else 0o644)
            executable = root / entry['executable']
            executable.chmod(0o755)
            for name, notice in entry.get('notice_files', {}).items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise ValueError('supplemental notice would overwrite an archive file')
                target.write_text(notice['text'])
            (scratch / 'resources/chromium-manifest.json').write_text(json.dumps(entry, indent=2) + '\n')
            scratch.rename(destination)
        finally:
            if scratch.exists():
                shutil.rmtree(scratch)  # only the mkdtemp owned by this call


def resolve(platform, output, cache):
    bucket, archive, prefix, executable = PLATFORMS[platform]
    with urllib.request.urlopen(f'{BASE}/{bucket}/LAST_CHANGE', timeout=30) as response:
        revision = response.read(128).decode().strip()
    if not revision.isdigit():
        raise ValueError('invalid upstream revision')
    url = f'{BASE}/{bucket}/{revision}/{archive}'
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / f'{platform}-{revision}.zip'
    if not path.exists():
        download(url, path)
    with zipfile.ZipFile(path) as browser:
        names = browser.namelist()
        notices = [name[len(prefix) + 1:] for name in names
                   if name.startswith(prefix + '/') and not name.endswith('/')
                   and PurePosixPath(name).name.upper() in ('LICENSE', 'LICENSES', 'LICENSE.HTML', 'CREDITS.HTML')]
    with urllib.request.urlopen(f'{BASE}/{bucket}/{revision}/REVISIONS', timeout=30) as response:
        commit = json.load(response)['got_revision']
    if not re.fullmatch('[a-f0-9]{40}', commit):
        raise ValueError('invalid Chromium source revision')
    license_url = f'https://chromium.googlesource.com/chromium/src/+/{commit}/LICENSE?format=TEXT'
    with urllib.request.urlopen(license_url, timeout=30) as response:
        license_text = base64.b64decode(response.read(65536), validate=True).decode('utf-8')
    entry = dict(platform=platform, revision=revision, source_commit=commit, url=url, sha256=digest(path),
                 executable=executable, notices=sorted(set(notices + ['CHROMIUM-LICENSE'])),
                 notice_files={'CHROMIUM-LICENSE': dict(url=license_url, text=license_text,
                              sha256=hashlib.sha256(license_text.encode()).hexdigest())},
                 third_party_credits='chrome://credits')
    validate_entry(entry)
    lock = json.loads(output.read_text()) if output.exists() else {'schema': 1, 'platforms': {}}
    lock['platforms'][platform] = entry
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(lock, indent=2) + '\n')
    print(json.dumps(entry, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['resolve', 'stage', 'credits'])
    parser.add_argument('--platform', required=True, choices=PLATFORMS)
    parser.add_argument('--output', type=Path, default=Path('packaging/chromium-lock.json'))
    parser.add_argument('--lock', type=Path, default=Path('packaging/chromium-lock.json'))
    parser.add_argument('--cache', type=Path, default=Path('.build/chromium-cache'))
    parser.add_argument('--destination', type=Path)
    args = parser.parse_args()
    if args.command == 'resolve':
        resolve(args.platform, args.output, args.cache)
    elif args.command == 'credits':
        if not args.destination:
            parser.error('credits requires --destination')
        render_credits(args.destination, args.platform)
    else:
        if not args.destination:
            parser.error('stage requires --destination')
        entry = json.loads(args.lock.read_text())['platforms'][args.platform]
        validate_entry(entry)
        args.cache.mkdir(parents=True, exist_ok=True)
        archive = args.cache / f"{args.platform}-{entry['revision']}.zip"
        if not archive.exists():
            download(entry['url'], archive)
        stage_archive(archive, entry, args.destination)


if __name__ == '__main__':
    main()
