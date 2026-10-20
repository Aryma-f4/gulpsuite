import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / 'chromium.py'


class ChromiumTests(unittest.TestCase):
    def module(self):
        self.assertTrue(MODULE.exists(), 'Chromium staging is not implemented')
        spec = importlib.util.spec_from_file_location('chromium', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root, extra=None):
        archive = root / 'browser.zip'
        with zipfile.ZipFile(archive, 'w') as out:
            out.writestr('chrome-linux/chrome', b'fake-browser')
            out.writestr('chrome-linux/LICENSE', b'upstream notice')
            if extra:
                out.writestr(*extra)
        entry = {'platform': 'linux-x64', 'revision': '123',
                 'url': 'https://storage.googleapis.com/chromium-browser-snapshots/Linux_x64/123/chrome-linux.zip',
                 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                 'executable': 'chrome', 'notices': ['LICENSE']}
        return archive, entry

    def test_stages_browser_and_manifest_in_spaced_path(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, entry = self.fixture(root)
            destination = root / 'spaced staging'
            module.stage_archive(archive, entry, destination)
            self.assertEqual((destination / 'resources/chromium/chrome').read_bytes(), b'fake-browser')
            self.assertTrue((destination / 'resources/chromium-manifest.json').is_file())

    def test_checksum_failure_preserves_destination(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, entry = self.fixture(root)
            entry['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'checksum'):
                module.stage_archive(archive, entry, root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_refuses_occupied_destination(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, entry = self.fixture(root)
            destination = root / 'output'
            destination.mkdir()
            (destination / 'keep').write_text('mine')
            with self.assertRaisesRegex(ValueError, 'exist'):
                module.stage_archive(archive, entry, destination)
            self.assertEqual((destination / 'keep').read_text(), 'mine')

    def test_rejects_traversal_and_symlinks(self):
        module = self.module()
        for name in ['../escape', '/absolute', 'chrome-linux/../../escape', 'chrome-linux/..\\escape']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive, entry = self.fixture(root, (name, b'bad'))
                with self.assertRaises(ValueError):
                    module.stage_archive(archive, entry, root / 'output')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            info = zipfile.ZipInfo('chrome-linux/link')
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            archive, entry = self.fixture(root, (info, b'../outside'))
            with self.assertRaisesRegex(ValueError, 'symlink'):
                module.stage_archive(archive, entry, root / 'output')

    def test_rejects_missing_notice_and_oversized_expansion(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, entry = self.fixture(root)
            entry['notices'] = ['missing-LICENSE']
            with self.assertRaisesRegex(ValueError, 'notice'):
                module.stage_archive(archive, entry, root / 'output')
            entry['notices'] = ['LICENSE']
            with self.assertRaisesRegex(ValueError, 'size'):
                module.stage_archive(archive, entry, root / 'output', max_expanded=1)

    def test_rejects_cross_platform_url_and_executable(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, entry = self.fixture(root)
            entry['platform'] = 'windows-x64'
            with self.assertRaises(ValueError):
                module.stage_archive(archive, entry, root / 'output')


if __name__ == '__main__':
    unittest.main()
