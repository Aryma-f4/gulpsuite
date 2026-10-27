import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


class PackageTests(unittest.TestCase):
    def module(self):
        path = Path(__file__).resolve().parents[1] / 'package.py'
        self.assertTrue(path.exists(), 'Installer assembly is not implemented')
        spec = importlib.util.spec_from_file_location('gulp_package', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root):
        stage = root / 'stage with spaces'
        browser = stage / 'resources/chromium'
        browser.mkdir(parents=True)
        (browser / 'chrome').write_bytes(b'fixture')
        (browser / 'LICENSE').write_text('notice')
        (browser / 'THIRD-PARTY-CREDITS.html').write_text('<html><title>Credits</title>' + 'Redistribution notice. ' * 1000 + '</html>')
        entry = {'platform': 'linux-x64', 'revision': '123', 'sha256': 'a' * 64,
                 'url': 'https://storage.googleapis.com/chromium-browser-snapshots/Linux_x64/123/chrome-linux.zip',
                 'executable': 'chrome', 'notices': ['LICENSE']}
        (stage / 'resources/chromium-manifest.json').write_text(json.dumps(entry))
        binary = root / 'gulpsuite'
        binary.write_bytes(b'fixture')
        return stage, binary

    def test_linux_layout_copies_browser_notices_and_desktop_entry(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, binary = self.fixture(root)
            package_root = root / 'output'
            module.assemble_layout('linux-x64', binary, stage, package_root, '0.2.0')
            self.assertTrue((package_root / 'opt/gulpsuite/resources/chromium/chrome').is_file())
            self.assertTrue((package_root / 'opt/gulpsuite/resources/chromium/LICENSE').is_file())
            self.assertTrue((package_root / 'usr/share/applications/gulpsuite.desktop').is_file())
            self.assertTrue((package_root / 'usr/bin/gulpsuite').is_symlink())

    def test_mismatched_browser_or_missing_credits_refuses_package(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, binary = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'platform'):
                module.assemble_layout('windows-x64', binary, stage, root / 'output', '0.2.0')
            (stage / 'resources/chromium/THIRD-PARTY-CREDITS.html').unlink()
            with self.assertRaisesRegex(ValueError, 'credits'):
                module.assemble_layout('linux-x64', binary, stage, root / 'output', '0.2.0')
            self.assertFalse((root / 'output').exists())

    def test_existing_output_is_preserved(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, binary = self.fixture(root)
            output = root / 'output'
            output.mkdir()
            (output / 'keep').write_text('user data')
            with self.assertRaisesRegex(ValueError, 'exist'):
                module.assemble_layout('linux-x64', binary, stage, output, '0.2.0')
            self.assertEqual((output / 'keep').read_text(), 'user data')

    def test_placeholder_credits_are_not_accepted_for_distribution(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, binary = self.fixture(root)
            (stage / 'resources/chromium/THIRD-PARTY-CREDITS.html').write_text('<html><title>Credits</title>This is sample credits page. set generate_about_credits=true</html>')
            with self.assertRaisesRegex(ValueError, 'credits'):
                module.assemble_layout('linux-x64', binary, stage, root / 'output', '0.2.0')

    def test_linux_self_extracting_setup_run_installs_and_uninstalls_cleanly(self):
        import subprocess
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage, binary = self.fixture(root)
            layout = root / 'layout'
            module.assemble_layout('linux-x64', binary, stage, layout, '0.2.0')
            run_file = root / 'Gulpsuite-0.2.0-linux-x64-setup.run'
            module.build_linux_setup_run(layout, run_file, '0.2.0')
            self.assertTrue(run_file.is_file())
            prefix = root / 'installed-opt'
            env = {**os.environ, 'HOME': str(root / 'home')}
            subprocess.run(['sh', str(run_file), '--prefix', str(prefix), '--yes'], env=env, check=True)
            self.assertTrue((prefix / 'gulpsuite').is_file())
            self.assertTrue((prefix / 'resources/chromium/chrome').is_file())
            sentinel = prefix / 'user-sentinel.txt'
            sentinel.write_text('keep')
            subprocess.run(['sh', str(run_file), '--prefix', str(prefix), '--uninstall'], env=env, check=True)
            self.assertFalse((prefix / 'gulpsuite').exists())
            self.assertTrue(sentinel.is_file())

    def test_macos_dmg_retries_or_falls_back_to_makehybrid_on_resource_busy(self):
        from unittest import mock
        module = self.module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            layout = root / 'layout'
            layout.mkdir()
            (layout / 'dummy.txt').write_text('hello')
            artifact = root / 'Gulpsuite-0.0.9-macos-x64.dmg'

            calls = []

            def fake_run(cmd, *args, **kwargs):
                calls.append(cmd)
                if cmd[:2] == ['hdiutil', 'create']:
                    res = mock.MagicMock()
                    res.returncode = 1
                    return res
                if cmd[:2] == ['hdiutil', 'makehybrid']:
                    out_idx = cmd.index('-o') + 1
                    Path(cmd[out_idx]).write_bytes(b'hybrid-dmg')
                elif cmd[:2] == ['hdiutil', 'convert']:
                    out_idx = cmd.index('-o') + 1
                    Path(cmd[out_idx]).write_bytes(b'udzo-dmg')
                res = mock.MagicMock()
                res.returncode = 0
                return res

            with mock.patch.object(module.subprocess, 'run', side_effect=fake_run), \
                 mock.patch('time.sleep', return_value=None):
                out = module.build_macos_dmg(layout, artifact)
            self.assertEqual(out, artifact)
            self.assertTrue((layout / '.metadata_never_index').is_file())
            self.assertEqual(artifact.read_bytes(), b'udzo-dmg')
            self.assertFalse(artifact.with_suffix('.hybrid.dmg').exists())


if __name__ == '__main__':
    unittest.main()
