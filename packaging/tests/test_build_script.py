import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.name == 'nt', 'POSIX build.sh')
class BuildScriptTests(unittest.TestCase):
    def test_failed_cargo_build_does_not_ship_a_stale_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(Path(__file__).resolve().parents[2] / 'build.sh', root)
            (root / 'engine/target/release').mkdir(parents=True)
            (root / 'engine/target/release/gulpsuite').write_text('stale')
            (root / 'tools').mkdir()
            cargo = root / 'tools/cargo'
            cargo.write_text('#!/bin/sh\nif [ "$1" = build ]; then echo "build failed"; exit 42; fi\necho "test result: ok"\n')
            cargo.chmod(0o755)
            result = subprocess.run(['sh', str(root / 'build.sh')], env={**os.environ, 'PATH': str(root / 'tools') + os.pathsep + os.environ['PATH']}, capture_output=True)
            self.assertNotEqual(result.returncode, 0, 'failed build was masked by the filter pipeline')
            self.assertFalse((root / 'gulpsuite').exists(), 'stale binary was shipped')
