"""Release invariants: pinned inputs, archive layout, and lockfile scope."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ce_build', ROOT / 'ce/build.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ReleaseTests(unittest.TestCase):
    def test_upstream_pin_is_a_commit_not_an_annotated_tag(self):
        kind = subprocess.check_output(['git', 'cat-file', '-t', build.CONFIG['upstream_commit']], cwd=ROOT, text=True).strip()
        self.assertEqual(kind, 'commit')

    def test_external_dependencies_match_upstream(self):
        original = subprocess.check_output(['git', 'show', build.CONFIG['upstream_commit'] + ':codex-rs/Cargo.lock'], cwd=ROOT)
        packages = lambda value: [p for p in tomllib.loads(value)['package'] if 'source' in p]
        self.assertEqual(packages(original.decode()), packages((ROOT / 'codex-rs/Cargo.lock').read_text()))

    def test_bwrap_hash_is_executable_hash(self):
        config = build.CONFIG
        self.assertNotEqual(config['bwrap']['sha256'], config['bwrap']['binary_sha256'])
        env = build.cross_environment(ROOT / '.cache/ce-unit-fixture', {})
        self.assertEqual(env['CODEX_BWRAP_SHA256'], config['bwrap']['binary_sha256'])

    def test_download_rejects_tampered_input(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = base / 'input'
            source.write_bytes(b'not the pinned release')
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                build.download(source.as_uri(), '0' * 64, base / 'downloads')
            self.assertFalse((base / 'downloads/input').exists())
            self.assertFalse((base / 'downloads/input.partial').exists())


if __name__ == '__main__':
    unittest.main()
