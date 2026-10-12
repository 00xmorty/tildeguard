import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "tildeguard"
loader = importlib.machinery.SourceFileLoader("tildeguard", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
tool = importlib.util.module_from_spec(spec)
loader.exec_module(tool)


class PathTests(unittest.TestCase):
    def run_cli(self, value, *args):
        env = dict(os.environ)
        if value is None:
            env.pop("PATH", None)
        else:
            env["PATH"] = value
        return subprocess.run([sys.executable, str(SCRIPT), *args], env=env,
                              capture_output=True, text=True, timeout=5)

    def test_absolute(self):
        self.assertEqual(tool.inspect_path("/usr/bin:/bin")['status'], "NO_FINDINGS")

    def test_empty_positions(self):
        r = tool.inspect_path(":/bin::")
        self.assertEqual([f['entry'] for f in r['findings']], [1, 3, 4])
        self.assertTrue(all(f['kind'] == 'empty' for f in r['findings']))

    def test_empty_path_is_one_cwd_entry(self):
        self.assertEqual(tool.inspect_path("")['entry_count'], 1)
        self.assertEqual(tool.inspect_path("")['status'], "REVIEW")

    def test_tildes(self):
        r = tool.inspect_path("~:~/bin:~someone/bin:~+")
        self.assertEqual([f['kind'] for f in r['findings']],
                         ['literal_home_tilde'] * 2 + ['literal_other_tilde'] * 2)

    def test_relative(self):
        self.assertEqual(len(tool.inspect_path(".:../bin:tools/bin")['findings']), 3)

    def test_absolute_embedded_tilde_not_flagged(self):
        self.assertEqual(tool.inspect_path("/opt/~cache/bin")['findings'], [])

    def test_unknown(self):
        self.assertEqual(tool.inspect_path(None)['status'], "UNKNOWN")

    def test_check_exit_codes(self):
        for value, code in [("/bin", 0), ("~/bin", 1), (None, 2), ("", 1)]:
            with self.subTest(value=value):
                p = self.run_cli(value, '--check', '--json')
                self.assertEqual(p.returncode, code, p.stderr)
                json.loads(p.stdout)

    def test_advisory_exit_zero(self):
        self.assertEqual(self.run_cli("relative").returncode, 0)
        self.assertEqual(self.run_cli(None).returncode, 0)

    def test_values_never_echoed(self):
        value = "~/private-sentinel-998:relative-secret-998:/private-token-998:\x1b[31m"
        for args in [[], ['--json']]:
            p = self.run_cli(value, *args)
            self.assertNotIn('998', p.stdout + p.stderr)
            self.assertNotIn('\x1b', p.stdout + p.stderr)

    def test_no_eval_or_filesystem_side_effect(self):
        with tempfile.TemporaryDirectory() as root:
            sentinel = Path(root) / 'side-effect'
            value = '$(touch ' + str(sentinel) + '):`touch ' + str(sentinel) + '`'
            p = self.run_cli(value, '--json')
            self.assertEqual(p.returncode, 0)
            self.assertFalse(sentinel.exists())
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_schema(self):
        r = json.loads(self.run_cli("~/bin:/usr/bin", '--json').stdout)
        self.assertEqual(r, {'schema_version': 1, 'status': 'REVIEW', 'entry_count': 2,
                             'findings': [{'entry': 1, 'kind': 'literal_home_tilde',
                                           'cwd_dependent': True}]})

    def test_example_only_for_home_tilde(self):
        self.assertIn('$HOME/.local/bin', self.run_cli('~/bin').stdout)
        self.assertNotIn('$HOME/.local/bin', self.run_cli('~someone/bin').stdout)

    def test_version(self):
        self.assertEqual(self.run_cli('/bin', '--version').stdout.strip(), '0.1.0')


if __name__ == '__main__':
    unittest.main()
