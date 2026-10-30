"""tools/build.py is deterministic and build/ in the repository is what it produces (needs PyYAML)."""
import filecmp
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    yaml = None


@unittest.skipIf(yaml is None, "tools/build.py needs PyYAML")
class BuildTest(unittest.TestCase):
    def build(self, out, site="baseline/site.example.yaml"):
        return subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--site", str(ROOT / site), "--out", str(out)],
                              capture_output=True, text=True)

    def files(self, d):
        return sorted(str(p.relative_to(d)) for p in Path(d).rglob("*") if p.is_file())

    def test_two_builds_identical_and_match_repository(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            for d in (a, b):
                self.assertEqual(self.build(d).returncode, 0)
            self.assertEqual(self.files(a), self.files(b))
            self.assertEqual(self.files(a), self.files(ROOT / "build"))
            for rel in self.files(a):
                self.assertTrue(filecmp.cmp(Path(a) / rel, Path(b) / rel, shallow=False), rel)
                self.assertTrue(filecmp.cmp(Path(a) / rel, ROOT / "build" / rel, shallow=False), f"build/{rel} is stale")

    def test_site_minimum_below_rule_minimum_refused(self):
        with tempfile.TemporaryDirectory() as d:
            site = Path(d) / "site.yaml"
            site.write_text((ROOT / "baseline/site.example.yaml").read_text().replace('min: "2.1.285"', 'min: "2.1.150"'))
            p = subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--site", str(site), "--out", d],
                               capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("below 2.1.285", p.stderr)


if __name__ == "__main__":
    unittest.main()
