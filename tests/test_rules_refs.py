"""rules.yaml names only checks and probes that exist (read through build/coverage.json, no YAML needed)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "gate"))
import check  # noqa: E402
import decide  # noqa: E402

COVERAGE = json.loads((ROOT / "build/coverage.json").read_text())["rules"]


class RuleReferencesTest(unittest.TestCase):
    def test_every_check_exists(self):
        for rid, rule in COVERAGE.items():
            for ref in rule["checks"]:
                kind, _, rest = ref.partition(".")
                if kind == "gate":
                    agent, _, probe = rest.partition(".")
                    self.assertIn(probe, decide.EXPECTED.get(agent, ()), f"{rid}: {ref} is not a gate probe")
                elif kind == "repo":
                    self.assertIn(rest, check.REPO_CHECKS, f"{rid}: {ref}")
                elif kind == "machine":
                    self.assertIn(rest, check.MACHINE_CHECKS, f"{rid}: {ref}")
                else:
                    self.fail(f"{rid}: unknown check kind {ref}")

    def test_every_probe_belongs_to_a_rule(self):
        claimed = {ref for rule in COVERAGE.values() for ref in rule["checks"]}
        for agent, probes in decide.EXPECTED.items():
            for probe in probes:
                self.assertIn(f"gate.{agent}.{probe}", claimed)

    def test_min_versions_are_versions(self):
        for rid, rule in COVERAGE.items():
            for agent, version in rule["min_version"].items():
                self.assertIn(agent, ("claude", "codex"))
                decide.vkey(version)


if __name__ == "__main__":
    unittest.main()
