#!/usr/bin/env python3
"""The project's headline numbers, computed from files only. Writes results/numbers.json.

  rules              rules in baseline/rules.yaml whose every quote was found on its page (results/sources.json)
  claude_keys/codex  keys each agent's generated policy sets (build/MANIFEST.md, platform "all")
  checker_findings   findings on the planted repository; how many the baseline neutralises
  versions_tested    agent versions the gate ran completely; admitted; regressions between adjacent versions
"""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"


def codex_coverage(rule):
    """key / site / deployment / built in / none — how a rule reaches Codex."""
    if rule.get("codex"):
        return "key"
    if any(k.startswith("codex.") for k in rule.get("site") or {}):
        return "site"
    if rule.get("deployment"):
        return "deployment"
    return "built in" if (rule.get("gap") or {}).get("codex", "").startswith("Built in") else "none"


def negative_control():
    """The gate run with the baseline minus R16 (results/gate-negative/): versions tested and denied."""
    p = R / "gate-negative/summary.json"
    if not p.exists():
        return None
    agents = json.loads(p.read_text())["agents"]
    return {"versions_tested": sum(a["versions_tested"] for a in agents.values()),
            "denied": sum(len(a["denied"]) for a in agents.values())}


def main():
    rules = yaml.safe_load((ROOT / "baseline/rules.yaml").read_text())["rules"]
    quotes = json.loads((R / "sources.json").read_text())["quotes"]
    verified = [r["id"] for r in rules if r.get("sources")
                and all(q["found"] for q in quotes if q["rule"] == r["id"])
                and any(q["rule"] == r["id"] for q in quotes)]
    manifest = (ROOT / "build/MANIFEST.md").read_text()
    keys = {a: len(re.findall(rf"^\| R\d+ \| {a} \| .* \| all \|$", manifest, re.M)) for a in ("claude", "codex")}
    repo = (R / "checker/repo-fixture.txt").read_text().splitlines() if (R / "checker/repo-fixture.txt").exists() else []
    findings = [x for x in repo if "does_not_hold" in x]
    gate = json.loads((R / "gate/summary.json").read_text()) if (R / "gate/summary.json").exists() else {"agents": {}}
    out = {
        "rules": len(rules), "rules_with_verified_sources": len(verified),
        "claude_keys": keys["claude"], "codex_keys": keys["codex"],
        "codex_built_in": [r["id"] for r in rules if codex_coverage(r) == "built in"],
        "codex_no_control": [r["id"] for r in rules if codex_coverage(r) == "none"],
        "checker_findings": len(findings),
        "checker_neutralised": sum("[neutralised by the baseline]" in x for x in findings),
        "versions_tested": {a: v["versions_tested"] for a, v in gate["agents"].items()},
        "versions_admitted": {a: len(v["admitted"]) for a, v in gate["agents"].items()},
        "regressions": {a: len(v["regressions"]) for a, v in gate["agents"].items()},
        "negative_control": negative_control(),
    }
    (R / "numbers.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
