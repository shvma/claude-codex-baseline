#!/usr/bin/env bash
# Checker against known machine states (Linux container) and a planted repository.
# Raw output goes to results/checker/. Needs Docker and the gate image (gate/run_gate.py builds it).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=results/checker
mkdir -p "$OUT"
docker build -q -t coding-agent-gate:1 gate >/dev/null

docker run --rm -v "$PWD:/repo:ro" coding-agent-gate:1 bash -c '
mkdir -p /etc/claude-code /etc/codex
cp /repo/build/claude/managed-settings.json /etc/claude-code/ && cp /repo/build/codex/requirements.toml /etc/codex/
chk(){ echo "### $1"; runuser -u dev -- python3 /repo/tools/check.py machine | grep -v version_admitted || true; }
chk "baseline installed by root"
chmod 664 /etc/claude-code/managed-settings.json; chown root:dev /etc/claude-code/managed-settings.json
chk "Claude policy file writable by the user'"'"'s group"
chmod 644 /etc/claude-code/managed-settings.json; chown root:root /etc/claude-code/managed-settings.json
chown dev /etc/codex
chk "Codex policy directory owned by the user"
chown root /etc/codex
python3 -c "import json;p=\"/etc/claude-code/managed-settings.json\";s=json.load(open(p));del s[\"allowManagedHooksOnly\"];s[\"sandbox\"][\"enabled\"]=False;json.dump(s,open(p,\"w\"))"
chk "Claude policy edited: hook lock removed, sandbox off"
cp /repo/build/claude/managed-settings.json /etc/claude-code/
python3 -c "import json;p=\"/etc/claude-code/managed-settings.json\";s=json.load(open(p));s[\"sandbox\"][\"excludedCommands\"]=[\"*\"];s[\"permissions\"][\"allow\"]=[\"Bash(*)\"];json.dump(s,open(p,\"w\"))"
chk "Claude policy weakened by additions: excludedCommands *, allow Bash(*)"
rm -f /etc/claude-code/managed-settings.json /etc/codex/requirements.toml
chk "no policy delivered"
' > "$OUT/machine-cases.txt"

python3 - <<'PY' > "$OUT/repo-fixture.txt"
import subprocess, sys, tempfile, unittest
sys.path.insert(0, "tests"); sys.path.insert(0, "tools")
import check, test_check_repo as t
case = t.RepoModeTest("test_every_plant_is_reported"); case.setUp()
for r in check.check_repo(case.repo):
    cov = "" if r["outcome"] != "does_not_hold" else (" [neutralised by the baseline]" if r["neutralised_by_baseline"] else " [NOT covered by the baseline]")
    print(f"{r['outcome']:>14}  {r['check']:<28} {r['rule'] or '':<4} {r['evidence']}{cov}")
case.tearDown()
PY
cat "$OUT/machine-cases.txt" "$OUT/repo-fixture.txt"
