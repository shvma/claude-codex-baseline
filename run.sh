#!/usr/bin/env bash
# Reproduce everything: sources, build, tests, checker cases, release gate, decisions, numbers.
#   ./run.sh              full run (the gate takes about an hour for the listed versions)
#   ./run.sh --no-gate    everything except installing and probing agent versions
# Needs: Python 3.9+ with PyYAML, Docker. macOS additionally validates profiles with plutil.
# tools/check.py and gate/decide.py need the standard library only.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results

echo "== sources: every quote in baseline/rules.yaml is on the cited page"
python3 tools/verify_sources.py

echo "== build"
python3 tools/build.py
if command -v plutil >/dev/null; then
  for f in build/macos/*.mobileconfig build/jamf/*.plist; do plutil -lint "$f"; done
fi

echo "== unit tests (this Python, then Python 3.12 with the standard library only: tomllib checks the TOML)"
python3 -m unittest discover -s tests -v 2>&1 | tee results/unit-tests.txt | tail -1
docker run --rm -v "$PWD:/src:ro" python:3.12-alpine sh -c \
  'apk add -q git >/dev/null && cp -r /src /w && cd /w && python -I -m unittest discover -s tests -v' 2>&1 \
  | tee results/unit-tests-py312.txt | tail -1

echo "== checker against known machine states and a planted repository"
tests/checker_cases.sh > /dev/null && echo "results/checker/"

if [ "${1:-}" != "--no-gate" ]; then
  echo "== release gate"
  python3 gate/run_gate.py claude --versions-file gate/versions-claude.txt
  python3 gate/run_gate.py codex --versions-file gate/versions-codex.txt
  echo "== negative control: the baseline without R16 must be denied"
  python3 gate/run_gate.py claude 2.1.150 2.1.312 --site gate/site.negative.yaml --results results/gate-negative
fi
python3 gate/decide.py > /dev/null && echo "results/gate/decisions.md"
python3 gate/decide.py results/gate-negative > /dev/null && echo "results/gate-negative/decisions.md"

echo "== numbers"
python3 tools/numbers.py
