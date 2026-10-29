#!/usr/bin/env bash
# Entry point inside the gate container: install one agent version, start the API stubs, run its probes.
#   in_container.sh claude 2.1.312      in_container.sh codex 0.165.0
set -euo pipefail
agent="$1" version="$2"
case "$agent" in
  claude) pkg="@anthropic-ai/claude-code" ;;
  codex)  pkg="@openai/codex" ;;
  *) echo "unknown agent $agent" >&2; exit 2 ;;
esac
runuser -u dev -- npm install -g --no-fund --no-audit "$pkg@$version" >/tmp/npm.log 2>&1 \
  || { echo "{\"agent\":\"$agent\",\"version\":\"$version\",\"probe\":\"install\",\"outcome\":\"did_not_run\",\"output\":$(tail -c 800 /tmp/npm.log | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')}"; exit 0; }
LOG=/tmp/api.log python3 /gate/stub_api.py 8099 &
LOG=/tmp/attacker.log python3 /gate/stub_api.py 8098 &
sleep 0.5
python3 "/gate/probes_$agent.py"
