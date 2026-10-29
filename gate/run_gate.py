#!/usr/bin/env python3
"""Run the release gate: each agent version in a fresh container, raw probe results to results/gate/.

    python3 gate/run_gate.py claude 2.1.311 2.1.312
    python3 gate/run_gate.py codex --versions-file gate/versions-codex.txt

The baseline under test is built with gate/site.gate.yaml (API endpoint pinned to the in-container
stub) into gate/.build. A version already in results/gate/<agent>/ is skipped unless --force.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "coding-agent-gate:1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", choices=["claude", "codex"])
    ap.add_argument("versions", nargs="*")
    ap.add_argument("--versions-file")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--site", default=str(ROOT / "gate/site.gate.yaml"))
    ap.add_argument("--results", default=str(ROOT / "results/gate"))
    a = ap.parse_args()
    versions = list(a.versions)
    if a.versions_file:
        for line in Path(a.versions_file).read_text().splitlines():
            versions += line.split("#", 1)[0].split()
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(ROOT / "gate")], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--site", a.site,
                    "--out", str(ROOT / "gate/.build")], check=True, stdout=subprocess.DEVNULL)
    out_dir = Path(a.results) / a.agent
    out_dir.mkdir(parents=True, exist_ok=True)
    for v in versions:
        out = out_dir / f"{v}.jsonl"
        if out.exists() and not a.force:
            print(f"{a.agent} {v}: already in results, skipped")
            continue
        # seccomp=unconfined: the agents' own sandboxes (bubblewrap) need user namespaces inside the container.
        p = subprocess.run(["docker", "run", "--rm", "--security-opt", "seccomp=unconfined",
                            "-v", f"{ROOT / 'gate/.build'}:/build:ro", "-v", f"{ROOT / 'gate'}:/gate:ro", "-v", f"{ROOT / 'wrappers'}:/wrappers:ro",
                            IMAGE, "/gate/in_container.sh", a.agent, v], capture_output=True, text=True, timeout=1800)
        rows = [json.loads(x) for x in p.stdout.splitlines() if x.startswith("{")]
        if not rows:
            rows = [{"agent": a.agent, "version": v, "probe": "container", "rule": None, "outcome": "did_not_run",
                     "output": (p.stdout + p.stderr)[-1500:]}]
        out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(f"{a.agent} {v}: " + ", ".join(f"{r['probe']}={r['outcome']}" for r in rows), flush=True)


if __name__ == "__main__":
    main()
