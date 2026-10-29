#!/usr/bin/env python3
"""Run the release gate: each agent version in a fresh container, raw probe results to results/gate/.

    python3 gate/run_gate.py claude 2.1.311 2.1.312
    python3 gate/run_gate.py codex --versions-file gate/versions-codex.txt

The baseline under test is built with gate/site.gate.yaml (API endpoint pinned to the in-container
stub) into gate/.build. A version already in results/gate/<agent>/ is skipped unless --force.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from decide import evidence, vkey

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
    if not versions:
        ap.error('at least one version is required')
    for version in versions:
        try:
            vkey(version)
        except ValueError as exc:
            ap.error(str(exc))
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(ROOT / "gate")], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([sys.executable, str(ROOT / "tools/build.py"), "--site", a.site,
                    "--out", str(ROOT / "gate/.build")], check=True, stdout=subprocess.DEVNULL)
    snapshot = tempfile.TemporaryDirectory(prefix='coding-agent-gate-')
    snapshot_root = Path(snapshot.name)
    for folder in ('gate', 'wrappers'):
        shutil.copytree(ROOT / folder, snapshot_root / folder,
                        ignore=shutil.ignore_patterns('__pycache__', '.build'))
    shutil.copytree(ROOT / 'gate/.build', snapshot_root / 'build')
    inputs = [p for p in sorted(snapshot_root.rglob('*')) if p.is_file()]
    image_id = subprocess.run(['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'],
                              check=True, capture_output=True, text=True).stdout.strip()
    fingerprint = hashlib.sha256((image_id + ''.join(hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs)).encode()).hexdigest()
    out_dir = Path(a.results) / a.agent
    out_dir.mkdir(parents=True, exist_ok=True)
    for v in versions:
        out = out_dir / f"{v}.jsonl"
        if out.exists() and not a.force:
            try:
                cached = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
                if cached and all(r.get('input_sha256') == fingerprint for r in cached) and not evidence(a.agent, v, cached)[1]:
                    print(f"{a.agent} {v}: verified matching inputs, skipped")
                    continue
            except (ValueError, KeyError, TypeError):
                pass
        # seccomp=unconfined: the agents' own sandboxes (bubblewrap) need user namespaces inside the container.
        p = subprocess.run(["docker", "run", "--rm", "--security-opt", "seccomp=unconfined",
                            "-v", f"{snapshot_root / 'build'}:/build:ro", "-v", f"{snapshot_root / 'gate'}:/gate:ro", "-v", f"{snapshot_root / 'wrappers'}:/wrappers:ro",
                            image_id, "/gate/in_container.sh", a.agent, v], capture_output=True, text=True, timeout=1800)
        rows = [json.loads(x) for x in p.stdout.splitlines() if x.startswith("{")]
        if not rows:
            rows = [{"agent": a.agent, "version": v, "probe": "container", "rule": None, "outcome": "did_not_run",
                     "output": (p.stdout + p.stderr)[-1500:]}]
        if p.returncode != 0:
            rows.append({'agent': a.agent, 'version': v, 'probe': 'container', 'outcome': 'did_not_run',
                         'output': p.stderr[-1500:]})
        for row in rows:
            row['input_sha256'] = fingerprint
        out.write_text("".join(json.dumps(r) + "\n" for r in rows))
        print(f"{a.agent} {v}: " + ", ".join(f"{r['probe']}={r['outcome']}" for r in rows), flush=True)
    snapshot.cleanup()


if __name__ == "__main__":
    main()
