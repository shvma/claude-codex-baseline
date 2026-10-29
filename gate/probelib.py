"""Shared probe machinery for the release gate (runs inside the gate container as root).

Every probe is run twice as the unprivileged user `dev`:
  control  no managed policy installed  -> the probe's signal must fire, otherwise it says nothing
  policy   the baseline installed       -> the signal must stay silent while the agent still reaches
                                           the model API (proof that it got past start-up)
Outcome: holds / does_not_hold / invalid_control / did_not_run.
"""
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

API_LOG, ATTACKER_LOG = Path("/tmp/api.log"), Path("/tmp/attacker.log")
CANARY = Path("/tmp/canary")
TOOL_FILE = Path("/tmp/stub-tool.json")
REPO = Path("/work/repo")
HOME = Path("/home/dev")


def run_as_dev(cmd, cwd, env, timeout=30):
    """Run in its own process group and kill the whole group on timeout, so that children the agent
    started (MCP servers, hooks) cannot keep the pipes open."""
    p = subprocess.Popen(["runuser", "-u", "dev", "--", "env", *[f"{k}={v}" for k, v in env.items()], *cmd],
                         cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        code = p.returncode
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        code = "timeout"
    try:
        os.killpg(p.pid, signal.SIGKILL)  # leftovers such as an MCP server still sleeping
    except ProcessLookupError:
        pass
    return code, out.decode("utf-8", "replace")


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []


def fresh_repo(files):
    shutil.rmtree(REPO, ignore_errors=True)
    REPO.mkdir(parents=True)
    for rel, content in files.items():
        (REPO / rel).parent.mkdir(parents=True, exist_ok=True)
        (REPO / rel).write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=REPO, check=True)
    subprocess.run(["chown", "-R", "dev:dev", str(REPO)], check=True)
    return REPO


def write_home(files):
    for rel, content in files.items():
        (HOME / rel).parent.mkdir(parents=True, exist_ok=True)
        (HOME / rel).write_text(content)
    subprocess.run(["chown", "-R", "dev:dev", str(HOME)], check=True)


def reset(home_dirs, extra=()):
    for p in (CANARY, API_LOG, ATTACKER_LOG, TOOL_FILE, *extra):
        p.unlink(missing_ok=True)
    for d in home_dirs:
        target = HOME / d
        shutil.rmtree(target, ignore_errors=True) if target.is_dir() else target.unlink(missing_ok=True)


def install_policy(src, dst, on):
    if on:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)
    else:
        dst.unlink(missing_ok=True)


def judge(control, policy):
    if control.get("exit") != 0:
        return "did_not_run"
    if not control["fired"]:
        return "invalid_control"
    if policy["fired"]:
        return "does_not_hold"
    if not policy["started"]:
        return "did_not_run"
    if policy.get("exit") != 0 and not policy.get("validated_refusal"):
        return "did_not_run"
    return "holds"


def run_probes(agent, version, probes, run_one):
    for name, spec in probes.items():
        control = run_one(spec, with_policy=False)
        policy = run_one(spec, with_policy=True)
        print(json.dumps({"agent": agent, "version": version, "probe": name, "rule": spec["rule"],
                          "outcome": judge(control, policy), "control": control, "policy": policy}), flush=True)
        time.sleep(0.2)
