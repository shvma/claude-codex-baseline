#!/usr/bin/env python3
"""Release-gate probes for OpenAI Codex. See probelib.py for the control/policy method.

Codex prints its effective approval policy and sandbox in the session header of `codex exec`; R03, R04
and R08 are read from that header. R01 and R02 use canaries planted in a trusted project.
"""
import os
import re
import subprocess
import time
from pathlib import Path

from probelib import (API_LOG, CANARY, HOME, fresh_repo, install_policy, lines, reset, run_as_dev, run_probes,
                      warnings, write_home)

POLICY_SRC = Path("/build/codex/requirements.toml")
POLICY_DST = Path("/etc/codex/requirements.toml")
ENV = {"HOME": str(HOME), "PATH": os.environ["PATH"], "OPENAI_API_KEY": "sk-gate-stub"}
USER_CONFIG = """model = "stub"
model_provider = "stub"

[model_providers.stub]
name = "stub"
base_url = "http://127.0.0.1:8099/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"

[projects."/work/repo"]
trust_level = "trusted"
"""
HOOK = '{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"touch %s"}]}]}}' % CANARY
MCP = '[mcp_servers.probe]\ncommand = "sh"\nargs = ["-c", "touch %s; sleep 5"]\n' % CANARY
EXEC = ["codex", "exec", "--skip-git-repo-check"]

_last = {}


def header(field):
    m = re.search(rf"^{field}: (.+)$", _last.get("out", ""), re.M)
    return m.group(1).strip() if m else ""


PROBES = {
    # R01: a hook in a trusted project, with hook review skipped by flag as a developer might do.
    "repo_hook": {"rule": "R01", "files": {".codex/hooks.json": HOOK},
                  "cmd": EXEC + ["--dangerously-bypass-hook-trust", "hi"], "fired": CANARY.exists},
    # R02: an MCP server declared in a trusted project's .codex/config.toml.
    "repo_mcp": {"rule": "R02", "files": {".codex/config.toml": MCP}, "cmd": EXEC + ["hi"], "fired": CANARY.exists},
    # R03: codex exec runs with approval "never" unless requirements forbid it.
    "approval_never": {"rule": "R03", "files": {}, "cmd": EXEC + ["hi"],
                       "fired": lambda: header("approval") == "never"},
    # R04: full access requested on the command line.
    "sandbox_full_access": {"rule": "R04", "files": {}, "cmd": EXEC + ["-s", "danger-full-access", "hi"],
                            "fired": lambda: header("sandbox").startswith("danger-full-access")},
    # R03/R04: the combined bypass flag.
    "bypass_all_flag": {"rule": "R03", "files": {}, "cmd": EXEC + ["--dangerously-bypass-approvals-and-sandbox", "hi"],
                        "fired": lambda: header("sandbox").startswith("danger-full-access")},
    # R08: the user's own config asks for full access.
    "user_config_relax": {"rule": "R08", "files": {}, "user_extra": 'sandbox_mode = "danger-full-access"\n',
                          "cmd": EXEC + ["hi"], "fired": lambda: header("sandbox").startswith("danger-full-access")},
}


def run_one(spec, with_policy):
    reset([".codex"])
    install_policy(POLICY_SRC, POLICY_DST, with_policy)
    write_home({".codex/config.toml": spec.get("user_extra", "") + USER_CONFIG})
    repo = fresh_repo(spec["files"])
    code, out = run_as_dev(spec["cmd"], repo, ENV)
    _last["out"] = out
    time.sleep(0.3)
    return {"fired": spec["fired"](), "started": bool(lines(API_LOG)), "exit": code,
            "approval": header("approval"), "sandbox": header("sandbox"), "warnings": warnings(out),
            "output": out[-1500:]}


if __name__ == "__main__":
    version = subprocess.run(["codex", "--version"], capture_output=True, text=True).stdout.split()[-1]
    run_probes("codex", version, PROBES, run_one)
