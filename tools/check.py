#!/usr/bin/env python3
"""Checker: is the baseline in force on this machine, and what in a repository runs when it is opened?

    python3 tools/check.py machine [--json]
    python3 tools/check.py repo PATH [--json]

Standard library only, Python 3.9+. Every check returns holds / does_not_hold / could_not_run with the
evidence it looked at; the exit code is 1 if any check does not hold.
"""
import argparse
import base64
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_CLAUDE = ROOT / "build/claude/managed-settings.json"
EXPECTED_CODEX = ROOT / "build/codex/requirements.toml"
GATE_SUMMARY = ROOT / "results/gate/summary.json"

HOLDS, FAILS, NOT_RUN = "holds", "does_not_hold", "could_not_run"


def result(check, outcome, evidence, rule=None):
    return {"check": check, "outcome": outcome, "rule": rule, "evidence": evidence}


# ---------------------------------------------------------------------------------------------
# machine
# ---------------------------------------------------------------------------------------------
def os_kind():
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("win"):
        return "windows"
    try:
        if "microsoft" in Path("/proc/version").read_text().lower():
            return "wsl"
    except OSError:
        pass
    return "linux"


def writable_by_non_root(path):
    """True if a non-root user could replace this file: owner is not root, or group/other can write,
    for the file and every parent directory up to /."""
    p = Path(path)
    for node in [p, *p.parents]:
        try:
            st = node.lstat()
        except FileNotFoundError:
            continue
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            if node.is_dir() and st.st_mode & stat.S_ISVTX and node != p.parent:
                continue  # sticky directory such as /tmp above the file does not let others replace it
            return str(node)
    return None


def unix_policy_files(kind):
    claude_dir = Path("/Library/Application Support/ClaudeCode") if kind == "macos" else Path("/etc/claude-code")
    return {"claude_file": claude_dir / "managed-settings.json", "claude_dropins": claude_dir / "managed-settings.d",
            "codex_file": Path("/etc/codex/requirements.toml"),
            "claude_mdm": Path("/Library/Managed Preferences/com.anthropic.claudecode.plist"),
            "codex_mdm": Path("/Library/Managed Preferences/com.openai.codex.plist"),
            "claude_user_plist": Path.home() / "Library/Preferences/com.anthropic.claudecode.plist"}


def load_claude_delivered(kind, files):
    """Return (source, settings) for the Claude Code policy as delivered, highest-ranked admin source first."""
    if kind == "macos" and files["claude_mdm"].exists():
        with open(files["claude_mdm"], "rb") as f:
            return "plist", plistlib.load(f)
    if kind == "windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\ClaudeCode") as k:
                return "HKLM", json.loads(winreg.QueryValueEx(k, "Settings")[0])
        except OSError:
            pass
    if files["claude_file"].exists() or any(files["claude_dropins"].glob("*.json")):
        settings = json.loads(files["claude_file"].read_text()) if files["claude_file"].exists() else {}
        if not isinstance(settings, dict):
            raise ValueError("managed settings must be an object")
        for path in sorted(files["claude_dropins"].glob("*.json")):
            overlay = json.loads(path.read_text())
            settings = merge_settings(settings, overlay)
        return "file", settings
    return None, None


def merge_settings(base, overlay):
    if not isinstance(overlay, dict):
        raise ValueError("managed drop-in must be an object")
    merged = dict(base)
    for key, value in overlay.items():
        old = merged.get(key)
        if isinstance(old, dict) and isinstance(value, dict):
            merged[key] = merge_settings(old, value)
        elif isinstance(old, list) and isinstance(value, list):
            merged[key] = old + [item for item in value if item not in old]
        else:
            merged[key] = value
    return merged


def load_codex_delivered(kind, files):
    if kind == "macos" and files["codex_mdm"].exists():
        with open(files["codex_mdm"], "rb") as f:
            data = plistlib.load(f)
        if "requirements_toml_base64" in data:
            return "plist", base64.b64decode(data["requirements_toml_base64"]).decode()
    if files["codex_file"].exists():
        return "file", files["codex_file"].read_text()
    return None, None


def policy_mismatch(expected, actual, path=""):
    """Paths where the delivered policy differs from the baseline: missing, different, or extra.
    Extra keys and extra list items count too: `excludedCommands: ["*"]` or `allow: ["Bash(*)"]` weaken the policy.
    List order is ignored."""
    out = []
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [path or "(root)"]
        for k, v in expected.items():
            out += policy_mismatch(v, actual.get(k, None) if k in actual else _MISSING, f"{path}.{k}" if path else k)
        out += [f"{path}.{k}" if path else k for k in actual if k not in expected]
        return out
    if isinstance(expected, list) and isinstance(actual, list):
        canon = lambda items: sorted(json.dumps(x, sort_keys=True) for x in items)
        return [] if canon(expected) == canon(actual) else [path]
    return [] if expected == actual else [path]


_MISSING = object()


def norm_toml(text):
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


def agent_version(cmd):
    exe = shutil.which(cmd)
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def check_machine():
    kind = os_kind()
    out = []
    files = unix_policy_files(kind) if kind != "windows" else {}
    if kind == "windows":
        pf, pd = Path(os.environ.get("ProgramFiles", r"C:\Program Files")), Path(os.environ.get("ProgramData", r"C:\ProgramData"))
        files = {"claude_file": pf / "ClaudeCode/managed-settings.json", "claude_dropins": pf / "ClaudeCode/managed-settings.d",
                 "codex_file": pd / "OpenAI/Codex/requirements.toml", "claude_mdm": Path("-"), "codex_mdm": Path("-"),
                 "claude_user_plist": Path("-")}

    # Claude Code: delivered, matches the build, not replaceable by the user (R15)
    source, settings = load_claude_delivered(kind, files)
    if source is None:
        out.append(result("claude.policy_delivered", FAILS, "no managed source found (plist, HKLM or managed-settings.json)", "R15"))
    else:
        out.append(result("claude.policy_delivered", HOLDS, f"local delivered source: {source}; remote effective policy is not inspected", "R15"))
        if EXPECTED_CLAUDE.exists():
            diff = policy_mismatch(json.loads(EXPECTED_CLAUDE.read_text()), settings)
            out.append(result("claude.policy_matches_baseline", FAILS if diff else HOLDS,
                              ("missing, different or extra: " + ", ".join(diff)) if diff else "identical to build/claude/managed-settings.json"))
        else:
            out.append(result("claude.policy_matches_baseline", NOT_RUN, "build baseline is missing"))
        if source == "file" and kind != "windows":
            w = writable_by_non_root(files["claude_file"])
            out.append(result("claude.policy_file_owner", FAILS if w else HOLDS,
                              f"replaceable through {w}" if w else "file and parents owned by root, not group/other-writable", "R15"))
            for dropin in sorted(files["claude_dropins"].glob("*.json")):
                w = writable_by_non_root(dropin)
                out.append(result("claude.dropin_owner", FAILS if w else HOLDS,
                                  str(dropin) + (f" replaceable through {w}" if w else " admin-owned"), "R15"))
            if files["claude_dropins"].exists():
                w = writable_by_non_root(files["claude_dropins"])
                out.append(result("claude.dropin_directory_owner", FAILS if w else HOLDS,
                                  str(files["claude_dropins"]) + (f" replaceable through {w}" if w else " admin-owned"), "R15"))
    if kind == "windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Policies\ClaudeCode") as k:
                winreg.QueryValueEx(k, "Settings")
            hkcu = True
        except OSError:
            hkcu = False
        out.append(result("claude.no_user_writable_policy", FAILS if hkcu and source is None else HOLDS,
                          "HKCU policy present" + (" and no admin source: it would apply" if source is None else ", shadowed by the admin source")
                          if hkcu else "no HKCU policy", "R15"))
    if kind == "macos":
        up = files["claude_user_plist"]
        out.append(result("claude.no_user_preference_file", FAILS if up.exists() else HOLDS,
                          f"{up} exists; whether Claude Code reads it is not documented" if up.exists() else "none", "R15"))
    if kind == "wsl":
        win = Path("/mnt/c/Program Files/ClaudeCode/managed-settings.json")
        inherits = False
        try:
            inherits = json.loads(win.read_text()).get("wslInheritsWindowsSettings") is True
        except (OSError, ValueError):
            pass
        out.append(result("claude.wsl_chain", HOLDS if inherits else FAILS,
                          "Windows policy sets wslInheritsWindowsSettings" if inherits else
                          "/etc/claude-code is user-writable on WSL and the Windows chain is not on", "R14"))

    # Codex
    source, text = load_codex_delivered(kind, files)
    if source is None:
        out.append(result("codex.policy_delivered", FAILS, "no requirements.toml or MDM requirements found", "R15"))
    else:
        out.append(result("codex.policy_delivered", HOLDS, f"selected source: {source}", "R15"))
        if EXPECTED_CODEX.exists():
            same = norm_toml(text) == norm_toml(EXPECTED_CODEX.read_text())
            out.append(result("codex.policy_matches_baseline", HOLDS if same else FAILS,
                              "identical to build/codex/requirements.toml" if same else "differs from build/codex/requirements.toml"))
        else:
            out.append(result("codex.policy_matches_baseline", NOT_RUN, "build baseline is missing"))
        if source == "file" and kind != "windows":
            w = writable_by_non_root(files["codex_file"])
            out.append(result("codex.policy_file_owner", FAILS if w else HOLDS,
                              f"replaceable through {w}" if w else "file and parents owned by root, not group/other-writable", "R15"))

    # Versions admitted by the release gate (R11)
    admitted = {}
    if GATE_SUMMARY.exists():
        admitted = {a: set(v["admitted"]) for a, v in json.loads(GATE_SUMMARY.read_text())["agents"].items()}
    for agent, cmd in (("claude", "claude"), ("codex", "codex")):
        v = agent_version(cmd)
        if v is None:
            out.append(result(f"{agent}.version_admitted", NOT_RUN, f"`{cmd}` not found on PATH", "R11"))
        elif agent not in admitted:
            out.append(result(f"{agent}.version_admitted", NOT_RUN, f"{v}; no gate results for {agent}", "R11"))
        else:
            out.append(result(f"{agent}.version_admitted", HOLDS if v in admitted[agent] else FAILS,
                              f"{v} {'is' if v in admitted[agent] else 'is not'} in the gate's admitted list", "R11"))
    return out


# ---------------------------------------------------------------------------------------------
# repo
# ---------------------------------------------------------------------------------------------
HELPER_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "statusLine",
               "fileSuggestion")


def finding(check, path, what, rule, neutralised_by):
    return {"check": check, "outcome": FAILS, "rule": rule, "evidence": f"{path}: {what}",
            "neutralised_by_baseline": neutralised_by}


def git_tracked(repo, rel):
    try:
        return subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", rel],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan_claude_settings(repo, rel):
    out = []
    try:
        s = json.loads((repo / rel).read_text())
        if not isinstance(s, dict):
            raise ValueError("settings must be an object")
    except (OSError, ValueError):
        return [finding("repo.claude_settings_unreadable", rel, "not valid JSON", None, False)]
    if s.get("hooks"):
        out.append(finding("repo.hooks", rel, "hooks: " + ", ".join(s["hooks"]), "R01", True))
    # Helpers and the env block: interactive sessions hold them behind the trust dialog; non-interactive
    # runs ignore project settings only when started through wrappers/claude-untrusted (R17).
    for k in HELPER_KEYS:
        if k in s:
            out.append(finding("repo.helper_command", rel, f"{k} runs a command", "R17", True))
    env = s.get("env") or {}
    if env:
        out.append(finding("repo.env", rel, "env sets " + ", ".join(sorted(env)), "R17", True))
    mode = (s.get("permissions") or {}).get("defaultMode")
    if mode in ("bypassPermissions", "auto"):
        out.append(finding("repo.default_mode", rel, f"permissions.defaultMode = {mode}", "R03", True))
    if s.get("enableAllProjectMcpServers"):
        out.append(finding("repo.mcp_autoapprove", rel, "enableAllProjectMcpServers = true", "R02", True))
    if (s.get("permissions") or {}).get("allow"):
        out.append(finding("repo.allow_rules", rel, "allow rules: " + ", ".join(s["permissions"]["allow"][:5]), "R08", True))
    return out


def check_repo(repo):
    repo = Path(repo).resolve()
    if not repo.is_dir():
        return [finding("repo.missing", str(repo), "repository directory is missing", None, False)]
    out = []
    for rel in (".claude/settings.json", ".claude/settings.local.json"):
        if (repo / rel).exists():
            if rel.endswith("local.json") and not git_tracked(repo, rel):
                continue  # an untracked local file is the developer's own, not the repository's
            out += scan_claude_settings(repo, rel)
    if (repo / ".mcp.json").exists():
        try:
            servers = json.loads((repo / ".mcp.json").read_text()).get("mcpServers", {})
        except ValueError:
            servers = {"(unparsable)": {}}
        for name, spec in servers.items():
            what = "runs " + " ".join([spec.get("command", "")] + spec.get("args", [])) if "command" in spec else f"connects {spec.get('url', '?')}"
            out.append(finding("repo.mcp", ".mcp.json", f"server {name} {what}", "R02", True))
    codex_cfg = repo / ".codex/config.toml"
    if codex_cfg.exists():
        text = codex_cfg.read_text()
        try:
            config = tomllib.loads(text)
            if not isinstance(config.get("mcp_servers", {}), dict):
                raise ValueError("mcp_servers must be a table")
        except (ValueError, TypeError):
            config = {}
            out.append(finding("repo.codex_config_invalid", ".codex/config.toml", "invalid TOML", None, False))
        for name in config.get("mcp_servers", {}):
            out.append(finding("repo.mcp", ".codex/config.toml", f"server {name}", "R02", True))
        if config.get("hooks"):
            out.append(finding("repo.hooks", ".codex/config.toml", "inline hooks", "R01", True))
        if "notify" in config:
            out.append(finding("repo.helper_command", ".codex/config.toml", "notify runs a command (ignored by Codex in project config)", None, True))
    if (repo / ".codex/hooks.json").exists():
        out.append(finding("repo.hooks", ".codex/hooks.json", "hook definitions", "R01", True))
    for skill in list(repo.glob(".claude/skills/*/SKILL.md")) + list(repo.glob(".claude/commands/**/*.md")):
        text = skill.read_text(errors="replace")
        rel = str(skill.relative_to(repo))
        if re.search(r"!`|```!", text):
            out.append(finding("repo.skill_shell", rel, "inline shell execution", "R10", True))
        if re.search(r"^hooks:", text, re.M):
            out.append(finding("repo.hooks", rel, "hooks in skill frontmatter", "R01", True))
    env_file = repo / ".env"
    if env_file.exists() and re.search(r"^\s*CODEX_HOME\s*=", env_file.read_text(errors="replace"), re.M):
        out.append(finding("repo.codex_home", ".env", "sets CODEX_HOME (CVE-2025-61260 pattern)", None, False))
    commondir = repo / ".git/commondir"
    if commondir.exists():
        out.append(finding("repo.git_commondir", ".git/commondir", "points to " + commondir.read_text().strip()
                           + " (GHSA-q5hj-mxqh-vv77 pattern)", None, False))
    for rel in (".yarnrc.yml", ".yarnrc"):
        p = repo / rel
        if p.exists() and re.search(r"yarnPath|yarn-path", p.read_text(errors="replace")):
            out.append(finding("repo.package_manager_exec", rel, "yarnPath runs repository code on any yarn call "
                               "(GHSA-2jjv-qf24-vfm4 pattern)", None, False))
    for rel in ("CLAUDE.md", "AGENTS.md"):
        if (repo / rel).exists():
            out.append({"check": "repo.instructions", "outcome": "info", "rule": None,
                        "evidence": f"{rel}: instructions the agent reads every session; review like code",
                        "neutralised_by_baseline": False})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["machine", "repo"])
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rows = check_machine() if a.mode == "machine" else check_repo(a.path)
    if a.json:
        print(json.dumps({"mode": a.mode, "os": os_kind(), "python": platform.python_version(), "results": rows}, indent=1))
    else:
        for r in rows:
            extra = ""
            if "neutralised_by_baseline" in r and r["outcome"] == FAILS:
                extra = " [neutralised by the baseline]" if r["neutralised_by_baseline"] else " [NOT covered by the baseline]"
            print(f"{r['outcome']:>14}  {r['check']:<32} {r['rule'] or '':<4} {r['evidence']}{extra}")
    bad = [r for r in rows if r["outcome"] == FAILS and not r.get("neutralised_by_baseline", False)]
    incomplete = any(r["outcome"] == NOT_RUN for r in rows)
    sys.exit(1 if bad else 2 if incomplete else 0)


if __name__ == "__main__":
    main()
