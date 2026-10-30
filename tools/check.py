#!/usr/bin/env python3
"""Checker: is the baseline in force on this machine, and what in a repository runs when it is opened?

    python3 tools/check.py machine [--json]
    python3 tools/check.py repo PATH [--json]

Standard library only, Python 3.9+ (TOML: tomllib on 3.11+, the small parser below on 3.9 and 3.10).
Every check returns holds / does_not_hold / could_not_run with the evidence it looked at; the exit code
is 1 if any check does not hold, 2 if none fails but some could not run.

Machine mode rebuilds the policy the agent applies from every managed source it can see, the way the
vendors document the composition (Claude Code: managed-settings docs; Codex: config_requirements.rs),
and compares it with build/: a stricter value passes, a looser one, a missing one or an unknown extra
key fails. Server-managed (Claude) and cloud (Codex) policies are not visible here and are reported as
could_not_run unless Claude Code's local cache of them is present.
"""
import argparse
import base64
import copy
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
except ModuleNotFoundError:  # Python 3.9 / 3.10: the parser below covers what requirements.toml uses
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
GATE_SUMMARY = ROOT / "results/gate/summary.json"

HOLDS, FAILS, NOT_RUN, INFO = "holds", "does_not_hold", "could_not_run", "info"
MISSING = object()

# Check ids this script can emit; rules.yaml refers to them as machine.<id> / repo.<id>.
MACHINE_CHECKS = {"policy_delivered", "policy_parse", "policy_matches_baseline", "policy_file_owner",
                  "dropin_owner", "dropin_directory_owner", "dropin_ignored", "server_managed",
                  "no_user_writable_policy", "no_user_preference_file", "wsl_chain", "user_sandbox_exceptions",
                  "legacy_managed_config", "cloud_requirements", "version_admitted"}
REPO_CHECKS = {"missing", "claude_settings_unreadable", "hooks", "helper_command", "env", "default_mode",
               "mcp_autoapprove", "allow_rules", "marketplaces", "plugins", "sandbox_exceptions", "mcp",
               "mcp_unreadable", "codex_config_invalid", "skill_shell", "agent_bypass", "agent_mcp",
               "agent_hooks", "codex_home", "git_commondir", "package_manager_exec", "instructions"}


def result(check, outcome, evidence, rule=None):
    return {"check": check, "outcome": outcome, "rule": rule, "evidence": evidence}


# ---------------------------------------------------------------------------------------------
# TOML
# ---------------------------------------------------------------------------------------------
class TOMLError(ValueError):
    pass


def toml_loads(text):
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise TOMLError(str(e)) from None
    return MiniToml(text).parse()


class MiniToml:
    """TOML without dates: tables, arrays of tables, dotted and quoted keys, strings, numbers, booleans,
    arrays and inline tables. Anything else raises TOMLError, so an unsupported file is never misread."""
    BARE = re.compile(r"[A-Za-z0-9_-]+")
    NUMBER = re.compile(r"[+-]?(?:0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|inf|nan|"
                        r"(?:\d[\d_]*)(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)(?=[\s,\]}#]|$)")
    ESCAPES = {"b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r", '"': '"', "\\": "\\"}

    def __init__(self, text):
        self.s, self.i = text, 0

    def error(self, msg):
        line = self.s.count("\n", 0, self.i) + 1
        raise TOMLError(f"{msg} (line {line})")

    def peek(self, n=1):
        return self.s[self.i:self.i + n]

    def spaces(self):
        while self.peek() in (" ", "\t"):
            self.i += 1

    def blank(self):  # whitespace, newlines and comments
        while True:
            self.spaces()
            c = self.peek()
            if c == "#":
                while self.peek() not in ("\n", ""):
                    self.i += 1
            elif c in ("\n", "\r"):
                self.i += 1
            else:
                return

    def end_of_line(self):
        self.spaces()
        if self.peek() == "#":
            while self.peek() not in ("\n", ""):
                self.i += 1
        if self.peek() == "\r":
            self.i += 1
        if self.peek() not in ("\n", ""):
            self.error("expected end of line")

    def parse(self):
        root, table = {}, None
        table = root
        while True:
            self.blank()
            if self.i >= len(self.s):
                return root
            if self.peek(2) == "[[":
                self.i += 2
                keys = self.key()
                if self.peek(2) != "]]":
                    self.error("expected ]]")
                self.i += 2
                parent = self.walk(root, keys[:-1])
                arr = parent.setdefault(keys[-1], [])
                if not isinstance(arr, list):
                    self.error(f"{'.'.join(keys)} is not an array of tables")
                table = {}
                arr.append(table)
            elif self.peek() == "[":
                self.i += 1
                keys = self.key()
                if self.peek() != "]":
                    self.error("expected ]")
                self.i += 1
                table = self.walk(root, keys)
            else:
                keys = self.key()
                if self.peek() != "=":
                    self.error("expected =")
                self.i += 1
                self.assign(table, keys, self.value())
            self.end_of_line()

    def walk(self, root, keys):
        node = root
        for k in keys:
            node = node.setdefault(k, {})
            if isinstance(node, list):
                node = node[-1]
            if not isinstance(node, dict):
                self.error(f"{k} is not a table")
        return node

    def assign(self, table, keys, value):
        node = self.walk(table, keys[:-1])
        if keys[-1] in node:
            self.error(f"duplicate key {keys[-1]}")
        node[keys[-1]] = value

    def key(self):
        keys = []
        while True:
            self.spaces()
            c = self.peek()
            if c == '"':
                keys.append(self.basic_string())
            elif c == "'":
                keys.append(self.literal_string())
            else:
                m = self.BARE.match(self.s, self.i)
                if not m:
                    self.error("expected a key")
                keys.append(m.group())
                self.i = m.end()
            self.spaces()
            if self.peek() != ".":
                return keys
            self.i += 1

    def value(self):
        self.spaces()
        c = self.peek()
        if c == '"':
            return self.basic_string()
        if c == "'":
            return self.literal_string()
        if c == "[":
            self.i += 1
            out = []
            while True:
                self.blank()
                if self.peek() == "]":
                    self.i += 1
                    return out
                out.append(self.value())
                self.blank()
                if self.peek() == ",":
                    self.i += 1
                elif self.peek() != "]":
                    self.error("expected , or ]")
        if c == "{":
            self.i += 1
            out = {}
            self.spaces()
            if self.peek() == "}":
                self.i += 1
                return out
            while True:
                keys = self.key()
                if self.peek() != "=":
                    self.error("expected =")
                self.i += 1
                self.assign(out, keys, self.value())
                self.spaces()
                if self.peek() == "}":
                    self.i += 1
                    return out
                if self.peek() != ",":
                    self.error("expected , or }")
                self.i += 1
        for word, val in (("true", True), ("false", False)):
            if self.s.startswith(word, self.i):
                self.i += len(word)
                return val
        m = self.NUMBER.match(self.s, self.i)
        if not m:
            self.error("unsupported value")
        self.i = m.end()
        text = m.group().replace("_", "")
        if text.lstrip("+-") in ("inf", "nan"):
            return float(text)
        if text[1:2] in ("x", "o", "b") or text[:1] in "+-" and text[2:3] in ("x", "o", "b"):
            return int(text, 0)
        return float(text) if any(ch in text for ch in ".eE") else int(text)

    def basic_string(self):
        multi = self.peek(3) == '"""'
        self.i += 3 if multi else 1
        if multi and self.peek() == "\n":
            self.i += 1
        out = []
        while True:
            c = self.peek()
            if c == "":
                self.error("unterminated string")
            if multi and self.peek(3) == '"""':
                self.i += 3
                return "".join(out)
            if not multi and c == '"':
                self.i += 1
                return "".join(out)
            if not multi and c == "\n":
                self.error("newline in string")
            if c == "\\":
                e = self.s[self.i + 1:self.i + 2]
                if e in self.ESCAPES:
                    out.append(self.ESCAPES[e])
                    self.i += 2
                elif e in ("u", "U"):
                    n = 4 if e == "u" else 8
                    out.append(chr(int(self.s[self.i + 2:self.i + 2 + n], 16)))
                    self.i += 2 + n
                elif multi and e in ("\n", " ", "\t", "\r"):
                    self.i += 1
                    while self.peek() in ("\n", " ", "\t", "\r"):
                        self.i += 1
                else:
                    self.error("bad escape")
                continue
            out.append(c)
            self.i += 1

    def literal_string(self):
        multi = self.peek(3) == "'''"
        self.i += 3 if multi else 1
        if multi and self.peek() == "\n":
            self.i += 1
        end = self.s.find("'''" if multi else "'", self.i)
        if end < 0 or (not multi and "\n" in self.s[self.i:end]):
            self.error("unterminated string")
        text = self.s[self.i:end]
        self.i = end + (3 if multi else 1)
        return text


# ---------------------------------------------------------------------------------------------
# policy trees
# ---------------------------------------------------------------------------------------------
def get_path(tree, path):
    for k in path.split(".") if path else []:
        if not isinstance(tree, dict) or k not in tree:
            return MISSING
        tree = tree[k]
    return tree


def set_path(tree, path, value):
    keys = path.split(".")
    for k in keys[:-1]:
        tree = tree.setdefault(k, {})
    tree[keys[-1]] = value


def canon(x):
    return json.dumps(x, sort_keys=True)


def union(*lists):
    out, seen = [], set()
    for items in lists:
        for x in items or []:
            if canon(x) not in seen:
                seen.add(canon(x))
                out.append(x)
    return out


# Direction of each key: which change only restricts. Keys not named compare for equality.
CLAUDE_SEMANTICS = {
    "superset_ok": {"permissions.deny", "permissions.ask", "sandbox.credentials.files", "sandbox.credentials.envVars",
                    "deniedMcpServers", "sandbox.filesystem.denyRead", "sandbox.filesystem.denyWrite",
                    "sandbox.network.deniedDomains", "blockedMarketplaces"},
    "subset_ok": {"sandbox.network.allowedDomains", "allowedMcpServers", "strictKnownMarketplaces", "permissions.allow",
                  "sandbox.excludedCommands", "sandbox.filesystem.allowWrite", "sandbox.filesystem.allowRead",
                  "permissions.additionalDirectories", "availableModels", "allowedProviders"},
    "at_most": {"cleanupPeriodDays"},
    "version_at_least": {"requiredMinimumVersion"},
    "version_at_most": {"requiredMaximumVersion"},
    # keys a baseline may lack that only restrict when present with this value (None: any value)
    "extra_ok": {"permissions.deny": None, "permissions.ask": None, "deniedMcpServers": None,
                 "blockedMarketplaces": None, "sandbox.filesystem.denyRead": None, "sandbox.filesystem.denyWrite": None,
                 "sandbox.network.deniedDomains": None, "availableModels": None, "companyAnnouncements": None,
                 "requiredMaximumVersion": None, "forceRemoteSettingsRefresh": True, "disableAllHooks": True,
                 "disableClaudeAiConnectors": True, "sandbox.network.strictAllowlist": True,
                 "managedSourcesBehavior": "first-wins", "permissions.disableAutoMode": "disable",
                 "permissions.defaultMode": ("default", "plan")},
    "choices": {},
}
CODEX_SEMANTICS = {
    "superset_ok": {"permissions.filesystem.deny_read", "rules.prefix_rules"},
    "subset_ok": {"allowed_approval_policies", "allowed_sandbox_modes", "allowed_web_search_modes",
                  "allowed_login_methods", "allowed_chatgpt_workspaces", "allowed_approvals_reviewers"},
    "subset_tables": {"mcp_servers", "marketplaces.allowed_sources"},  # name -> identity; fewer names is stricter
    "allow_tables": {"experimental_network.domains", "allowed_permission_profiles"},  # extra entries only as deny/false
    "at_most": set(), "version_at_least": set(), "version_at_most": set(),
    "extra_ok": {"rules": None, "allowed_approval_policies": None, "allowed_sandbox_modes": None,
                 "allowed_web_search_modes": None, "allowed_login_methods": None, "allowed_chatgpt_workspaces": None,
                 "allowed_approvals_reviewers": None, "enforce_residency": None, "allow_browser_and_computer_use": False,
                 "allow_remote_control": False, "allow_appshots": False},
    "choices": {"default_permissions": {":read-only", ":workspace"}},  # any profile the baseline allows
}


def vkey(version):
    return tuple(int(p) for p in re.findall(r"\d+", str(version))[:3])


def weaker(expected, actual, sem, path=""):
    """Where `actual` is looser than `expected`: missing or changed keys, added allow entries, removed
    deny entries, unknown extra keys. Stricter values and known restricting additions pass."""
    out = []
    if path in sem.get("subset_tables", ()) or path in sem.get("allow_tables", ()):
        if not isinstance(actual, dict):
            return [f"{path}: missing" if actual is MISSING else f"{path}: not a table"]
        allow = path in sem.get("allow_tables", ())
        for k, v in actual.items():
            if allow and v in ("deny", False):
                continue
            if k not in expected or canon(expected[k]) != canon(v) and not (allow and expected[k] in (True, "allow")
                                                                             and v in (True, "allow")):
                out.append(f"{path}.{k}: added or changed ({canon(v)})")
        return out
    if isinstance(expected, dict):
        if actual is MISSING:
            return [f"{path}: missing"]
        if not isinstance(actual, dict):
            return [f"{path or '(root)'}: not an object"]
        for k, v in expected.items():
            out += weaker(v, actual.get(k, MISSING), sem, f"{path}.{k}" if path else k)
        for k, v in actual.items():
            if k not in expected:
                p = f"{path}.{k}" if path else k
                allowed = sem["extra_ok"].get(p, MISSING)
                if allowed is None or allowed is not MISSING and (v in allowed if isinstance(allowed, tuple) else v == allowed):
                    continue
                out.append(f"{p}: not in the baseline and not known to restrict ({canon(v)[:80]})")
        return out
    if actual is MISSING:
        return [f"{path}: missing"]
    if path in sem["choices"]:
        return [] if actual in sem["choices"][path] else [f"{path}: {canon(actual)} is not one the baseline allows"]
    if path in sem["superset_ok"] and isinstance(actual, list):
        lost = [x for x in expected if canon(x) not in {canon(y) for y in actual}]
        return [f"{path}: drops {canon(lost)[:120]}"] if lost else []
    if path in sem["subset_ok"] and isinstance(actual, list):
        added = [x for x in actual if canon(x) not in {canon(y) for y in expected}]
        return [f"{path}: adds {canon(added)[:120]}"] if added else []
    if path in sem["at_most"] and isinstance(actual, (int, float)) and not isinstance(actual, bool):
        return [] if 1 <= actual <= expected else [f"{path}: {actual} > {expected}"]
    if path in sem["version_at_least"] and isinstance(actual, str):
        return [] if vkey(actual) >= vkey(expected) else [f"{path}: {actual} < {expected}"]
    if path in sem["version_at_most"] and isinstance(actual, str):
        return [] if vkey(actual) <= vkey(expected) else [f"{path}: {actual} > {expected}"]
    if isinstance(expected, list) and isinstance(actual, list):
        return [] if sorted(map(canon, expected)) == sorted(map(canon, actual)) else [f"{path}: list differs"]
    return [] if canon(expected) == canon(actual) else [f"{path}: {canon(actual)[:80]} instead of {canon(expected)[:80]}"]


def policy_mismatch(expected, actual):
    """Paths where the Claude Code policy is looser than the baseline (kept for callers of the old name)."""
    return [x.split(":", 1)[0] for x in weaker(expected, actual, CLAUDE_SEMANTICS)]


# ---------------------------------------------------------------------------------------------
# Claude Code: managed sources and how they compose
# ---------------------------------------------------------------------------------------------
CONTROL_KEYS = {"managedSourcesBehavior", "wslInheritsWindowsSettings"}
# Within the file tier (managed-settings.json, then managed-settings.d/*.json in name order)
FILE_TIER_REPLACE_BY_NAME = {"extraKnownMarketplaces", "managedMcpServers"}
FILE_TIER_REPLACE_WHOLE = {"fallbackModel", "modelPicker"}
# Across admin sources ("Keys read from every admin source", managed-settings docs)
CROSS_ANY_TRUE = ["sandbox.network.allowManagedDomainsOnly", "sandbox.filesystem.allowManagedReadPathsOnly",
                  "allowManagedMcpServersOnly", "disableClaudeAiConnectors", "forceRemoteSettingsRefresh"]
CROSS_FILL = ["sandbox.bwrapPath", "sandbox.socatPath", "sandbox.ripgrep", "sandbox.filesystem.disabled",
              "sandbox.network.strictAllowlist", "allowAllClaudeAiMcps"]
# Under managedSourcesBehavior: "merge" (settings-reference, managedSourcesBehavior table)
MERGE_LOCKS = {"allowManagedHooksOnly": True, "allowManagedPermissionRulesOnly": True,
               "allowManagedMcpServersOnly": True, "disableSideloadFlags": True, "disableSkillShellExecution": True,
               "permissions.disableBypassPermissionsMode": "disable", "disableAutoMode": "disable",
               "sandbox.network.allowManagedDomainsOnly": True, "sandbox.filesystem.allowManagedReadPathsOnly": True}
MERGE_TAKE_WHOLE = {"availableModels", "allowedMcpServers", "allowedProviders", "strictKnownMarketplaces",
                    "allowedChannelPlugins", "fallbackModel", "sandbox.credentials.awsPairs", "sandbox.ripgrep"}
MERGE_HIGHEST_ONLY = {"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper",
                      "proxyAuthHelper", "parentSettingsBehavior", "modelPicker", "policyHelper",
                      "permissions.defaultMode"}


def has_policy_key(settings):
    return isinstance(settings, dict) and any(k not in CONTROL_KEYS and v is not None for k, v in settings.items())


def merge_file_tier(base, overlay, path=""):
    out = dict(base)
    for key, value in overlay.items():
        p = f"{path}.{key}" if path else key
        old = out.get(key)
        if p in FILE_TIER_REPLACE_WHOLE:
            out[key] = value
        elif p in FILE_TIER_REPLACE_BY_NAME and isinstance(old, dict) and isinstance(value, dict):
            out[key] = {**old, **value}
        elif isinstance(old, dict) and isinstance(value, dict):
            out[key] = merge_file_tier(old, value, p)
        elif isinstance(old, list) and isinstance(value, list):
            out[key] = union(old, value)
        else:
            out[key] = value
    return out


def merge_ranked(ranked, path=""):
    """managedSourcesBehavior "merge": combine admin sources (highest first) by kind of key."""
    out, keys = {}, []
    for s in ranked:
        keys += [k for k in s if k not in keys]
    for k in keys:
        p = f"{path}.{k}" if path else k
        vals = [s[k] for s in ranked if k in s]
        if p in MERGE_HIGHEST_ONLY:
            if k in ranked[0]:
                out[k] = ranked[0][k]
        elif p == "env":
            env = {}
            for v in vals:
                for name, value in (v or {}).items():
                    env.setdefault(name, value)
            out[k] = env
        elif p in MERGE_LOCKS:
            out[k] = MERGE_LOCKS[p] if MERGE_LOCKS[p] in vals else vals[0]
        elif p in MERGE_TAKE_WHOLE:
            out[k] = vals[0]
        elif p == "managedMcpServers":
            out[k] = {}
            for v in reversed(vals):
                out[k].update(v)
        elif all(isinstance(v, dict) for v in vals):
            sub = [s[k] if isinstance(s.get(k), dict) else {} for s in ranked]
            out[k] = merge_ranked(sub, p)
        elif all(isinstance(v, list) for v in vals):
            out[k] = union(*vals)
        else:
            out[k] = vals[0]
    return out


def apply_cross_source(policy, ranked):
    """managedSourcesBehavior "first-wins": the selected source plus the keys read from every admin source."""
    for p in CROSS_ANY_TRUE:
        if any(get_path(s, p) is True for s in ranked):
            set_path(policy, p, True)
    for p in CROSS_FILL:
        for s in ranked:
            if get_path(s, p) is not MISSING:
                set_path(policy, p, get_path(s, p))
                break
    denied = union(*[get_path(s, "deniedMcpServers") for s in ranked if isinstance(get_path(s, "deniedMcpServers"), list)])
    if denied:
        policy["deniedMcpServers"] = denied
    if get_path(policy, "sandbox.network.allowManagedDomainsOnly") is True:
        lists = [get_path(s, "sandbox.network.allowedDomains") for s in ranked]
        set_path(policy, "sandbox.network.allowedDomains", union(*[x for x in lists if isinstance(x, list)]))
        fetch = [r for s in ranked for r in (get_path(s, "permissions.allow") if isinstance(get_path(s, "permissions.allow"), list) else [])
                 if isinstance(r, str) and r.startswith("WebFetch(domain:")]
        if fetch:
            current = get_path(policy, "permissions.allow")
            set_path(policy, "permissions.allow", union(current if isinstance(current, list) else [], fetch))
    if get_path(policy, "sandbox.filesystem.allowManagedReadPathsOnly") is True:
        lists = [get_path(s, "sandbox.filesystem.allowRead") for s in ranked]
        if any(isinstance(x, list) for x in lists):
            set_path(policy, "sandbox.filesystem.allowRead", union(*[x for x in lists if isinstance(x, list)]))
    if get_path(policy, "allowManagedMcpServersOnly") is True:
        for s in ranked:
            if isinstance(s.get("allowedMcpServers"), list):
                policy["allowedMcpServers"] = s["allowedMcpServers"]
                break
    env = {}
    for s in ranked:  # per variable, highest source first (Claude Code 2.1.223+)
        for name, value in (s.get("env") or {}).items() if isinstance(s.get("env"), dict) else ():
            env.setdefault(name, value)
    if env:
        policy["env"] = env
    return policy


def effective_claude(sources):
    """sources: [(name, settings)] for the admin sources present, highest rank first.
    Returns (policy, behaviour, names of the sources that contribute) or (None, None, [])."""
    policy_sources = [(n, s) for n, s in sources if has_policy_key(s)]
    if not policy_sources:
        return None, None, []
    carrier = next(s for n, s in sources if has_policy_key(s) or "managedSourcesBehavior" in s)
    behaviour = carrier.get("managedSourcesBehavior", "first-wins")
    ranked = [{k: v for k, v in s.items() if k != "managedSourcesBehavior"} for _, s in policy_sources]
    if behaviour == "merge":
        policy, used = merge_ranked(ranked), [n for n, _ in policy_sources]
    else:
        policy = apply_cross_source(copy.deepcopy(ranked[0]), ranked)
        used = [policy_sources[0][0]] + [n for n, s in policy_sources[1:]
                                         if any(get_path(s, p) is not MISSING for p in CROSS_ANY_TRUE + CROSS_FILL)
                                         or s.get("env") or s.get("deniedMcpServers")
                                         or get_path(s, "sandbox.network.allowedDomains") is not MISSING]
    if "managedSourcesBehavior" in carrier:
        policy["managedSourcesBehavior"] = behaviour
    return policy, behaviour, used


def read_json_object(path, what):
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{what} {path} is not a JSON object")
    return data


def dropin_files(directory):
    """Claude Code reads *.json in name order and ignores hidden files and other extensions."""
    used, ignored = [], []
    if directory.is_dir():
        for p in sorted(directory.iterdir(), key=lambda x: x.name):
            if p.name.startswith(".") or not p.name.endswith(".json") or not p.is_file():
                ignored.append(p)
            else:
                used.append(p)
    return used, ignored


def read_registry(hive, path=r"SOFTWARE\Policies\ClaudeCode"):
    """The Settings value of a Windows policy key as text, or None."""
    try:
        import winreg
        root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
        with winreg.OpenKey(root, path) as k:
            return winreg.QueryValueEx(k, "Settings")[0]
    except (OSError, ImportError):
        return None


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
            "codex_legacy": Path("/etc/codex/managed_config.toml"),
            "claude_mdm": Path("/Library/Managed Preferences/com.anthropic.claudecode.plist"),
            "codex_mdm": Path("/Library/Managed Preferences/com.openai.codex.plist"),
            "claude_user_plist": Path.home() / "Library/Preferences/com.anthropic.claudecode.plist",
            "claude_remote_cache": Path.home() / ".claude/remote-settings.json",
            "claude_user_settings": Path.home() / ".claude/settings.json"}


def windows_policy_files():
    pf = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    pd = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
    return {"claude_file": pf / "ClaudeCode/managed-settings.json", "claude_dropins": pf / "ClaudeCode/managed-settings.d",
            "codex_file": pd / "OpenAI/Codex/requirements.toml", "codex_legacy": pd / "OpenAI/Codex/managed_config.toml",
            "claude_remote_cache": Path.home() / ".claude/remote-settings.json",
            "claude_user_settings": Path.home() / ".claude/settings.json"}


def policy_files(kind):
    return windows_policy_files() if kind == "windows" else unix_policy_files(kind)


def present(files, key):
    p = files.get(key)
    return p if p is not None and p.exists() else None


def claude_sources(kind, files, out):
    """Admin sources present on this machine, highest rank first: [(name, settings)]. Parse errors and
    the server-managed visibility are reported into `out`."""
    sources = []
    cache = present(files, "claude_remote_cache")
    if cache:
        try:
            sources.append(("server-managed (local cache)", read_json_object(cache, "server-managed cache")))
            out.append(result("claude.server_managed", INFO, f"{cache} found and ranked above the local policy; "
                              "the live payload may differ until the next fetch", "R15"))
        except (OSError, ValueError) as e:
            out.append(result("claude.server_managed", NOT_RUN, f"{cache} unreadable: {e}", "R15"))
    elif "claude_remote_cache" in files:
        out.append(result("claude.server_managed", NOT_RUN, "server-managed settings (claude.ai console or a gateway) "
                          "rank above every local source and are not visible here; no local cache at "
                          f"{files['claude_remote_cache']}", "R15"))
    else:
        out.append(result("claude.server_managed", NOT_RUN, "server-managed settings not inspected", "R15"))
    try:
        if kind == "macos" and present(files, "claude_mdm"):
            with open(files["claude_mdm"], "rb") as f:
                sources.append(("plist", plistlib.load(f)))
        if kind == "windows":
            text = read_registry("HKLM")
            if text is not None:
                sources.append(("HKLM", json.loads(text)))
        used, ignored = dropin_files(files["claude_dropins"]) if "claude_dropins" in files else ([], [])
        for p in ignored:
            out.append(result("claude.dropin_ignored", INFO, f"{p}: hidden or not *.json, Claude Code does not read it"))
        if present(files, "claude_file") or used:
            settings = read_json_object(files["claude_file"], "managed settings") if present(files, "claude_file") else {}
            for path in used:
                settings = merge_file_tier(settings, read_json_object(path, "managed drop-in"))
            sources.append(("file" if not used else "file + drop-ins" if present(files, "claude_file") else "drop-ins",
                            settings))
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        out.append(result("claude.policy_parse", FAILS, f"{e}; Claude Code refuses to start on an unparsable source", "R15"))
    return sources


def check_claude(kind, files, out):
    expected_path = BUILD / ("claude/managed-settings.windows.json" if kind == "windows" else "claude/managed-settings.json")
    sources = claude_sources(kind, files, out)
    hkcu = read_registry("HKCU") if kind == "windows" else None
    policy, behaviour, used = effective_claude(sources)
    if policy is None and hkcu is not None:
        out.append(result("claude.no_user_writable_policy", FAILS, "HKCU policy present and no admin source: it applies", "R15"))
    elif kind == "windows":
        out.append(result("claude.no_user_writable_policy", HOLDS, "HKCU policy present, shadowed by the admin source"
                          if hkcu is not None else "no HKCU policy", "R15"))
    if policy is None:
        out.append(result("claude.policy_delivered", FAILS, "no managed source with a policy key "
                          "(server-managed cache, plist, HKLM or managed-settings.json/.d)", "R15"))
    else:
        out.append(result("claude.policy_delivered", HOLDS, f"in effect: {', '.join(used)} ({behaviour}); "
                          f"present: {', '.join(n for n, _ in sources)}", "R15"))
        if expected_path.exists():
            diff = weaker(json.loads(expected_path.read_text()), policy, CLAUDE_SEMANTICS)
            out.append(result("claude.policy_matches_baseline", FAILS if diff else HOLDS,
                              ("looser than the baseline: " + "; ".join(diff)) if diff
                              else f"at least as strict as {expected_path.relative_to(ROOT)}"))
        else:
            out.append(result("claude.policy_matches_baseline", NOT_RUN, f"{expected_path} is missing"))
    if kind != "windows" and (present(files, "claude_file") or present(files, "claude_dropins")):
        if present(files, "claude_file"):
            w = writable_by_non_root(files["claude_file"])
            out.append(result("claude.policy_file_owner", FAILS if w else HOLDS,
                              f"replaceable through {w}" if w else "file and parents owned by root, not group/other-writable", "R15"))
        for dropin in dropin_files(files["claude_dropins"])[0]:
            w = writable_by_non_root(dropin)
            out.append(result("claude.dropin_owner", FAILS if w else HOLDS,
                              str(dropin) + (f" replaceable through {w}" if w else " admin-owned"), "R15"))
        if present(files, "claude_dropins"):
            w = writable_by_non_root(files["claude_dropins"])
            out.append(result("claude.dropin_directory_owner", FAILS if w else HOLDS,
                              str(files["claude_dropins"]) + (f" replaceable through {w}" if w else " admin-owned"), "R15"))
    if kind == "macos" and "claude_user_plist" in files:
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
    user = present(files, "claude_user_settings")
    if user:
        try:
            s = read_json_object(user, "user settings")
            entries = {k: get_path(s, k) for k in ("sandbox.excludedCommands", "sandbox.filesystem.allowWrite")}
            entries = {k: v for k, v in entries.items() if isinstance(v, list) and v}
            out.append(result("claude.user_sandbox_exceptions", FAILS if entries else HOLDS,
                              f"{user}: " + "; ".join(f"{k} = {canon(v)[:100]}" for k, v in entries.items())
                              + " (no managed-only lock exists for these keys)" if entries else f"{user}: none", "R20"))
        except (OSError, ValueError) as e:
            out.append(result("claude.user_sandbox_exceptions", NOT_RUN, f"{user}: {e}", "R20"))


# ---------------------------------------------------------------------------------------------
# Codex: requirements layers
# ---------------------------------------------------------------------------------------------
CODEX_ALIASES = {"network_proxy": "experimental_network", "feature_requirements": "features"}


def effective_codex(layers):
    """layers: [(name, requirements)] highest precedence first. Per config_requirements.rs
    (merge_unset_fields), each top-level field comes whole from the highest layer that sets it.
    allowed_permission_profiles combine by profile name (managed-configuration docs); taking the union
    with the higher layer winning per name can only make the checker stricter."""
    out = {}
    for _, req in layers:
        req = {CODEX_ALIASES.get(k, k): v for k, v in req.items()}
        for k, v in req.items():
            if k == "allowed_permission_profiles" and isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = {**v, **out[k]}
            elif k not in out:
                out[k] = v
    return out


def check_codex(kind, files, out):
    layers = []
    try:
        if kind == "macos" and present(files, "codex_mdm"):
            with open(files["codex_mdm"], "rb") as f:
                data = plistlib.load(f)
            if "requirements_toml_base64" in data:
                layers.append(("MDM", toml_loads(base64.b64decode(data["requirements_toml_base64"]).decode())))
        if present(files, "codex_legacy"):
            out.append(result("codex.legacy_managed_config", NOT_RUN, f"{files['codex_legacy']} present: Codex "
                              "reinterprets its approval_policy and sandbox_mode as requirements; not modelled here", "R15"))
        out.append(result("codex.cloud_requirements", NOT_RUN, "cloud-delivered requirements (ChatGPT workspace) rank "
                          "above the system file and are not visible here", "R15"))
        if present(files, "codex_file"):
            layers.append(("file", toml_loads(files["codex_file"].read_text())))
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        out.append(result("codex.policy_parse", FAILS, str(e), "R15"))
    if not layers:
        out.append(result("codex.policy_delivered", FAILS, "no requirements.toml or MDM requirements found", "R15"))
    else:
        out.append(result("codex.policy_delivered", HOLDS, "layers: " + ", ".join(n for n, _ in layers), "R15"))
        expected = BUILD / "codex/requirements.toml"
        if expected.exists():
            diff = weaker(toml_loads(expected.read_text()), effective_codex(layers), CODEX_SEMANTICS)
            out.append(result("codex.policy_matches_baseline", FAILS if diff else HOLDS,
                              ("looser than the baseline: " + "; ".join(diff)) if diff
                              else "at least as strict as build/codex/requirements.toml"))
        else:
            out.append(result("codex.policy_matches_baseline", NOT_RUN, "build baseline is missing"))
    if present(files, "codex_file") and kind != "windows":
        w = writable_by_non_root(files["codex_file"])
        out.append(result("codex.policy_file_owner", FAILS if w else HOLDS,
                          f"replaceable through {w}" if w else "file and parents owned by root, not group/other-writable", "R15"))


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
    files = policy_files(kind)
    out = []
    check_claude(kind, files, out)
    check_codex(kind, files, out)
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
HELPER_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper",
               "statusLine", "fileSuggestion")


def load_coverage(build=None):
    """Per rule: which keys this build sets and which checks the rule claims (build/coverage.json)."""
    build = Path(build or BUILD)
    try:
        cov = json.loads((build / "coverage.json").read_text())["rules"]
        policies = {"claude": json.loads((build / "claude/managed-settings.json").read_text()),
                    "codex": toml_loads((build / "codex/requirements.toml").read_text())}
    except (OSError, ValueError, KeyError):
        return {}, {}
    return cov, policies


def key_in_build(policy, key, want):
    have = get_path(policy, key)
    if have is MISSING:
        return False
    if isinstance(want, list):
        return isinstance(have, list) and all(canon(x) in {canon(y) for y in have} for x in want)
    if isinstance(want, dict) and isinstance(have, dict):
        return all(key_in_build(have, k, v) for k, v in want.items() if "." not in k) and \
            all(canon(have.get(k)) == canon(v) for k, v in want.items() if "." in k)
    return canon(have) == canon(want)


def covered(check_id, rule, agent, coverage):
    """How the baseline neutralises a finding, derived from rules.yaml (via build/coverage.json) and the
    built policy: 'build' when the rule claims this check and the build holds every key the rule sets for
    the agent; 'launcher' or 'deployment' when the rule works outside managed settings; None otherwise."""
    cov, policies = coverage
    r = cov.get(rule or "")
    if not r or check_id not in r["checks"]:
        return None, None
    keys = r[agent + "_keys"]
    version = (r.get("min_version") or {}).get(agent)
    if keys:
        return ("build" if all(key_in_build(policies[agent], k, v) for k, v in keys.items()) else None), version
    if r[agent + "_coverage"] == "built in":
        return "built in", version
    if r["deployment"]:
        return ("launcher" if rule == "R17" else "deployment"), version
    return None, version


def finding(check, path, what, rule, coverage, agent="claude"):
    how, version = covered(check, rule, agent, coverage)
    return {"check": check, "outcome": FAILS, "rule": rule, "evidence": f"{path}: {what}",
            "neutralised_by_baseline": how is not None, "neutralised_how": how,
            "requires": f"{'Claude Code' if agent == 'claude' else 'Codex'} {version}+" if how and version else None}


def git_tracked(repo, rel):
    try:
        return subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", rel],
                              capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def scan_claude_settings(repo, rel, cov):
    out = []
    try:
        s = read_json_object(repo / rel, "settings")
    except (OSError, ValueError):
        return [finding("repo.claude_settings_unreadable", rel, "not valid JSON", None, cov)]
    if s.get("hooks"):
        out.append(finding("repo.hooks", rel, "hooks: " + ", ".join(s["hooks"]), "R01", cov))
    # Helpers and the env block: interactive sessions hold them behind the trust dialog; non-interactive
    # runs ignore project settings only when started through wrappers/claude-untrusted (R17).
    for k in HELPER_KEYS:
        if k in s:
            out.append(finding("repo.helper_command", rel, f"{k} runs a command", "R17", cov))
    env = s.get("env") or {}
    if env:
        out.append(finding("repo.env", rel, "env sets " + ", ".join(sorted(env)), "R17", cov))
    perms = s.get("permissions") or {}
    mode = perms.get("defaultMode")
    if mode in ("bypassPermissions", "auto"):
        out.append(finding("repo.default_mode", rel, f"permissions.defaultMode = {mode}", "R03" if mode == "bypassPermissions" else "R18", cov))
    if s.get("enableAllProjectMcpServers") or s.get("enabledMcpjsonServers"):
        out.append(finding("repo.mcp_autoapprove", rel, "pre-approves the project's MCP servers", "R02", cov))
    if perms.get("allow"):
        out.append(finding("repo.allow_rules", rel, "allow rules: " + ", ".join(map(str, perms["allow"][:5])), "R08", cov))
    if s.get("extraKnownMarketplaces"):
        out.append(finding("repo.marketplaces", rel, "registers marketplaces: " + ", ".join(s["extraKnownMarketplaces"]), "R09", cov))
    if s.get("enabledPlugins"):
        out.append(finding("repo.plugins", rel, "enables plugins: " + ", ".join(s["enabledPlugins"]), "R09", cov))
    sandbox = s.get("sandbox") or {}
    loosen = {k: get_path(sandbox, k) for k in ("excludedCommands", "filesystem.allowWrite", "network.allowedDomains")}
    loosen = {k: v for k, v in loosen.items() if v not in (MISSING, None, [])}
    if loosen:
        out.append(finding("repo.sandbox_exceptions", rel, "; ".join(f"sandbox.{k} = {canon(v)[:80]}" for k, v in loosen.items()), "R20", cov))
    return out


FRONTMATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(\n|\Z)", re.S)


def scan_agent(repo, rel, cov):
    """A subagent definition: its frontmatter can set a permission mode, MCP servers and hooks."""
    m = FRONTMATTER.match((repo / rel).read_text(errors="replace"))
    if not m:
        return []
    fm, out = m.group(1), []
    if re.search(r"^permissionMode:\s*['\"]?bypassPermissions", fm, re.M):
        out.append(finding("repo.agent_bypass", rel, "permissionMode: bypassPermissions", "R03", cov))
    if re.search(r"^mcpServers:", fm, re.M):
        out.append(finding("repo.agent_mcp", rel, "defines MCP servers in frontmatter", "R02", cov))
    if re.search(r"^hooks:", fm, re.M):
        out.append(finding("repo.agent_hooks", rel, "hooks in frontmatter", "R01", cov))
    return out


def walk(repo):
    """Every file under the repository except .git, in a stable order, without following symlinked directories."""
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = sorted(d for d in dirnames if d != ".git")
        for name in sorted(filenames):
            yield (Path(dirpath) / name).relative_to(repo).as_posix()


def check_repo(repo, build=None):
    repo = Path(repo).resolve()
    cov = load_coverage(build)
    if not repo.is_dir():
        return [finding("repo.missing", str(repo), "repository directory is missing", None, cov)]
    out = []
    for rel in walk(repo):
        name, parts = rel.rsplit("/", 1)[-1], rel.split("/")
        parent = parts[-2] if len(parts) > 1 else ""
        if parent == ".claude" and name in ("settings.json", "settings.local.json"):
            if name == "settings.local.json" and not git_tracked(repo, rel):
                continue  # an untracked local file is the developer's own, not the repository's
            out += scan_claude_settings(repo, rel, cov)
        elif name == ".mcp.json":
            try:
                servers = read_json_object(repo / rel, ".mcp.json").get("mcpServers", {})
                if not isinstance(servers, dict):
                    raise ValueError("mcpServers is not an object")
            except (OSError, ValueError):
                out.append(finding("repo.mcp_unreadable", rel, "not valid JSON; Claude Code may still read part of it", None, cov))
                continue
            for sname, spec in servers.items():
                spec = spec if isinstance(spec, dict) else {}
                what = ("runs " + " ".join([str(spec.get("command", ""))] + [str(a) for a in spec.get("args", [])])
                        if "command" in spec else f"connects {spec.get('url', '?')}")
                out.append(finding("repo.mcp", rel, f"server {sname} {what}", "R02", cov))
        elif parent == ".codex" and name == "config.toml":
            try:
                config = toml_loads((repo / rel).read_text())
                if not isinstance(config.get("mcp_servers", {}), dict):
                    raise ValueError("mcp_servers must be a table")
            except (ValueError, TypeError):
                config = {}
                out.append(finding("repo.codex_config_invalid", rel, "invalid TOML", None, cov, "codex"))
            for sname in config.get("mcp_servers", {}):
                out.append(finding("repo.mcp", rel, f"server {sname}", "R02", cov, "codex"))
            if config.get("hooks"):
                out.append(finding("repo.hooks", rel, "inline hooks", "R01", cov, "codex"))
            if "notify" in config:
                row = finding("repo.helper_command", rel, "notify runs a command (ignored by Codex in project config)", None, cov, "codex")
                row.update(neutralised_by_baseline=True, neutralised_how="built in")
                out.append(row)
        elif parent == ".codex" and name == "hooks.json":
            out.append(finding("repo.hooks", rel, "hook definitions", "R01", cov, "codex"))
        elif (len(parts) >= 4 and parts[-4] == ".claude" and parts[-3] == "skills" and name == "SKILL.md") or \
                (".claude" in parts and "commands" in parts and parts.index("commands") == parts.index(".claude") + 1
                 and name.endswith(".md")):
            text = (repo / rel).read_text(errors="replace")
            if re.search(r"!`|```!", text):
                out.append(finding("repo.skill_shell", rel, "inline shell execution", "R10", cov))
            if re.search(r"^hooks:", text, re.M):
                out.append(finding("repo.hooks", rel, "hooks in skill frontmatter", "R01", cov))
        elif ".claude" in parts and "agents" in parts and parts.index("agents") == parts.index(".claude") + 1 \
                and name.endswith(".md"):
            out += scan_agent(repo, rel, cov)
        elif name == ".env" and re.search(r"^\s*CODEX_HOME\s*=", (repo / rel).read_text(errors="replace"), re.M):
            out.append(finding("repo.codex_home", rel, "sets CODEX_HOME (CVE-2025-61260 pattern)", None, cov, "codex"))
        elif name in (".yarnrc.yml", ".yarnrc") and re.search(r"yarnPath|yarn-path", (repo / rel).read_text(errors="replace")):
            out.append(finding("repo.package_manager_exec", rel, "yarnPath runs repository code on any yarn call "
                               "(GHSA-2jjv-qf24-vfm4 pattern)", None, cov))
        elif name in ("CLAUDE.md", "AGENTS.md"):
            out.append({"check": "repo.instructions", "outcome": INFO, "rule": None,
                        "evidence": f"{rel}: instructions the agent reads every session; review like code",
                        "neutralised_by_baseline": False, "neutralised_how": None, "requires": None})
    commondir = repo / ".git/commondir"
    if commondir.exists():
        out.append(finding("repo.git_commondir", ".git/commondir", "points to " + commondir.read_text().strip()
                           + " (GHSA-q5hj-mxqh-vv77 pattern)", None, cov))
    return out


def label(r):
    if r["outcome"] != FAILS or "neutralised_by_baseline" not in r:
        return ""
    if not r["neutralised_by_baseline"]:
        return " [NOT covered by the baseline]"
    how = {"build": "", "built in": " (built into the agent)", "deployment": " (by deployment, see the rule)",
           "launcher": " when started through wrappers/claude-untrusted"}[r["neutralised_how"]]
    return f" [neutralised by the baseline{how}" + (f"; needs {r['requires']}" if r.get("requires") else "") + "]"


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
            print(f"{r['outcome']:>14}  {r['check']:<32} {r['rule'] or '':<4} {r['evidence']}{label(r)}")
    bad = [r for r in rows if r["outcome"] == FAILS and not r.get("neutralised_by_baseline", False)]
    incomplete = any(r["outcome"] == NOT_RUN for r in rows)
    sys.exit(1 if bad else 2 if incomplete else 0)


if __name__ == "__main__":
    main()
