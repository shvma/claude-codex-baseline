#!/usr/bin/env python3
"""Build every deliverable from baseline/rules.yaml and baseline/site.yaml (or site.example.yaml).

    python3 tools/build.py [--site baseline/site.yaml]

Writes to build/:
  claude/managed-settings.json            macOS, Linux
  claude/managed-settings.windows.json    Windows (adds Windows-only rules)
  codex/requirements.toml
  macos/coding-agent-baseline.mobileconfig   both preference domains; Jamf or Intune (macOS custom profile)
  jamf/com.anthropic.claudecode.plist        Jamf "Application & Custom Settings", one per domain
  jamf/com.openai.codex.plist
  intune/windows/Install-CodingAgentBaseline.ps1   Intune platform script
  MANIFEST.md                              which rule produced which key
  coverage.json                            per rule: keys, checks, min_version; read by check.py and gate/decide.py
Output is deterministic: the same input gives byte-identical files.
"""
import argparse
import base64
import copy
import json
import plistlib
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build"  # overridden by --out
NS = uuid.UUID("6f1d2c4e-8a3b-4c5d-9e7f-0a1b2c3d4e5f")  # fixed namespace -> stable payload UUIDs


def set_dotted(tree, dotted, value):
    keys = dotted.split(".")
    for k in keys[:-1]:
        tree = tree.setdefault(k, {})
    merge_value(tree, keys[-1], value)


def merge_value(tree, key, value):
    """Lists union, tables merge key by key (two rules, or a rule and a site value, may fill one table)."""
    old = tree.get(key)
    if isinstance(old, list) and isinstance(value, list):
        tree[key] = old + [v for v in value if v not in old]
    elif isinstance(old, dict) and isinstance(value, dict):
        for k, v in value.items():
            merge_value(old, k, v)
    else:
        tree[key] = copy.deepcopy(value)


def get_dotted(tree, dotted):
    for k in dotted.split("."):
        if not isinstance(tree, dict) or k not in tree:
            return None
        tree = tree[k]
    return tree


def compose(rules, site, platform):
    claude, codex, manifest = {}, {}, []
    for rule in rules:
        if platform not in rule.get("platforms", ["macos", "linux", "windows"]):
            continue
        for agent, tree in (("claude", claude), ("codex", codex)):
            for key, value in (rule.get(agent) or {}).items():
                set_dotted(tree, key, value)
                manifest.append((rule["id"], agent, key))
        for target, site_path in (rule.get("site") or {}).items():
            value = get_dotted(site, site_path)
            if value is None:
                continue
            agent, key = target.split(".", 1)
            set_dotted(claude if agent == "claude" else codex, key, value)
            manifest.append((rule["id"], agent, key + " (site)"))
    return claude, codex, manifest


def vkey(version):
    return tuple(int(p) for p in str(version).split("."))


def coverage(rules, claude, codex):
    """What each rule puts into this build, for the checker and the gate (they need no YAML parser).
    Rule keys carry the value the rule asks for; site keys the value the build ended up with."""
    out = {}
    for rule in rules:
        keys = {"claude": dict(rule.get("claude") or {}), "codex": dict(rule.get("codex") or {})}
        for target in rule.get("site") or {}:
            agent, key = target.split(".", 1)
            value = get_dotted(claude if agent == "claude" else codex, key)
            if value is not None:
                keys[agent][key] = value
        out[rule["id"]] = {"title": rule["title"], "checks": rule.get("checks") or [],
                           "claude_keys": keys["claude"], "codex_keys": keys["codex"],
                           "deployment": bool(rule.get("deployment")), "min_version": rule.get("min_version") or {},
                           "platforms": rule.get("platforms", ["macos", "linux", "windows"]),
                           "claude_coverage": agent_coverage(rule, "claude"),
                           "codex_coverage": agent_coverage(rule, "codex")}
    return out


def agent_coverage(rule, agent):
    """key / built in / deployment / none — how a rule reaches one agent."""
    gap = (rule.get("gap") or {}).get(agent, "")
    if rule.get(agent) or any(t.startswith(agent + ".") for t in rule.get("site") or {}):
        return "key"
    if gap.startswith(("Built in", "Project config is covered")):
        return "built in"
    if gap:
        return "none"
    return "deployment" if rule.get("deployment") else "none"


# --- TOML: the subset requirements.toml needs (strings, booleans, numbers, arrays, inline and nested tables) ---
def toml_value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{toml_key(k)} = {toml_value(x)}" for k, x in v.items()) + "}"
    raise TypeError(f"unsupported TOML value {v!r}")


def toml_key(k):
    return k if k.replace("_", "").replace("-", "").isalnum() else json.dumps(k)


def to_toml(tree, prefix=()):
    scalars = {k: v for k, v in tree.items() if not isinstance(v, dict)}
    tables = {k: v for k, v in tree.items() if isinstance(v, dict)}
    lines = []
    if prefix and (scalars or not tables):
        lines.append("[" + ".".join(toml_key(p) for p in prefix) + "]")
    lines += [f"{toml_key(k)} = {toml_value(v)}" for k, v in scalars.items()]
    for k, v in tables.items():
        if lines:
            lines.append("")
        lines.append(to_toml(v, prefix + (k,)).rstrip("\n"))
    return "\n".join(lines) + "\n"


# --- macOS profile -------------------------------------------------------------------------------
def payload(domain, settings):
    pid = str(uuid.uuid5(NS, domain)).upper()
    return {"PayloadDisplayName": domain, "PayloadIdentifier": f"org.baseline.coding-agents.{pid}",
            "PayloadType": "com.apple.ManagedClient.preferences", "PayloadUUID": pid, "PayloadVersion": 1,
            "PayloadContent": {domain: {"Forced": [{"mcx_preference_settings": settings}]}}}


def mobileconfig(claude, codex_b64):
    return {"PayloadDisplayName": "Coding agent baseline (Claude Code, Codex)",
            "PayloadDescription": "Managed policy for Claude Code and OpenAI Codex, built from baseline/rules.yaml.",
            "PayloadIdentifier": "org.baseline.coding-agents", "PayloadScope": "System",
            "PayloadType": "Configuration", "PayloadUUID": str(uuid.uuid5(NS, "profile")).upper(),
            "PayloadVersion": 1, "PayloadRemovalDisallowed": True,
            "PayloadContent": [payload("com.anthropic.claudecode", claude),
                               payload("com.openai.codex", {"requirements_toml_base64": codex_b64})]}


# --- Windows -------------------------------------------------------------------------------------
PS1 = r"""<#
Coding agent baseline for Windows: Claude Code managed settings and Codex requirements.
Generated by tools/build.py from baseline/rules.yaml. Do not edit by hand.

Intune: Devices > Scripts and remediations > Platform scripts > Add (Windows 10 and later).
  Run this script using the logged on credentials: No      (runs as SYSTEM)
  Run script in 64 bit PowerShell Host: Yes

Both directories are reset to administrator-only write access before the files are written:
a directory a standard user created in advance would otherwise let that user replace the policy
(GHSA-5cwg-9f6j-9jvx is this class of issue for Claude Code; rule R15).
#>
$ErrorActionPreference = 'Stop'

function Write-AdminOnlyFile([string]$Dir, [string]$Name, [string]$Content) {
    New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    # Refuse reparse points and replaceable parents; never follow an attacker-owned link.
    $parent = (Get-Item -LiteralPath $Dir).Parent
    while ($null -ne $parent) {
        if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse parent: $parent" }
        $parentAcl = Get-Acl -LiteralPath $parent.FullName
        $owner = $parentAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-18', 'S-1-5-32-544') -and -not $owner.StartsWith('S-1-5-80-')) {
            throw "Untrusted parent owner: $parent"
        }
        foreach ($ace in $parentAcl.Access) {
            $sid = $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            $dangerous = [Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
            if ($ace.AccessControlType -eq 'Allow' -and ($ace.FileSystemRights -band $dangerous) -and
                $sid -notin @('S-1-5-18', 'S-1-5-32-544') -and -not $sid.StartsWith('S-1-5-80-')) {
                throw "Replaceable parent: $parent"
            }
        }
        $parent = $parent.Parent
    }
    # Fresh DACL, not /grant:r: remove pre-existing explicit grants too.
    function Protect-Item([string]$ItemPath, [bool]$Directory) {
        $item = Get-Item -LiteralPath $ItemPath -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point: $ItemPath" }
        $type = if ($Directory) { 'System.Security.AccessControl.DirectorySecurity' } else { 'System.Security.AccessControl.FileSecurity' }
        $acl = New-Object $type
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        foreach ($entry in @(@('S-1-5-18', 'FullControl'), @('S-1-5-32-544', 'FullControl'), @('S-1-5-32-545', 'ReadAndExecute'))) {
            $sid = New-Object Security.Principal.SecurityIdentifier($entry[0])
            $inheritance = if ($Directory) { 'ContainerInherit,ObjectInherit' } else { 'None' }
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, $entry[1], $inheritance, 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $ItemPath -AclObject $acl
    }
    Protect-Item $Dir $true
    $path = Join-Path $Dir $Name
    if (Test-Path -LiteralPath $path) { Protect-Item $path $false }
    [System.IO.File]::WriteAllText($path, $Content, (New-Object System.Text.UTF8Encoding($false)))
    Protect-Item $path $false
    Write-Output "Wrote $path"
}

$claude = @'
__CLAUDE__
'@

$codex = @'
__CODEX__
'@

Write-AdminOnlyFile (Join-Path $env:ProgramFiles 'ClaudeCode') 'managed-settings.json' $claude
Write-AdminOnlyFile (Join-Path $env:ProgramData 'OpenAI\Codex') 'requirements.toml' $codex
"""


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    default_site = ROOT / "baseline/site.yaml"
    ap.add_argument("--site", default=str(default_site if default_site.exists() else ROOT / "baseline/site.example.yaml"))
    ap.add_argument("--out", default=str(ROOT / "build"))
    args = ap.parse_args()
    global OUT
    OUT = Path(args.out).resolve()
    rules = yaml.safe_load((ROOT / "baseline/rules.yaml").read_text())["rules"]
    site = yaml.safe_load(Path(args.site).read_text()) or {}
    floor = max((r["min_version"]["claude"] for r in rules if "claude" in (r.get("min_version") or {})), key=vkey)
    site_min = get_dotted(site, "versions.claude.min")
    if site_min is not None and vkey(site_min) < vkey(floor):
        raise SystemExit(f"{args.site}: versions.claude.min {site_min} is below {floor}, the oldest Claude Code "
                         "that enforces every rule (min_version in rules.yaml)")

    claude, codex, manifest = compose(rules, site, "macos")
    claude_win, codex_win, manifest_win = compose(rules, site, "windows")
    claude_json = json.dumps(claude, indent=2) + "\n"
    claude_win_json = json.dumps(claude_win, indent=2) + "\n"
    codex_toml = to_toml(codex)
    codex_win_toml = to_toml(codex_win)
    codex_b64 = base64.b64encode(codex_toml.encode()).decode()

    write(OUT / "claude/managed-settings.json", claude_json)
    write(OUT / "claude/managed-settings.windows.json", claude_win_json)
    write(OUT / "codex/requirements.toml", codex_toml)
    write(OUT / "macos/coding-agent-baseline.mobileconfig", plistlib.dumps(mobileconfig(claude, codex_b64), sort_keys=False))
    write(OUT / "jamf/com.anthropic.claudecode.plist", plistlib.dumps(claude, sort_keys=False))
    write(OUT / "jamf/com.openai.codex.plist", plistlib.dumps({"requirements_toml_base64": codex_b64}))
    write(OUT / "intune/windows/Install-CodingAgentBaseline.ps1",
          PS1.replace("__CLAUDE__", claude_win_json.rstrip("\n")).replace("__CODEX__", codex_win_toml.rstrip("\n")))

    rows = ["# Build manifest", "", f"Site file: `{Path(args.site).resolve().relative_to(ROOT)}`.", "",
            "| Rule | Agent | Key | Platforms |", "|---|---|---|---|"]
    seen = {}
    for rid, agent, key in manifest_win:
        seen.setdefault((rid, agent, key), "windows")
    for rid, agent, key in manifest:
        seen[(rid, agent, key)] = "all"
    rows += [f"| {r} | {a} | `{k}` | {p} |" for (r, a, k), p in seen.items()]
    cov = coverage(rules, claude, codex)
    for agent, name in (("codex", "Codex"), ("claude", "Claude Code")):
        by = {kind: [rid for rid, c in cov.items() if c[agent + "_coverage"] == kind]
              for kind in ("built in", "deployment", "none")}
        rows += ["", f"{name} rules without a key (see `gap` and `deployment` in rules.yaml): "
                 f"built in: {', '.join(by['built in']) or 'none'}; "
                 f"by deployment: {', '.join(by['deployment']) or 'none'}; "
                 f"no control: {', '.join(by['none']) or 'none'}."]
    write(OUT / "MANIFEST.md", "\n".join(rows) + "\n")
    write(OUT / "coverage.json", json.dumps({"rules": cov}, indent=1, sort_keys=True) + "\n")
    print(f"{len(rules)} rules -> {len(claude)} Claude top-level keys, {len(codex)} Codex top-level keys; build/ written")


if __name__ == "__main__":
    main()
