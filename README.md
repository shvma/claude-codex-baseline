# claude-codex-baseline

**One threat-driven security baseline for Claude Code and OpenAI Codex: generated MDM profiles for Jamf and Intune, a checker that shows where the policy is not in force, and a release gate that re-tests the policy on every new agent version.**

```
baseline/rules.yaml ──► tools/build.py ──► managed-settings.json · requirements.toml · .mobileconfig · Jamf plists · Intune script
        │
        ├──► tools/check.py machine   is the policy delivered, unchanged, and not replaceable by the user?
        ├──► tools/check.py repo      what in this repository runs when an agent opens it?
        └──► gate/                    does each agent version still enforce it?  admit / deny
```

## Why

Coding agents run shell commands, read the file system, start MCP servers and load configuration from whatever repository they open. Both vendors provide enterprise controls (Claude Code's managed settings, Codex's `requirements.toml`), but:

- **the two policies have different formats and different gaps**, and vendor templates carry one example key ([Anthropic's MDM templates](https://github.com/anthropics/claude-code/tree/main/examples/mdm) set only `disableBypassPermissionsMode` and are described as *"community-maintained templates which may be unsupported or incorrect"*; Codex ships none);
- **a delivered policy is not an enforced one.** Claude Code uses the highest-ranked managed source and *"shows no warning for the sources it skips"*; the Windows HKCU key *"is user-writable"* and still *"applies like any selected source"* when no admin source is present ([managed settings](https://code.claude.com/docs/en/managed-settings));
- **non-interactive runs have no trust dialog.** In `claude -p` and the Agent SDK, repository hooks, the `env` block and `.mcp.json` servers are used without asking ([permissions](https://code.claude.com/docs/en/permissions));
- **agents ship several releases a week**, and trust-dialog bypasses and policy-loading bugs have been fixed in both products ([Claude Code advisories](https://github.com/anthropics/claude-code/security/advisories), [Codex advisories](https://github.com/openai/codex/security/advisories)).

## Baseline

[`baseline/rules.yaml`](baseline/rules.yaml) holds 17 rules. Each names the threat, the Claude Code keys, the Codex keys (or says plainly that Codex has no equivalent), and the vendor sentence it relies on, quoted verbatim. `tools/verify_sources.py` fetches every cited page and fails if a quote is no longer there.

| Rule | Threat it addresses | Claude Code | Codex |
|---|---|---|---|
| R01 | repository hooks run on open | `allowManagedHooksOnly` | `allow_managed_hooks_only` |
| R02 | repository MCP servers start | `allowManagedMcpServersOnly`, `allowedMcpServers` | `[mcp_servers]` allowlist |
| R03 | approvals switched off | `disableBypassPermissionsMode` | `allowed_approval_policies` |
| R04 | commands outside the OS sandbox | `sandbox.*` (enabled, fail if unavailable, no escape hatch) | `allowed_sandbox_modes` |
| R05 | credential files read | `sandbox.credentials.files`, `permissions.deny` | `permissions.filesystem.deny_read` |
| R06 | tokens in the command environment | `sandbox.credentials.envVars` | no control found |
| R07 | network egress | `sandbox.network.*` managed-only allowlist | `[experimental_network]` (vendor: experimental) |
| R08 | local rules widen company rules | `allowManagedPermissionRulesOnly` | built in |
| R09 | plugins from anywhere, sideload flags | `strictKnownMarketplaces`, `disableSideloadFlags` | `marketplaces.restrict_to_allowed_sources` |
| R10 | inline shell in skills | `disableSkillShellExecution` | no control found |
| R11 | untested or vulnerable versions | `requiredMinimumVersion` / `requiredMaximumVersion`, `autoUpdatesChannel` | no version lock documented; updates off, version held by the deployed package |
| R12 | sign-in to a foreign tenant | `forceLoginMethod`, `forceLoginOrgUUID` | `allowed_login_methods`, `allowed_chatgpt_workspaces` |
| R13 | live web search | `permissions.deny: WebSearch` | `allowed_web_search_modes = []` |
| R14 | WSL replaces the Windows policy | `wslInheritsWindowsSettings` | not covered |
| R15 | policy delivered through a user-writable source | delivery to plist, HKLM and system directories with admin-only ACLs; checked by `check.py` | same |
| R16 | repository redirects the API endpoint, key included | `env.ANTHROPIC_BASE_URL` pinned by policy | built in |
| R17 | non-interactive runs in unreviewed repositories run the project's `env` and helper commands | launcher [`wrappers/claude-untrusted`](wrappers/claude-untrusted) passes `--setting-sources user`; not settable through managed settings | built in for untrusted projects |

Organisation-specific values (allowed domains, MCP servers, marketplaces, tenant, version window) live in [`baseline/site.example.yaml`](baseline/site.example.yaml); copy it to `site.yaml`. It starts R07 from a short allowlist — git hosting, package registries, the agents' APIs — because a closed network breaks installs and pushes on the first day; [`baseline/site.strict.yaml`](baseline/site.strict.yaml) closes everything. Rules that cost developers something say what in a `cost` field (R07, R13).

### Deliverables

`python3 tools/build.py` writes `build/`:

| File | Use |
|---|---|
| `macos/coding-agent-baseline.mobileconfig` | one profile with both preference domains (`com.anthropic.claudecode`, `com.openai.codex` → `requirements_toml_base64`); Jamf Pro or Intune custom profile for macOS |
| `jamf/com.anthropic.claudecode.plist`, `jamf/com.openai.codex.plist` | Jamf *Application & Custom Settings*, one per domain |
| `intune/windows/Install-CodingAgentBaseline.ps1` | Intune platform script: writes both files and resets their directories to administrator-only write access |
| `claude/managed-settings.json`, `codex/requirements.toml` | the policies themselves, for Linux or any file-based deployment |
| `MANIFEST.md` | which rule produced which key |

## Checker

`tools/check.py` is a single standard-library script; [`skills/baseline-check`](skills/baseline-check/SKILL.md) wraps it as a Claude Code skill. Every check reports *holds*, *does not hold* or *could not run*, with the evidence it looked at.

- **`machine`** — is a managed source delivered for each agent, does it match the build, can a non-administrator replace it (file and parent ownership, HKCU without HKLM, WSL without the Windows chain, a user preference file on macOS), and is the installed version one the gate admitted.
- **`repo PATH`** — hooks, helper commands and `env` in `.claude/settings*.json` (a local file only when tracked in git), `.mcp.json`, `.codex/config.toml` servers and hooks, `.codex/hooks.json`, inline shell in skills, `.env` setting `CODEX_HOME`, a planted `.git/commondir`, `yarnPath`. Each finding says whether the baseline neutralises it.

## Release gate

For each agent version, [`gate/run_gate.py`](gate/run_gate.py) starts a fresh Linux container, installs that version from npm, and runs every probe twice as an unprivileged user:

1. **control** — no policy installed: the probe's canary must fire, otherwise the probe says nothing about this version;
2. **policy** — the baseline installed as the real system-level managed file: the canary must stay silent **and** the agent must still reach the model API, proving it got past start-up.

A local stub stands in for the model API, so no credentials are involved and runs are deterministic. A version is **admitted** when every probe holds, **denied** otherwise; a **regression** is a probe that held on the previous tested version and fails on this one.

| Probe | Planted | Rule |
|---|---|---|
| claude.repo_hook | `SessionStart` hook in `.claude/settings.json`, `claude -p` | R01 |
| claude.repo_mcp | stdio server in `.mcp.json`, `claude -p` | R02 |
| claude.bypass_flag | `--dangerously-skip-permissions`; the stub requests a write outside the working directory | R03 |
| claude.sideload_mcp_flag | `--mcp-config` with a stdio server | R09 |
| claude.repo_env_base_url | `env.ANTHROPIC_BASE_URL` in `.claude/settings.json` pointing at a second stub | R16 |
| claude.repo_api_key_helper | `apiKeyHelper` in `.claude/settings.json`; the policy run starts the agent through the R17 wrapper | R17 |
| codex.repo_hook | `.codex/hooks.json` in a trusted project, hook review skipped by flag | R01 |
| codex.repo_mcp | `[mcp_servers]` in a trusted project's `.codex/config.toml` | R02 |
| codex.approval_never | `codex exec` default approval policy | R03 |
| codex.sandbox_full_access | `-s danger-full-access` | R04 |
| codex.bypass_all_flag | `--dangerously-bypass-approvals-and-sandbox` | R03, R04 |
| codex.user_config_relax | `sandbox_mode = "danger-full-access"` in `~/.codex/config.toml` | R08 |

## Results

All numbers below are produced by `tools/numbers.py` from `results/` (run of 2026-10-28).

| | |
|---|---|
| Baseline rules | 17, every cited quote found on its page (`results/sources.json`, 38 quotes) |
| Keys set | Claude Code 25, Codex 15 (`build/MANIFEST.md`) |
| Codex coverage | built-in protection for R08 and R16; no control found for R06, R10, R14 |
| Checker, planted repository | 15 findings; 12 neutralised by the baseline; 3 not covered — `CODEX_HOME` in `.env`, a planted `.git/commondir`, `yarnPath` — which are fixed in agent versions or package-manager configuration, not by policy (`results/checker/repo-fixture.txt`) |
| Checker, machine states | baseline installed: all hold; policy file writable by the user's group, policy directory owned by the user, keys removed, weakening keys added (`sandbox.excludedCommands: ["*"]`, `permissions.allow: ["Bash(*)"]`), no policy: each reported as *does not hold* (`results/checker/machine-cases.txt`) |
| Release gate | 45 versions: Claude Code 27 (2.1.150 – 2.1.312), Codex 18 (0.137.0 – 0.165.0); 42 admitted, 3 denied; 0 regressions between adjacent tested versions (`results/gate/decisions.md`). Denied: Claude Code 2.1.150, where `disableSideloadFlags` is not enforced (the documentation says "Requires Claude Code v2.1.193 or later"; the sideloaded server is stopped by a different key, so R09 is not proven); Codex 0.137.0 and 0.138.0, where the repository hook does not fire even without the policy, so the probe proves nothing and the gate does not admit on missing evidence |
| Negative control | the baseline without R16 on Claude Code 2.1.150 and 2.1.312: both denied (`results/gate-negative/decisions.md`) |

**A documented leak path, closed and verified.** Claude Code's documentation states that `claude -p` shows no trust dialog and uses a repository's `env` block, hooks and `apiKeyHelper` ([What runs before you trust a folder](https://code.claude.com/docs/en/permissions)). The gate shows the consequence on every Claude Code version tested: a repository that sets `env.ANTHROPIC_BASE_URL` receives the requests, API key included. Pinning that variable in managed settings (R16) stopped it on all 27 versions; starting non-interactive runs through `--setting-sources user` (R17) also keeps the rest of the project's `env` and its helper commands from running.

**What "0 regressions" means.** Over this window, no tested release stopped enforcing a rule that the previous tested release enforced. For Codex 0.137.0 and 0.138.0 the repository-hook probe does not fire even without a policy, so it says nothing about the policy on those versions. The gate's own probes use the strict network setting; R07's allowlist does not affect them.

## Limits

- No live Intune or Jamf tenant: profiles are validated with `plutil` and by the agents themselves in the gate (the files are the same), not pushed from a server.
- Windows code paths (HKLM/HKCU, ACLs) are written to the vendors' documentation but have not been run.
- Probes cover start-up behaviour and flag handling. Model behaviour — prompt injection through `CLAUDE.md`, `AGENTS.md` or tool output — is out of scope.
- The gate container runs with `seccomp=unconfined` so the agents' own bubblewrap sandboxes can create namespaces; this relaxes the test environment, not the agents.

## Reproduce

```bash
./run.sh            # sources, build, tests, checker cases, gate for gate/versions-*.txt, decisions, numbers
./run.sh --no-gate  # everything except installing and probing agent versions
```

Needs Python 3.9+ with PyYAML and Docker.

## License

[Apache-2.0](LICENSE)
