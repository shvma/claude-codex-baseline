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

[`baseline/rules.yaml`](baseline/rules.yaml) holds 22 rules. Each names the threat, the Claude Code keys, the Codex keys (or says plainly that Codex has no equivalent), and the vendor sentence it relies on, quoted verbatim. `tools/verify_sources.py` fetches every cited page and fails if a quote is no longer there.

| Rule | Threat it addresses | Claude Code | Codex |
|---|---|---|---|
| R01 | repository hooks run on open | `allowManagedHooksOnly` | `allow_managed_hooks_only` |
| R02 | repository MCP servers start | `allowManagedMcpServersOnly`, `allowedMcpServers` | `[mcp_servers]` allowlist |
| R03 | approvals switched off | `disableBypassPermissionsMode` | `allowed_approval_policies` |
| R04 | commands outside the OS sandbox | `sandbox.*` (enabled, fail if unavailable, no escape hatch) | `allowed_permission_profiles`, `default_permissions` (0.138.0+); legacy `allowed_sandbox_modes` kept |
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
| R16 | repository redirects the API endpoint, key included | `env.ANTHROPIC_BASE_URL` pinned by policy | project config: built in; `model_provider` pinned against user config (0.156.0+) |
| R17 | non-interactive runs in unreviewed repositories run the project's `env` and helper commands | launcher [`wrappers/claude-untrusted`](wrappers/claude-untrusted) passes `--setting-sources user`; not settable through managed settings | built in for untrusted projects |
| R18 | a model approves actions instead of the developer | `disableAutoMode` | `allowed_approvals_reviewers = ["user"]` |
| R19 | sandboxed commands run without a prompt | `sandbox.autoAllowBashIfSandboxed: false` | `[rules]` prompt for `git push`, `curl`, `wget`, `scp`, `rsync`, `ssh`, `gh` |
| R20 | `excludedCommands` / `allowWrite` take commands out of the sandbox | no managed lock exists: repository entries ignored from 2.1.285 (admin-required sandbox), the developer's own reported by `check.py machine` | no equivalent key |
| R21 | no record of what agents ran | OTel `env` from the site file (collector, exporters) | `[otel]`, `log_user_prompt = false` (0.166.0+) |
| R22 | transcripts with secrets kept on disk for 30 days | `cleanupPeriodDays: 14` | no key found |

Organisation-specific values (allowed domains, MCP servers, marketplaces, tenant, version window, telemetry collector) live in [`baseline/site.example.yaml`](baseline/site.example.yaml); copy it to `site.yaml`. It starts R07 from a short allowlist — git hosting, package registries, the agents' APIs — because a closed network breaks installs and pushes on the first day; [`baseline/site.strict.yaml`](baseline/site.strict.yaml) closes everything. **`github.com` in that list is an exfiltration channel**: any account can receive a push or a gist, so code leaves through it inside the sandbox. Replace it with your own git host; if you keep it, keep R19 so every command asks first. Rules that cost developers something say what in a `cost` field (R07, R13, R18, R19, R21, R22).

Rules carry a `min_version` where the vendor names the first release that enforces a key (R03 frontmatter bypass: Claude Code 2.1.223; R09 `disableSideloadFlags`: 2.1.193; R20 repository locks: 2.1.285; R04 profiles: Codex 0.138.0; R16 `model_provider`: 0.156.0; R21 `[otel]`: 0.166.0, from the `config_requirements.rs` source at each release tag). `versions.claude.min` in the site file is set to 2.1.285 and `build.py` refuses a lower value.

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

`tools/check.py` is a single standard-library script for Python 3.9+: TOML goes through `tomllib` on 3.11+ and through a small built-in parser for the subset requirements files use on 3.9 and 3.10 (tested against `tomllib`; run as `/usr/bin/python3 -I tools/check.py` on stock macOS). [`skills/baseline-check`](skills/baseline-check/SKILL.md) wraps it as a Claude Code skill. Every check reports *holds*, *does not hold* or *could not run*, with the evidence it looked at.

- **`machine`** — rebuilds the policy each agent applies from every managed source it can see and compares it with `build/`. Claude Code: macOS plist or HKLM, then `managed-settings.json` with `managed-settings.d/*.json` in name order (hidden and non-`.json` files ignored, as Claude Code does), combined under `managedSourcesBehavior` as the [managed settings](https://code.claude.com/docs/en/managed-settings) page documents: under the default *first-wins* the selected source plus the keys read from every admin source (locked domain allowlists, `env` per variable, MCP locks); under *merge* by kind of key. Codex: MDM over the system file, each top-level requirement from the highest layer that sets it (`merge_unset_fields` in `config_requirements.rs`). The comparison has a direction: a stricter value passes (more deny rules, fewer allowed domains, shorter retention), a looser, missing or unknown key fails and is named. Server-managed (claude.ai, gateway) and Codex cloud requirements rank above the local policy and are not visible: they are reported as *could not run* unless Claude Code's local cache of them exists. Also: file and parent ownership, HKCU without HKLM, WSL without the Windows chain, a user preference file on macOS, `excludedCommands`/`allowWrite` in the developer's own settings (R20), and whether the installed version is one the gate admitted. On Windows the Windows build is the reference.
- **`repo PATH`** — walks the whole tree (nested packages included): hooks, helper commands and `env` in any `.claude/settings*.json` (a local file only when tracked in git), `extraKnownMarketplaces`, `enabledPlugins`, sandbox exceptions, subagent definitions in `.claude/agents/` (bypass mode, MCP servers, hooks in frontmatter), any `.mcp.json`, `.codex/config.toml` servers and hooks, `.codex/hooks.json`, inline shell in skills and commands, `.env` setting `CODEX_HOME`, a planted `.git/commondir`, `yarnPath`. Whether the baseline neutralises a finding is derived, not written into the checker: the rule must list the check in `rules.yaml` and the build must hold every key the rule sets (`build/coverage.json`); a version floor is printed when the rule has one.

## Release gate

For each agent version, [`gate/run_gate.py`](gate/run_gate.py) starts a fresh Linux container, installs that version from npm, and runs every probe twice as an unprivileged user:

1. **control** — no policy installed: the probe's canary must fire, otherwise the probe says nothing about this version;
2. **policy** — the baseline installed as the real system-level managed file: the canary must stay silent **and** the agent must still reach the model API, proving it got past start-up.

A local stub stands in for the model API, so no credentials are involved and runs are deterministic. A version is **admitted** when every probe holds with a valid control, the agent's output reports no ignored requirement (Codex prints `Ignoring unknown ... requirement` and carries on), the sideload probe ends in the documented refusal rather than a clean exit, and the version is not older than any rule's `min_version`; it is **denied** otherwise. A **regression** is a probe that held on the previous tested version and fails on this one.

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

Twelve probes cover 8 of the 22 rules (R01, R02, R03, R04, R08, R09, R16, R17). R05, R06, R07, R10, R11–R15 and R18–R22 have no gate probe: they are checked as delivered policy by `check.py`, not as behaviour of an agent version. `rules.yaml` lists only probes that exist; `tests/test_rules_refs.py` enforces it.

## Results

All numbers below are produced by `tools/numbers.py` from `results/` (`results/numbers.json`).

| | |
|---|---|
| Baseline rules | 22, every cited quote found on its page (`results/sources.json`, 60 quotes, checked 2026-10-30) |
| Keys set | Claude Code 30, Codex 22 (`build/MANIFEST.md`) |
| Codex coverage | built-in protection for R08 and R17; by deployment R15; no control found for R06, R10, R14, R20, R22 (`build/MANIFEST.md`) |
| Checker, planted repository | 24 findings, nested packages and subagent definitions included; 21 neutralised by the baseline (R17 ones only when started through the wrapper, R03/R09 ones from the version named); 3 not covered — `CODEX_HOME` in `.env`, a planted `.git/commondir`, `yarnPath` (`results/checker/repo-fixture.txt`) |
| Checker, machine states | in a Linux container: baseline installed, a root-owned drop-in that only tightens, and a hidden drop-in hold; group-writable policy, user-owned Codex directory, keys removed, weakening additions, a root-owned drop-in adding `*.ngrok.io` and `HTTPS_PROXY`, `excludedCommands: ["*"]` in the developer's settings, and no policy each *do not hold* (`results/checker/machine-cases.txt`). macOS plist + drop-in, merge mode, Windows HKLM/HKCU and Codex layers are covered by unit tests with a faked machine (`tests/test_machine_sources.py`) |
| Release gate | 45 versions: Claude Code 27 (2.1.150 – 2.1.312), Codex 18 (0.137.0 – 0.165.0); Claude Code 21 admitted (2.1.285 – 2.1.312), 6 denied as older than a rule's `min_version`; Codex 0 admitted: every tested release predates `[otel]` in requirements (0.166.0) and 0.137.0–0.138.0 also report `Ignoring unknown features requirement`; 0 regressions (`results/gate/decisions.md`) |
| Negative control | the baseline without R16 on Claude Code 2.1.150 and 2.1.312: both denied (`results/gate-negative/decisions.md`) |

**What the gate results are, and are not.** The probe results in `results/gate/` were recorded against the baseline as it stood before this change (17 rules) and committed on 2026-10-29: 23 of 27 Claude Code files and all 18 Codex files in 77e482e, by an earlier runner that did not record `input_sha256` (`decisions.md` marks them *legacy*); Claude Code 2.1.150, 2.1.193, 2.1.242 and 2.1.257 in b98c399, re-run with the fingerprinting runner. The decisions above are the current `gate/decide.py` applied to those stored rows: no version was re-run with R18–R22, the Codex profile and provider keys, or the new admission rules. `python3 gate/decide.py --require-fingerprint` denies every legacy result. Claude Code 2.1.314 and Codex 0.166.0 are listed in `gate/versions-*.txt` for the next run.

**A documented leak path, closed and verified.** Claude Code's documentation states that `claude -p` shows no trust dialog and uses a repository's `env` block, hooks and `apiKeyHelper` ([What runs before you trust a folder](https://code.claude.com/docs/en/permissions)). The gate shows the consequence on every Claude Code version tested: a repository that sets `env.ANTHROPIC_BASE_URL` receives the requests, API key included. Pinning that variable in managed settings (R16) stopped it on all 27 versions; starting non-interactive runs through `--setting-sources user` (R17) also keeps the rest of the project's `env` and its helper commands from running.

**What "0 regressions" means.** Over this window, no tested release stopped enforcing a rule that the previous tested release enforced. For Codex 0.137.0 and 0.138.0 the repository-hook probe does not fire even without a policy, so it says nothing about the policy on those versions. The gate's own probes use the strict network setting and no telemetry collector; R07's allowlist and R21 do not affect them.

## Limits

- No live Intune or Jamf tenant: profiles are validated with `plutil` and by the agents themselves in the gate (the files are the same), not pushed from a server.
- Windows code paths (HKLM/HKCU, ACLs) are written to the vendors' documentation but have not been run.
- Probes cover start-up behaviour and flag handling for 8 of 22 rules. Model behaviour — prompt injection through `CLAUDE.md`, `AGENTS.md` or tool output — is out of scope.
- The checker cannot see server-managed Claude Code settings (unless cached locally) or Codex cloud requirements; it says so on every run. It models the documented composition of managed sources, not every per-key exception (login keys, `allowedProviders`, `policyHelper` output).
- R20 is detection, not prevention: Claude Code has no managed-only lock for the developer's own `excludedCommands` and `allowWrite`.
- The gate container runs with `seccomp=unconfined` so the agents' own bubblewrap sandboxes can create namespaces; this relaxes the test environment, not the agents.

## Reproduce

```bash
./run.sh            # sources, build, tests, checker cases, gate for gate/versions-*.txt, decisions, numbers
./run.sh --no-gate  # everything except installing and probing agent versions
```

`tools/check.py` and `gate/decide.py` need only the Python 3.9+ standard library. `tools/build.py`, `tools/verify_sources.py` and `tools/numbers.py` need PyYAML; the gate and the checker cases need Docker. `python3 -m unittest discover -s tests` runs on stock `/usr/bin/python3` 3.9 (the PyYAML and `tomllib` tests skip there) and on 3.12.

## License

[Apache-2.0](LICENSE)
