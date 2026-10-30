---
name: baseline-check
description: Check whether the company baseline for Claude Code and OpenAI Codex is actually in force on this machine, and whether a repository contains files that run commands or change agent policy when it is opened. Use when asked "is our agent policy applied here", "can this be overridden", "is this repo safe to open with Claude Code or Codex", or before working in an unfamiliar repository.
---

# Baseline check

The verdicts come from `tools/check.py`, not from your reading of files. Run it, then report what it
says. Do not change any system file, registry key or profile.

## Steps

1. From the root of the `claude-codex-baseline` checkout, run both modes with JSON output:

   ```bash
   python3 tools/check.py machine --json
   python3 tools/check.py repo <path to the repository in question> --json
   ```

2. Report the machine results first, as a table: check, outcome, rule, evidence.
   - `does_not_hold` on `*.policy_delivered`, `*.policy_file_owner`, `claude.no_user_writable_policy`
     or `claude.wsl_chain` means the company policy can be absent or replaced on this machine. Say which
     rule (see `baseline/rules.yaml`) is affected.
   - `*.policy_matches_baseline` compares the policy the agent applies — every managed source combined
     the way the vendor documents it — with `build/`. A stricter value passes; a looser, missing or
     unknown key fails, and the evidence names the path.
   - `could_not_run` is not a pass. Say what was missing (for example, the agent is not on PATH).
     `claude.server_managed` and `codex.cloud_requirements` are always reported: a claude.ai, gateway
     or ChatGPT-workspace policy ranks above the local one and this check cannot see it.
   - `claude.user_sandbox_exceptions` failing means the developer's own settings take commands out of
     the sandbox (R20); no managed key prevents that.

3. Report the repository findings, split in two groups:
   - **neutralised by the baseline**: present in the repository, but the baseline disables it *if* the
     machine checks above hold. If they do not hold, these findings are live. Findings marked R17 are
     neutralised in non-interactive runs only when the agent is started through
     `wrappers/claude-untrusted`; in an interactive session they wait for the trust dialog. A finding
     that says "needs Claude Code 2.1.x+" is neutralised only on that version or later.
   - **not covered by the baseline**: will act when the repository is opened or used, whatever the
     policy. Name the file and what it does.

4. End with one line: whether it is safe to run an agent in this repository on this machine, and the
   one action that would change the answer. Do not offer to delete or edit the repository's files
   unless asked.

## What this check does not see

- Whether the running agent honours a key: that is what the release gate tests per version
  (`results/gate/decisions.md`).
- Instructions in `CLAUDE.md` and `AGENTS.md`: reported as information, not judged.
- Live MDM state on the server side (Intune, Jamf): only what reached this machine.
