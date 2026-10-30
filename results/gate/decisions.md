# Release gate decisions

Admit requires the complete expected probe set, valid positive controls, no requirement the agent reports as ignored, and a version no older than any rule's min_version (build/coverage.json). Missing, invalid or unavailable evidence denies admission.

Evidence: *fingerprinted* rows carry input_sha256 from the current runner (gate/run_gate.py); *legacy* rows were written by an earlier runner without it and were judged by this file's current rules, not re-run.

## claude

Minimum versions: R03 2.1.223, R09 2.1.193, R20 2.1.285.

| version | bypass_flag | repo_api_key_helper | repo_env_base_url | repo_hook | repo_mcp | sideload_mcp_flag | evidence | decision |
|---|---|---|---|---|---|---|---|---|
| 2.1.150 | holds | holds | holds | holds | holds | did not run | fingerprinted | **deny** |
| 2.1.193 | holds | holds | holds | holds | holds | holds | fingerprinted | **deny** |
| 2.1.242 | holds | holds | holds | holds | holds | holds | fingerprinted | **deny** |
| 2.1.257 | holds | holds | holds | holds | holds | holds | fingerprinted | **deny** |
| 2.1.260 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 2.1.282 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 2.1.285 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.291 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.292 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.293 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.294 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.295 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.296 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.299 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.300 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.301 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.302 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.303 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.304 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.305 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.306 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.307 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.308 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.309 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.310 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.311 | holds | holds | holds | holds | holds | holds | legacy | **admit** |
| 2.1.312 | holds | holds | holds | holds | holds | holds | legacy | **admit** |

Denial reasons:

- 2.1.150: below_min_version:R03>=2.1.223; below_min_version:R09>=2.1.193; below_min_version:R20>=2.1.285; sideload_mcp_flag:did_not_run
- 2.1.193: below_min_version:R03>=2.1.223; below_min_version:R20>=2.1.285
- 2.1.242: below_min_version:R20>=2.1.285
- 2.1.257: below_min_version:R20>=2.1.285
- 2.1.260: below_min_version:R20>=2.1.285
- 2.1.282: below_min_version:R20>=2.1.285

## codex

Minimum versions: R04 0.138.0, R16 0.156.0, R21 0.166.0.

| version | approval_never | bypass_all_flag | repo_hook | repo_mcp | sandbox_full_access | user_config_relax | evidence | decision |
|---|---|---|---|---|---|---|---|---|
| 0.137.0 | holds | holds | invalid control | holds | holds | holds | legacy | **deny** |
| 0.138.0 | holds | holds | invalid control | holds | holds | holds | legacy | **deny** |
| 0.156.1 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.157.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.157.1 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.158.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.159.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.159.1 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.159.2 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.159.3 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.160.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.160.1 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.161.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.162.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.162.1 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.163.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.164.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |
| 0.165.0 | holds | holds | holds | holds | holds | holds | legacy | **deny** |

Denial reasons:

- 0.137.0: below_min_version:R04>=0.138.0; below_min_version:R16>=0.156.0; below_min_version:R21>=0.166.0; policy_ignored:approval_never:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:bypass_all_flag:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:repo_hook:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:repo_mcp:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:sandbox_full_access:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:user_config_relax:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; repo_hook:invalid_control
- 0.138.0: below_min_version:R16>=0.156.0; below_min_version:R21>=0.166.0; policy_ignored:approval_never:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:bypass_all_flag:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:repo_hook:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:repo_mcp:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:sandbox_full_access:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; policy_ignored:user_config_relax:Ignoring unknown `features` requirement `in_app_updates` from /etc/codex/requirements.toml; repo_hook:invalid_control
- 0.156.1: below_min_version:R21>=0.166.0
- 0.157.0: below_min_version:R21>=0.166.0
- 0.157.1: below_min_version:R21>=0.166.0
- 0.158.0: below_min_version:R21>=0.166.0
- 0.159.0: below_min_version:R21>=0.166.0
- 0.159.1: below_min_version:R21>=0.166.0
- 0.159.2: below_min_version:R21>=0.166.0
- 0.159.3: below_min_version:R21>=0.166.0
- 0.160.0: below_min_version:R21>=0.166.0
- 0.160.1: below_min_version:R21>=0.166.0
- 0.161.0: below_min_version:R21>=0.166.0
- 0.162.0: below_min_version:R21>=0.166.0
- 0.162.1: below_min_version:R21>=0.166.0
- 0.163.0: below_min_version:R21>=0.166.0
- 0.164.0: below_min_version:R21>=0.166.0
- 0.165.0: below_min_version:R21>=0.166.0

