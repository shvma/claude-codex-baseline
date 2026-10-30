# Release gate decisions

Admit requires the complete expected probe set, valid positive controls, no requirement the agent reports as ignored, and a version no older than any rule's min_version (build/coverage.json). Missing, invalid or unavailable evidence denies admission.

Evidence: *fingerprinted* rows carry input_sha256 from the current runner (gate/run_gate.py); *legacy* rows were written by an earlier runner without it and were judged by this file's current rules, not re-run.

## claude

Minimum versions: R03 2.1.223, R09 2.1.193, R20 2.1.285.

| version | bypass_flag | repo_api_key_helper | repo_env_base_url | repo_hook | repo_mcp | sideload_mcp_flag | evidence | decision |
|---|---|---|---|---|---|---|---|---|
| 2.1.150 | holds | holds | does not hold | holds | holds | did not run | legacy | **deny** |
| 2.1.312 | holds | holds | does not hold | holds | holds | holds | legacy | **deny** |

Denial reasons:

- 2.1.150: below_min_version:R03>=2.1.223; below_min_version:R09>=2.1.193; below_min_version:R20>=2.1.285; unproven_hold:sideload_mcp_flag; repo_env_base_url:does_not_hold; sideload_mcp_flag:did_not_run
- 2.1.312: repo_env_base_url:does_not_hold

