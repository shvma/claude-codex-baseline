# Release gate decisions

Admit requires the complete expected probe set and valid positive controls. Missing, invalid or unavailable evidence denies admission.

## claude

| version | bypass_flag | repo_api_key_helper | repo_env_base_url | repo_hook | repo_mcp | sideload_mcp_flag | decision |
|---|---|---|---|---|---|---|---|
| 2.1.150 | holds | holds | does not hold | holds | holds | holds | **deny** |
| 2.1.312 | holds | holds | does not hold | holds | holds | holds | **deny** |

