# Build manifest

Site file: `baseline/site.example.yaml`.

| Rule | Agent | Key | Platforms |
|---|---|---|---|
| R01 | claude | `allowManagedHooksOnly` | all |
| R01 | codex | `allow_managed_hooks_only` | all |
| R02 | claude | `allowManagedMcpServersOnly` | all |
| R02 | claude | `allowedMcpServers` | all |
| R02 | codex | `mcp_servers` | all |
| R02 | claude | `allowedMcpServers (site)` | all |
| R02 | codex | `mcp_servers (site)` | all |
| R03 | claude | `permissions.disableBypassPermissionsMode` | all |
| R03 | codex | `allowed_approval_policies` | all |
| R04 | claude | `sandbox.enabled` | all |
| R04 | claude | `sandbox.failIfUnavailable` | all |
| R04 | claude | `sandbox.allowUnsandboxedCommands` | all |
| R04 | claude | `sandbox.enableWeakerNetworkIsolation` | all |
| R04 | claude | `sandbox.allowAppleEvents` | all |
| R04 | codex | `allowed_sandbox_modes` | all |
| R05 | claude | `sandbox.filesystem.allowManagedReadPathsOnly` | all |
| R05 | claude | `sandbox.credentials.files` | all |
| R05 | claude | `permissions.deny` | all |
| R05 | codex | `permissions.filesystem.deny_read` | all |
| R06 | claude | `sandbox.credentials.envVars` | all |
| R07 | claude | `sandbox.network.allowedDomains` | all |
| R07 | claude | `sandbox.network.allowManagedDomainsOnly` | all |
| R07 | codex | `experimental_network.enabled` | all |
| R07 | codex | `experimental_network.managed_allowed_domains_only` | all |
| R07 | codex | `experimental_network.domains` | all |
| R07 | claude | `sandbox.network.allowedDomains (site)` | all |
| R07 | codex | `experimental_network.domains (site)` | all |
| R08 | claude | `allowManagedPermissionRulesOnly` | all |
| R09 | claude | `strictKnownMarketplaces` | all |
| R09 | claude | `disableSideloadFlags` | all |
| R09 | codex | `marketplaces.restrict_to_allowed_sources` | all |
| R09 | claude | `strictKnownMarketplaces (site)` | all |
| R09 | codex | `marketplaces.allowed_sources (site)` | all |
| R10 | claude | `disableSkillShellExecution` | all |
| R11 | claude | `autoUpdatesChannel` | all |
| R11 | codex | `check_for_update_on_startup` | all |
| R11 | codex | `features.in_app_updates` | all |
| R13 | claude | `permissions.deny` | all |
| R13 | codex | `allowed_web_search_modes` | all |
| R14 | claude | `wslInheritsWindowsSettings` | windows |
| R16 | claude | `env.ANTHROPIC_BASE_URL (site)` | all |

Rules with no Codex control (see `gap` in rules.yaml): R06, R08, R10, R14, R16, R17.
Rules with no Claude Code control: R16.
