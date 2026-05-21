# Fylgyr Coverage Map

Attack catalog mapped to OWASP CI/CD Top 10 and MITRE ATT&CK supply-chain techniques. Empty cells are roadmap gaps.

Last regenerated: 2026-05-20 (Phase 9 feature update; check-to-attack mappings unchanged).

## OWASP CI/CD Top 10

| OWASP ID | Risk Name | Attack Catalog Entries | Covering Checks |
|---|---|---|---|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | `solarwinds-orion` | `Test-CodeScanning` |
| CICD-SEC-2 | Inadequate Identity and Access Management | `dropbox-github-breach`, `gentoo-github-compromise`, `github-device-code-phishing` | `Test-OrgMfaPolicy`, `Test-OrgDefaultPermissions`, `Test-OAuthAppPolicy`, `Test-OrgActionRestrictions`, `Test-OutsideCollaborators`, `Test-PatPolicy`, `Test-IpAllowlist` |
| CICD-SEC-3 | Dependency Chain Abuse | `trivy-tag-poisoning`, `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise`, `codecov-bash-uploader`, `event-stream-hijack`, `solarwinds-orion`, `trivy-supply-chain-2026`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04`, `artifact-poisoning-workflow-run` | `Test-ActionPinning`, `Test-Rulesets`, `Test-DependabotAlert`, `Test-DependencyReview`, `Test-ArtifactPoisoning`, `Test-ReusableWorkflowTrust`, `Test-PublishIntegrity` |
| CICD-SEC-4 | Poisoned Pipeline Execution | `nx-pwn-request`, `prt-scan-ai-automated`, `hackerbot-claw`, `trivy-supply-chain-2026`, `unauthorized-env-deployment`, `azure-karpenter-pwn-request`, `bitwarden-cli-2026-04`, `github-actions-script-injection`, `cache-poisoning-pr-branch`, `artifact-poisoning-workflow-run`, `shai-hulud-runner-backdoor`, `oidc-trust-abuse` | `Test-DangerousTrigger`, `Test-ScriptInjection`, `Test-TriggerFilter`, `Test-CacheIntegrity`, `Test-ForkPullPolicy`, `Test-EnvironmentProtection`, `Test-ArtifactPoisoning`, `Test-OidcTrust`, `Test-PublishIntegrity` |
| CICD-SEC-5 | Insufficient PBAC | `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise`, `axios-npm-token-leak`, `uber-credential-leak`, `hackerbot-claw`, `github-app-token-theft`, `unauthorized-env-deployment`, `toyota-source-exposure`, `committed-credentials-exposure`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04`, `github-device-code-phishing`, `oidc-trust-abuse` | `Test-WorkflowPermission`, `Test-SecretScanning`, `Test-ForkSecretExposure`, `Test-GitHubAppSecurity`, `Test-RepoVisibility`, `Test-PublishIntegrity`, `Test-PatPolicy`, `Test-OAuthAppPolicy`, `Test-OidcTrust` |
| CICD-SEC-6 | Insufficient Credential Hygiene | `codecov-bash-uploader`, `trivy-force-push-main`, `github-app-token-theft`, `xz-utils-backdoor` | `Test-BranchProtection`, `Test-Rulesets`, `Test-SignedCommit` |
| CICD-SEC-7 | Insecure System Configuration | `github-actions-cryptomining`, `praetorian-runner-pivot`, `shai-hulud-runner-backdoor` | `Test-RunnerHygiene`, `Test-TriggerFilter`, `Test-EgressControl` |
| CICD-SEC-8 | Ungoverned Usage of Third-Party Services | — | — |
| CICD-SEC-9 | Improper Artifact Integrity Validation | `solarwinds-orion`, `codecov-bash-uploader`, `artifact-poisoning-workflow-run`, `oidc-trust-abuse`, `cache-poisoning-pr-branch` | `Test-BinaryArtifact` (partial), `Test-PublishIntegrity`, `Test-ArtifactAttestation`, `Test-ArtifactPoisoning`, `Test-OidcTrust`, `Test-CacheIntegrity` |
| CICD-SEC-10 | Insufficient Logging and Visibility | — | — |

**Coverage: 8 of 10 OWASP risks addressed. Open gaps: CICD-SEC-8, CICD-SEC-10.**

## MITRE ATT&CK Supply-Chain Techniques

| Technique | Description | Attack Catalog Entries | Covering Checks |
|---|---|---|---|
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `nx-pwn-request`, `prt-scan-ai-automated`, `hackerbot-claw`, `trivy-supply-chain-2026`, `azure-karpenter-pwn-request`, `github-actions-script-injection`, `artifact-poisoning-workflow-run`, `shai-hulud-runner-backdoor` | `Test-DangerousTrigger`, `Test-ScriptInjection`, `Test-ArtifactPoisoning`, `Test-TriggerFilter`, `Test-ForkPullPolicy` |
| T1078.004 | Valid Accounts: Cloud Accounts | `github-app-token-theft`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04`, `dropbox-github-breach`, `gentoo-github-compromise`, `github-device-code-phishing`, `oidc-trust-abuse` | `Test-GitHubAppSecurity`, `Test-PublishIntegrity`, `Test-OidcTrust`, `Test-OrgMfaPolicy`, `Test-OrgDefaultPermissions`, `Test-PatPolicy` |
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | `event-stream-hijack` | `Test-DependabotAlert` |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | `trivy-tag-poisoning`, `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise`, `codecov-bash-uploader`, `solarwinds-orion`, `prt-scan-ai-automated`, `trivy-supply-chain-2026`, `xz-utils-backdoor`, `unauthorized-env-deployment`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04`, `artifact-poisoning-workflow-run`, `cache-poisoning-pr-branch` | `Test-ActionPinning`, `Test-BranchProtection`, `Test-CodeScanning`, `Test-BinaryArtifact`, `Test-ArtifactPoisoning`, `Test-CacheIntegrity`, `Test-ReusableWorkflowTrust`, `Test-PublishIntegrity` |
| T1199 | Trusted Relationship | `codecov-bash-uploader`, `trivy-force-push-main`, `xz-utils-backdoor` | `Test-BranchProtection`, `Test-SignedCommit` |
| T1213 | Data from Information Repositories | `toyota-source-exposure` | `Test-RepoVisibility` |
| T1496 | Resource Hijacking | `github-actions-cryptomining`, `praetorian-runner-pivot`, `shai-hulud-runner-backdoor` | `Test-RunnerHygiene`, `Test-TriggerFilter` |
| T1550 | Use Alternate Authentication Material | `oidc-trust-abuse` | `Test-OidcTrust` |
| T1552.001 | Unsecured Credentials: Credentials in Files | `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise`, `axios-npm-token-leak`, `uber-credential-leak`, `committed-credentials-exposure`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `bitwarden-cli-2026-04` | `Test-SecretScanning`, `Test-PublishIntegrity` |
| T1552.004 | Unsecured Credentials: Private Keys | `github-app-token-theft` | `Test-GitHubAppSecurity` |
| T1610 | Deploy Container | `praetorian-runner-pivot` | `Test-RunnerHygiene` |
| T1098 | Account Manipulation | `gentoo-github-compromise` | `Test-OrgDefaultPermissions`, `Test-OutsideCollaborators` |
| T1566 | Phishing | `github-device-code-phishing`, `dropbox-github-breach` | `Test-OAuthAppPolicy`, `Test-OrgMfaPolicy`, `Test-PatPolicy` |

**Open gaps (no current check): T1036 (Masquerading), T1562 (Impair Defenses).**

## Roadmap Signal

Checks targeting open OWASP/MITRE gaps, in priority order:

| Gap | Planned check | Phase |
|---|---|---|
| CICD-SEC-4 / T1059 — script injection via untrusted input | closed by `Test-ScriptInjection` | v0.6.0 |
| CICD-SEC-9 — OIDC trusted publishing without environment gating | closed by `Test-OidcTrust` | v0.6.0 |
| CICD-SEC-9 — unsigned releases, missing attestations | closed by `Test-ArtifactAttestation`, `Test-ArtifactPoisoning` | v0.6.0 |
| CICD-SEC-9 — cache keys derived from attacker-controlled refs | closed by `Test-CacheIntegrity` | v0.6.0 |
| CICD-SEC-10 / T1078.004 / T1213 — token-risk events correlated with abnormal repository-access bursts | `Test-RecentTokenExposure` | Phase 9.5 |
| CICD-SEC-2 — MFA, PAT policy, outside collaborators | closed by Phase 7 org checks | v0.5.0 |
