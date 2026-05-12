# Fylgyr Coverage Map

Attack catalog mapped to OWASP CI/CD Top 10 and MITRE ATT&CK supply-chain techniques. Empty cells are roadmap gaps.

## OWASP CI/CD Top 10

| OWASP ID | Risk Name | Attack Catalog Entries | Covering Checks |
|---|---|---|---|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | `solarwinds-orion` | `Test-CodeScanning` |
| CICD-SEC-2 | Inadequate Identity and Access Management | — | — |
| CICD-SEC-3 | Dependency Chain Abuse | `trivy-tag-poisoning`, `tj-actions-shai-hulud`, `codecov-bash-uploader`, `event-stream-hijack`, `solarwinds-orion`, `trivy-supply-chain-2026`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04` | `Test-ActionPinning`, `Test-DependabotAlert`, `Test-PublishIntegrity` |
| CICD-SEC-4 | Poisoned Pipeline Execution | `nx-pwn-request`, `prt-scan-ai-automated`, `hackerbot-claw`, `trivy-supply-chain-2026`, `unauthorized-env-deployment`, `azure-karpenter-pwn-request`, `bitwarden-cli-2026-04` | `Test-DangerousTrigger`, `Test-ForkPullPolicy`, `Test-EnvironmentProtection`, `Test-PublishIntegrity` |
| CICD-SEC-5 | Insufficient PBAC | `tj-actions-shai-hulud`, `axios-npm-token-leak`, `uber-credential-leak`, `hackerbot-claw`, `github-app-token-theft`, `unauthorized-env-deployment`, `toyota-source-exposure`, `committed-credentials-exposure`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04` | `Test-WorkflowPermission`, `Test-SecretScanning`, `Test-ForkSecretExposure`, `Test-GitHubAppSecurity`, `Test-RepoVisibility`, `Test-PublishIntegrity` |
| CICD-SEC-6 | Insufficient Credential Hygiene | `codecov-bash-uploader`, `trivy-force-push-main`, `github-app-token-theft`, `xz-utils-backdoor` | `Test-BranchProtection`, `Test-SignedCommit` |
| CICD-SEC-7 | Insecure System Configuration | `github-actions-cryptomining`, `praetorian-runner-pivot` | `Test-RunnerHygiene`, `Test-EgressControl` |
| CICD-SEC-8 | Ungoverned Usage of Third-Party Services | — | — |
| CICD-SEC-9 | Improper Artifact Integrity Validation | — | `Test-BinaryArtifact` (partial), `Test-PublishIntegrity` (partial) |
| CICD-SEC-10 | Insufficient Logging and Visibility | — | — |

**Coverage: 7 of 10 OWASP risks addressed. Open gaps: CICD-SEC-2, CICD-SEC-8, CICD-SEC-10.**

## MITRE ATT&CK Supply-Chain Techniques

| Technique | Description | Attack Catalog Entries | Covering Checks |
|---|---|---|---|
| T1059.004 | Command and Scripting Interpreter: Unix Shell | `nx-pwn-request`, `prt-scan-ai-automated`, `hackerbot-claw`, `trivy-supply-chain-2026`, `azure-karpenter-pwn-request` | `Test-DangerousTrigger`, `Test-ForkPullPolicy` |
| T1078.004 | Valid Accounts: Cloud Accounts | `github-app-token-theft`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04` | `Test-GitHubAppSecurity`, `Test-PublishIntegrity` |
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | `event-stream-hijack` | `Test-DependabotAlert` |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | `trivy-tag-poisoning`, `tj-actions-shai-hulud`, `codecov-bash-uploader`, `solarwinds-orion`, `prt-scan-ai-automated`, `trivy-supply-chain-2026`, `xz-utils-backdoor`, `unauthorized-env-deployment`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04` | `Test-ActionPinning`, `Test-BranchProtection`, `Test-CodeScanning`, `Test-BinaryArtifact`, `Test-PublishIntegrity` |
| T1199 | Trusted Relationship | `codecov-bash-uploader`, `trivy-force-push-main`, `xz-utils-backdoor` | `Test-BranchProtection`, `Test-SignedCommit` |
| T1213 | Data from Information Repositories | `toyota-source-exposure` | `Test-RepoVisibility` |
| T1496 | Resource Hijacking | `github-actions-cryptomining`, `praetorian-runner-pivot` | `Test-RunnerHygiene` |
| T1552.001 | Unsecured Credentials: Credentials in Files | `tj-actions-shai-hulud`, `axios-npm-token-leak`, `uber-credential-leak`, `committed-credentials-exposure`, `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `bitwarden-cli-2026-04` | `Test-SecretScanning`, `Test-PublishIntegrity` |
| T1552.004 | Unsecured Credentials: Private Keys | `github-app-token-theft` | `Test-GitHubAppSecurity` |
| T1610 | Deploy Container | `praetorian-runner-pivot` | `Test-RunnerHygiene` |

**Open gaps (no current check): T1036 (Masquerading), T1562 (Impair Defenses), T1098 (Account Manipulation).**

## Roadmap Signal

Checks targeting open OWASP/MITRE gaps, in priority order:

| Gap | Planned check | Phase |
|---|---|---|
| CICD-SEC-4 / T1059 — script injection via untrusted input | `Test-ScriptInjection` | Phase 8 |
| CICD-SEC-9 — OIDC trusted publishing without environment gating | `Test-OidcTrust` | Phase 8 |
| CICD-SEC-9 — unsigned releases, missing attestations | `Test-ArtifactAttestation`, `Test-ArtifactPoisoning` | Phase 8 |
| CICD-SEC-9 — cache keys derived from attacker-controlled refs | `Test-CacheIntegrity` | Phase 8 |
| CICD-SEC-2 — MFA, PAT policy, outside collaborators | org-level checks | Phase 7 |
