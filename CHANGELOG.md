# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.8.1] - 2026-06-28

### Security

- `Invoke-GitHubApi` now validates absolute HTTPS endpoints against an allowlist of GitHub API hosts (`api.github.com`, `github.com`, and the GHES base host when configured), blocking SSRF to non-GitHub URLs.
- `Invoke-GitHubApi` rejects REST endpoint paths containing path traversal segments (`../`) and enforces a URL-safe character allowlist to prevent endpoint injection.
- `Invoke-GitHubApi` now respects `GITHUB_API_URL` and `GHES_URL` environment variables for GitHub Enterprise Server support, with HTTPS enforcement on both.
- `Get-WorkflowFile` adds `[ValidatePattern('^[a-zA-Z0-9._-]+$')]` to `$Owner` and `$Repo` parameters, consistent with all public check functions.
- `Send-FylgyrToLogAnalytics` now validates ingestion URIs via a new `Resolve-FylgyrIngestionBaseUri` helper that enforces HTTPS and blocks private/link-local IP targets (10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x) to prevent SSRF. DNS resolution is performed to catch rebinding attacks.
- IMDS HTTP fallback (`http://169.254.169.254/metadata/identity/...`) removed from `Send-FylgyrToLogAnalytics` — it used an HTTP endpoint incompatible with Fylgyr's HTTPS-only policy. Bare-VM deployments should use `-ClientId`/`-ClientSecret` or run inside Azure Functions/App Service where `IDENTITY_ENDPOINT` is available.

## [0.8.0] - 2026-06-26

### Added

- Ten new checks:
	- `Test-DefaultTokenPermission` — flags platform default `GITHUB_TOKEN` workflow permission set to `write` and workflows allowed to approve pull requests, at both repo and org scope.
	- `Test-DeployKey` — flags deploy keys with write access (MFA-less, unattributed push path) and stale read-only keys.
	- `Test-TagProtection` — evaluates tag-ruleset rule depth: active tag rulesets missing `deletion`/`non_fast_forward` rules (the release retagging primitive). Absence of tag rulesets remains `Test-Rulesets` territory.
	- `Test-OrgSecretVisibility` — flags organization Actions secrets with `visibility: all` (org scope, runs with `-IncludeOrgChecks`).
	- `Test-AccountSecurity` — verifies two-factor authentication on personal accounts (Fail/Critical when disabled); degrades to an Info advisory when the token does not belong to the scanned account.
	- `Test-AccountKey` — flags stale account SSH keys (>730 days) and expired GPG signing keys on personal accounts; never echoes key material.
	- `Test-WorkflowConcurrency` — detects deployment jobs targeting an environment without a concurrency group, preventing race-condition bypass of approval gates. Maps to `unauthorized-env-deployment`.
	- `Test-ContinueOnError` — flags security-gate jobs/steps with `continue-on-error: true`, which silences scan failures and lets compromised pipelines proceed undetected. Maps to `solarwinds-orion`, `codecov-bash-uploader`.
	- `Test-RunnerPinning` — detects mutable `-latest` runner labels, including labels supplied via `strategy.matrix`, causing silent environment drift. Maps to `trivy-supply-chain-2026`, `solarwinds-orion`.
	- `Test-DefaultWorkflowPermission` — flags repo-level `GITHUB_TOKEN` default set to `write` and Actions allowed to approve pull requests (repo scope; `Test-DefaultTokenPermission` covers both repo and org scope). Maps to `tj-actions-shai-hulud`, `nx-pwn-request`, `prt-scan-ai-automated`.
- Eight new attack catalog entries:
	- `reviewdog-action-setup-2025` (CVE-2025-30154) — root cause of the tj-actions/changed-files Shai-Hulud supply chain incident.
	- `artipacked-token-artifact-leak-2024` — GitHub Actions artifact-based GITHUB_TOKEN exfiltration.
	- `ultralytics-cache-pivot-2024` — Actions cache poisoning used to compromise downstream builds.
	- `miasma-worm-redhat-npm-2026` — self-propagating npm worm targeting Red Hat packages.
	- `miasma-worm-leo-platform-2026` — npm worm variant targeting the Leo AI platform.
	- `mastra-sapphire-sleet-2026` — SAPPHIRE SLEET campaign compromise of Mastra AI packages.
	- `simonecorsi-mawesome-2026` — popular GitHub Actions repository compromised via stale token.
	- `microsoft-durabletask-teampcp-2026` — TEAM PCP group compromise of microsoft/durabletask package.
- `Test-ActionPinning` now also scans composite action definitions (`action.yml`/`action.yaml`) for unpinned `uses:` references via the new `Get-ActionDefinitionFile` helper — closes the tj-actions-style composite-action propagation path.
- `Test-ScriptInjection` now detects bracket-notation event expressions, `actions/github-script` `script:` inputs, additional unsafe contexts (`workflow_run.pull_requests`, `pull_request_review_comment.body`), and untrusted input routed indirectly through `env:` variables.
- Solo-maintainer profile (`-SoloMaintainer` switch) re-ranks structurally impossible findings (multi-reviewer requirements) to Info with a compensating context note. See `docs/SOLO-MAINTAINER.md`.

### Changed

- `Test-WorkflowPermission` now detects job-level `permissions: write-all` even when no top-level permissions block is present (previously the medium "missing top-level" finding eclipsed the higher-severity job-level signal).
- `Test-BranchProtection` raises `enforce_admins` finding to High severity and expands attack mapping to `trivy-force-push-main`, `dropbox-github-breach`, `xz-utils-backdoor`.
- `Test-SecretScanning` adds push-protection posture as a secondary finding when secret scanning is enabled but push protection is not.
- `Test-EnvironmentProtection` adds `prevent_self_review` enforcement check; a deployment environment that allows self-review is flagged.
- `Test-Rulesets` detects `bypass_actors` configured on default-branch rulesets, which can silently nullify all ruleset protections.
- `Test-CodeOwner` detects CODEOWNERS enforcement via branch rulesets in addition to classic branch protection; rulesets API call is now paginated (`?per_page=100` + `-AllPages`) to prevent false negatives on repos with many rulesets.
- Org-level Actions secret visibility moved from `Test-ForkSecretExposure` into the new org-scoped `Test-OrgSecretVisibility` — it previously re-emitted once per repo and silently no-oped without org permissions. Single-repo scans no longer surface this signal; run an org scan with `-IncludeOrgChecks`.
- `Test-ForkSecretExposure` now also covers `workflow_run`-triggered workflows referencing non-`GITHUB_TOKEN` secrets, and detects bracket-notation secret references.
- `Test-DangerousTrigger` now distinguishes "approval gate verification forbidden by token scope" (single Info per repo) from "no approval gate configured" instead of silently suppressing on 403.
- `-IncludeOrgChecks` against a personal account now emits one consolidated skip notice and runs `Test-AccountSecurity`/`Test-AccountKey` instead of ~12 separate "personal account" Info results.

### Security

- API-derived values (default branch names, ruleset IDs, blob SHAs, collaborator logins) are now URL-encoded before interpolation into API paths via the new `ConvertTo-FylgyrEscapedPathSegment` helper. Also fixes silent 404s for repos whose default branch contains `/`.
- Baseline JSON parsing is now depth-bounded (`-Depth 25`) in `Compare-FylgyrBaseline` and `Get-FylgyrBaselineFingerprintSet`.
- `Send-FylgyrToLogAnalytics` now clears the plaintext client secret immediately after the token request (try/finally).
- Documented baseline-tampering risk: baseline JSON drives finding suppression, so baselines must be write-protected from contributors (README Drift Mode + docs/SENTINEL.md).
- `Test-DefaultWorkflowPermission` uses pre-captured `$msg` in error Detail strings instead of `$($_.Exception.Message)` to prevent accidental stack trace leakage.

## [0.7.5] - 2026-05-21

### Added

- Drift execution mode support in `Invoke-Fylgyr`:
	- `-Mode Audit|Drift|Both`
	- `-SinceHours` lookback window
- Eight drift checks:
	- `Test-RecentCollaboratorChange`
	- `Test-RecentAppAuthorization`
	- `Test-RecentProtectionChange`
	- `Test-RecentForcePush`
	- `Test-RecentRunnerRegistration`
	- `Test-RecentSecretChange`
	- `Test-RecentTokenExposure`
	- `Test-RecentWorkflowAdd`
- Drift helper primitives:
	- `Get-OrgAuditLog` with per-run cache
	- `Compare-FylgyrBaseline` snapshot diff helper using `Get-FylgyrFingerprint`
- Sentinel output and ingestion:
	- `-OutputFormat LogAnalytics` via `ConvertTo-FylgyrLogAnalytics`
	- `Send-FylgyrToLogAnalytics` for DCR/Logs Ingestion API posting (managed identity, federated token, or secret fallback)
- Sentinel implementation artifacts:
	- `docs/SENTINEL.md`
	- `docs/sentinel/dcr.json`
	- `docs/sentinel/table-schema.json`
	- `docs/sentinel/rules/*.yaml`
	- `docs/sentinel/workbook.json`
	- `docs/sentinel/github-actions-cron.yml`
	- `docs/sentinel/azure-function/*`
	- architecture diagrams: `docs/sentinel/architecture.drawio`, `docs/sentinel/architecture.mmd`
- Pester coverage for drift orchestration and Log Analytics formatting in `tests/DriftMode.Tests.ps1`.

### Changed

- `Format-FylgyrResult` now supports `Status = Drift` and `Mode = Audit|Drift`.
- Console/JSON/SARIF/HTML formatters updated for drift findings.
- Module loader now dot-sources `.ps1` files recursively under `Public/` and `Private/`.
- Module manifest version bumped to `0.7.5` and exports updated for drift/Sentinel functions.

## [0.7.4] - 2026-05-21

### Changed

- Bumped module manifest version to `0.7.4` to align with existing remote tags and keep release tag/version parity checks passing.

## [0.7.2] - 2026-05-21

### Fixed

- Release workflow publish path now installs `powershell-yaml` in the `publish` job before `Publish-Module` so manifest-required dependencies resolve reliably on tag builds.

## [0.7.0] - 2026-05-20

### Added

- Org-wide parallel scanning controls:
	- `-ThrottleLimit` on `Invoke-Fylgyr` for owner scans.
	- rate-limit-aware throttle clamping via `Get-FylgyrOrgScanThrottle`.
- Baseline and suppression flow improvements:
	- baseline fingerprint suppression (`Status = Suppressed`).
	- `.fylgyr.yml` suppression parsing with optional expiry.
	- `-IgnoreConfig` for strict no-suppression runs.
- NDJSON output support via `ConvertTo-FylgyrNdjson` with `_meta` per finding.
- CI gate wrapper script `scripts/fylgyr-ci.ps1` to propagate `$LASTEXITCODE`.
- Evidence bundle support:
	- `-IncludeEvidence` switch.
	- standardized `Evidence` field on result objects.
	- `Add-FylgyrEvidence` helper for `YamlSnippet`, `CommitSha`, `ScanTime`, and `Permalink`.
- HTML reporting:
	- `ConvertTo-FylgyrHtml` output formatter.
	- standalone report template at `src/Fylgyr/Data/report-template.html`.

### Changed

- `Invoke-Fylgyr` output formats now include `NDJSON` and `HTML`.
- Console formatter supports `Suppressed` counts and optional evidence details in verbose mode.
- SARIF formatter now projects evidence metadata into result properties when present.
- Module manifest:
	- `RequiredModules` includes `powershell-yaml`.
	- `FileList` includes `Data/report-template.html`.
	- `ModuleVersion` bumped to `0.7.0`.
- CI and release workflows now install `powershell-yaml` for reproducible manifest validation.

### Documentation

- Added `docs/PRE-COMMIT.md` with changed-only hook recipe.
- README expanded with usage examples for NDJSON, HTML, evidence, suppressions, changed-only, CI gates, and performance tuning.
- `docs/COVERAGE.md` regenerated marker updated for the drift telemetry update.

### Tests

- Added/expanded Pester coverage for:
	- throttle and rate-limit-aware parallel scan behavior.
	- evidence helpers and inclusion flow.
	- HTML formatter output.
	- NDJSON, baseline/suppression, changed-only, and exit-code paths.

### Changed

- `Test-Rulesets` org-scope permission handling refined:
	- `403` on `orgs/{org}/rulesets` now returns advisory `Info` when org rulesets cannot be read with least-privilege tokens.
	- `404` on rulesets endpoint now returns advisory `Info` (unverified governance) instead of implying missing governance by default.
	- Org-scope missing tag ruleset is now `Warning`/`Medium` (governance gap), while repo scope remains the stronger enforcement signal.
- `Test-PatPolicy` endpoint availability handling refined to avoid misleading failure states when PAT-policy endpoints are gated by plan/feature/token-type restrictions.
- Permissions documentation aligned with current GitHub API behavior:
	- `GET /orgs/{org}/rulesets` may require fine-grained PAT Organization Administration:write.
	- PAT governance endpoints may require GitHub App user/installation tokens in some org contexts.

## [0.6.0] - 2026-05-19

### Added

- Two new private workflow parsing helpers:
	- `Get-RunBlock` for extracting `run:` content including YAML block scalars (`|`, `>`).
	- `Get-WorkflowJobBlock` for extracting per-job YAML blocks for job-scoped analysis.
- Nine new checks:
	- `Test-ScriptInjection`
	- `Test-ArtifactPoisoning`
	- `Test-OidcTrust`
	- `Test-CacheIntegrity`
	- `Test-TriggerFilter`
	- `Test-DependencyReview`
	- `Test-ArtifactAttestation`
	- `Test-ReusableWorkflowTrust`
	- `Test-PrivateVulnReporting`
- Optional `-ReusableWorkflowAllowlist <string[]>` parameter on `Invoke-Fylgyr` to extend trusted reusable-workflow sources beyond default trust roots.
- New Pester suite: `tests/WorkflowDeepAnalysis.Tests.ps1` with vulnerable/safe fixtures and OIDC severity branch coverage.
- Five attack-catalog entries:
	- `github-actions-script-injection`
	- `artifact-poisoning-workflow-run`
	- `oidc-trust-abuse`
	- `cache-poisoning-pr-branch`
	- `shai-hulud-runner-backdoor`

### Changed

- `Invoke-FylgyrScan` workflow check pipeline now includes all new workflow deep-analysis checks.
- `Test-RunnerHygiene` expanded to flag self-hosted runners with `discussion`, `issue_comment`, and `workflow_dispatch` triggers, plus missing `types:` filters for high-risk event families.
- `Test-ScriptInjection` remediation now explicitly documents the current `env:` interpolation limitation.
- `ConvertTo-FylgyrSarif` org/repo sentinel labeling improved for org-scoped checks (including `Rulesets`) and qualified resources.
- `README.md` check reference and attack catalog tables updated for v0.6.0 checks/campaigns.

### Fixed

- `Invoke-FylgyrOrgScan` now normalizes org check names in error-path output (`Test-OrgMfaPolicy` -> `OrgMfaPolicy`) for stable result contracts.
- SARIF sentinel labeling regression fixed for org-scoped `Rulesets` and org-qualified resource strings.

### Security

- Added workflow-level detections for script injection, artifact execution trust-boundary abuse, OIDC trust hardening gaps, cache poisoning, and reusable-workflow trust bypass patterns aligned to active 2024-2026 attack tradecraft.

### Added

- New attack catalog entry: `actions-cool-issues-helper-compromise` (actions-cool/issues-helper tag hijack, 2026-05-18).

### Changed

- `Test-ActionPinning`, `Test-Rulesets`, and `Test-EgressControl` now map findings to `actions-cool-issues-helper-compromise` in addition to existing incidents.
- `README.md` and `docs/COVERAGE.md` updated to include the new incident in attack mapping references.

## [0.5.0] - 2026-05-12

### Added

- `-IncludeOrgChecks` switch on `Invoke-Fylgyr` to run organization-policy checks once per owner during org-wide scans (`-Repo` omitted).
- Nine new public checks:
	- `Test-OrgMfaPolicy`
	- `Test-OrgDefaultPermissions`
	- `Test-IpAllowlist` (GraphQL)
	- `Test-AuditLogStreaming`
	- `Test-Rulesets`
	- `Test-OAuthAppPolicy`
	- `Test-OrgActionRestrictions`
	- `Test-OutsideCollaborators`
	- `Test-PatPolicy`
- Three new attack catalog entries:
	- `dropbox-github-breach`
	- `gentoo-github-compromise`
	- `github-device-code-phishing`
- `tests/OrgChecks.Tests.ps1` with pass/fail/insufficient-permission/user-owner coverage for all new org checks.

### Changed

- `Invoke-GitHubApi` GraphQL usage is now explicit and release-aligned:
	- Added `-Query` and `-Variables` parameters for GraphQL requests.
	- Added GraphQL `errors[]` response surfacing as sanitized PowerShell errors.
	- `-AllPages` is now explicitly rejected for GraphQL calls (cursor pagination required).
	- Backward compatibility preserved for legacy GraphQL calls that passed query text through `-Endpoint`.
- `Test-GitHubAppSecurity` extended in place (no rename) with org-governance detections:
	- `organization_administration:write`
	- all-repos write-scope blast radius analysis
	- suspicious combinations (`members:write + contents:write`, `secrets:write + actions:write`)
	- stale installation signal (>90 days)
	- user-owner runs now return org-app `Info` skip instead of using `/user/installations`
- SARIF sentinel messages now distinguish organization settings for org-check findings while still mapping to `SECURITY.md`.
- README, `docs/PERMISSIONS.md`, and `docs/COVERAGE.md` updated for org-policy checks and new attack mappings.

### Security

- Organization-level checks uniformly use `Get-FylgyrOwnerContext` and return `Info` for personal-account owners to avoid incorrect org endpoint usage.
- `Test-OutsideCollaborators` enforces a bounded permission-check budget to reduce rate-limit exhaustion risk on large organizations.

## [0.4.2] - 2026-05-08

### Added

- `Test-PublishIntegrity` check — detects insecure release publishing patterns in workflow YAML:
	- npm publish without `--provenance`
	- PyPI publish using static `password:` token auth instead of trusted publishing
	- container/image publish without signing or build provenance attestation
	- GitHub Release publishing without attestation signals
- `Get-FylgyrOwnerContext` private helper — shared owner/persona context (`Type`, `Login`, `PlanName`, `TokenOwner`, `TokenMatchesOwner`) with per-invocation cache.
- Four attack catalog entries:
	- `shai-hulud-npm-worm`
	- `lottie-player-npm-compromise`
	- `ua-parser-js-npm-compromise`
	- `bitwarden-cli-2026-04`
- `docs/MAINTAINER-GUIDE.md` — solo-maintainer quickstart, personal-account behavior matrix, and complementary-tool guidance.
- `examples/maintainer/fylgyr.yml` — SHA-pinned drop-in workflow for weekly maintainer scans and SARIF upload.

### Changed

- `Test-CodeOwner` now consumes `Get-FylgyrOwnerContext` instead of calling `users/{owner}` inline.
- `Test-GitHubAppSecurity` now consumes `Get-FylgyrOwnerContext` for owner type and token-owner matching.
- `Test-SecretScanning` behavior now surfaces richer risk signals:
	- Pass: scanning enabled and zero open alerts
	- Warning: open alerts with highest severity below High
	- Fail: open High/Critical alerts
	- Info fallback on alert-scope gaps with actionable `secret_scanning_alerts:read` remediation
	- detail now includes open-alert count, highest severity, and oldest alert age
- README expanded with maintainer quickstart and check/reference updates for 19 checks.

### Security

- Owner-context cache hardened to key on owner + token hash to prevent stale cross-token identity assumptions.
- Secret alert date parsing hardened to avoid runtime parsing failures while preserving safe error handling.

## [0.4.1] - 2026-05-07

### Added

- `Test-WebhookSecurity` check — audits repository webhooks for missing shared secrets. Without a secret, receivers cannot authenticate payloads and an attacker who learns the webhook URL can forge or replay events to downstream CI, chat, or deploy automation. Degrades gracefully to Info on 403 (requires Webhooks:read scope). Maps to `codecov-bash-uploader`.
- `Test-BinaryArtifact` check — walks the default branch tree via the git trees API and flags committed binary files (`.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.jar`, `.war`, `.a`, `.o`, `.pyc`, `.class`). Handles truncated trees (>100 k entries) with an Info result. Maps to `solarwinds-orion`.
- `Get-RepoTree` private helper — fetches the recursive git tree for the default branch, used by `Test-BinaryArtifact`.
- `committed-credentials-exposure` attack catalog entry — covers Uber 2016 (AWS keys in private repo, 57M records) and Toyota 2022 (partner credentials exposed five years). Maps to `CICD-SEC-5`, `T1552.001`. Seeded for a future `Test-SecretScanning` enhancement.
- `owaspCiCd` and `mitre` fields added to all 20 attack catalog entries. Pester now enforces both fields are present and non-empty for every entry.
- `docs/COVERAGE.md` — OWASP CI/CD Top 10 × MITRE ATT&CK supply-chain technique coverage matrix with roadmap signal for open gaps.
- `docs/CATALOG-MAINTENANCE.md` — monthly triage cadence, sources to watch, triage rubric, schema requirements, and catalog-only release policy.
- `docs/RELEASE-TESTING.md` — manual test checklist (PAT scope matrix, pass-case commands, edge cases, signoff gate) executed before every tagged release.
- `release.yml` now emits SLSA build provenance via `actions/attest-build-provenance@v2` (SHA-pinned). Publish job gains `id-token: write` and `attestations: write` permissions. Module is packaged as a zip artifact and attached to the GitHub Release.

### Changed

- `Test-GitHubAppSecurity` extended: now detects `workflows:write` (direct workflow injection path), `secrets:write` (Critical when org-wide), and `packages:write` (High when org-wide). Filters `user/installations` response to personal-account installs only (excludes org-type installations that are audited via the org endpoint). New Pester cases cover all added permission combinations and the org-type filter.
- `attacks.json` `github-app-token-theft` entry enriched with three additional `detectionSignals` for `workflows:write`, `secrets:write`, and `packages:write`.
- `CLAUDE.md` updated: check coverage table extended to all 18 shipped checks; gaps section trimmed to only still-open items; Release process, Catalog maintenance, and Scope discipline sections added; WebhookSecurity and BinaryArtifact moved from Gaps to the coverage table.
- `README.md` updated: WebhookSecurity and BinaryArtifact rows added to check reference table; architecture tree updated; check count updated to 18; GHES compatibility statement added; attestation verification snippet added; `committed-credentials-exposure` added to attack catalog table.

## [0.4.0] - 2026-04-12

### Added

- `Test-CodeOwner` check — fetches `CODEOWNERS` (root, `.github/`, `docs/`) and flags missing files, single-distinct-owner repositories, and catch-all `*` rules assigned to one owner. Maps to `xz-utils-backdoor`.
- `Test-SignedCommit` check — reports whether the default branch enforces required signed commits via `required_signatures`. Medium severity warning (not hard failure) with lower-friction remediation guidance. Maps to `xz-utils-backdoor`.
- `Test-ForkPullPolicy` check — workflow-level check that fails when `pull_request_target` is combined with checkout of `github.event.pull_request.head.sha`, `head.ref`, or `github.head_ref`, the exact primitive behind the nx Pwn Request and tj-actions/changed-files incidents. Maps to `nx-pwn-request`, `tj-actions-shai-hulud`, `prt-scan-ai-automated`.
- `Test-EnvironmentProtection` check — lists deployment environments and flags those without required reviewers or deployment branch policies. Maps to `unauthorized-env-deployment`, `prt-scan-ai-automated`.
- `Test-RepoVisibility` check — cross-checks repository visibility against naming heuristics (`-internal`, `-private`, `-confidential`, etc.) to catch Toyota-style exposures. Maps to `toyota-source-exposure`.
- `Test-EgressControl` check — detects missing or audit-only network egress filtering in workflows. Detects step-security/harden-runner, code-cargo/cargowall-action, and bullfrogsec/bullfrog. Notes BullFrog DNS-over-TCP bypass. Maps to `tj-actions-shai-hulud`, `trivy-supply-chain-2026`, `codecov-bash-uploader`.
- `Test-ForkSecretExposure` check — detects secrets accessible to fork PRs via pull_request_target, unprotected deployment environments, and unrestricted org-level secrets. Maps to `prt-scan-ai-automated`, `hackerbot-claw`, `nx-pwn-request`, `azure-karpenter-pwn-request`.
- `Test-GitHubAppSecurity` check — audits GitHub App installations at org level for overly permissive configurations (org-wide installs with write permissions, contents:write + actions:write combo, administration permission). Maps to `github-app-token-theft`.
- Nine new attack catalog entries: `praetorian-runner-pivot`, `prt-scan-ai-automated`, `hackerbot-claw`, `trivy-supply-chain-2026`, `github-app-token-theft`, `azure-karpenter-pwn-request`, `xz-utils-backdoor`, `unauthorized-env-deployment`, `toyota-source-exposure`.
- `Info` status type added to `Format-FylgyrResult` for advisory/recommendation output.
- `docs/PERMISSIONS.md` — GitHub token permission reference documenting the scopes required by each check.

### Changed

- `Test-DangerousTrigger` expanded: now detects pull_request_target with secret references, actor-restriction conditions, and maps to new attacks (prt-scan, hackerbot-claw, Trivy 2026, Azure Karpenter). Includes kill-chain details from real campaigns.
- `Test-RunnerHygiene` expanded: now checks org-wide runner groups, non-ephemeral runners, and self-hosted runners on public repos via GitHub API. Maps to `praetorian-runner-pivot` in addition to existing mappings.
- Orchestrator (`Invoke-Fylgyr`) updated to pass Owner/Repo/Token to workflow-based checks that need API access, and to register all new checks.
- `Write-FylgyrConsole` output reformatted: per-check results split onto separate lines with a dimmed detail row, new `Info` status rendering, and a `ScannedRepoCount` parameter so org-wide scans report total repositories scanned.

## [0.3.2] - 2026-04-06

### Security

- Error messages now use `$_.Exception.Message` instead of raw `$_` across all check functions and orchestrator to prevent token/path leakage.
- `Invoke-GitHubApi` sanitizes error output by parsing GitHub JSON error responses and stripping token fragments from URIs.
- HTTP endpoints are explicitly rejected — HTTPS-only enforcement added to `Invoke-GitHubApi`.
- Pagination bounded at 100 pages to prevent infinite loops from malformed API responses.
- `Owner` and `Repo` parameters enforce `[ValidatePattern('^[a-zA-Z0-9._-]+$')]` to reject injection attempts.
- Base64 decoding in `Get-WorkflowFile` wrapped in try/catch to handle corrupt blobs gracefully.

### Added

- `.github/copilot-instructions.md` — security-first coding guidance for GitHub Copilot.
- Security Requirements section in `CLAUDE.md` — mandatory rules for all AI-assisted code changes.
- Security Posture section in README documenting how Fylgyr practices what it preaches.
- "Why Fylgyr?" section in README explaining the Norse mythology origin of the name.
- Security Impact section and error sanitization checkbox in PR template.
- Expanded `SECURITY.md` with supported versions, scope, usage security guidance, and security design principles.

### Fixed

- Changelog dates for v0.1.0 and v0.2.0 updated from TBD.

## [0.3.1] - 2026-04-05

### Fixed

- SARIF output now fully compliant with GitHub code scanning requirements.
- All results include `physicalLocation` (required by GitHub's SARIF processor).
- Repo-level findings (BranchProtection, SecretScanning, etc.) use `SECURITY.md` as sentinel file with context in `location.message.text`.
- Added `partialFingerprints` (SHA-256 based `primaryLocationLineHash`) to prevent duplicate alerts across runs.
- Added `properties.security-severity` scores on rules so findings appear as security results in the Security tab.
- Added `security` and `supply-chain` tags and `precision: high` on all rules.
- Updated `$schema` to GitHub-recommended `json.schemastore.org` URL.
- Improved repo-level resource detection to handle dotted repo names (e.g., `org/repo.name`).

### Changed

- Release workflow now scopes `contents: write` to publish job only (least privilege).

## [0.3.0] - 2026-04-05

### Added

- `Test-BranchProtection` check — audits default branch protection rules (required reviews, status checks, force push, signed commits). Maps to `codecov-bash-uploader`.
- `Test-SecretScanning` check — verifies Secret Scanning is enabled and flags unresolved alerts. Maps to `uber-credential-leak`.
- `Test-DependabotAlert` check — checks for open critical/high Dependabot alerts. Maps to `event-stream-hijack` and `solarwinds-orion`.
- `Test-CodeScanning` check — verifies GitHub Code Scanning is configured with recent analyses. Maps to `solarwinds-orion`.
- `Test-RunnerHygiene` check — detects risky self-hosted runner configurations in workflow YAML. Maps to `github-actions-cryptomining`.
- Five new attack catalog entries: `codecov-bash-uploader`, `uber-credential-leak`, `event-stream-hijack`, `solarwinds-orion`, `github-actions-cryptomining`.
- Release workflow hardened with validate job (manifest, tag/version match, lint, tests) before publish.
- Automatic GitHub Release creation with `gh release create`.

## [0.2.0] - 2026-04-05

### Added

- `Invoke-Fylgyr` public entrypoint orchestrating all checks with pipeline support (`ValueFromPipeline` for repo names, `ValueFromPipelineByPropertyName` for structured objects).
- Org-wide scan: omit `-Repo` to enumerate and scan all repositories under an owner or organization.
- `Test-ActionPinning` check — detects third-party actions referenced by tag or branch instead of a full 40-character commit SHA. Maps to `trivy-tag-poisoning` and `tj-actions-shai-hulud`.
- `Test-DangerousTrigger` check — detects `pull_request_target` and `workflow_run` patterns combined with untrusted code checkout. Maps to `nx-pwn-request`.
- `Test-WorkflowPermission` check — detects workflow files missing a top-level `permissions:` block. Maps to `tj-actions-shai-hulud` and `nx-pwn-request`.
- `Get-WorkflowFile` private helper — fetches workflow YAML content via the GitHub Contents API, shared across all checks to minimize API calls.
- `Invoke-GitHubApi` private helper — GitHub REST/GraphQL wrapper with rate-limit detection, configurable timeout, and `-AllPages` pagination via `Link` response header.
- `Format-FylgyrResult` private helper — enforces the standard result schema (`CheckName`, `Status`, `Severity`, `Resource`, `Detail`, `Remediation`, `AttackMapping`, `Target`).
- `-OutputFormat` parameter on `Invoke-Fylgyr` with four modes: `Object` (default), `Console`, `JSON`, `SARIF`.
- `ConvertTo-FylgyrJson` — JSON output with metadata and summary counts.
- `ConvertTo-FylgyrSarif` — SARIF 2.1.0 output for GitHub Code Scanning integration.
- `Write-FylgyrConsole` — colored, grouped terminal output with per-repo finding summaries.
- `FunctionsToExport` in `Fylgyr.psd1` updated to explicit list.
- Dogfood CI workflow now runs Fylgyr against its own repository workflows and uploads SARIF to GitHub Security tab.
- README overhauled with quick start, check reference table, sample output, output format guide, attack catalog summary, and architecture diagram.

## [0.1.0] - TBD

### Added

- Initial Fylgyr foundation scaffold.
- Repository governance files: Code of Conduct, Security Policy, CODEOWNERS, issue templates, and PR template.
- GitHub Actions workflows for CI and PSGallery release with SHA-pinned actions and least-privilege permissions.
- PowerShell module skeleton under src/Fylgyr.
- Attack campaign catalog with five initial campaigns in attacks.json.
- Baseline Pester tests for manifest validity, module import, and attacks catalog schema.
