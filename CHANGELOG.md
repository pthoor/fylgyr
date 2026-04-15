# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

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

- Initial Fylgyr Phase 1 foundation scaffold.
- Repository governance files: Code of Conduct, Security Policy, CODEOWNERS, issue templates, and PR template.
- GitHub Actions workflows for CI and PSGallery release with SHA-pinned actions and least-privilege permissions.
- PowerShell module skeleton under src/Fylgyr.
- Attack campaign catalog with five initial campaigns in attacks.json.
- Baseline Pester tests for manifest validity, module import, and attacks catalog schema.
