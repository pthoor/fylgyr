# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [0.3.1] - 2026-04-05

### Fixed

- SARIF output now fully compliant with GitHub code scanning requirements.
- All results include `physicalLocation` (required by GitHub's SARIF processor).
- Repo-level findings (BranchProtection, SecretScanning, etc.) use `.github/SECURITY.md` as sentinel file with context in `location.message.text`.
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

## [0.2.0] - TBD

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
