# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Fylgyr** is a PowerShell module that audits GitHub repositories and organizations for supply chain risks by mapping every finding to a real-world attack campaign. Unlike score-based tools (e.g., OpenSSF Scorecard), Fylgyr is *attack-mapped* — each result explains which known incident it aligns with and why the behavior matters.

Public entry point (once implemented): `Invoke-Fylgyr -Owner <org-or-user> -Repo <repo>`

## Common Commands

All commands run from the repository root in PowerShell 7+.

### Install dev dependencies
```powershell
Install-Module -Name Pester -MinimumVersion 5.0 -Repository PSGallery -Scope CurrentUser -Force -AcceptLicense
Install-Module -Name PSScriptAnalyzer -Repository PSGallery -Scope CurrentUser -Force -AcceptLicense
```

### Lint
```powershell
Invoke-ScriptAnalyzer -Path ./src -Recurse -Severity Error,Warning
```

### Run all tests
```powershell
Invoke-Pester -Path ./tests -Output Detailed
```

### Run a single test or test suite
```powershell
# By file
Invoke-Pester -Path ./tests/Fylgyr.Tests.ps1 -Output Detailed

# By name pattern
Invoke-Pester -Path ./tests/Fylgyr.Tests.ps1 -Output Detailed -TestName "*module manifest*"
```

### Validate module manifest
```powershell
Test-ModuleManifest -Path ./src/Fylgyr/Fylgyr.psd1
```

## Architecture

### Module layout

```
src/Fylgyr/
├── Fylgyr.psd1          # Module manifest (version, exports, dependencies)
├── Fylgyr.psm1          # Entry point — dynamically dot-sources Public/ and Private/
├── Public/              # Exported functions (Invoke-Fylgyr + check implementations: Test-*.ps1)
├── Private/
│   ├── Invoke-GitHubApi.ps1      # GitHub REST/GraphQL wrapper with rate-limit handling and 30s default timeout
│   └── Format-FylgyrResult.ps1   # Standardizes output schema for all checks
└── Data/
    └── attacks.json     # Attack campaign catalog (id, name, date, detectionSignals, …)
tests/
└── Fylgyr.Tests.ps1     # Pester tests — module validation + attacks.json schema validation
plans/                   # Local-only phase plans (not tracked by git)
```

`Fylgyr.psm1` discovers and loads all `.ps1` files under `Public/` and `Private/` at import time. Only `Public/` functions are exported.

### Check pattern

`Invoke-Fylgyr` is the orchestrator — it calls each `Test-*` check function explicitly and returns the collected results. Individual check failures produce `Status = 'Error'` results; `Invoke-Fylgyr` never throws on a per-check failure.

New security checks are added as `Test-<CheckName>.ps1` in `src/Fylgyr/Public/`. Every check must:

1. Call `Format-FylgyrResult` to return a standardized result object.
2. Map findings to one or more attack IDs from `attacks.json`.

The result schema enforced by `Format-FylgyrResult` includes: `CheckName`, `Status`, `Severity`, `Resource`, `Detail`, `Remediation`, `AttackMapping`.

### Attack catalog (`attacks.json`)

Each entry requires: `id`, `name`, `date`, `description`, `affectedPackages`, `cves`, `references`, `detectionSignals`. Schema is validated by Pester tests — the tests will fail if required fields are missing.

### GitHub API integration

`Invoke-GitHubApi` wraps both REST and GraphQL endpoints. Authentication uses `$env:GITHUB_TOKEN`. Rate-limit detection is built in. Default timeout is 30 seconds; override with `-TimeoutSec`.

### CI/CD workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | PR to `main` | Lint + test gate |
| `release.yml` | Tag push (`v*`) | Publish to PowerShell Gallery (requires `PSGALLERY_API_KEY` secret) |
| `dogfood.yml` | PR to `main`, scheduled (Mon 03:17 UTC), manual | Enforces supply-chain policy on the repo's own workflow files |

#### Dogfood rules — enforced on every `.github/workflows/*.yml`

Any new or modified workflow file must satisfy all three, or the dogfood CI job fails:

1. **Workflow-level `permissions:` block** declared before the first `jobs:` key.
2. **All `uses:` references SHA-pinned** to a full 40-character hex commit SHA (e.g., `uses: actions/checkout@abc123...40chars`). Tags and branch names are rejected.
3. **No `write-all` permission pattern** anywhere in the file.

## Conventions

- Use `Format-FylgyrResult` for all check output — never return ad-hoc objects.
- Use only approved PowerShell verbs (`Get-Verb` lists them).
- PSScriptAnalyzer must report zero errors and zero warnings — CI enforces this.
- Secrets and tokens go in environment variables (`$env:GITHUB_TOKEN`, etc.), never in code.
- Add or update `attacks.json` entries when introducing new attack mappings; include all required fields.
- `FunctionsToExport` in `Fylgyr.psd1` must be kept as an explicit list matching `Public/` — do not leave it as `'*'` once functions exist.
- Branch naming: `phase{N}/description` (e.g., `phase2/core-checks`).
