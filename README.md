# Fylgyr

> Guardian spirit for your repos

[![CI](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml/badge.svg)](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml)
[![PSGallery Version](https://img.shields.io/powershellgallery/v/Fylgyr)](https://www.powershellgallery.com/packages/Fylgyr)

Fylgyr audits GitHub repositories and organizations for supply chain risks by mapping every finding to a real-world attack campaign.

Unlike score-based tools such as [OpenSSF Scorecard](https://securityscorecards.dev/), Fylgyr is **attack-mapped, not score-based**. Every finding explains which known campaign it aligns with and why that behavior matters.

## Quick Start

```powershell
# Install from PowerShell Gallery
Install-Module Fylgyr

# Scan a single repository
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo'

# Scan all repositories in an organization
Invoke-Fylgyr -Owner 'myorg'
```

> Requires PowerShell 7+ and a GitHub token (`$env:GITHUB_TOKEN` or `-Token`).

## Sample Output

### Console (default objects)

```
CheckName          : ActionPinning
Status             : Fail
Severity           : High
Resource           : .github/workflows/ci.yml:12
Detail             : Unpinned action reference: actions/checkout@v4
Remediation        : Pin this action to a full 40-character commit SHA instead of a tag or branch.
AttackMapping      : {trivy-tag-poisoning, tj-actions-shai-hulud}
```

### Colored console output

```powershell
# Single repo
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat Console

# Org-wide scan (with progress bar)
Invoke-Fylgyr -Owner 'myorg' -OutputFormat Console
```

```
  Fylgyr Supply-Chain Audit: myorg
  ------------------------------------------------------------

  [myorg/web-app]
    ActionPinning: 1 passed, 2 finding(s):
      [FAIL] Unpinned action reference: actions/checkout@v4
        Resource:    .github/workflows/ci.yml:12
        Severity:    High
        Remediation: Pin this action to a full 40-character commit SHA instead of a tag or branch.
        Attacks:     trivy-tag-poisoning, tj-actions-shai-hulud
      [FAIL] Unpinned action reference: actions/setup-node@v3
        Resource:    .github/workflows/ci.yml:15
        Severity:    High
        Remediation: Pin this action to a full 40-character commit SHA instead of a tag or branch.
        Attacks:     trivy-tag-poisoning, tj-actions-shai-hulud
    DangerousTrigger: [PASS] No dangerous trigger patterns found. (2 files)
    WorkflowPermissions: [PASS] Workflow declares a top-level permissions block. (2 files)

  [myorg/api-service]
    ActionPinning: [PASS] All action references are SHA-pinned. (3 files)
    DangerousTrigger: [PASS] No dangerous trigger patterns found. (3 files)
    WorkflowPermissions: [PASS] Workflow declares a top-level permissions block. (3 files)

  Repos with no workflow files (1):
    - myorg/docs-site

  ------------------------------------------------------------
  3 repo(s) scanned | 8 passed, 2 failed, 0 warnings, 0 errors
```

## Output Formats

| Format | Flag | Description |
|---|---|---|
| Object | `-OutputFormat Object` (default) | Returns `PSCustomObject[]` for pipeline processing |
| Console | `-OutputFormat Console` | Colored, grouped terminal display with summary |
| JSON | `-OutputFormat JSON` | Machine-readable JSON with metadata and summary counts |
| SARIF | `-OutputFormat SARIF` | SARIF 2.1.0 for GitHub Code Scanning integration |

### Feeding SARIF into GitHub Code Scanning

```yaml
- name: Run Fylgyr
  shell: pwsh
  run: |
    Invoke-Fylgyr -Owner '${{ github.repository_owner }}' `
                  -Repo '${{ github.event.repository.name }}' `
                  -OutputFormat SARIF | Out-File -FilePath fylgyr.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@48ab28a6f5dbc2a99bf1e0131198dd8f1df78169 # v3.28.0
  with:
    sarif_file: fylgyr.sarif
```

## Usage

### Single repository

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo'
```

### Organization-wide scan

Omit `-Repo` to scan every repository under an owner or organization:

```powershell
Invoke-Fylgyr -Owner 'myorg'
```

### Pipeline input

```powershell
# Structured objects
@(
    [PSCustomObject]@{ Owner = 'myorg'; Repo = 'repo1' }
    [PSCustomObject]@{ Owner = 'myorg'; Repo = 'repo2' }
) | Invoke-Fylgyr

# String repo names for a single owner
'repo1', 'repo2' | Invoke-Fylgyr -Owner 'myorg'
```

### Export results

```powershell
# JSON file
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat JSON | Out-File results.json

# SARIF file
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat SARIF | Out-File fylgyr.sarif

# Filter failures only
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' | Where-Object Status -eq 'Fail'
```

## Check Reference

| Check | Detects | Severity | Attack Mapping |
|---|---|---|---|
| `ActionPinning` | Third-party actions referenced by tag/branch instead of SHA | High | `trivy-tag-poisoning`, `tj-actions-shai-hulud` |
| `DangerousTrigger` | `pull_request_target` / `workflow_run` with untrusted code checkout | Critical | `nx-pwn-request` |
| `WorkflowPermissions` | Missing top-level `permissions:` block in workflow files | Medium | `tj-actions-shai-hulud`, `nx-pwn-request` |

## Attack Catalog

Every finding maps to a real-world supply chain incident. The full catalog lives in [`src/Fylgyr/Data/attacks.json`](src/Fylgyr/Data/attacks.json).

| ID | Campaign | Date |
|---|---|---|
| `trivy-tag-poisoning` | Trivy tag poisoning | 2024-07 |
| `tj-actions-shai-hulud` | tj-actions/changed-files (Shai-Hulud) token exfiltration | 2025-03 |
| `nx-pwn-request` | nx/Pwn Request | 2025-01 |
| `axios-npm-token-leak` | Axios npm token leak | 2024-01 |
| `trivy-force-push-main` | Trivy force-push to main | 2024-07 |

## Architecture

```
src/Fylgyr/
├── Fylgyr.psd1              # Module manifest
├── Fylgyr.psm1              # Entry point (dot-sources Public/ and Private/)
├── Public/
│   ├── Invoke-Fylgyr.ps1    # Orchestrator + output formatting
│   ├── Test-ActionPinning.ps1
│   ├── Test-DangerousTrigger.ps1
│   └── Test-WorkflowPermission.ps1
├── Private/
│   ├── Invoke-GitHubApi.ps1       # REST/GraphQL wrapper with pagination
│   ├── Get-WorkflowFile.ps1       # Fetches workflows via Git Trees API
│   ├── Format-FylgyrResult.ps1    # Standardized result schema
│   ├── ConvertTo-FylgyrJson.ps1   # JSON output formatter
│   ├── ConvertTo-FylgyrSarif.ps1  # SARIF 2.1.0 output formatter
│   └── Write-FylgyrConsole.ps1    # Colored console output
└── Data/
    └── attacks.json               # Attack campaign catalog
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
