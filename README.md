# Fylgyr

> Guardian spirit for your repos

[![CI](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml/badge.svg)](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml)
[![PSGallery Version](https://img.shields.io/powershellgallery/v/Fylgyr)](https://www.powershellgallery.com/packages/Fylgyr)

Fylgyr audits GitHub repositories and organizations for supply chain risks by mapping every finding to a real-world attack campaign.

Unlike score-based tools such as [OpenSSF Scorecard](https://securityscorecards.dev/), Fylgyr is **attack-mapped, not score-based**. Every finding explains which known campaign it aligns with and why that behavior matters.

### Why "Fylgyr"?

In Norse mythology, a *fylgja* (plural *fylgjur*) is a supernatural guardian spirit that accompanies a person throughout their life. Often appearing as an animal, the fylgja watches over its ward and can serve as a warning of danger ahead. Fylgyr serves the same role for your repositories — a vigilant guardian that watches for supply chain threats others might miss.

## Quick Start

```powershell
# Install from PowerShell Gallery
Install-Module Fylgyr

# Scan a single repository
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo'

# Scan all repositories in an organization
Invoke-Fylgyr -Owner 'myorg'
```

> Requires PowerShell 7+ and a GitHub token. Fylgyr reads `$env:GITHUB_TOKEN` by default, or you can pass `-Token` explicitly:
>
> ```powershell
> $env:GITHUB_TOKEN = 'github_pat_...'
> Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo'
>
> # Or pass a different token for a single call
> Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Token $otherToken
> ```
>
> **Fylgyr strongly recommends [fine-grained PATs](docs/PERMISSIONS.md#recommended-token--fine-grained-pat)** — every check works with least-privilege fine-grained permissions, and no feature requires a classic PAT. Never hardcode tokens; load them from a secret manager.

## Sample Output

### Object output (default)

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

Abridged example (a real scan runs ~14 checks per repo):

```
  Fylgyr Supply-Chain Audit: myorg
  ------------------------------------------------------------

  [myorg/web-app]
    > ActionPinning  [1 passed, 2 finding(s)]
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

    > DangerousTrigger  [PASS]
        No dangerous trigger patterns found. (2 files)

    > WorkflowPermissions  [PASS]
        Workflow declares a top-level permissions block. (2 files)

  [myorg/api-service]
    > ActionPinning  [PASS]
        All action references are SHA-pinned. (3 files)

    > DangerousTrigger  [PASS]
        No dangerous trigger patterns found. (3 files)

    > WorkflowPermissions  [PASS]
        Workflow declares a top-level permissions block. (3 files)

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

Add a workflow to run Fylgyr on every push and PR. Results appear in your repository's **Security** tab under **Code scanning**.

> **Important:** The workflow must trigger on `push` to your default branch — not just `pull_request` — for results to appear in the Security tab. PR-only triggers show results in PR checks but not in the Security tab.

A ready-to-use workflow template is available at [`docs/fylgyr-workflow.yml`](docs/fylgyr-workflow.yml). Copy it to your repo:

```bash
# From your repository root
mkdir -p .github/workflows
cp docs/fylgyr-workflow.yml .github/workflows/fylgyr.yml
# Or simply copy the file from the Fylgyr repo
```

> **Note:** The template targets `main` and `master` branches. If your default branch has a different name (e.g., `trunk`), update the `on.push.branches` and `on.pull_request.branches` filters in the copied workflow file.

Or add these steps to an existing workflow:

```yaml
- name: Install Fylgyr
  shell: pwsh
  run: Install-Module -Name Fylgyr -Repository PSGallery -Force -Scope CurrentUser

- name: Run Fylgyr scan
  shell: pwsh
  run: |
    Invoke-Fylgyr -Owner '${{ github.repository_owner }}' `
                  -Repo '${{ github.event.repository.name }}' `
                  -OutputFormat SARIF `
      | Out-File -FilePath fylgyr.sarif -Encoding utf8
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@48ab28a6f5dbc2a99bf1e0131198dd8f1df78169 # v3.28.0
  with:
    sarif_file: fylgyr.sarif
```

### Where to find results

After the workflow runs on your default branch:

1. Go to your repository on GitHub.
2. Click the **Security** tab.
3. Click **Code scanning** in the left sidebar.
4. Filter by **Tool: Fylgyr** to see only supply chain findings.

Each alert shows the severity, remediation steps, and which real-world attack campaign it maps to.

> **Note:** Code scanning requires GitHub Advanced Security for private repos on GitHub Enterprise. It's free for all public repositories.

### Permissions

The workflow uses the built-in `GITHUB_TOKEN` with minimal permissions:

| Permission | Purpose |
|---|---|
| `contents: read` | Read workflow files and repository content |
| `security-events: write` | Upload SARIF results to Code Scanning |

These two permissions are the only valid `GITHUB_TOKEN` scopes needed. They cover the workflow-based checks (ActionPinning, DangerousTrigger, WorkflowPermissions, RunnerHygiene, EgressControl, ForkPullPolicy, CodeScanning).

#### Repo-level checks that need a PAT

Several checks require a **Personal Access Token** (PAT) because the workflow `GITHUB_TOKEN` does not have access to those APIs. **Fylgyr strongly recommends fine-grained PATs** — every check below works with least-privilege fine-grained permissions:

| Check | Fine-grained permission (read-only) |
|---|---|
| `BranchProtection` | Administration |
| `SecretScanning` | Secret scanning alerts |
| `DependabotAlert` | Dependabot alerts |
| `CodeOwners` | Contents |
| `SignedCommits` | Administration |
| `EnvironmentProtection` | Environments |
| `RepoVisibility` | Metadata |
| `ForkSecretExposure` | Environments (plus org Secrets for org-level secret enumeration) |
| `GitHubAppSecurity` | Org Administration (falls back gracefully for user accounts) |
| `RunnerHygiene` (org-level) | Org Administration |

Without a PAT these checks gracefully report `Status = 'Error'` with a clear message — they won't fail the workflow or block other checks.

> See [docs/PERMISSIONS.md](docs/PERMISSIONS.md) for the full per-check permission matrix, the recommended least-privilege fine-grained PAT, guidance on classic PAT fallback, and troubleshooting for the common `404 Not Found` error caused by org-level fine-grained PAT approval.

To enable them, create a fine-grained PAT, add it as a repository secret (e.g., `FYLGYR_TOKEN`), and update the workflow step:

```yaml
- name: Run Fylgyr scan
  shell: pwsh
  run: |
    Invoke-Fylgyr -Owner '${{ github.repository_owner }}' `
                  -Repo '${{ github.event.repository.name }}' `
                  -Token $env:FYLGYR_TOKEN `
                  -OutputFormat SARIF `
      | Out-File -FilePath fylgyr.sarif -Encoding utf8
  env:
    FYLGYR_TOKEN: ${{ secrets.FYLGYR_TOKEN }}
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
| `DangerousTrigger` | `pull_request_target` / `workflow_run` with untrusted code checkout, missing actor restrictions, secret exposure in PRT context | Critical | `nx-pwn-request`, `prt-scan-ai-automated`, `trivy-supply-chain-2026`, `azure-karpenter-pwn-request`, `hackerbot-claw` |
| `WorkflowPermissions` | Missing top-level `permissions:` block in workflow files | Medium | `tj-actions-shai-hulud`, `nx-pwn-request` |
| `EgressControl` | Missing or audit-only network egress filtering in workflows | Medium | `tj-actions-shai-hulud`, `trivy-supply-chain-2026`, `codecov-bash-uploader` |
| `ForkSecretExposure` | Secrets accessible to fork PRs, unprotected environments, unrestricted org secrets | Critical | `prt-scan-ai-automated`, `hackerbot-claw`, `nx-pwn-request`, `azure-karpenter-pwn-request` |
| `GitHubAppSecurity` | Overly permissive GitHub App installations (org or user account) | Critical | `github-app-token-theft` |
| `BranchProtection` | Weak or missing default branch protection rules | High | `codecov-bash-uploader` |
| `SecretScanning` | Secret Scanning not enabled or unresolved alerts | High | `uber-credential-leak` |
| `DependabotAlert` | Open critical/high Dependabot vulnerability alerts | High | `event-stream-hijack`, `solarwinds-orion` |
| `CodeScanning` | Code Scanning not configured or stale analyses | Medium | `solarwinds-orion` |
| `RunnerHygiene` | Risky self-hosted runner configurations, org-wide runner groups, non-ephemeral runners, public repo runners | High | `github-actions-cryptomining`, `praetorian-runner-pivot` |
| `CodeOwners` | Missing `CODEOWNERS` file, single-owner catch-all rules, too few distinct reviewers | Medium | `xz-utils-backdoor` |
| `SignedCommits` | Default branch does not require signed commits | Medium | `xz-utils-backdoor` |
| `ForkPullPolicy` | `pull_request_target` combined with checkout of fork-controlled `head.sha`/`head.ref`/`github.head_ref` | High | `nx-pwn-request`, `tj-actions-shai-hulud`, `prt-scan-ai-automated` |
| `EnvironmentProtection` | Deployment environments without required reviewers or branch policies | High | `unauthorized-env-deployment`, `prt-scan-ai-automated` |
| `RepoVisibility` | Public repositories with internal/private naming patterns | Medium | `toyota-source-exposure` |

## Attack Catalog

Every finding maps to a real-world supply chain incident. The full catalog lives in [`src/Fylgyr/Data/attacks.json`](src/Fylgyr/Data/attacks.json).

| ID | Campaign | Date |
|---|---|---|
| `trivy-tag-poisoning` | Trivy tag poisoning | 2024-07 |
| `tj-actions-shai-hulud` | tj-actions/changed-files (Shai-Hulud) token exfiltration | 2025-03 |
| `nx-pwn-request` | nx/Pwn Request | 2025-01 |
| `axios-npm-token-leak` | Axios npm token leak | 2024-01 |
| `trivy-force-push-main` | Trivy force-push to main | 2024-07 |
| `codecov-bash-uploader` | Codecov bash uploader compromise | 2021-01 |
| `uber-credential-leak` | Uber credential leak breach | 2022-09 |
| `event-stream-hijack` | event-stream npm package hijack | 2018-11 |
| `solarwinds-orion` | SolarWinds Orion supply chain attack | 2020-12 |
| `github-actions-cryptomining` | GitHub Actions crypto-mining campaigns | 2022-04 |
| `praetorian-runner-pivot` | Praetorian self-hosted runner lateral movement | 2024-07 |
| `prt-scan-ai-automated` | prt-scan AI-automated PR poisoning | 2026-03 |
| `hackerbot-claw` | hackerbot-claw autonomous CI/CD attacker | 2026-03 |
| `trivy-supply-chain-2026` | Trivy supply chain worm | 2026-03 |
| `github-app-token-theft` | GitHub App installation token abuse | 2025-ongoing |
| `azure-karpenter-pwn-request` | Azure Karpenter Provider Pwn Request | 2025 |
| `xz-utils-backdoor` | XZ Utils (liblzma) maintainer backdoor | 2024-03 |
| `unauthorized-env-deployment` | Unauthorized deployment via unprotected environment | pattern |
| `toyota-source-exposure` | Toyota source code public repository exposure | 2022-10 |

## Security Posture

Fylgyr is a security tool and holds itself to the same standard it applies to the repositories it audits.

| Practice | How Fylgyr applies it |
|---|---|
| **SHA-pinned actions** | All workflow `uses:` references pin to full 40-char commit SHAs |
| **Least-privilege permissions** | Workflows declare minimal `permissions:` blocks; `contents: write` scoped to publish job only |
| **No secret leakage** | Error handling is designed to avoid logging secrets; tokens are never logged or included in output |
| **Input validation** | All user-facing parameters enforce `[ValidatePattern]` to reject injection attempts |
| **HTTPS-only** | HTTP API endpoints are explicitly rejected |
| **Bounded pagination** | API pagination capped at 100 pages to prevent infinite loops |
| **Self-auditing** | The [dogfood workflow](.github/workflows/dogfood.yml) runs Fylgyr against its own repo on every push |
| **No dynamic execution** | `Invoke-Expression`, `Start-Process`, and similar cmdlets are never used |
| **Fork-safe CI** | Dogfood workflow skips fork PRs to prevent token exfiltration |

See [SECURITY.md](SECURITY.md) for vulnerability reporting, scope, and security design principles.

## Architecture

```
src/Fylgyr/
├── Fylgyr.psd1              # Module manifest
├── Fylgyr.psm1              # Entry point (dot-sources Public/ and Private/)
├── Public/
│   ├── Invoke-Fylgyr.ps1    # Orchestrator + output formatting
│   ├── Test-ActionPinning.ps1
│   ├── Test-BranchProtection.ps1
│   ├── Test-CodeOwner.ps1
│   ├── Test-CodeScanning.ps1
│   ├── Test-DangerousTrigger.ps1
│   ├── Test-DependabotAlert.ps1
│   ├── Test-EgressControl.ps1
│   ├── Test-EnvironmentProtection.ps1
│   ├── Test-ForkPullPolicy.ps1
│   ├── Test-ForkSecretExposure.ps1
│   ├── Test-GitHubAppSecurity.ps1
│   ├── Test-RepoVisibility.ps1
│   ├── Test-RunnerHygiene.ps1
│   ├── Test-SecretScanning.ps1
│   ├── Test-SignedCommit.ps1
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
