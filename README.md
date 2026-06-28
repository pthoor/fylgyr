# Fylgyr

> Guardian spirit for your repos

[![CI](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml/badge.svg)](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml)
[![PSGallery Version](https://img.shields.io/powershellgallery/v/Fylgyr)](https://www.powershellgallery.com/packages/Fylgyr)

Fylgyr finds exploitable GitHub supply-chain weaknesses in repositories and organizations, then maps each finding to a real-world attack campaign with actionable remediation.

Built for maintainers and security teams, Fylgyr emphasizes explainable findings over opaque scores and supports console, JSON, and SARIF output for local triage and CI integration.

Unlike score-based tools such as [OpenSSF Scorecard](https://securityscorecards.dev/), Fylgyr is **attack-mapped, not score-based**. Every finding explains which known campaign it aligns with and why that behavior matters.

## Why "Fylgyr"?

In Norse mythology, a *fylgja* (plural *fylgjur*) is a supernatural guardian spirit that accompanies a person throughout their life. Often appearing as an animal, the fylgja watches over its ward and can serve as a warning of danger ahead. Fylgyr serves the same role for your repositories — a vigilant guardian that watches for supply chain threats others might miss.

## Why Fylgyr + Microsoft Sentinel

Fylgyr gives you high-context findings. Microsoft Sentinel gives you operational visibility and alerting at scale.

Use them together when you need both:

- **Explainable detections:** findings map directly to known attack campaigns, not opaque numeric scores.
- **Security operations workflow:** stream findings into Sentinel tables, analytics rules, and workbooks for triage and escalation.
- **Low-noise drift monitoring:** run scheduled scans to detect trust-boundary and policy changes without alerting on every CI execution.
- **Practical rollout:** start with GitHub-hosted runners and public Azure Monitor ingestion over TLS, then harden runtime/networking later.

## Quick Start for local use:

> Prerequisites:
>
> - PowerShell 7+
> - GitHub token for scans (for local runs, use a fine-grained Personal Access Token (PAT))
> - Optional (only for provenance verification): GitHub CLI (`gh`)
> - Windows install for GitHub CLI: `winget install --id GitHub.cli --exact`

```powershell
# Install from PowerShell Gallery
Install-Module Fylgyr

# Provide a GitHub token (required for local runs, this is typically a fine-grained PAT)
$env:GITHUB_TOKEN = Read-Host -Prompt 'GitHub PAT' -MaskInput

# Scan a single repository
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo'

# Scan all repositories in an organization
Invoke-Fylgyr -Owner 'myorg'

# Scan organization repositories + org-level policy controls (opt-in)
Invoke-Fylgyr -Owner 'myorg' -IncludeOrgChecks

# Optional cleanup
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
```

> Why cleanup? Removing token variables after use reduces accidental exposure in later commands, logs, child processes, and shared terminal output.

> Requires PowerShell 7+ and a GitHub token. For local runs, this is typically a fine-grained PAT. In GitHub Actions, the built-in `GITHUB_TOKEN` can run workflow-file checks. Fylgyr reads `$env:GITHUB_TOKEN` by default, or you can pass `-Token` explicitly:
>
> ```powershell
> # Preferred: load from SecretManagement (or your secret manager)
> # and pass the token directly for this invocation
> $token = Get-Secret -Name 'FYLGYR_PAT' -AsPlainText
> Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Token $token
> Remove-Variable token -ErrorAction SilentlyContinue
>
> # Fallback: masked interactive prompt
> # $token = Read-Host -Prompt 'GitHub token' -MaskInput
> # Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Token $token
>
> # Or pass a different token for a single call
> Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Token $otherToken
> ```
>
> **Fylgyr strongly recommends [fine-grained PATs](docs/PERMISSIONS.md#recommended-token--fine-grained-pat)** for default operation. Core repository checks and most organization checks work with least-privilege fine-grained permissions, and no feature requires a classic PAT. Some organization governance APIs (currently PAT policy evidence endpoints) can be restricted by GitHub to GitHub App token types; in those contexts Fylgyr reports advisory `Info` results instead of a misleading fail. Never hardcode tokens; load them from a secret manager.

## Maintainer of open-source projects - Quick Start Guide

> If you're a maintainer of popular open-source projects looking for quick local use, start here. For Sentinel integration, see the next section. Recent supply-chain attacks have shown that public repositories are high-value targets. Fylgyr helps you find and fix weaknesses before attackers do.

If you maintain a personal open-source repo, start here.

1. Install and run once locally:

```powershell
Install-Module Fylgyr -Repository PSGallery -Force

# Run against your repo with a GitHub token (PAT recommended for full check coverage)

$token = Read-Host -Prompt 'PAT' -MaskInput

# Or load from SecretManagement and pass directly (recommended for scripts and automation)
# $token = Get-Secret -Name 'FYLGYR_PAT' -AsPlainText

# Run the scan, and change output format as needed (Console, JSON, SARIF, etc.)
Invoke-Fylgyr -Owner 'your-user-or-org' -Repo 'your-repo' -OutputFormat Console -Token $token

# Remove the token variable after use to avoid accidental exposure in the session
Remove-Variable token -ErrorAction SilentlyContinue
```

2. Add the drop-in workflow from `examples/maintainer/fylgyr.yml`.

3. Optional: start from the suppression template and copy it to the repository root:

```powershell
Copy-Item -Path 'examples/maintainer/fylgyr-suppressions.example.yml' -Destination '.fylgyr.yml'
```

```yaml
name: Fylgyr Maintainer Scan

on:
  pull_request:
    paths:
      - '.github/workflows/*.yml'
      - '.github/workflows/*.yaml'
  schedule:
    - cron: '17 3 * * 1'
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  fylgyr:
    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
      - name: Install Fylgyr
        shell: pwsh
        run: Install-Module -Name Fylgyr -Repository PSGallery -Force -Scope CurrentUser
      - name: Run Fylgyr scan (SARIF)
        shell: pwsh
        run: |
          Invoke-Fylgyr -Owner '${{ github.repository_owner }}' `
                        -Repo '${{ github.event.repository.name }}' `
                        -OutputFormat SARIF `
            | Out-File -FilePath fylgyr.sarif -Encoding utf8
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - name: Upload SARIF
        if: always() && hashFiles('fylgyr.sarif') != ''
        uses: github/codeql-action/upload-sarif@c10b8064de6f491fea524254123dbe5e09572f13
        with:
          sarif_file: fylgyr.sarif
```

This workflow intentionally does not fail PRs on findings. It uploads findings to Security > Code scanning for triage.

Read the full maintainer guide for tool users: [docs/MAINTAINER-GUIDE.md](docs/MAINTAINER-GUIDE.md).

If you're a **solo maintainer**, also read the [Solo-Maintainer Security Baseline](docs/SOLO-MAINTAINER.md) — a one-person hardening playbook (tiered by impact and friction) plus the `-SoloMaintainer` scan profile, which re-ranks the findings that structurally require a second person (require-approval, multi-owner CODEOWNERS) to non-blocking Info with compensating-control guidance, so your report is an achievable punch-list rather than unfixable noise.

## Recommended Protection Baseline

Use this baseline as the default hardening profile for repositories scanned by Fylgyr.

### Branch protection (default branch)

- Require pull requests before merge.
- Require status checks to pass and require branches to be up to date.
- Block force-pushes (non-fast-forward updates).
- Block branch deletion.
- Require signed commits.
- Require stale review dismissal on new commits.

Recommended approval policy:

- Team-maintained repo: require at least 1 approving review.
- Solo-maintainer repo: allowing 0 approvals can be an acceptable tradeoff when the controls above are enforced and documented. See the dedicated [Solo-Maintainer Security Baseline](docs/SOLO-MAINTAINER.md) for the full one-person hardening playbook and the `-SoloMaintainer` scan profile.

### Tag protection (release tags)

- Add a tag ruleset for release patterns (for example `v*`).
- Prevent untrusted creation, update, or deletion of protected tags.
- Keep release tags immutable after publication.

Rationale: mutable release tags are a common supply-chain attack path (for example producer-side tag poisoning).

### Workflow egress controls

- Enforce workflow egress filtering in `block` mode (not audit-only).
- Place the egress-control step first in each job and allowlist only required endpoints.
- Supported options include `step-security/harden-runner`, `code-cargo/cargowall-action`, and `bullfrogsec/bullfrog`.

## Sample Output

### Object output (default)

```
CheckName          : ActionPinning
Status             : Fail
Severity           : High
Resource           : .github/workflows/ci.yml:12
Detail             : Unpinned action reference: actions/checkout@v4
Remediation        : Pin this action to a full 40-character commit SHA instead of a tag or branch.
AttackMapping      : {trivy-tag-poisoning, tj-actions-shai-hulud, actions-cool-issues-helper-compromise}
```

### Colored console output

```powershell
# Single repo
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat Console

# Org-wide scan (with progress bar)
Invoke-Fylgyr -Owner 'myorg' -OutputFormat Console
```

Abridged example (a real scan runs ~30 checks per repo):

```
  Fylgyr Supply-Chain Audit: myorg
  ------------------------------------------------------------

  [myorg/web-app]
    > ActionPinning  [1 passed, 2 finding(s)]
      [FAIL] Unpinned action reference: actions/checkout@v4
        Resource:    .github/workflows/ci.yml:12
        Severity:    High
        Remediation: Pin this action to a full 40-character commit SHA instead of a tag or branch.
        Attacks:     trivy-tag-poisoning, tj-actions-shai-hulud, actions-cool-issues-helper-compromise
      [FAIL] Unpinned action reference: actions/setup-node@v3
        Resource:    .github/workflows/ci.yml:15
        Severity:    High
        Remediation: Pin this action to a full 40-character commit SHA instead of a tag or branch.
        Attacks:     trivy-tag-poisoning, tj-actions-shai-hulud, actions-cool-issues-helper-compromise

    > DangerousTrigger  [PASS]
        No dangerous trigger patterns found. (2 files)

    > WorkflowPermission  [PASS]
        Workflow declares a top-level permissions block. (2 files)

  [myorg/api-service]
    > ActionPinning  [PASS]
        All action references are SHA-pinned. (3 files)

    > DangerousTrigger  [PASS]
        No dangerous trigger patterns found. (3 files)

    > WorkflowPermission  [PASS]
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
| NDJSON | `-OutputFormat NDJSON` | Newline-delimited JSON (one finding per line) with `_meta` scan context |
| HTML | `-OutputFormat HTML` | Standalone report with summary cards, coverage dashboard, and grouped findings |
| LogAnalytics | `-OutputFormat LogAnalytics` | ASIM-oriented NDJSON for Azure Monitor Logs / Sentinel ingestion |

## Drift Mode

Drift mode detects security-relevant change events ("drift") over time, not just current state.

- `Audit`: point-in-time posture checks against the repository/org as it exists now.
- `Drift`: recent trust-boundary and policy changes (for example force-pushes, protection weakening, new runner registration, secret changes).
- `Both`: combines posture (`Audit`) and change telemetry (`Drift`) in one run.

```powershell
# Audit-only (default)
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Mode Audit

# Drift-only
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Mode Drift -BaselinePath './last-scan.json'

# Audit + Drift in one run
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Mode Both -BaselinePath './last-scan.json'
```

Drift mode requires at least one of:

- `-BaselinePath` from a previous scan.
- Organization audit-log API access (`admin:org`, GitHub Enterprise Cloud).

If neither is available, drift mode fails with an explicit prerequisite error.

> [!IMPORTANT]
> **Baseline integrity.** The baseline JSON drives finding *suppression* — anyone who can modify the baseline file can silently hide drift findings from the next scan. Store baselines where the scan identity has read access but ordinary contributors do not, never commit them to the repository being scanned, and prefer immutable storage (see [docs/SENTINEL.md](docs/SENTINEL.md) for an Azure Blob immutability-policy pattern).

## Microsoft Sentinel Quick Start

For Sentinel pipelines, `-Mode Both` is usually the right default: you get baseline posture findings and recent-change (drift) signals in the same telemetry stream.

Recommended operating model:

- Run a dedicated scheduled ingestion workflow (for example every 6 hours).
- Add manual dispatch for incident response and validation runs.
- Avoid sending full telemetry on every application CI workflow run unless you have a specific detection reason.

Full setup and configuration guidance (public-ingestion scope): [docs/SENTINEL.md](docs/SENTINEL.md).

```powershell
# 1) Generate Log Analytics-shaped output
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -Mode Both -OutputFormat LogAnalytics -OutputPath './fylgyr-la.ndjson'

# 2) Ingest to Azure Monitor (managed identity example)
Get-Content ./fylgyr-la.ndjson |
  Send-FylgyrToLogAnalytics `
    -DcrImmutableId 'dcr-00000000000000000000000000000000' `
    -DceUri 'https://example.westeurope-1.ingest.monitor.azure.com' `
    -StreamName 'Custom-FylgyrRaw' `
    -UseManagedIdentity
```

`Send-FylgyrToLogAnalytics` currently supports the following ingestion identities. There is no IMDS fallback in the helper today, so a bare Azure VM would be the only environment where an IMDS-based token flow would be relevant. Ingestion endpoint parameters (`-DceUri`, `-DcrEndpointUri`) must be HTTPS and must not resolve to local/private/link-local targets.

| Deployment | Auth method | IMDS needed? |
| --- | --- | --- |
| GitHub Actions | OIDC / federated token | No |
| Azure Functions | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` | No |
| Azure Container Apps | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` | No |
| Azure App Service | `MSI_ENDPOINT` + `MSI_SECRET` | No |
| Bare Azure VM | IMDS | Yes — this is the only case |

### NDJSON for SIEM pipelines

Use NDJSON when forwarding findings into streaming systems.

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat NDJSON -OutputPath './fylgyr.ndjson'
```

Each line is an independent JSON object and includes `_meta` fields (`scanId`, `scanStartTime`, `fylgyrVersion`).

### HTML report

Generate a local HTML report for stakeholder review:

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -OutputFormat HTML -OutputPath './fylgyr-report.html'
```

The report includes:
- scan metadata and status summary
- scan scope counts (repos scanned, with results, without results)
- table of contents with clear Organization Scope vs Repository Scope sections
- risk prioritization summary (critical/high, medium, prioritized findings, missing OWASP coverage)
- overall recommendations split into scan-derived priorities and companion controls beyond GitHub
- Defender XDR custom detection starter queries (including VS Code extension inventory telemetry)
- grouped findings by target and check
- evidence details (when `-IncludeEvidence` is enabled)
- coverage dashboard snippets from `docs/COVERAGE.md`

### Evidence bundle (`-IncludeEvidence`)

Enable evidence enrichment for forensic and audit workflows:

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -IncludeEvidence -OutputFormat JSON
```

Evidence fields include `YamlSnippet`, `CommitSha`, `ScanTime`, and `Permalink` where applicable.

### Config-file suppressions (`.fylgyr.yml`)

> Use config-file suppressions for repository-specific exceptions and risk acceptance. This is ideal for public repositories where maintainers may want to acknowledge certain risks without losing the benefits of other checks and future drift monitoring.

Per-repository suppressions are supported via `.fylgyr.yml`:

```yaml
suppressions:
  - check: ActionPinning
    resource: ".github/workflows/ci.yml"
    reason: "Pinned to org-internal action by tag, accepted risk"
    expires: "2026-07-01"
```

There is no dedicated "suppression file path" parameter. Fylgyr automatically loads `.fylgyr.yml` from the current working directory (normally your repository root).

Starter template:

```powershell
Copy-Item -Path 'examples/maintainer/fylgyr-suppressions.example.yml' -Destination '.fylgyr.yml'
```

Use `-IgnoreConfig` to skip config suppression processing for strict runs.

### Changed-only mode and pre-commit usage

Use changed-only mode for local fast feedback loops:

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -ChangedOnly -SinceRef origin/main -OutputFormat Console
```

For hook recipes, see [docs/PRE-COMMIT.md](docs/PRE-COMMIT.md).

### CI gate mode (`-FailOn` and wrapper script)

Use severity gating in CI and propagate shell exit code with the wrapper script:

```powershell
pwsh ./scripts/fylgyr-ci.ps1 -Owner 'myorg' -Repo 'myrepo' -FailOn High -OutputFormat SARIF
```

### Performance for org-wide scans

For org-wide scans, tune concurrency with `-ThrottleLimit` (default `5`):

```powershell
Invoke-Fylgyr -Owner 'myorg' -IncludeOrgChecks -ThrottleLimit 8 -OutputFormat Console
```

Fylgyr applies conservative rate-limit-aware throttling automatically during org-wide parallel runs.

### Feeding SARIF into GitHub Code Scanning

Add a workflow to run Fylgyr on every push and PR. Results appear in your repository's **Security** tab under **Code scanning**.

> **Important:** The workflow must trigger on `push` to your default branch — not just `pull_request` — for results to appear in the Security tab. PR-only triggers show results in PR checks but not in the Security tab.

A ready-to-use workflow template is available at [`docs/fylgyr-workflow.yml`](docs/fylgyr-workflow.yml). Copy it to your repo:

```powershell
# From your repository root
New-Item -ItemType Directory -Path '.github/workflows' -Force | Out-Null
Copy-Item -Path 'docs/fylgyr-workflow.yml' -Destination '.github/workflows/fylgyr.yml'
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

These two permissions are the only `GITHUB_TOKEN` scopes needed for CI execution and SARIF upload. They cover workflow-file analysis checks such as ActionPinning, ScriptInjection, ContainerPinning, UntrustedDownload, ArtifactPoisoning, OidcTrust, CacheIntegrity, TriggerFilter, DependencyReview, ArtifactAttestation, ReusableWorkflowTrust, WorkflowPermission, PublishIntegrity, and EgressControl.

To read GitHub security alert APIs (Secret Scanning, Dependabot alerts, Code Scanning alerts), use a fine-grained PAT with the corresponding read permissions.

#### Repo-level checks that need a PAT

Several checks require a **Personal Access Token** (PAT) because the workflow `GITHUB_TOKEN` does not have access to those APIs. **Fylgyr strongly recommends fine-grained PATs** — every check below works with least-privilege fine-grained permissions:

| Check | Fine-grained permission (read-only) |
|---|---|
| `BranchProtection` | Administration |
| `SecretScanning` | Secret scanning alerts |
| `DependabotAlert` | Dependabot alerts |
| `CodeScanning` | Code scanning alerts |
| `CodeOwner` | Contents |
| `SignedCommit` | Administration |
| `EnvironmentProtection` | Environments |
| `RepoVisibility` | Metadata |
| `ForkSecretExposure` | Environments (plus org Secrets for org-level secret enumeration) |
| `GitHubAppSecurity` | Org Administration (falls back gracefully for user accounts) |
| `RunnerHygiene` (org-level) | Org Administration |

Without a PAT these checks gracefully report `Status = 'Error'` with a clear message — they won't fail the workflow or block other checks.

Org-level policy checks (`-IncludeOrgChecks`) additionally require organization-level visibility (`read:org` / `admin:org` on classic tokens, or equivalent organization read permissions on fine-grained tokens). Some controls are enterprise-only and downgrade to `Info` when the feature is unavailable.

> **GitHub App token note (current API behavior):** some PAT governance endpoints used by `PatPolicy` may be available only to GitHub App user/installation tokens in certain org contexts. If those endpoints are unavailable for your token type, Fylgyr intentionally returns `Info` (partial analysis) and explains the limitation.

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

### Organization-wide scan with org policy checks

Use `-IncludeOrgChecks` to run organization-level policy checks once per owner before repository iteration:

```powershell
Invoke-Fylgyr -Owner 'myorg' -IncludeOrgChecks
```

Org-level checks are intentionally skipped for single-repository scans (`-Repo`) to keep repo audits focused and deterministic. Note that org-level Actions secret visibility (`OrgSecretVisibility`) is part of the org check set, so that signal requires an org-wide scan with `-IncludeOrgChecks`.

When the owner is a **personal account**, `-IncludeOrgChecks` emits a single consolidated notice listing the organization-policy checks that do not apply, and runs the personal-account equivalents (`AccountSecurity`, `AccountKey`) instead — so a solo-maintainer scan produces signal rather than a dozen "not applicable" rows.

### Reusable workflow trust allowlist

Use `-ReusableWorkflowAllowlist` to permit external reusable workflow sources beyond the default trusted set (same-owner, `actions/*`, and `github/*`):

```powershell
Invoke-Fylgyr -Owner 'myorg' -Repo 'myrepo' -ReusableWorkflowAllowlist @('my-trusted-org/*', 'security-team/reusable-workflows')
```

### Solo-maintainer profile

Use `-SoloMaintainer` to re-rank findings that structurally require a second person — the "0 approving reviews" branch finding and single-owner `CODEOWNERS` findings — to non-blocking `Info`, with a compensating-control note appended. Every solo-achievable guardrail (pinning, signing, egress, token scope, secret scanning, …) keeps its full severity. The recalibration runs before `-FailOn`, so the impossible-solo items don't break your CI gate:

```powershell
Invoke-Fylgyr -Owner 'your-user' -Repo 'your-repo' -SoloMaintainer -OutputFormat Console
Invoke-Fylgyr -Owner 'your-user' -Repo 'your-repo' -SoloMaintainer -FailOn High
```

See the [Solo-Maintainer Security Baseline](docs/SOLO-MAINTAINER.md) for the full playbook.

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
| `ActionPinning` | Third-party actions referenced by tag/branch instead of SHA — in workflows and in composite action definitions (`action.yml`/`action.yaml`) | High | `trivy-tag-poisoning`, `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise` |
| `DangerousTrigger` | `pull_request_target` / `workflow_run` with untrusted code checkout, missing actor restrictions, secret exposure in PRT context | Critical | `nx-pwn-request`, `prt-scan-ai-automated`, `trivy-supply-chain-2026`, `azure-karpenter-pwn-request`, `hackerbot-claw` |
| `ScriptInjection` | Untrusted GitHub event expressions interpolated into `run:` and `github-script` blocks — including bracket notation, indirection through `env:` variables, and `workflow_dispatch`/`workflow_call` inputs | Critical | `github-actions-script-injection` |
| `ContainerPinning` | Container images pulled by mutable tag or `:latest` instead of immutable digest — `docker://` uses, job `container:` blocks, and `services:` images | High | `docker-hub-credential-breach`, `trivy-tag-poisoning` |
| `UntrustedDownload` | Remote scripts downloaded and executed in one step (`curl \| bash`, `irm \| iex`) in run steps | High | `codecov-bash-uploader` |
| `LifecycleScript` | CI dependency installs without `--ignore-scripts`, and suspicious install-time lifecycle scripts in the repo's own `package.json` | High | `shai-hulud-npm-worm`, `event-stream-hijack`, `ua-parser-js-npm-compromise` |
| `ArtifactPoisoning` | Downloaded artifacts executed without integrity verification, especially across `workflow_run` boundaries | High | `artifact-poisoning-workflow-run` |
| `OidcTrust` | `id-token: write` without environment scoping (elevated when publish-adjacent) | High | `oidc-trust-abuse`, `bitwarden-cli-2026-04` |
| `CacheIntegrity` | Cache keys derived from attacker-controlled refs (for example `github.head_ref`) | Medium | `cache-poisoning-pr-branch` |
| `TriggerFilter` | Trigger events (discussion/comment/review/project families) missing explicit `types:` filters | Medium | `shai-hulud-runner-backdoor` |
| `DependencyReview` | PR workflows missing `actions/dependency-review-action` pre-merge dependency gate | Medium | `event-stream-hijack` |
| `ArtifactAttestation` | Release-producing jobs missing build provenance attestation controls | Medium | `solarwinds-orion`, `codecov-bash-uploader` |
| `ReusableWorkflowTrust` | Reusable workflow calls not SHA-pinned or sourced from untrusted repos | High | `tj-actions-shai-hulud` |
| `WorkflowPermission` | Missing top-level `permissions:` block; top-level or job-level `permissions: write-all` | Critical/Medium | `tj-actions-shai-hulud`, `nx-pwn-request` |
| `PublishIntegrity` | Publish workflows missing provenance, trusted publishing, or artifact signing signals | High | `shai-hulud-npm-worm`, `lottie-player-npm-compromise`, `ua-parser-js-npm-compromise`, `bitwarden-cli-2026-04`, `event-stream-hijack` |
| `EgressControl` | Missing or audit-only network egress filtering in workflows | Medium | `tj-actions-shai-hulud`, `actions-cool-issues-helper-compromise`, `trivy-supply-chain-2026`, `codecov-bash-uploader` |
| `ForkSecretExposure` | Secrets referenced in `pull_request_target`/`workflow_run` workflows, unprotected environments reachable from fork PRs | Critical | `prt-scan-ai-automated`, `hackerbot-claw`, `nx-pwn-request`, `azure-karpenter-pwn-request` |
| `GitHubAppSecurity` | Overly permissive organization GitHub App installations (including org-admin, all-repos write, and dangerous permission combinations) | Critical | `github-app-token-theft` |
| `BranchProtection` | Weak or missing default branch protection rules, admin-bypass (`enforce_admins` disabled), and ruleset bypass actors with always-on bypass | High | `codecov-bash-uploader`, `trivy-force-push-main`, `dropbox-github-breach` |
| `SecretScanning` | Secret Scanning disabled, push protection disabled, high/critical open alerts, or alert telemetry unavailable to token scope | High | `committed-credentials-exposure`, `uber-credential-leak`, `axios-npm-token-leak`, `toyota-source-exposure` |
| `DependabotAlert` | Open critical/high Dependabot vulnerability alerts | High | `event-stream-hijack`, `solarwinds-orion` |
| `CodeScanning` | Code Scanning not configured or stale analyses | Medium | `solarwinds-orion` |
| `RunnerHygiene` | Risky self-hosted runner configurations, dangerous triggers, missing trigger filters, org-wide runner groups, non-ephemeral runners, public repo runners | High | `github-actions-cryptomining`, `praetorian-runner-pivot`, `shai-hulud-runner-backdoor` |
| `CodeOwner` | Missing `CODEOWNERS` file, single-owner catch-all, too few distinct reviewers, or CODEOWNERS not enforced via branch ruleset | Medium | `xz-utils-backdoor` |
| `SignedCommit` | Default branch does not require signed commits — recognizes enforcement via classic branch protection *or* a modern branch ruleset (`required_signatures` rule) | Medium | `xz-utils-backdoor` |
| `ForkPullPolicy` | `pull_request_target` combined with checkout of fork-controlled `head.sha`/`head.ref`/`github.head_ref` | High | `nx-pwn-request`, `tj-actions-shai-hulud`, `prt-scan-ai-automated` |
| `EnvironmentProtection` | Deployment environments without required reviewers, self-review not prevented, or missing branch policies | High | `unauthorized-env-deployment`, `prt-scan-ai-automated`, `xz-utils-backdoor` |
| `RepoVisibility` | Public repositories with internal/private naming patterns | Medium | `toyota-source-exposure` |
| `WebhookSecurity` | Repository webhooks configured without a secret for payload authentication | Low | `codecov-bash-uploader` |
| `BinaryArtifact` | Binary files (`.exe`, `.dll`, `.so`, `.jar`, etc.) committed in the repository tree | Low | `solarwinds-orion` |
| `Rulesets` | Missing modern branch/tag rulesets, missing tag protection, or bypass actors configured on default-branch rulesets (warns if no tags yet; fails when tags exist) | High | `trivy-tag-poisoning`, `actions-cool-issues-helper-compromise`, `trivy-force-push-main`, `xz-utils-backdoor` |
| `DefaultTokenPermission` | Platform default `GITHUB_TOKEN` permission set to write, or workflows allowed to approve pull requests (repo and org scope) | High | `tj-actions-shai-hulud`, `nx-pwn-request`, `prt-scan-ai-automated` |
| `DeployKey` | Deploy keys with write access (MFA-less, unattributed push path) or stale read-only keys | High | `committed-credentials-exposure`, `codecov-bash-uploader` |
| `TagProtection` | Active tag rulesets missing `deletion`/`non_fast_forward` rules (release retagging primitive) | High | `trivy-tag-poisoning`, `actions-cool-issues-helper-compromise` |
| `AccountSecurity` | Personal account without two-factor authentication (verifiable only with a token owned by the scanned account) | Critical | `dropbox-github-breach`, `github-device-code-phishing`, `ua-parser-js-npm-compromise` |
| `AccountKey` | Stale account SSH keys (>2 years) and expired GPG signing keys on personal accounts | Low | `gentoo-github-compromise`, `xz-utils-backdoor` |
| `OrgMfaPolicy` | Organization does not require MFA for members | Critical | `dropbox-github-breach` |
| `OrgDefaultPermissions` | Default org repository permission is broader than read/none | High | `gentoo-github-compromise` |
| `IpAllowlist` | Organization has no IP allowlist entries (enterprise recommendation) | Medium | `github-device-code-phishing`, `uber-credential-leak` |
| `AuditLogStreaming` | Organization audit log streaming not configured | Medium | `github-device-code-phishing`, `uber-credential-leak` |
| `OAuthAppPolicy` | Third-party OAuth app restrictions disabled | High | `github-device-code-phishing` |
| `OrgActionRestrictions` | Organization allows unrestricted third-party GitHub Actions | High | `tj-actions-shai-hulud` |
| `OutsideCollaborators` | Outside collaborators retain write/admin repository access | High | `uber-credential-leak` |
| `PatPolicy` | Organization PAT governance cannot be verified or appears weak | High | `uber-credential-leak`, `github-device-code-phishing` |
| `OrgSecretVisibility` | Organization Actions secrets visible to all repositories (`visibility: all`) | High | `prt-scan-ai-automated`, `hackerbot-claw`, `axios-npm-token-leak` |
| `PrivateVulnReporting` | Repository private vulnerability reporting (PVR) disabled or unsupported | Low | `xz-utils-backdoor` |
| `DefaultWorkflowPermission` | Repository default GITHUB_TOKEN set to write, or Actions allowed to self-approve pull requests | High | `tj-actions-shai-hulud`, `nx-pwn-request`, `prt-scan-ai-automated` |
| `WorkflowConcurrency` | Deployment jobs targeting a GitHub environment with no concurrency group configured | Medium | `unauthorized-env-deployment` |
| `ContinueOnError` | Security gate jobs (scan, CodeQL, Trivy, Snyk, etc.) with `continue-on-error: true` that would silence tool failures | Medium | `solarwinds-orion`, `codecov-bash-uploader` |
| `RunnerPinning` | Workflows using mutable `-latest` runner labels instead of a pinned OS version | Medium | `trivy-supply-chain-2026`, `solarwinds-orion` |

## Private Vulnerability Reporting Baseline

Use this baseline for coordinated disclosure hygiene on public and private repositories:

1. Enable Private Vulnerability Reporting in repository Settings > Security.
2. Maintain SECURITY.md with a private reporting path, scope, and safe-harbor language.
3. Define and publish response expectations, for example acknowledge within 3 business days and provide triage/remediation updates on a predictable cadence.
4. Keep vulnerability reports out of public issues by making private reporting the default path.
5. Review and test the disclosure path periodically so maintainers can respond quickly when a report arrives.

For first-time reporters, publish these exact steps in SECURITY.md:

1. Open the target repository on GitHub.
2. Go to Security > Advisories.
3. Click Report a vulnerability (or New draft security advisory).
4. Submit a private report with:
  - clear reproduction steps
  - affected branch, tag, or release version
  - impact statement and expected vs actual behavior
  - proof-of-concept artifacts (logs, screenshots, commits) with secrets redacted
5. Wait for maintainer acknowledgement in the advisory thread (do not open a public issue while unpatched).

If a repository does not support Private Vulnerability Reporting (PVR) on its plan, SECURITY.md should provide an alternate private contact path with the same required report fields.

## Compatibility

Fylgyr targets `github.com`. GitHub Enterprise Server (GHES) is **not supported in v1.x** — API path differences (`/api/v3/`) and feature-availability variance make it a v2.0 goal. Fylgyr may incidentally work against GHES for a subset of checks; this configuration is not tested or supported.

## Verify your install

Starting from v0.4.1 every Fylgyr release includes a [SLSA build provenance attestation](https://slsa.dev/provenance/v1). You can verify the published module was built from the expected source:

GitHub CLI is not required to run Fylgyr scans. It is only required for the provenance verification commands below.

Prerequisites for the commands below:

- Install GitHub CLI (`gh`): https://cli.github.com/
- Windows install (winget): `winget install --id GitHub.cli --exact`
- Confirm CLI is available: `gh --version`
- Recommended: authenticate first with `gh auth login`

```powershell
# List available release versions (latest first)
gh release list --repo pthoor/Fylgyr --limit 10

# Resolve latest release tag/version automatically
$tag = gh release view --repo pthoor/Fylgyr --json tagName --jq .tagName
$version = $tag.TrimStart('v')

# Download and verify the latest attested artifact
gh release download $tag --repo pthoor/Fylgyr --pattern "fylgyr-$version.zip" --dir .
gh attestation verify "./fylgyr-$version.zip" --repo pthoor/Fylgyr

# Example with a fixed version
gh release download v0.7.4 --repo pthoor/Fylgyr --pattern "fylgyr-0.7.4.zip" --dir .
gh attestation verify ./fylgyr-0.7.4.zip --repo pthoor/Fylgyr
```

Note: verification is tied to the exact attested artifact bytes. If you already installed Fylgyr with `Install-Module`, you still need the original release zip (or another byte-identical copy) to verify provenance.

## Attack Catalog

Every finding maps to a real-world supply chain incident. The full catalog lives in [`src/Fylgyr/Data/attacks.json`](src/Fylgyr/Data/attacks.json).

| ID | Campaign | Date |
|---|---|---|
| `trivy-tag-poisoning` | Trivy tag poisoning | 2024-07 |
| `tj-actions-shai-hulud` | tj-actions/changed-files (Shai-Hulud) token exfiltration | 2025-03 |
| `actions-cool-issues-helper-compromise` | actions-cool/issues-helper tag hijack | 2026-05 |
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
| `committed-credentials-exposure` | Committed credentials exposure (Uber 2016, Toyota 2022) | 2016-ongoing |
| `shai-hulud-npm-worm` | Shai-Hulud npm worm | 2025-09 |
| `lottie-player-npm-compromise` | lottie-player npm compromise | 2024-10 |
| `ua-parser-js-npm-compromise` | ua-parser-js npm compromise | 2021-10 |
| `bitwarden-cli-2026-04` | Bitwarden CLI npm compromise | 2026-04 |
| `dropbox-github-breach` | Dropbox GitHub breach | 2022-11 |
| `gentoo-github-compromise` | Gentoo GitHub organization compromise | 2018-06 |
| `github-device-code-phishing` | GitHub OAuth device code phishing | 2025-01 |
| `github-actions-script-injection` | GitHub Actions script injection via untrusted event context | 2026-01 |
| `artifact-poisoning-workflow-run` | Artifact poisoning across workflow_run boundaries | 2024-01 |
| `oidc-trust-abuse` | OIDC trust abuse from unscoped token requests | 2024-01 |
| `cache-poisoning-pr-branch` | PR branch cache poisoning | 2023-01 |
| `shai-hulud-runner-backdoor` | Shai-Hulud runner backdoor pattern | 2025-01 |
| `reviewdog-action-setup-2025` | reviewdog/action-setup supply chain attack (root cause of tj-actions/changed-files) | 2025-03 |
| `artipacked-token-artifact-leak-2024` | ArtiPacked artifact token leak via GitHub Actions artifacts | 2024-08 |
| `ultralytics-cache-pivot-2024` | Ultralytics cache poisoning via PR branch | 2024-12 |
| `miasma-worm-redhat-npm-2026` | Miasma worm — Red Hat npm namespace (Phantom Gyp) | 2026-06 |
| `miasma-worm-leo-platform-2026` | Miasma worm — Leo Platform 20-package sweep | 2026-06 |
| `mastra-sapphire-sleet-2026` | Mastra Sapphire Sleet — DPRK-attributed 140+ package dependency confusion | 2026-06 |
| `simonecorsi-mawesome-2026` | simonecorsi/mawesome tag repoint supply chain | 2026-06 |
| `microsoft-durabletask-teampcp-2026` | microsoft/durabletask TeamPCP PyPI dependency confusion | 2026-05 |

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

Architecture diagrams (end-to-end solution and Sentinel ingestion flow):

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/sentinel/architecture.md](docs/sentinel/architecture.md)

```
src/Fylgyr/
├── Fylgyr.psd1              # Module manifest
├── Fylgyr.psm1              # Entry point (dot-sources Public/ and Private/)
├── Public/
│   ├── Invoke-Fylgyr.ps1    # Orchestrator + output formatting
│   ├── Test-AccountKey.ps1
│   ├── Test-AccountSecurity.ps1
│   ├── Test-ActionPinning.ps1
│   ├── Test-ArtifactAttestation.ps1
│   ├── Test-ArtifactPoisoning.ps1
│   ├── Test-CacheIntegrity.ps1
│   ├── Test-BranchProtection.ps1
│   ├── Test-CodeOwner.ps1
│   ├── Test-ContainerPinning.ps1
│   ├── Test-LifecycleScript.ps1
│   ├── Test-UntrustedDownload.ps1
│   ├── Test-CodeScanning.ps1
│   ├── Test-DangerousTrigger.ps1
│   ├── Test-DefaultTokenPermission.ps1
│   ├── Test-DependabotAlert.ps1
│   ├── Test-DependencyReview.ps1
│   ├── Test-DeployKey.ps1
│   ├── Test-EgressControl.ps1
│   ├── Test-EnvironmentProtection.ps1
│   ├── Test-ForkPullPolicy.ps1
│   ├── Test-ForkSecretExposure.ps1
│   ├── Test-GitHubAppSecurity.ps1
│   ├── Test-OidcTrust.ps1
│   ├── Test-OrgSecretVisibility.ps1
│   ├── Test-PrivateVulnReporting.ps1
│   ├── Test-RepoVisibility.ps1
│   ├── Test-ReusableWorkflowTrust.ps1
│   ├── Test-RunnerHygiene.ps1
│   ├── Test-PublishIntegrity.ps1
│   ├── Test-ScriptInjection.ps1
│   ├── Test-SecretScanning.ps1
│   ├── Test-SignedCommit.ps1
│   ├── Test-TagProtection.ps1
│   ├── Test-TriggerFilter.ps1
│   ├── Test-WebhookSecurity.ps1
│   ├── Test-BinaryArtifact.ps1
│   ├── Test-ContinueOnError.ps1
│   ├── Test-DefaultWorkflowPermission.ps1
│   ├── Test-RunnerPinning.ps1
│   ├── Test-WorkflowConcurrency.ps1
│   └── Test-WorkflowPermission.ps1
├── Private/
│   ├── Invoke-GitHubApi.ps1       # REST/GraphQL wrapper with pagination
│   ├── Get-WorkflowFile.ps1       # Fetches workflows via Git Trees API
│   ├── Get-ActionDefinitionFile.ps1 # Fetches composite action.yml files via Git Trees API
│   ├── ConvertTo-FylgyrEscapedPathSegment.ps1 # URL-encodes API-derived path segments
│   ├── Get-RunBlock.ps1           # Extracts run: blocks (including block scalars)
│   ├── Get-WorkflowJobBlock.ps1   # Extracts per-job YAML blocks for job-scoped checks
│   ├── Get-FylgyrOwnerContext.ps1 # Owner/persona context helper (type, plan, token owner)
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
