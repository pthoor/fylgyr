# Fylgyr Maintainer Guide

This guide is for solo open-source maintainers who want fast, practical supply chain checks without enterprise setup.

## Five-minute install

1. Install Fylgyr:

```powershell
Install-Module Fylgyr -Repository PSGallery -Force
```

2. Set a GitHub token (fine-grained PAT recommended):

```powershell
# Preferred: load from SecretManagement (or your secret manager)
$env:GITHUB_TOKEN = Get-Secret -Name 'FYLGYR_PAT' -AsPlainText

# Fallback: masked interactive prompt (input is not echoed)
# $env:GITHUB_TOKEN = Read-Host -Prompt 'GitHub token' -MaskInput
```

3. Run a scan:

```powershell
Invoke-Fylgyr -Owner 'your-github-user-or-org' -Repo 'your-repo' -OutputFormat Console

# Optional cleanup after scanning
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
```

Minimum useful fine-grained permissions for maintainer scans:
- Metadata: read
- Contents: read
- Administration: read
- Dependabot alerts: read
- Secret scanning alerts: read
- Code scanning alerts: read
- Environments: read
- Webhooks: read

For full details, see docs/PERMISSIONS.md.

## What you will see

Fylgyr returns one result per check with a consistent schema.

Status meanings:
- Pass: No finding for this check.
- Fail: A high-confidence risk needs action.
- Warning: Risk detected, often lower severity or constrained by account model.
- Info: Advisory or not-applicable signal.
- Error: The check could not complete (usually token scope/API access).

## Personal-account behavior (all 19 checks)

| Check | Personal account behavior | Notes |
|---|---|---|
| Test-ActionPinning | Apply | Workflow-level check |
| Test-DangerousTrigger | Apply | Workflow-level check |
| Test-WorkflowPermission | Apply | Workflow-level check |
| Test-RunnerHygiene | Apply | Workflow-level check |
| Test-PublishIntegrity | Apply | Workflow-level check |
| Test-EgressControl | Apply | Workflow-level check |
| Test-ForkPullPolicy | Apply | Workflow-level check |
| Test-BranchProtection | Apply | Requires Administration: read |
| Test-SecretScanning | Apply | Includes open-alert count, highest severity, oldest age when accessible |
| Test-DependabotAlert | Apply | Requires Dependabot alerts: read |
| Test-CodeScanning | Apply | May fail if feature/API unavailable for repo plan |
| Test-CodeOwner | Downgrade to Warning | Structural limitation: personal accounts do not have teams |
| Test-SignedCommit | Apply | Requires Administration: read |
| Test-EnvironmentProtection | Apply | Environment features may vary by plan |
| Test-RepoVisibility | Apply | Repo metadata check |
| Test-ForkSecretExposure | Apply | Depends on environments/secret visibility |
| Test-GitHubAppSecurity | Info skip possible | If token owner does not match scanned user account |
| Test-WebhookSecurity | Apply | Degrades to Info if webhook scope is unavailable |
| Test-BinaryArtifact | Apply | Repository tree inspection |

## Drop-in workflow

Copy examples/maintainer/fylgyr.yml to .github/workflows/fylgyr.yml.

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

This flow does not hard-fail PRs on findings. Results go to Security > Code scanning so maintainers can triage intentionally.

## Three fixes to prioritize first

1. SHA-pin all third-party actions.
2. Harden publish flows with provenance and trusted publishing:
   - npm: npm publish --provenance
   - PyPI: Trusted Publishing via OIDC (avoid static password tokens)
3. Keep dependency and secret alerting active and triaged (Dependabot + Secret Scanning).

## What this track does not do

- It does not require Sentinel, SIEM setup, or enterprise controls.
- It does not run org-policy checks by default.
- It does not provide continuous drift detection beyond your scheduled workflow runs.

If you later need continuous drift/IR workflows, watch the Phase 9.5 roadmap items.

## Complementary tools for secret forensics

Fylgyr checks GitHub posture and policy. It does not replace content-forensics scanners.

Recommended companions:
- TruffleHog: deep secret scanning with verification support across git history and additional sources.
- GitLeaks: lighter-weight secret scanning, strong for local and pre-commit workflows.

Use both layers:
- Fylgyr answers: Is repository posture configured safely?
- TruffleHog/GitLeaks answer: Did secrets already land in git history?

In v0.4.2, Test-SecretScanning surfaces open alert count, highest severity, and oldest alert age when alert scope is available. That is the handoff signal to run deeper historical secret forensics.

## Need help

- Usage and architecture: README.md
- Token permissions: docs/PERMISSIONS.md
- Security issue reporting: SECURITY.md
- Questions and roadmap discussion: GitHub Issues (and Discussions when enabled)
