# Fylgyr Release Testing

Manual test plan executed by Pierre before every tagged release. Automated CI (lint + Pester) is necessary but not sufficient — this plan catches PAT scope issues, personal-vs-org code paths, real-world rate limiting, and severity calibration that mocked tests cannot reproduce.

**Gate:** Do not push a release tag until every item on the signoff checklist at the bottom is checked.

## Token setup

Use a **fine-grained PAT** scoped to `pthoor` (personal) and the `pthoor` org. The PAT must have the following permissions:

| Permission | Scope | Required by |
|---|---|---|
| Contents | Read | `Test-BinaryArtifact`, `Test-CodeOwner` |
| Administration | Read | `Test-BranchProtection`, `Test-SignedCommit` |
| Secret scanning alerts | Read | `Test-SecretScanning` |
| Dependabot alerts | Read | `Test-DependabotAlert` |
| Code scanning alerts | Read | `Test-CodeScanning` |
| Environments | Read | `Test-EnvironmentProtection`, `Test-ForkSecretExposure` |
| Metadata | Read | `Test-RepoVisibility`, `Test-GitHubAppSecurity` |
| Webhooks | Read | `Test-WebhookSecurity` |
| Organization administration | Read | `Test-GitHubAppSecurity` (org path), `Test-RunnerHygiene` (org runners) |

Load the token securely:

```powershell
# Recommended: load from your secret manager
$env:GITHUB_TOKEN = Get-Secret -Name 'FYLGYR_PAT' -AsPlainText  # requires SecretManagement module

# Or interactively (input is masked):
$env:GITHUB_TOKEN = Read-Host -Prompt 'PAT'
```

**Never paste a literal token directly in the terminal. Never use `ConvertFrom-SecureString`.**

## Pass-case: personal repo (pthoor/fylgyr)

Run against the Fylgyr repo itself — this is the dogfood baseline. Expected findings are documented inline.

```powershell
Import-Module ./src/Fylgyr/Fylgyr.psm1 -Force
$results = Invoke-Fylgyr -Owner pthoor -Repo fylgyr
$results | Format-Table CheckName, Status, Severity, Detail -Wrap
```

**Expected state (update this section whenever the repo posture changes):**

| Check | Expected status | Notes |
|---|---|---|
| `ActionPinning` | Pass | All actions SHA-pinned |
| `DangerousTrigger` | Pass | No pull_request_target misuse |
| `WorkflowPermission` | Pass | Workflow-level permissions declared |
| `BranchProtection` | Pass or Warning | Depends on current branch rules |
| `SecretScanning` | Pass | Secret scanning enabled |
| `DependabotAlert` | Pass | No open critical/high alerts |
| `CodeScanning` | Pass | SARIF upload configured |
| `RunnerHygiene` | Pass | GitHub-hosted runners only |
| `CodeOwner` | Warning | Personal account — expected downgrade |
| `SignedCommit` | varies | Depends on branch setting |
| `ForkPullPolicy` | Pass | No pull_request_target in workflows |
| `EnvironmentProtection` | Pass | Production environment protected |
| `RepoVisibility` | Pass | Public repo with no private-naming pattern |
| `EgressControl` | varies | Depends on workflow configuration |
| `ForkSecretExposure` | Pass | Fork PRs blocked from secrets |
| `GitHubAppSecurity` | Info | Personal account — token mismatch expected |
| `WebhookSecurity` | Pass or Info | Requires admin:repo_hook scope |
| `BinaryArtifact` | Pass | No binaries committed |

## Fail-case: deliberate misconfiguration

If a fixture repo with known misconfigurations is available (e.g. `pthoor/fylgyr-fixture`), run against it and verify findings match expected severities. Document the fixture repo state and expected findings here when created.

For now, cross-check specific checks by temporarily misconfiguring settings on a private test repo and verifying Fylgyr catches them. Restore after testing.

## Org-wide smoke test

```powershell
Import-Module ./src/Fylgyr/Fylgyr.psm1 -Force
Invoke-Fylgyr -Owner pthoor -OutputFormat Console
```

Review findings for:
- No unexpected errors from API scope issues
- Personal account checks degrade gracefully (Warning/Info, not Error) where org features are unavailable
- `WebhookSecurity` degrades to Info for repos where the token lacks webhook scope

## Rate-limit verification

For org-wide scans with many repos, verify the rate-limit handling is not producing spurious errors:

```powershell
$results = Invoke-Fylgyr -Owner pthoor
$errors = $results | Where-Object Status -EQ 'Error'
$errors | Format-Table CheckName, Resource, Detail
```

Verify any errors are genuine permission issues, not rate-limit panic.

## Edge cases to verify per release

- [ ] Repo with no workflow files — `ActionPinning`, `DangerousTrigger`, `WorkflowPermission`, `EgressControl`, `ForkPullPolicy` should all Pass with an informational note
- [ ] Empty repo — `BinaryArtifact` should Pass with Info (no files to check)
- [ ] Repo with no webhooks — `WebhookSecurity` should Pass with Info
- [ ] Personal account scan — `GitHubAppSecurity` should return Info with token-mismatch message, not Error
- [ ] Missing token scope — checks that need elevated scope should degrade to Info or Error with a clear message, not panic

## Signoff checklist

Complete this checklist before pushing the release tag:

- [ ] `Invoke-ScriptAnalyzer -Path ./src -Recurse -Severity Error,Warning` — **zero** findings
- [ ] `Invoke-Pester -Path ./tests -Output Detailed` — **zero** failures
- [ ] Pass-case run against `pthoor/fylgyr` reviewed and consistent with expected state
- [ ] Org-wide scan against `pthoor` reviewed — no unexpected errors
- [ ] Edge cases verified (at least: no-workflow repo, empty repo, no-webhook repo)
- [ ] `CHANGELOG.md` updated with release entry
- [ ] Version bumped in `Fylgyr.psd1`
- [ ] Tag matches `ModuleVersion` (release workflow enforces this, but verify locally first)
- [ ] Attestation visible under repo Attestations tab after the release workflow completes
