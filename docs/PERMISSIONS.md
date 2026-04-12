# Fylgyr — Token Permissions

Fylgyr authenticates to GitHub using a token from `$env:GITHUB_TOKEN` (or `-Token`). This document lists the exact permissions each check requires so you can mint a **least-privilege fine-grained PAT** — or fall back to a classic PAT when fine-grained is not an option.

> [!NOTE]
> **Passing the token.** Fylgyr reads `$env:GITHUB_TOKEN` by default, so you usually don't need to pass `-Token` at all:
>
> ```powershell
> $env:GITHUB_TOKEN = 'github_pat_...'
> Invoke-Fylgyr -Owner my-org -Repo my-repo
> ```
>
> If you need to use a different token for a single call (for example, scanning across two orgs with different PATs), pass it explicitly with `-Token`:
>
> ```powershell
> Invoke-Fylgyr -Owner my-org -Repo my-repo -Token $otherToken
> ```
>
> Never hardcode tokens in scripts or commit them to disk. Load them from a secret manager (`Get-Secret`, `az keyvault secret show`, `op read`, etc.) into a local variable and pass that variable to `-Token`.

> [!IMPORTANT]
> **Fine-grained PATs require org approval.** If you are scanning repositories in an organization you do not own, an org owner must approve your token under **Organization settings → Personal access tokens → Pending requests**. Without approval, every API call returns `404 Not Found` even when the scopes are correct — this is the most common cause of `Failed to retrieve repository info` errors.

## Permissions at a glance

Fylgyr is **read-only**. It never writes to GitHub, never modifies settings, and never stores tokens. All permissions below are *Read-only*.

- ✅ **Repository read access to** actions, administration, code (contents), code scanning alerts, commit statuses, dependabot alerts, environments, metadata, pull requests, and secret scanning alerts
- ✅ **Organization read access to** administration, members, and (optionally) Actions secrets — only required for org-level checks such as `Test-RunnerHygiene`, `Test-GitHubAppSecurity`, and `Test-ForkSecretExposure`
- 🚫 **No write access** to any resource
- 🚫 **No access to** user email, followers, gists, personal profile data, billing, or any resource not listed above

See the [per-check permission matrix](#per-check-permission-matrix) below for the exact scope each check needs.

## Recommended token — fine-grained PAT

> [!TIP]
> **Fylgyr strongly recommends fine-grained PATs.** They enforce least privilege, scope access to specific repositories, and expire on a predictable schedule. Every Fylgyr check is designed to work with fine-grained permissions — there is no feature that requires a classic PAT.

Create at <https://github.com/settings/personal-access-tokens/new>.

- **Resource owner:** the organization (or your user) that owns the repos you want to scan
- **Repository access:** *All repositories* or *Only select repositories*
- **Repository permissions** (all *Read-only* unless noted):
  - Metadata
  - Administration
  - Contents
  - Actions
  - Pull requests
  - Environments
  - Dependabot alerts
  - Code scanning alerts
  - Secret scanning alerts
  - Commit statuses
- **Organization permissions** (all *Read-only*):
  - Administration
  - Members
  - Secrets (only if you want `Test-ForkSecretExposure` to enumerate org-level Actions secrets)

### If fine-grained PATs are not available

> [!WARNING]
> **Classic PATs grant substantially broader access than any Fylgyr check needs.** `repo` alone includes full read *and write* access to code, issues, pull requests, and webhooks across every repository the user can reach. Use classic tokens only when your organization has not enabled fine-grained PATs, rotate them aggressively, and never store them outside a secret manager.

Required classic scopes: `repo` (full), `read:org`, `security_events`, `workflow`. Create at <https://github.com/settings/tokens/new>.

## Per-check permission matrix

| Check | GitHub API endpoints used | Fine-grained PAT permissions |
|---|---|---|
| `Test-ActionPinning` | Repo contents (`.github/workflows/*`) | Contents: read, Actions: read |
| `Test-BranchProtection` | `repos/{o}/{r}`, `repos/{o}/{r}/branches/{b}/protection` | Metadata: read, Administration: read |
| `Test-CodeOwner` | `repos/{o}/{r}/contents/{path}` | Contents: read |
| `Test-CodeScanning` | `repos/{o}/{r}/code-scanning/analyses` | Code scanning alerts: read |
| `Test-DangerousTrigger` | `repos/{o}/{r}/actions/permissions`, workflow files | Administration: read, Contents: read, Actions: read |
| `Test-DependabotAlert` | `repos/{o}/{r}/dependabot/alerts` | Dependabot alerts: read |
| `Test-EgressControl` | Workflow files (`.github/workflows/*`) | Contents: read, Actions: read |
| `Test-EnvironmentProtection` | `repos/{o}/{r}/environments` | Environments: read, Administration: read |
| `Test-ForkPullPolicy` | `repos/{o}/{r}/actions/permissions`, `repos/{o}/{r}` | Administration: read, Metadata: read |
| `Test-ForkSecretExposure` | `repos/{o}/{r}/environments`, `orgs/{o}/actions/secrets` | Environments: read, **Org Secrets: read** |
| `Test-GitHubAppSecurity` | `orgs/{o}/installations`, `user/installations` | Org Administration: read |
| `Test-RepoVisibility` | `repos/{o}/{r}` | Metadata: read |
| `Test-RunnerHygiene` | `repos/{o}/{r}/actions/runners`, `orgs/{o}/actions/runners`, `orgs/{o}/actions/runner-groups` | Administration: read (repo + org) |
| `Test-SecretScanning` | `repos/{o}/{r}/secret-scanning/alerts` | Secret scanning alerts: read |
| `Test-SignedCommit` | `repos/{o}/{r}/commits` | Contents: read |
| `Test-WorkflowPermission` | Workflow files (`.github/workflows/*`) | Contents: read, Actions: read |

All checks additionally require **Metadata: read** — this is mandatory for every fine-grained PAT and cannot be disabled.

## Common errors and what they mean

| Symptom | Likely cause | Fix |
|---|---|---|
| `Failed to retrieve repository info ... 404 Not Found` on a repo you know exists | Fine-grained PAT not approved by the target org | Ask an org owner to approve the token in **Org settings → Personal access tokens → Pending requests** |
| `403 Resource not accessible by personal access token` | Missing permission for that specific endpoint | Check the matrix above and add the corresponding permission |
| `401 Bad credentials` | Token expired, revoked, or not exported | Regenerate and set `$env:GITHUB_TOKEN` |
| Org-level checks (`Test-RunnerHygiene`, `Test-GitHubAppSecurity`) return `Error` while repo-level checks pass | Token has repo permissions but no org permissions | Add **Org Administration: read** |
| `Test-ForkSecretExposure` skips org-secret enumeration | Missing **Org Secrets: read** | Optional — add only if you need org-wide secret visibility |

## Why not a GitHub App?

Fylgyr runs as a local PowerShell module and in CI — an installation model that fits PATs well. A GitHub App would offer higher rate limits and org-wide scanning without per-user tokens, but would require hosted infrastructure to hold the private key and exchange JWTs for installation tokens. This is on the roadmap for a future hosted offering; for now, fine-grained PATs are the supported path.
