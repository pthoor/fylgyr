# Pre-Commit Workflow Recipe

Use Fylgyr in `-ChangedOnly` mode to quickly scan workflow changes before every commit.

## Purpose

`-ChangedOnly` is designed for developer feedback loops. It checks only changed workflow files under `.github/workflows/` relative to a git ref.

Default behavior:
- `-SinceRef origin/main`
- Repo-level and org-level checks are skipped

## One-Off Run

From your repository root:

```powershell
Invoke-Fylgyr -Owner '<owner>' -Repo '<repo>' -ChangedOnly -SinceRef origin/main -OutputFormat Console
```

## Recommended Token Handling

Fylgyr reads `$env:GITHUB_TOKEN` automatically.

```powershell
$env:GITHUB_TOKEN = Read-Host -Prompt 'GitHub token' -MaskInput
Invoke-Fylgyr -Owner '<owner>' -Repo '<repo>' -ChangedOnly -OutputFormat Console
Remove-Item Env:GITHUB_TOKEN -ErrorAction SilentlyContinue
```

## Git Hook Example

Create `.git/hooks/pre-commit` (or use your managed hook path) with:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Skip if no workflow files changed in staged content.
if ! git diff --cached --name-only | grep -E '^\.github/workflows/.*\.(yml|yaml)$' >/dev/null 2>&1; then
  exit 0
fi

# Requires GITHUB_TOKEN to be present in environment.
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "Fylgyr pre-commit skipped: GITHUB_TOKEN is not set" >&2
  exit 0
fi

pwsh -NoLogo -NoProfile -Command "\
  Import-Module ./src/Fylgyr/Fylgyr.psd1 -Force; \
  Invoke-Fylgyr -Owner '<owner>' -Repo '<repo>' -ChangedOnly -OutputFormat Console | Out-Null; \
  if ((Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue).Value -ne 0) { exit 1 }\
"
```

Replace `<owner>` and `<repo>` with your values.

## Optional Strict Gate

If you want pre-commit to fail only for higher severities, add `-FailOn High`:

```powershell
Invoke-Fylgyr -Owner '<owner>' -Repo '<repo>' -ChangedOnly -FailOn High -OutputFormat Console
```

## Notes

- `-ChangedOnly` compares against `HEAD`; use `-SinceRef` to compare with another base such as `origin/main`.
- For CI enforcement, prefer `scripts/fylgyr-ci.ps1`.
