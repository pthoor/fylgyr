#Requires -Version 7.0
<#
.SYNOPSIS
  Configure this clone of Fylgyr to use the tracked .githooks/ directory.

.DESCRIPTION
  Sets `core.hooksPath` to `.githooks` so that hooks are version-controlled and
  everyone gets the same pre-push gates (ScriptAnalyzer + pr-lint + Pester).

  Run once per clone:
      pwsh scripts/install-hooks.ps1

  To uninstall:
      git config --unset core.hooksPath
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $hooksDir = '.githooks'
    if (-not (Test-Path $hooksDir)) {
        throw "Expected $hooksDir directory in $repoRoot"
    }

    # Ensure hook files are executable (matters on WSL/Linux/macOS clones).
    $prePush = Join-Path $hooksDir 'pre-push'
    if (Test-Path $prePush) {
        if ($IsLinux -or $IsMacOS) {
            & chmod +x $prePush
        }
    }

    git config core.hooksPath $hooksDir
    Write-Host "core.hooksPath -> $hooksDir" -ForegroundColor Green
    Write-Host 'Pre-push gates: PSScriptAnalyzer, pr-lint, Pester.' -ForegroundColor Green
    Write-Host 'Bypass (emergency only): git push --no-verify' -ForegroundColor Yellow
}
finally {
    Pop-Location
}
