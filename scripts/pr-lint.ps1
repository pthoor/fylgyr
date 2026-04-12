#Requires -Version 7.0
<#
.SYNOPSIS
  Mechanical consistency checks that ScriptAnalyzer and Pester do not cover.

.DESCRIPTION
  Catches the recurring classes of issues that reviewers (human or Copilot)
  tend to find in PRs:

    1. Public Test-*.ps1 checks with Owner/Repo parameters must carry the
       [ValidatePattern('^[a-zA-Z0-9._-]+$')] attribute.
    2. Every CheckName string passed to Format-FylgyrResult must match the
       function's own name minus the 'Test-' prefix.
    3. docs/PERMISSIONS.md must list every exported Test-* check exactly once.
    4. No use of raw $_ in error message interpolation (security rule).

  Non-zero exit on any finding.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$publicDir = Join-Path $repoRoot 'src/Fylgyr/Public'
$permissionsDoc = Join-Path $repoRoot 'docs/PERMISSIONS.md'

$findings = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param([string]$File, [int]$Line, [string]$Message)
    $rel = [System.IO.Path]::GetRelativePath($repoRoot, $File)
    if ($Line -gt 0) {
        $findings.Add("${rel}:${Line}: $Message")
    }
    else {
        $findings.Add("${rel}: $Message")
    }
}

$testFiles = Get-ChildItem -Path $publicDir -Filter 'Test-*.ps1' -File

# --- Check 1: ValidatePattern on Owner/Repo parameters ---
foreach ($file in $testFiles) {
    $lines = Get-Content -Path $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*\[string\]\$(Owner|Repo)\b') {
            $paramName = $Matches[1]
            # Look back up to 5 lines for ValidatePattern
            $hasValidator = $false
            for ($j = [Math]::Max(0, $i - 5); $j -lt $i; $j++) {
                if ($lines[$j] -match 'ValidatePattern\(''\^\[a-zA-Z0-9\._-\]\+\$''\)') {
                    $hasValidator = $true
                    break
                }
            }
            if (-not $hasValidator) {
                Add-Finding -File $file.FullName -Line ($i + 1) `
                    -Message "[$paramName] parameter missing [ValidatePattern('^[a-zA-Z0-9._-]+$')]"
            }
        }
    }
}

# --- Check 2: CheckName string alignment ---
foreach ($file in $testFiles) {
    $expected = $file.BaseName -replace '^Test-', ''
    $content = Get-Content -Path $file.FullName -Raw
    $lines = Get-Content -Path $file.FullName

    $checkNameMatches = [regex]::Matches($content, "-CheckName\s+'([^']+)'")
    foreach ($m in $checkNameMatches) {
        $actual = $m.Groups[1].Value
        if ($actual -ne $expected) {
            # Find line number for the match
            $pre = $content.Substring(0, $m.Index)
            $lineNum = ($pre -split "`n").Count
            Add-Finding -File $file.FullName -Line $lineNum `
                -Message "CheckName '$actual' does not match function name (expected '$expected')"
        }
    }
}

# --- Check 3: PERMISSIONS.md coverage ---
if (Test-Path $permissionsDoc) {
    $doc = Get-Content -Path $permissionsDoc -Raw
    foreach ($file in $testFiles) {
        $name = $file.BaseName
        $needle = '`' + $name + '`'
        if (-not $doc.Contains($needle)) {
            Add-Finding -File $permissionsDoc -Line 0 `
                -Message "Missing row for check '$name' in permission matrix"
        }
    }
}
else {
    Add-Finding -File $permissionsDoc -Line 0 -Message 'docs/PERMISSIONS.md not found'
}

# --- Check 4: Unsafe error interpolation (security rule) ---
# CLAUDE.md: never use raw `$_` in error messages — use `$_.Exception.Message`.
# The specific unsafe patterns are:
#   - `$_.ToString()`         — dumps the full error record including stack trace
#   - `"Error: $_"` style    — bare $_ interpolated into a string
# Pipeline use (`Where-Object { $_ -notmatch ... }`) is fine and NOT flagged.
$srcFiles = Get-ChildItem -Path (Join-Path $repoRoot 'src/Fylgyr') -Filter '*.ps1' -Recurse
foreach ($file in $srcFiles) {
    $lines = Get-Content -Path $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        # `$_.ToString()` is always unsafe in this codebase.
        if ($line -match '\$_\.ToString\(\)') {
            Add-Finding -File $file.FullName -Line ($i + 1) `
                -Message '$_.ToString() leaks full error record — use $_.Exception.Message'
            continue
        }
        # Detect bare `$_` interpolated inside a double-quoted string: `"...$_..."` where
        # the $_ is NOT immediately followed by a `.` (which would be a property access).
        # Tokenize-free heuristic: find a `"` then look for `$_` (not followed by `.` or `\w`)
        # before the NEXT `"` on the same line.
        $matchStart = 0
        while (($qOpen = $line.IndexOf('"', $matchStart)) -ge 0) {
            $qClose = $line.IndexOf('"', $qOpen + 1)
            if ($qClose -lt 0) { break }
            $inside = $line.Substring($qOpen + 1, $qClose - $qOpen - 1)
            if ($inside -match '\$_(?![\.\w])') {
                Add-Finding -File $file.FullName -Line ($i + 1) `
                    -Message 'Bare $_ interpolated in string — use $_.Exception.Message'
                break
            }
            $matchStart = $qClose + 1
        }
    }
}

# --- Report ---
if ($findings.Count -gt 0) {
    Write-Host "pr-lint: $($findings.Count) finding(s):" -ForegroundColor Red
    foreach ($f in $findings) {
        Write-Host "  $f" -ForegroundColor Red
    }
    exit 1
}

Write-Host 'pr-lint: OK' -ForegroundColor Green
exit 0
