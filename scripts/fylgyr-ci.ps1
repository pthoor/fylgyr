#Requires -Version 7.0
<#
.SYNOPSIS
  CI wrapper for Invoke-Fylgyr that propagates process exit codes.

.DESCRIPTION
  Invoke-Fylgyr sets `$global:LASTEXITCODE` for severity gating.
  This wrapper runs the scan and exits the host process with that code,
  which is the recommended CI integration path.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [string]$Owner,

    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [string]$Repo,

    [switch]$IncludeOrgChecks,

    [ValidateSet('Object', 'JSON', 'SARIF', 'Console', 'NDJSON', 'HTML')]
    [string]$OutputFormat = 'SARIF',

    [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
    [string]$FailOn = 'High',

    [string]$OutputPath,

    [switch]$ChangedOnly,

    [ValidatePattern('^[a-zA-Z0-9._/-]+$')]
    [string]$SinceRef = 'origin/main',

    [string]$BaselinePath,

    [switch]$IgnoreConfig,

    [switch]$IncludeEvidence,

    [string]$Token = $env:GITHUB_TOKEN
)

$ErrorActionPreference = 'Stop'

try {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psd1'
    Import-Module -Name $modulePath -Force

    $invokeParams = @{
        Owner = $Owner
        OutputFormat = $OutputFormat
        FailOn = $FailOn
        ChangedOnly = $ChangedOnly
        SinceRef = $SinceRef
        IgnoreConfig = $IgnoreConfig
    }

    if ($PSBoundParameters.ContainsKey('Repo')) {
        $invokeParams.Repo = $Repo
    }

    if ($IncludeOrgChecks) {
        $invokeParams.IncludeOrgChecks = $true
    }

    if ($PSBoundParameters.ContainsKey('OutputPath')) {
        $invokeParams.OutputPath = $OutputPath
    }

    if ($PSBoundParameters.ContainsKey('BaselinePath')) {
        $invokeParams.BaselinePath = $BaselinePath
    }

    if ($IncludeEvidence) {
        $invokeParams.IncludeEvidence = $true
    }

    if ($PSBoundParameters.ContainsKey('Token')) {
        $invokeParams.Token = $Token
    }

    $results = Invoke-Fylgyr @invokeParams

    # Preserve stdout behavior for non-console formats when no OutputPath is set.
    if ($OutputFormat -ne 'Console' -and -not $PSBoundParameters.ContainsKey('OutputPath')) {
        $results
    }

    $exitCode = if ($null -ne $global:LASTEXITCODE) { [int]$global:LASTEXITCODE } else { 0 }
    exit $exitCode
}
catch {
    Write-Error "fylgyr-ci failed: $($_.Exception.Message)"
    exit 1
}
