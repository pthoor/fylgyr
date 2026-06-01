param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:FylgyrModuleReady = $false

$moduleSource = if ([string]::IsNullOrWhiteSpace($env:FYLGYR_MODULE_SOURCE)) { 'Bundled' } else { $env:FYLGYR_MODULE_SOURCE }
$allowedModuleSources = @('Auto', 'Gallery', 'Bundled')

if ($moduleSource -notin $allowedModuleSources) {
    throw "FYLGYR_MODULE_SOURCE must be one of: Auto, Gallery, Bundled."
}

function Write-FylgyrDebug {
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = (Get-Date).ToString('o')
    $line = "[$timestamp] $Message"
    Write-Host $line

    try {
        Add-Content -Path '/home/LogFiles/Application/fylgyr-debug.log' -Value $line -Encoding UTF8
    }
    catch {
        # Best-effort local debug sink; host logging remains the primary signal.
    }
}

function Import-FylgyrModule {
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Auto', 'Gallery', 'Bundled')]
        [string]$ModuleSource
    )

    if ($script:FylgyrModuleReady) {
        return
    }

    $bundledManifestPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Modules/Fylgyr/Fylgyr.psd1'
    $hasBundledManifest = Test-Path -Path $bundledManifestPath -PathType Leaf

    if ($ModuleSource -eq 'Bundled') {
        if (-not $hasBundledManifest) {
            throw 'FYLGYR_MODULE_SOURCE is Bundled, but no packaged Fylgyr module is available. Include Fylgyr in the function package under Modules/.'
        }

        try {
            Import-Module -Name $bundledManifestPath -Force -ErrorAction Stop
            $script:FylgyrModuleReady = $true
            return
        }
        catch {
            throw "Failed to import bundled Fylgyr module: $($_.Exception.Message)"
        }
    }

    try {
        # Install the newest PSGallery version when online, then import it for this run.
        Install-Module -Name 'Fylgyr' -Repository 'PSGallery' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module -Name 'Fylgyr' -Force -ErrorAction Stop
        $script:FylgyrModuleReady = $true
    }
    catch {
        if ($ModuleSource -eq 'Auto' -and $hasBundledManifest) {
            try {
                Import-Module -Name $bundledManifestPath -Force -ErrorAction Stop
                $script:FylgyrModuleReady = $true
                return
            }
            catch {
                throw "Failed PSGallery install and bundled fallback import: $($_.Exception.Message)"
            }
        }

        throw "Failed to install or import latest Fylgyr module from PSGallery: $($_.Exception.Message)"
    }
}

$owner = $env:FYLGYR_OWNER
$repo = $env:FYLGYR_REPO
$dcrImmutableId = $env:FYLGYR_DCR_IMMUTABLE_ID
$dceUri = $env:FYLGYR_DCE_URI
$streamName = if ([string]::IsNullOrWhiteSpace($env:FYLGYR_STREAM_NAME)) { 'Custom-FylgyrRaw' } else { $env:FYLGYR_STREAM_NAME }
$scanMode = if ([string]::IsNullOrWhiteSpace($env:FYLGYR_MODE)) { 'Audit' } else { $env:FYLGYR_MODE }

$allowedScanModes = @('Audit', 'Drift', 'Both')
if ($scanMode -notin $allowedScanModes) {
    throw "FYLGYR_MODE must be one of: Audit, Drift, Both."
}

$namePattern = '^[a-zA-Z0-9._-]+$'

if ([string]::IsNullOrWhiteSpace($owner)) {
    throw 'FYLGYR_OWNER environment variable is required.'
}

if ($owner -notmatch $namePattern) {
    throw 'FYLGYR_OWNER contains invalid characters. Allowed: a-z, A-Z, 0-9, dot, underscore, hyphen.'
}

if (-not [string]::IsNullOrWhiteSpace($repo) -and $repo -notmatch $namePattern) {
    throw 'FYLGYR_REPO contains invalid characters. Allowed: a-z, A-Z, 0-9, dot, underscore, hyphen.'
}

if ([string]::IsNullOrWhiteSpace($dcrImmutableId)) {
    throw 'FYLGYR_DCR_IMMUTABLE_ID environment variable is required.'
}

if ([string]::IsNullOrWhiteSpace($dceUri)) {
    throw 'FYLGYR_DCE_URI environment variable is required.'
}

$dceUriObject = $null
if (-not [System.Uri]::TryCreate($dceUri, [System.UriKind]::Absolute, [ref]$dceUriObject) -or $dceUriObject.Scheme -ne 'https') {
    throw 'FYLGYR_DCE_URI must be a valid HTTPS URI.'
}

try {
    $scanTarget = if ([string]::IsNullOrWhiteSpace($repo)) { $owner } else { "$owner/$repo" }
    Write-FylgyrDebug "FylgyrTimer: started target='$scanTarget' mode='$scanMode' moduleSource='$moduleSource' dceHost='$($dceUriObject.Host)' stream='$streamName'."

    Import-FylgyrModule -ModuleSource $moduleSource
    Write-FylgyrDebug 'FylgyrTimer: module import completed.'
    $activeModule = Get-Module -Name 'Fylgyr' | Select-Object -First 1
    if ($null -ne $activeModule) {
        Write-FylgyrDebug "FylgyrTimer: active module path='$($activeModule.Path)' version='$($activeModule.Version)'."
    }

    $invokeParams = @{
        Owner = $owner
        Mode = $scanMode
        OutputFormat = 'LogAnalytics'
    }
    if (-not [string]::IsNullOrWhiteSpace($repo)) {
        $invokeParams['Repo'] = $repo
    }

    $scanLines = Invoke-Fylgyr @invokeParams

    $scanPayloadType = if ($null -eq $scanLines) { '<null>' } else { $scanLines.GetType().FullName }
    $scanRecordCount = if ($scanLines -is [string]) {
        @($scanLines -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
    }
    else {
        @($scanLines).Count
    }
    Write-FylgyrDebug "FylgyrTimer: scan completed payloadType='$scanPayloadType' recordCount=$scanRecordCount."

    $ingestionResult = $scanLines |
        Send-FylgyrToLogAnalytics `
            -DcrImmutableId $dcrImmutableId `
            -DceUri $dceUri `
            -StreamName $streamName `
            -UseManagedIdentity

    Write-FylgyrDebug "FylgyrTimer: ingestion completed sentBatches=$($ingestionResult.SentBatches) sentRecords=$($ingestionResult.SentRecords) endpoint='$($ingestionResult.Endpoint)'."
}
catch {
    Write-FylgyrDebug "FylgyrTimer: failed message='$($_.Exception.Message)'."
    throw "Fylgyr Azure Function run failed: $($_.Exception.Message)"
}
