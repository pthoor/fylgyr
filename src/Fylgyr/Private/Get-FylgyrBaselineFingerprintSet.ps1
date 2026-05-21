function Get-FylgyrBaselineFingerprintSet {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory)]
        [string]$BaselinePath
    )

    if (-not (Test-Path -Path $BaselinePath -PathType Leaf)) {
        throw "Baseline file not found: $BaselinePath"
    }

    $raw = Get-Content -Path $BaselinePath -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Baseline file is empty: $BaselinePath"
    }

    try {
        $parsed = $raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse baseline JSON: $($_.Exception.Message)"
    }

    $baselineResults = if ($parsed -is [System.Array]) {
        @($parsed)
    }
    elseif ($parsed -and $parsed.PSObject.Properties['results']) {
        @($parsed.results)
    }
    elseif ($parsed) {
        @($parsed)
    }
    else {
        @()
    }

    $fingerprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($baselineResult in $baselineResults) {
        if (-not $baselineResult) {
            continue
        }

        if (-not $baselineResult.PSObject.Properties['CheckName'] -or
            -not $baselineResult.PSObject.Properties['Resource'] -or
            -not $baselineResult.PSObject.Properties['Detail']) {
            continue
        }

        if ($baselineResult.PSObject.Properties['Status'] -and $baselineResult.Status -eq 'Pass') {
            continue
        }

        $fingerprint = Get-FylgyrFingerprint -Result $baselineResult
        if (-not [string]::IsNullOrWhiteSpace($fingerprint)) {
            $fingerprints.Add($fingerprint) | Out-Null
        }
    }

    return $fingerprints
}
