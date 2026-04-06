function Test-CodeScanning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = $target
    $staleThresholdDays = 30

    try {
        $analyses = Invoke-GitHubApi `
            -Endpoint "repos/$Owner/$Repo/code-scanning/analyses?per_page=10" `
            -Token $Token
    }
    catch {
        $msg = $_.ToString()

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'CodeScanning' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Code Scanning is not configured on this repository.' `
                -Remediation 'Set up Code Scanning in Security → Code scanning. Use CodeQL or a third-party scanner via a GitHub Actions workflow.' `
                -AttackMapping @('solarwinds-orion') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'CodeScanning' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read Code Scanning analyses. Requires a token with security_events scope or GitHub Advanced Security.' `
                -Remediation 'Use a token with security_events scope or enable GitHub Advanced Security on this repository.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'CodeScanning' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Unexpected error reading Code Scanning analyses: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if (-not $analyses -or ($analyses -is [System.Array] -and $analyses.Count -eq 0)) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'CodeScanning' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail 'Code Scanning is configured but no analysis runs have been recorded.' `
            -Remediation 'Trigger a code scanning workflow run. Verify the scanning workflow is not skipped or failing.' `
            -AttackMapping @('solarwinds-orion') `
            -Target $target))
        return $results.ToArray()
    }

    # Check freshness of most recent analysis
    $latestAnalysis = if ($analyses -is [System.Array]) { $analyses[0] } else { $analyses }
    $analysisDate = [datetime]::Parse($latestAnalysis.created_at)
    $daysSince = ([datetime]::UtcNow - $analysisDate).TotalDays

    if ($daysSince -gt $staleThresholdDays) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'CodeScanning' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Last Code Scanning analysis was $([math]::Floor($daysSince)) day(s) ago (threshold: $staleThresholdDays days). Scanning may not be running on recent commits." `
            -Remediation 'Verify the code scanning workflow is scheduled or triggered on push/pull_request events. Check for workflow failures.' `
            -AttackMapping @('solarwinds-orion') `
            -Target $target))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'CodeScanning' `
        -Status 'Pass' `
        -Severity 'Info' `
        -Resource $resource `
        -Detail "Code Scanning is active. Last analysis: $($analysisDate.ToString('yyyy-MM-dd')) ($([math]::Floor($daysSince)) day(s) ago)." `
        -Remediation 'No action needed.' `
        -Target $target))

    $results.ToArray()
}
