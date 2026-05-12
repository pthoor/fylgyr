function Test-SecretScanning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = $target
    $attackMap = @('committed-credentials-exposure', 'axios-npm-token-leak', 'uber-credential-leak')

    try {
        $alerts = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/secret-scanning/alerts?state=open&per_page=100" -Token $Token -AllPages
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404' -or ($msg -match '403' -and $msg -match '(?i)disabled')) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SecretScanning' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Secret Scanning is not enabled on this repository.' `
                -Remediation 'Enable Secret Scanning in Settings → Security → Code security and analysis.' `
                -AttackMapping $attackMap `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $featureEnabled = $null

            try {
                $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
                if ($repoInfo -and
                    $repoInfo.PSObject.Properties['security_and_analysis'] -and
                    $repoInfo.security_and_analysis -and
                    $repoInfo.security_and_analysis.PSObject.Properties['secret_scanning'] -and
                    $repoInfo.security_and_analysis.secret_scanning -and
                    $repoInfo.security_and_analysis.secret_scanning.PSObject.Properties['status']) {
                    $featureEnabled = $repoInfo.security_and_analysis.secret_scanning.status -eq 'enabled'
                }
            }
            catch {
                Write-Debug "Could not resolve secret_scanning feature state: $($_.Exception.Message)"
            }

            if ($featureEnabled -eq $false) {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'SecretScanning' `
                    -Status 'Fail' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail 'Secret Scanning is not enabled on this repository.' `
                    -Remediation 'Enable Secret Scanning in Settings → Security → Code security and analysis.' `
                    -AttackMapping $attackMap `
                    -Target $target))
                return $results.ToArray()
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'SecretScanning' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Secret Scanning appears enabled, but open-alert telemetry is unavailable with the current token scope.' `
                -Remediation 'Enable secret_scanning_alerts:read on a fine-grained token (or security_events on a classic token) to surface open alert count, highest severity, and oldest alert age.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'SecretScanning' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Unexpected error reading Secret Scanning alerts: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if ($alerts.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'SecretScanning' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Secret Scanning is enabled and no open alerts found.' `
            -Remediation 'No action needed.' `
            -AttackMapping $attackMap `
            -Target $target))
        return $results.ToArray()
    }

    $severityRank = @{
        low = 1
        medium = 2
        high = 3
        critical = 4
    }

    $highestSeverity = 'unknown'
    $highestRank = 0
    $oldestAlert = $null

    foreach ($alert in @($alerts)) {
        if ($alert -and $alert.PSObject.Properties['severity'] -and $alert.severity) {
            $sev = ([string]$alert.severity).ToLowerInvariant()
            if ($severityRank.ContainsKey($sev) -and $severityRank[$sev] -gt $highestRank) {
                $highestRank = $severityRank[$sev]
                $highestSeverity = $sev
            }
        }

        if ($alert -and $alert.PSObject.Properties['created_at'] -and $alert.created_at) {
            try {
                $parsedDate = [datetime]$alert.created_at
                if ($null -eq $oldestAlert -or $parsedDate -lt $oldestAlert) {
                    $oldestAlert = $parsedDate
                }
            }
            catch {
                Write-Debug "Could not parse secret scanning alert created_at value '$($alert.created_at)': $($_.Exception.Message)"
            }
        }
    }

    $oldestAge = 'unknown'
    if ($oldestAlert) {
        $oldestAge = [math]::Floor(([datetime]::UtcNow - $oldestAlert.ToUniversalTime()).TotalDays)
    }

    $status = if ($highestRank -ge 3) { 'Fail' } else { 'Warning' }
    $severity = if ($highestRank -ge 3) { 'High' } else { 'Medium' }
    $detail = "$($alerts.Count) open Secret Scanning alert(s) found. Highest severity: $highestSeverity. Oldest open alert age: $oldestAge day(s)."
    $remediation = if ($highestRank -ge 3) {
        'Prioritize High/Critical secret alerts immediately. Rotate affected credentials, remove leaked secrets from active code paths, and close alerts after remediation. Use TruffleHog or GitLeaks for deeper historical secret hunting.'
    }
    else {
        'Triage and resolve open secret alerts to reduce credential exposure risk. Rotate exposed credentials and use TruffleHog or GitLeaks for deeper historical secret hunting.'
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'SecretScanning' `
        -Status $status `
        -Severity $severity `
        -Resource $resource `
        -Detail $detail `
        -Remediation $remediation `
        -AttackMapping $attackMap `
        -Target $target))

    $results.ToArray()
}
