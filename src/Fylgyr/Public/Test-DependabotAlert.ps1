function Test-DependabotAlert {
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

    try {
        $alerts = Invoke-GitHubApi `
            -Endpoint "repos/$Owner/$Repo/dependabot/alerts?state=open&per_page=100" `
            -Token $Token `
            -AllPages
    }
    catch {
        $msg = $_.ToString()

        if ($msg -match '404' -or ($msg -match '403' -and $msg -match '(?i)disabled')) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DependabotAlerts' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Dependabot alerts are not enabled on this repository.' `
                -Remediation 'Enable Dependabot alerts in Settings → Security → Code security and analysis.' `
                -AttackMapping @('event-stream-hijack') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DependabotAlerts' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read Dependabot alerts. Requires a fine-grained token with Dependabot alerts:read permission.' `
                -Remediation 'Use a fine-grained token with the Dependabot alerts:read permission, or a classic token with security_events scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'DependabotAlerts' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Unexpected error reading Dependabot alerts: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    $critical = @($alerts | Where-Object { $_.security_advisory.severity -eq 'critical' })
    $high = @($alerts | Where-Object { $_.security_advisory.severity -eq 'high' })

    if ($critical.Count -eq 0 -and $high.Count -eq 0) {
        $detail = if ($alerts.Count -eq 0) {
            'No open Dependabot alerts found.'
        }
        else {
            "$($alerts.Count) open alert(s) found, none critical or high severity."
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'DependabotAlerts' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail $detail `
            -Remediation 'No action needed for critical/high alerts.' `
            -Target $target))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'DependabotAlerts' `
        -Status 'Fail' `
        -Severity 'High' `
        -Resource $resource `
        -Detail "$($critical.Count) critical and $($high.Count) high severity open Dependabot alert(s) found." `
        -Remediation 'Review and resolve critical and high Dependabot alerts in Security → Dependabot alerts. Update or replace affected dependencies.' `
        -AttackMapping @('event-stream-hijack') `
        -Target $target))

    $results.ToArray()
}
