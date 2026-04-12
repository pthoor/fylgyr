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

    try {
        $alerts = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/secret-scanning/alerts?state=open&per_page=100" -Token $Token -AllPages
    }
    catch {
        $msg = $_.ToString()

        if ($msg -match '404' -or ($msg -match '403' -and $msg -match '(?i)disabled')) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SecretScanning' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Secret Scanning is not enabled on this repository.' `
                -Remediation 'Enable Secret Scanning in Settings → Security → Code security and analysis.' `
                -AttackMapping @('axios-npm-token-leak', 'uber-credential-leak') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SecretScanning' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read Secret Scanning alerts.' `
                -Remediation 'Use a fine-grained token with Secret scanning alerts:read permission, or a classic token with security_events scope.' `
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
            -Target $target))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'SecretScanning' `
        -Status 'Fail' `
        -Severity 'High' `
        -Resource $resource `
        -Detail "$($alerts.Count) open Secret Scanning alert(s) found. Exposed secret types: $(($alerts | Select-Object -ExpandProperty secret_type -Unique) -join ', ')." `
        -Remediation 'Review and resolve open Secret Scanning alerts in Security → Secret Scanning. Rotate any exposed credentials immediately.' `
        -AttackMapping @('axios-npm-token-leak', 'uber-credential-leak') `
        -Target $target))

    $results.ToArray()
}
