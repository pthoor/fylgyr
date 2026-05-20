function Test-PrivateVulnReporting {
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

    try {
        $response = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/private-vulnerability-reporting" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PrivateVulnReporting' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'Private Vulnerability Reporting endpoint is unavailable for this repository or plan.' `
                -Remediation 'If your plan supports it, enable Private Vulnerability Reporting in Settings > Security and keep SECURITY.md updated with a private disclosure contact, scope, and response SLA.' `
                -AttackMapping @('xz-utils-backdoor') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PrivateVulnReporting' `
                -Status 'Error' `
                -Severity 'Low' `
                -Resource $target `
                -Detail 'Insufficient permissions to read Private Vulnerability Reporting status.' `
                -Remediation 'Use a fine-grained token with repository Metadata:read or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'PrivateVulnReporting' `
            -Status 'Error' `
            -Severity 'Low' `
            -Resource $target `
            -Detail "Unexpected error while reading Private Vulnerability Reporting status: $($_.Exception.Message)" `
            -Remediation 'Re-run with valid token scope and confirm api.github.com connectivity.' `
            -Target $target))
        return $results.ToArray()
    }

    $isEnabled = $false
    if ($response -and $response.PSObject.Properties['enabled']) {
        $isEnabled = [bool]$response.enabled
    }

    if ($isEnabled) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'PrivateVulnReporting' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'Private Vulnerability Reporting is enabled, providing a private disclosure channel for researchers.' `
            -Remediation 'No action needed. Keep SECURITY.md aligned with disclosure workflow, severity triage expectations, and response timelines.' `
            -AttackMapping @('xz-utils-backdoor') `
            -Target $target))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'PrivateVulnReporting' `
        -Status 'Warning' `
        -Severity 'Low' `
        -Resource $target `
        -Detail 'Private Vulnerability Reporting is not enabled. Security reporters may be forced into public disclosure channels, increasing pre-patch exposure risk.' `
        -Remediation 'Enable Private Vulnerability Reporting in Settings > Security. Best practice: pair it with a maintained SECURITY.md that defines private contact path, in-scope assets, acknowledgement SLA (for example 3 business days), and remediation communication cadence.' `
        -AttackMapping @('xz-utils-backdoor') `
        -Target $target))

    return $results.ToArray()
}
