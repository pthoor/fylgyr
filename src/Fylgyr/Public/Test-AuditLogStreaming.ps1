function Test-AuditLogStreaming {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $resource = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'User') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AuditLogStreaming' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization audit log streaming does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $streamKey = Invoke-GitHubApi -Endpoint "orgs/$Owner/audit-log/stream-key" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'AuditLogStreaming' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Audit log streaming endpoint is not available at organization scope in the current feature/policy/access context. Enterprise-level streaming can be configured centrally and still return 404 for org endpoint checks.' `
                -Remediation 'Advisory for now. Confirm streaming under enterprise settings, then use org-level checks as supplemental visibility when endpoint support is available.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'AuditLogStreaming' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read organization audit log streaming configuration.' `
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'AuditLogStreaming' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to evaluate audit log streaming: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $configured = $false
    if ($streamKey -and $streamKey.PSObject.Properties['stream_key'] -and $streamKey.stream_key) {
        $configured = $true
    }

    if ($configured) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AuditLogStreaming' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Organization audit log streaming key is configured.' `
            -Remediation 'No action needed. Validate downstream SIEM ingestion and retention.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AuditLogStreaming' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail 'Organization audit log streaming is not configured. Incident response and forensic reconstruction become harder after compromise.' `
            -Remediation 'Configure audit log streaming to an external SIEM or immutable storage target with alerting on privileged events.' `
            -AttackMapping @('github-device-code-phishing', 'uber-credential-leak') `
            -Target $resource))
    }

    $results.ToArray()
}
