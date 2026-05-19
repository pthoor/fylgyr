function Test-OAuthAppPolicy {
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
            -CheckName 'OAuthAppPolicy' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization OAuth app restriction policy does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $policy = Invoke-GitHubApi -Endpoint "orgs/$Owner/third-party-application-policy" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OAuthAppPolicy' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Third-party OAuth app policy endpoint is unavailable for this organization plan.' `
                -Remediation 'Use organization app restrictions where available. Prefer GitHub Apps over OAuth apps for modern, fine-grained access control.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OAuthAppPolicy' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read third-party OAuth app policy.' `
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with read:org/admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OAuthAppPolicy' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to evaluate OAuth app policy: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $restricted = $false
    if ($policy -and $policy.PSObject.Properties['enabled_for_organization']) {
        $restricted = [bool]$policy.enabled_for_organization
    }

    if ($restricted) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OAuthAppPolicy' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Third-party OAuth application access restrictions are enabled for this organization.' `
            -Remediation 'No action needed. Continue migrating legacy OAuth integrations to GitHub Apps where possible.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OAuthAppPolicy' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail 'Third-party OAuth application access restrictions are disabled. Device code phishing can trick a user into authorizing attacker-controlled OAuth apps with broad scopes.' `
            -Remediation 'Enable third-party application restrictions and require admin approval. Migrate legacy OAuth integrations to GitHub Apps with least-privilege, short-lived installation tokens.' `
            -AttackMapping @('github-device-code-phishing') `
            -Target $resource))
    }

    $results.ToArray()
}
