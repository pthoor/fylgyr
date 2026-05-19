function Test-IpAllowlist {
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
            -CheckName 'IpAllowlist' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization IP allowlist does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    $query = @'
query($org: String!) {
  organization(login: $org) {
    ipAllowListEntries(first: 1) {
      totalCount
    }
  }
}
'@

    try {
        $response = Invoke-GitHubApi -GraphQL -Query $query -Variables @{ org = $Owner } -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match 'Enterprise' -or $msg -match 'enterprise' -or $msg -match 'not available') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'IpAllowlist' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'IP allowlist is not available for this organization plan. This feature requires GitHub Enterprise Cloud.' `
                -Remediation 'Use identity-aware controls first: enforce SSO, require MFA, protect rulesets, and prefer short-lived GitHub App tokens.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '403' -or
            $msg -match 'FORBIDDEN' -or
            $msg -match 'Resource not accessible by personal access token' -or
            $msg -match 'right permission to retrieve') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'IpAllowlist' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Unable to verify organization IP allowlist via GraphQL with the current token/plan. This check is advisory and may be unavailable depending on enterprise identity/IP policy mode.' `
                -Remediation 'Treat this as a recommendation signal. If you want verification, use a token with organization Administration:read and confirm enterprise IP allowlist mode permits GraphQL access.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'IpAllowlist' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Unable to verify IP allowlist currently: $($_.Exception.Message)" `
            -Remediation 'Treat this check as advisory when GraphQL validation is unavailable. Use enterprise/org documentation and UI settings for manual confirmation.' `
            -Target $resource))
        return $results.ToArray()
    }

    $entryCount = 0
    if ($response -and $response.PSObject.Properties['data'] -and
        $response.data -and $response.data.PSObject.Properties['organization'] -and
        $response.data.organization -and $response.data.organization.PSObject.Properties['ipAllowListEntries']) {
        $entryCount = [int]$response.data.organization.ipAllowListEntries.totalCount
    }

    if ($entryCount -gt 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'IpAllowlist' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Organization has $entryCount IP allowlist entr$(if ($entryCount -eq 1) { 'y' } else { 'ies' })." `
            -Remediation 'No action needed. Keep the allowlist reviewed and current.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'IpAllowlist' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail 'Organization has no IP allowlist entries. This is an advisory defense-in-depth recommendation for stolen-token scenarios.' `
            -Remediation 'If on Enterprise Cloud, consider configuring IP allowlist as a supplemental control. Pair with SSO/device trust, rulesets, and short-lived GitHub App installation tokens.' `
            -AttackMapping @('github-device-code-phishing', 'uber-credential-leak') `
            -Target $resource))
    }

    $results.ToArray()
}
