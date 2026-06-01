function Test-PatPolicy {
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
            -CheckName 'PatPolicy' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization PAT policy does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    $requestsAvailable = $false
    $tokensAvailable = $false
    $tokensUnavailableReason = ''
    $requestCount = 0

    try {
        $patRequests = Invoke-GitHubApi -Endpoint "orgs/$Owner/personal-access-token-requests?per_page=100" -Token $Token
        $requestsAvailable = $true
        if ($patRequests -is [System.Array]) {
            $requestCount = $patRequests.Count
        }
        elseif ($patRequests -and $patRequests.PSObject.Properties['requests']) {
            $requestCount = @($patRequests.requests).Count
        }
        else {
            $requestCount = @($patRequests).Count
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PatPolicy' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Unable to evaluate organization PAT policy endpoint. Access may be blocked by token permissions, organization plan/feature gating, or endpoint token-type restrictions.' `
                -Remediation 'Verify endpoint availability for your organization plan and, when required, use a GitHub App user/installation token with Personal access token requests/read and Personal access tokens/read organization permissions.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PatPolicy' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Organization PAT policy endpoint is not available for this organization plan/feature context.' `
                -Remediation 'Use available access-control features and enforce short PAT expirations. If PAT policy verification is required, verify endpoint availability and token-type requirements in GitHub REST docs.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'PatPolicy' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to evaluate personal access token request policy: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $null = Invoke-GitHubApi -Endpoint "orgs/$Owner/personal-access-tokens?per_page=1" -Token $Token
        $tokensAvailable = $true
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PatPolicy' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Token cannot read active fine-grained PAT records. PAT policy analysis is partial (permission, plan/feature gating, or token-type restriction).' `
                -Remediation 'Verify endpoint availability for your organization plan and, when required, use a GitHub App user/installation token with Personal access tokens/read organization permission.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $tokensUnavailableReason = '404'
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PatPolicy' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Failed to evaluate active PAT records: $($_.Exception.Message)" `
                -Remediation 'Verify token scope and organization access, then rerun.' `
                -Target $resource))
            return $results.ToArray()
        }
    }

    if ($requestsAvailable -and -not $tokensAvailable -and $tokensUnavailableReason -eq '404') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'PatPolicy' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'PAT request endpoint is reachable, but active PAT records endpoint is unavailable (404) in this org context. Governance verification is partial.' `
            -Remediation 'Treat this check as advisory in this org context. Confirm PAT governance in organization settings and verify token-type requirements for PAT policy endpoints in GitHub docs.' `
            -Target $resource))
        return $results.ToArray()
    }

    if ($requestsAvailable -and $tokensAvailable -and $requestCount -gt 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'PatPolicy' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "PAT policy endpoints are active and $requestCount fine-grained PAT request record(s) were observed." `
            -Remediation 'No action needed. Keep requiring PAT approval and continue reducing classic PAT usage.' `
            -Target $resource))
    }
    elseif ($requestsAvailable -and $tokensAvailable) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'PatPolicy' `
            -Status 'Warning' `
            -Severity 'High' `
            -Resource $resource `
            -Detail 'PAT governance endpoints are reachable, but no request records were observed. Fine-grained PAT approval enforcement could not be confirmed from API evidence alone.' `
            -Remediation 'Review organization PAT settings: require approval for fine-grained PATs and restrict classic PAT access where possible.' `
            -AttackMapping @('uber-credential-leak', 'github-device-code-phishing') `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'PatPolicy' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail 'Could not verify organization PAT governance. Unrestricted or long-lived tokens increase the blast radius of endpoint compromise and phishing attacks.' `
            -Remediation 'Enable fine-grained PAT approval workflow, restrict classic PAT access, and enforce short token expiration policies.' `
            -AttackMapping @('uber-credential-leak', 'github-device-code-phishing') `
            -Target $resource))
    }

    $results.ToArray()
}
