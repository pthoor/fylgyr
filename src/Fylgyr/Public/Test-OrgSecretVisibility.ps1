function Test-OrgSecretVisibility {
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
            -CheckName 'OrgSecretVisibility' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization secret visibility does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $secrets = @(Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/secrets?per_page=100" -Token $Token -AllPages)
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgSecretVisibility' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Organization Actions secrets are not available for this owner.' `
                -Remediation 'No action needed.' `
                -Target $resource))
            return $results.ToArray()
        }
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgSecretVisibility' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to list organization secrets.' `
                -Remediation 'Use a fine-grained token with organization Secrets:read, or a classic token with admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgSecretVisibility' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to list organization secrets: $($_.Exception.Message)" `
            -Remediation 'Verify the owner and token, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $findingCount = 0
    foreach ($secret in $secrets) {
        if (-not $secret -or -not $secret.PSObject.Properties['name']) { continue }
        if ($secret.PSObject.Properties['visibility'] -and $secret.visibility -eq 'all') {
            $findingCount++
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgSecretVisibility' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (org-secret: $($secret.name))" `
                -Detail "Organization secret '$($secret.name)' is visible to all repositories. Any repository - including one with a pull_request_target or workflow_run workflow that processes fork content - can read it, turning a single risky repo into an org-wide secret exposure." `
                -Remediation "Restrict this secret to selected repositories (Settings > Secrets and variables > Actions > org secret > Repository access = 'Selected repositories')." `
                -AttackMapping @('prt-scan-ai-automated', 'hackerbot-claw', 'axios-npm-token-leak') `
                -Target $resource))
        }
    }

    if ($findingCount -eq 0) {
        $detail = if ($secrets.Count -eq 0) {
            'Organization has no Actions secrets.'
        }
        else {
            "Organization has $($secrets.Count) Actions secret(s); none are visible to all repositories."
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgSecretVisibility' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail $detail `
            -Remediation 'No action needed.' `
            -Target $resource))
    }

    $results.ToArray()
}
