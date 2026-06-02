function Test-OrgActionRestrictions {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public check name follows project check contract.')]
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
            -CheckName 'OrgActionRestrictions' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization Actions restriction policy does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $actionsPerm = Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/permissions" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgActionRestrictions' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read organization Actions restrictions.' `
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with read:org/admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgActionRestrictions' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Organization Actions restrictions endpoint is unavailable for this plan or account type.' `
                -Remediation 'No action needed unless this org should enforce Actions allowlists.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgActionRestrictions' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to evaluate Actions restrictions: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $allowedActions = 'unknown'
    if ($actionsPerm -and $actionsPerm.PSObject.Properties['allowed_actions'] -and $actionsPerm.allowed_actions) {
        $allowedActions = [string]$actionsPerm.allowed_actions
    }

    if ($allowedActions -eq 'selected') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgActionRestrictions' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Organization Actions policy is restricted to selected actions.' `
            -Remediation 'No action needed. Continue curating the allowlist and standardize approved templates in the .github repository.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgActionRestrictions' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Organization allows '$allowedActions' action usage. Unrestricted action sources increase the chance of running a compromised third-party action." `
            -Remediation "Set allowed_actions to 'selected' and maintain an explicit allowlist. Use the .github repository for starter workflow templates that reference only approved actions." `
            -AttackMapping @('tj-actions-shai-hulud') `
            -Target $resource))
    }

    $results.ToArray()
}
