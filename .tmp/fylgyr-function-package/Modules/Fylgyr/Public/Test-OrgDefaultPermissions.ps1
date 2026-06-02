function Test-OrgDefaultPermissions {
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
            -CheckName 'OrgDefaultPermissions' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization default repository permission does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $orgInfo = Invoke-GitHubApi -Endpoint "orgs/$Owner" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OrgDefaultPermissions' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read organization default repository permission.' `
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with read:org/admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgDefaultPermissions' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to read organization default repository permission: $($_.Exception.Message)" `
            -Remediation 'Verify the owner and token, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $defaultPerm = 'unknown'
    if ($orgInfo -and $orgInfo.PSObject.Properties['default_repository_permission'] -and $orgInfo.default_repository_permission) {
        $defaultPerm = [string]$orgInfo.default_repository_permission
    }

    if ($defaultPerm -in @('read', 'none')) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgDefaultPermissions' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Organization default repository permission is '$defaultPerm'." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgDefaultPermissions' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Organization default repository permission is '$defaultPerm'. Broad default write/admin access increases lateral movement risk if a single account is compromised, as seen in Gentoo-style org compromise patterns." `
            -Remediation "Set the organization default repository permission to 'read' or 'none' and grant elevated access only per repository by exception." `
            -AttackMapping @('gentoo-github-compromise') `
            -Target $resource))
    }

    $results.ToArray()
}
