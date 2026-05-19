function Test-OrgMfaPolicy {
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
            -CheckName 'OrgMfaPolicy' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization MFA policy does not apply." `
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
                -CheckName 'OrgMfaPolicy' `
                -Status 'Error' `
                -Severity 'Critical' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read organization MFA policy.' `
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with read:org/admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgMfaPolicy' `
            -Status 'Error' `
            -Severity 'Critical' `
            -Resource $resource `
            -Detail "Failed to read organization MFA policy: $($_.Exception.Message)" `
            -Remediation 'Verify the owner and token, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $mfaRequired = $false
    if ($orgInfo -and $orgInfo.PSObject.Properties['two_factor_requirement_enabled']) {
        $mfaRequired = [bool]$orgInfo.two_factor_requirement_enabled
    }

    if ($mfaRequired) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgMfaPolicy' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Organization requires two-factor authentication for members.' `
            -Remediation 'No action needed.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OrgMfaPolicy' `
            -Status 'Fail' `
            -Severity 'Critical' `
            -Resource $resource `
            -Detail 'Organization does not require two-factor authentication for all members. A single phished password can unlock organization access, as seen in the Dropbox GitHub breach pattern.' `
            -Remediation 'Enable Require two-factor authentication in organization security settings and remove non-compliant members until they enroll.' `
            -AttackMapping @('dropbox-github-breach') `
            -Target $resource))
    }

    $results.ToArray()
}
