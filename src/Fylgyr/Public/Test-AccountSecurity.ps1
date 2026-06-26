function Test-AccountSecurity {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $resource = "user/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Run once per owner across an org-wide repo scan (cache reset by Invoke-Fylgyr).
    $cacheKey = "$Owner::2fa"
    if ($script:FylgyrOwnerAccountChecked -is [hashtable]) {
        if ($script:FylgyrOwnerAccountChecked.ContainsKey($cacheKey)) {
            return $results.ToArray()
        }
        $script:FylgyrOwnerAccountChecked[$cacheKey] = $true
    }

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token

    if ($ownerContext.Type -eq 'Organization') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is an organization. Member two-factor enforcement is covered by Test-OrgMfaPolicy." `
            -Remediation 'No action needed. This check targets personal accounts.' `
            -Target $resource))
        return $results.ToArray()
    }

    if ($ownerContext.Type -ne 'User') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Could not determine the account type for '$Owner', so account security could not be evaluated." `
            -Remediation 'Verify the owner name and that the token can read the account, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    # two_factor_authentication is only returned by GET /user for the token's own account.
    if (-not $ownerContext.TokenMatchesOwner) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Two-factor status for '$Owner' is only visible to a token owned by that account; the supplied token belongs to a different user, so 2FA could not be verified." `
            -Remediation "Re-run with a token owned by '$Owner', or confirm 2FA is enabled under Settings > Password and authentication." `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $user = Invoke-GitHubApi -Endpoint 'user' -Token $Token
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Could not read account security details: $($_.Exception.Message)" `
            -Remediation 'Verify the token is valid and rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    if (-not ($user.PSObject.Properties['two_factor_authentication'])) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'The token cannot read two-factor status (fine-grained PATs and some token types omit this field), so 2FA could not be verified.' `
            -Remediation "Confirm 2FA is enabled under Settings > Password and authentication, or use a token that exposes account security details." `
            -Target $resource))
        return $results.ToArray()
    }

    if ($user.two_factor_authentication) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Account '$Owner' has two-factor authentication enabled." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountSecurity' `
            -Status 'Fail' `
            -Severity 'Critical' `
            -Resource $resource `
            -Detail "Account '$Owner' does not have two-factor authentication enabled. For a solo maintainer, account takeover is supply-chain takeover: a single phished or reused password unlocks every repository, release, and token, as in the Dropbox GitHub breach and device-code phishing campaigns." `
            -Remediation 'Enable two-factor authentication immediately (Settings > Password and authentication), preferring a security key or TOTP app over SMS.' `
            -AttackMapping @('dropbox-github-breach', 'github-device-code-phishing', 'ua-parser-js-npm-compromise') `
            -Target $resource))
    }

    $results.ToArray()
}
