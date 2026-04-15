function Test-GitHubAppSecurity {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = $Owner

    # Determine whether the owner is an Organization or a User.
    $ownerType = $null
    try {
        $ownerInfo = Invoke-GitHubApi -Endpoint "users/$Owner" -Token $Token
        if ($ownerInfo -and $ownerInfo.PSObject.Properties['type']) {
            $ownerType = $ownerInfo.type
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Owner '$Owner' not found." `
                -Remediation 'Verify the owner name.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to resolve owner type: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $resource))
        return $results.ToArray()
    }

    $installationsResponse = $null
    $auditScope = $null

    if ($ownerType -eq 'Organization') {
        $auditScope = 'organization'
        try {
            $installationsResponse = Invoke-GitHubApi -Endpoint "orgs/$Owner/installations" -Token $Token
        }
        catch {
            $msg = $_.Exception.Message

            if ($msg -match '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'GitHubAppSecurity' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail 'Insufficient permissions to read organization GitHub App installations.' `
                    -Remediation 'Use a classic token with admin:org scope, or a fine-grained PAT with organization admin access to audit GitHub App installations.' `
                    -Target $resource))
                return $results.ToArray()
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Failed to list organization GitHub App installations: $($_.Exception.Message)" `
                -Remediation 'Verify the token has org admin access.' `
                -Target $resource))
            return $results.ToArray()
        }
    }
    else {
        # User account path. GitHub has no `users/{user}/installations` endpoint;
        # the only way to list a user's installed apps is via `user/installations`,
        # which requires that the supplied token belong to that user.
        $auditScope = 'user'

        $authenticatedLogin = $null
        try {
            $authed = Invoke-GitHubApi -Endpoint 'user' -Token $Token
            if ($authed -and $authed.PSObject.Properties['login']) {
                $authenticatedLogin = $authed.login
            }
        }
        catch {
            Write-Debug "Failed to resolve authenticated user: $($_.Exception.Message)"
        }

        if (-not $authenticatedLogin -or ($authenticatedLogin -ne $Owner)) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "Owner '$Owner' is a personal GitHub account. Auditing GitHub App installations on a user account requires a token belonging to that user; the supplied token belongs to '$authenticatedLogin'. Personal account App audit skipped." `
                -Remediation "Re-run with a token owned by '$Owner' (fine-grained PAT or classic token) to audit personal GitHub App installations. For organizations, use a token with admin:org access." `
                -Target $resource))
            return $results.ToArray()
        }

        try {
            $installationsResponse = Invoke-GitHubApi -Endpoint 'user/installations' -Token $Token
        }
        catch {
            $msg = $_.Exception.Message

            if ($msg -match '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'GitHubAppSecurity' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail 'Insufficient permissions to read user GitHub App installations.' `
                    -Remediation 'Use a fine-grained PAT with access to the user account, or a classic token with the read:user scope.' `
                    -Target $resource))
                return $results.ToArray()
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Failed to list user GitHub App installations: $($_.Exception.Message)" `
                -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
                -Target $resource))
            return $results.ToArray()
        }
    }

    $appList = $null
    if ($installationsResponse -and $installationsResponse.PSObject.Properties['installations']) {
        $appList = $installationsResponse.installations
    }
    elseif ($installationsResponse -is [System.Array]) {
        $appList = $installationsResponse
    }

    if (-not $appList -or $appList.Count -eq 0) {
        $scopeWord = if ($auditScope -eq 'organization') { 'organization' } else { 'user account' }
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "No GitHub App installations found on this $scopeWord." `
            -Remediation 'No action needed.' `
            -Target $resource))
        return $results.ToArray()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($app in $appList) {
        $appName = if ($app.app_slug) { $app.app_slug } else { "installation-$($app.id)" }
        $permissions = $app.permissions

        if (-not $permissions) {
            continue
        }

        $hasContentsWrite = $permissions.PSObject.Properties['contents'] -and $permissions.contents -eq 'write'
        $hasActionsWrite = $permissions.PSObject.Properties['actions'] -and $permissions.actions -eq 'write'
        $hasAdminPerm = $permissions.PSObject.Properties['administration'] -and $permissions.administration -in @('write', 'read')

        # Apps installed against "all" repositories have the largest blast radius.
        $isAllRepos = $app.repository_selection -eq 'all'
        $scopeLabel = if ($auditScope -eq 'organization') { 'org-wide' } else { 'across all of your repositories' }

        if ($isAllRepos -and $hasContentsWrite -and $hasActionsWrite) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed $scopeLabel with both contents:write and actions:write permissions. If this app is compromised, an attacker can modify workflow files and trigger them across every repository the app can reach." `
                -Remediation "Restrict this app to specific repositories and audit whether it needs both contents:write and actions:write. Remove unnecessary permissions following the principle of least privilege." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }
        elseif ($isAllRepos -and ($hasContentsWrite -or $hasActionsWrite)) {
            $writePerm = if ($hasContentsWrite) { 'contents:write' } else { 'actions:write' }
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed $scopeLabel with $writePerm permission. Compromising this app grants write access across every repository the app can reach." `
                -Remediation "Restrict this app to only the repositories that require it. Review whether $writePerm is necessary." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }
        elseif ($isAllRepos) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed $scopeLabel. Even with read-only permissions, installing against all repositories increases the blast radius if the app is compromised." `
                -Remediation 'Consider restricting this app to specific repositories that need it.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasAdminPerm) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' has administration permission. This allows modifying repository settings including branch protection rules." `
                -Remediation "Audit whether this app requires administration permission. Apps with admin access can disable branch protection, enabling direct pushes to protected branches." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }
    }

    if ($findings.Count -eq 0) {
        $scopeWord = if ($auditScope -eq 'organization') { 'organization' } else { 'user account' }
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "All $($appList.Count) GitHub App installation(s) on this $scopeWord have appropriate scoping and permissions." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }
    else {
        foreach ($finding in $findings) { $results.Add($finding) }
    }

    $results.ToArray()
}
