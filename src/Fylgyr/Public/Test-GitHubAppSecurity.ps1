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

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    $ownerType = $ownerContext.Type

    $installationsResponse = $null
    $auditScope = $null

    if ($ownerType -ne 'User') {
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

        if (-not $ownerContext.TokenMatchesOwner) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "Owner '$Owner' is a personal GitHub account. Auditing GitHub App installations on a user account requires a token belonging to that user; the supplied token belongs to '$($ownerContext.TokenOwner)'. Personal account App audit skipped." `
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
                    -Status 'Info' `
                    -Severity 'Info' `
                    -Resource $resource `
                    -Detail "The /user/installations endpoint requires an OAuth user-to-server token issued by a GitHub App or OAuth App authorization flow. Personal access tokens (classic or fine-grained) are explicitly rejected by GitHub - this is an API ceiling, not a token scope issue. Personal GitHub App installations could not be audited automatically." `
                    -Remediation "Review personal GitHub App installations manually at https://github.com/settings/installations. Automated auditing via PAT is blocked by the GitHub API - the endpoint requires an OAuth user-to-server token." `
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

    # /user/installations returns every installation visible to the token, including
    # those on organisations the user belongs to. Filter to personal-account installs
    # only; org installs are audited via the orgs/{Owner}/installations path.
    if ($auditScope -eq 'user' -and $appList) {
        $appList = @($appList | Where-Object { $_.target_type -eq 'User' })
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

        $hasContentsWrite  = $permissions.PSObject.Properties['contents']       -and $permissions.contents       -eq 'write'
        $hasActionsWrite   = $permissions.PSObject.Properties['actions']         -and $permissions.actions         -eq 'write'
        $hasWorkflowsWrite = $permissions.PSObject.Properties['workflows']       -and $permissions.workflows       -eq 'write'
        $hasAdminPerm      = $permissions.PSObject.Properties['administration']  -and $permissions.administration  -in @('write', 'read')
        $hasSecretsWrite   = $permissions.PSObject.Properties['secrets']         -and $permissions.secrets         -eq 'write'
        $hasPackagesWrite  = $permissions.PSObject.Properties['packages']        -and $permissions.packages        -eq 'write'

        # Apps installed against "all" repositories have the largest blast radius.
        $isAllRepos = $app.repository_selection -eq 'all'
        $scopeLabel = if ($auditScope -eq 'organization') { 'org-wide' } else { 'across all of your repositories' }

        # Critical: contents:write paired with workflow manipulation = full CI injection path.
        # workflows:write targets .github/workflows/ directly; actions:write targets the Actions API.
        if ($isAllRepos -and $hasContentsWrite -and ($hasActionsWrite -or $hasWorkflowsWrite)) {
            $dangerPerms = [System.Collections.Generic.List[string]]::new()
            $dangerPerms.Add('contents:write')
            if ($hasWorkflowsWrite) { $dangerPerms.Add('workflows:write') }
            if ($hasActionsWrite)   { $dangerPerms.Add('actions:write') }
            $permList = $dangerPerms -join ', '
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed $scopeLabel with $permList. A compromised app can inject and trigger malicious workflows across every repository it can reach - the same attack path used in the tj-actions/changed-files and reviewdog supply chain incidents." `
                -Remediation "Restrict this app to specific repositories and remove unnecessary permissions. An app rarely needs both contents:write and workflows:write or actions:write simultaneously." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }
        elseif ($isAllRepos -and ($hasContentsWrite -or $hasActionsWrite -or $hasWorkflowsWrite)) {
            $writePerm = if ($hasContentsWrite) { 'contents:write' } elseif ($hasWorkflowsWrite) { 'workflows:write' } else { 'actions:write' }
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed $scopeLabel with $writePerm. Compromising this app grants write access across every repository the app can reach." `
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
                -Detail "GitHub App '$appName' has administration permission. This allows modifying repository settings including branch protection rules, enabling direct pushes to protected branches." `
                -Remediation "Audit whether this app requires administration permission. Remove it if the app does not need to manage repository settings." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasSecretsWrite) {
            $sev       = if ($isAllRepos) { 'Critical' } else { 'High' }
            $scopeDesc = if ($isAllRepos) { $scopeLabel } else { 'selected repositories' }
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity $sev `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' has secrets:write on $scopeDesc. A compromised app can overwrite or enumerate repository secrets, enabling credential theft - the same root cause as the Codecov and CircleCI breach patterns." `
                -Remediation "Revoke secrets:write unless the app is an authorised secrets manager. Prefer environment-scoped secrets with deployment protection rules over repository-level secrets." `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasPackagesWrite) {
            $sev       = if ($isAllRepos) { 'High' } else { 'Medium' }
            $scopeDesc = if ($isAllRepos) { $scopeLabel } else { 'selected repositories' }
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity $sev `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' has packages:write on $scopeDesc. A compromised app can publish malicious package versions to the GitHub Package Registry, creating a supply chain attack vector for any consumer of those packages." `
                -Remediation "Restrict packages:write to CI/CD apps explicitly responsible for publishing. Verify the publishing workflow is protected by environment protection rules with required reviewers." `
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
