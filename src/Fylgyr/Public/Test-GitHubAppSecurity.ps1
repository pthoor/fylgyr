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

    $resource = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'User') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization-level GitHub App installation audit does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    if ($ownerContext.Type -eq 'Unknown') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Could not resolve owner type for '$Owner'." `
            -Remediation 'Verify owner name and token permissions, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

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
                -Remediation 'Use a fine-grained token with organization Administration:read, or a classic token with admin:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to list organization GitHub App installations: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access.' `
            -Target $resource))
        return $results.ToArray()
    }

    $appList = if ($installationsResponse -and $installationsResponse.PSObject.Properties['installations']) {
        @($installationsResponse.installations)
    }
    elseif ($installationsResponse -is [System.Array]) {
        @($installationsResponse)
    }
    else {
        @()
    }

    if ($appList.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No GitHub App installations found for this organization.' `
            -Remediation 'No action needed.' `
            -Target $resource))
        return $results.ToArray()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($app in $appList) {
        $appName = if ($app.app_slug) { [string]$app.app_slug } else { "installation-$($app.id)" }
        $permissions = $app.permissions
        if (-not $permissions) {
            continue
        }

        $writePermissions = [System.Collections.Generic.List[string]]::new()
        foreach ($property in $permissions.PSObject.Properties) {
            if ($property.Value -eq 'write') {
                $writePermissions.Add("$($property.Name):write")
            }
        }

        $hasContentsWrite = $permissions.PSObject.Properties['contents'] -and $permissions.contents -eq 'write'
        $hasActionsWrite = $permissions.PSObject.Properties['actions'] -and $permissions.actions -eq 'write'
        $hasWorkflowsWrite = $permissions.PSObject.Properties['workflows'] -and $permissions.workflows -eq 'write'
        $hasMembersWrite = $permissions.PSObject.Properties['members'] -and $permissions.members -eq 'write'
        $hasSecretsWrite = $permissions.PSObject.Properties['secrets'] -and $permissions.secrets -eq 'write'
        $hasRepoAdminWrite = $permissions.PSObject.Properties['administration'] -and $permissions.administration -eq 'write'
        $hasOrgAdminWrite = $permissions.PSObject.Properties['organization_administration'] -and $permissions.organization_administration -eq 'write'

        $isAllRepos = $app.repository_selection -eq 'all'
        $isSelectedRepos = $app.repository_selection -eq 'selected'

        if ($hasOrgAdminWrite) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' has organization_administration:write. A stolen installation token can directly alter organization security posture and drive full org takeover." `
                -Remediation 'Remove organization_administration:write unless strictly required, and scope this app to least privilege.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($isAllRepos -and $writePermissions.Count -gt 0) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is installed on all repositories with write permissions ($($writePermissions -join ', ')). Compromise of this app has organization-wide blast radius." `
                -Remediation 'Restrict installation to selected repositories and remove write scopes not required for the app function.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }
        elseif ($isSelectedRepos -and $writePermissions.Count -gt 0) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is scoped to selected repositories with write permissions ($($writePermissions -join ', ')). This is lower blast radius than all-repos installs but should still be periodically reviewed." `
                -Remediation 'Keep selected-repository scoping and review write permissions during access reviews.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($isAllRepos -and $hasContentsWrite -and ($hasActionsWrite -or $hasWorkflowsWrite)) {
            $permPairs = [System.Collections.Generic.List[string]]::new()
            $permPairs.Add('contents:write')
            if ($hasActionsWrite) { $permPairs.Add('actions:write') }
            if ($hasWorkflowsWrite) { $permPairs.Add('workflows:write') }

            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' is all-repos with $($permPairs -join ', '). This enables direct workflow injection and execution across the organization." `
                -Remediation 'Remove one of the write capabilities and restrict install scope to selected repositories.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasMembersWrite -and $hasContentsWrite) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' combines members:write with contents:write. This enables identity-plane and code-plane abuse from one compromised integration." `
                -Remediation 'Split this capability across separate apps or remove one of the write scopes.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasSecretsWrite -and $hasActionsWrite) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' combines secrets:write with actions:write. This creates a direct secret-overwrite and workflow-execution abuse path." `
                -Remediation 'Remove one of these write scopes or isolate responsibilities across separate GitHub Apps.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        if ($hasRepoAdminWrite) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'GitHubAppSecurity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$resource (app: $appName)" `
                -Detail "GitHub App '$appName' has repository administration:write. This can weaken branch protections or repository security controls." `
                -Remediation 'Drop administration:write unless required by app design.' `
                -AttackMapping @('github-app-token-theft') `
                -Target $resource))
        }

        # Installation activity date fields vary by endpoint payload. If an installation
        # has a parseable timestamp older than 90 days, flag as stale for review.
        $activityDate = $null
        foreach ($candidateField in @('updated_at', 'last_used_at', 'created_at')) {
            if ($app.PSObject.Properties[$candidateField] -and $app.$candidateField) {
                try {
                    $activityDate = [DateTime]::Parse([string]$app.$candidateField)
                    break
                }
                catch {
                    Write-Debug "Could not parse '$candidateField' for app '$appName': $($_.Exception.Message)"
                }
            }
        }

        if ($activityDate) {
            $inactiveDays = [int]([DateTime]::UtcNow - $activityDate.ToUniversalTime()).TotalDays
            if ($inactiveDays -gt 90) {
                $findings.Add((Format-FylgyrResult `
                    -CheckName 'GitHubAppSecurity' `
                    -Status 'Warning' `
                    -Severity 'Medium' `
                    -Resource "$resource (app: $appName)" `
                    -Detail "GitHub App '$appName' appears inactive for $inactiveDays days based on installation metadata. Dormant integrations increase attack surface." `
                    -Remediation 'Review whether this app is still needed. Uninstall stale integrations and rotate any related credentials.' `
                    -AttackMapping @('github-app-token-theft') `
                    -Target $resource))
            }
        }
    }

    if ($findings.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'GitHubAppSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "All $($appList.Count) GitHub App installation(s) have acceptable scope and permission posture." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }
    else {
        foreach ($finding in $findings) {
            $results.Add($finding)
        }
    }

    $results.ToArray()
}
