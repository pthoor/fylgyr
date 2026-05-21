function Test-RecentAppAuthorization {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168,

        [string]$BaselinePath,

        [PSCustomObject[]]$AuditEvents = @()
    )

    $resource = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'User') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization app authorization drift is not applicable." `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $auditLogUsable = $false
    $events = @($AuditEvents)
    if ($events.Count -eq 0) {
        try {
            $events = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
            $auditLogUsable = $true
        }
        catch {
            Write-Debug "Org audit log unavailable for '$resource': $($_.Exception.Message)"
        }
    }
    else {
        $auditLogUsable = $true
    }

    if ($auditLogUsable) {
        $appGrantEvents = @($events | Where-Object {
            $_.action -match 'org_credential_authorization\.grant|oauth_authorization\.create|integration_installation\.create|integration_installation\.add_repository'
        })

        if ($appGrantEvents.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentAppAuthorization' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "No recent app authorization grants detected in the last $SinceHours hour(s)." `
                -Remediation 'No action needed.' `
                -Target $resource `
                -Evidence @{
                    Source = 'audit-log'
                    EventCount = 0
                } `
                -Mode 'Drift'))
            return $results.ToArray()
        }

        foreach ($appGrantRecord in $appGrantEvents) {
            $scopeText = ''
            if ($appGrantRecord.data) {
                $scopeText = ($appGrantRecord.data | ConvertTo-Json -Depth 10 -Compress)
            }

            $hasWriteScope = $scopeText -match '"(write|admin|maintain|all)"|:write|_write'
            $severity = if ($hasWriteScope) { 'High' } else { 'Medium' }
            $appName = if ($appGrantRecord.programmatic_access_type) { [string]$appGrantRecord.programmatic_access_type } elseif ($appGrantRecord.user) { [string]$appGrantRecord.user } else { 'application' }

            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentAppAuthorization' `
                -Status 'Drift' `
                -Severity $severity `
                -Resource $resource `
                -Detail "New app authorization drift detected: '$appName' via action '$($appGrantRecord.action)'." `
                -Remediation 'Review app permission scopes, revoke unexpected grants, and restrict app authorization policy to approved apps only.' `
                -AttackMapping @('github-device-code-phishing', 'github-app-token-theft') `
                -Target $resource `
                -Evidence @{
                    Source = 'audit-log'
                    ChangedAt = $appGrantRecord.created_at
                    ChangedBy = if ($appGrantRecord.actor) { $appGrantRecord.actor } else { $null }
                    Action = $appGrantRecord.action
                    App = $appName
                    HasWriteScope = $hasWriteScope
                    RawData = $appGrantRecord.data
                } `
                -Mode 'Drift'))
        }

        return $results.ToArray()
    }

    $currentInstallations = @()
    try {
        $response = Invoke-GitHubApi -Endpoint "orgs/$Owner/installations?per_page=100" -Token $Token
        if ($response -and $response.PSObject.Properties['installations']) {
            $currentInstallations = @($response.installations | ForEach-Object {
                [PSCustomObject]@{
                    Id = $_.id
                    AppSlug = [string]$_.app_slug
                    TargetType = [string]$_.target_type
                }
            } | Sort-Object -Property Id)
        }
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Audit log unavailable and fallback app installation inventory failed: $($_.Exception.Message)" `
            -Remediation 'Grant admin:org scope for audit log access or provide a baseline with org installation state.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    if (-not $BaselinePath) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Audit log unavailable. Captured current app installation snapshot for baseline diff fallback.' `
            -Remediation 'Provide -BaselinePath on subsequent runs to detect newly authorized apps without audit log coverage.' `
            -Target $resource `
            -Evidence @{
                Source = 'baseline-diff'
                To = @{ Installations = $currentInstallations }
                Fidelity = 'No actor attribution in baseline mode; enable audit log for identity context.'
                StateSnapshot = @{ Installations = $currentInstallations }
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    try {
        $comparison = Compare-FylgyrBaseline -BaselinePath $BaselinePath -CheckName 'RecentAppAuthorization' -Resource $resource -CurrentSnapshot @{ Installations = $currentInstallations }
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed baseline comparison for app authorization drift: $($_.Exception.Message)" `
            -Remediation 'Provide a valid baseline file generated by Invoke-Fylgyr.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $previousInstallations = @()
    if ($comparison.BaselineSnapshot -and $comparison.BaselineSnapshot.PSObject.Properties['Installations']) {
        $previousInstallations = @($comparison.BaselineSnapshot.Installations)
    }

    $previousIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $previousInstallations) {
        if ($item -and $item.PSObject.Properties['Id']) {
            $previousIds.Add([string]$item.Id) | Out-Null
        }
    }

    $newInstalls = @($currentInstallations | Where-Object { -not $previousIds.Contains([string]$_.Id) })
    if ($newInstalls.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No app authorization drift detected in baseline fallback mode.' `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Evidence @{
                Source = 'baseline-diff'
                From = @{ Installations = $previousInstallations }
                To = @{ Installations = $currentInstallations }
                StateSnapshot = @{ Installations = $currentInstallations }
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    foreach ($install in $newInstalls) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentAppAuthorization' `
            -Status 'Drift' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "New organization app installation detected by baseline diff: '$($install.AppSlug)'." `
            -Remediation 'Validate the installation request and app permissions. Revoke unauthorized installations.' `
            -AttackMapping @('github-device-code-phishing', 'github-app-token-theft') `
            -Target $resource `
            -Evidence @{
                Source = 'baseline-diff'
                From = @{ Installations = $previousInstallations }
                To = @{ Installations = $currentInstallations }
                AppSlug = $install.AppSlug
                InstallationId = $install.Id
                Fidelity = 'Baseline diff has no actor attribution; use audit log when available.'
                StateSnapshot = @{ Installations = $currentInstallations }
            } `
            -Mode 'Drift'))
    }

    return $results.ToArray()
}
