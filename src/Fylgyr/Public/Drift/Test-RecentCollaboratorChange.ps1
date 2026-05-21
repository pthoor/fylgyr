function Test-RecentCollaboratorChange {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168,

        [string]$BaselinePath
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $since = [datetime]::UtcNow.AddHours(-1 * $SinceHours)

    $events = @()
    try {
        $events = @(Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/events?per_page=100" -Token $Token)
    }
    catch {
        Write-Debug "Event fetch failed for '$target': $($_.Exception.Message)"
    }

    $memberEvents = @($events | Where-Object {
        $_.type -eq 'MemberEvent' -and $_.created_at -and ([datetime]$_.created_at) -ge $since
    })

    if ($memberEvents.Count -gt 0) {
        foreach ($memberRecord in $memberEvents) {
            $action = if ($memberRecord.payload -and $memberRecord.payload.action) { [string]$memberRecord.payload.action } else { 'changed' }
            $member = if ($memberRecord.payload -and $memberRecord.payload.member -and $memberRecord.payload.member.login) { [string]$memberRecord.payload.member.login } else { 'unknown' }
            $permission = if ($memberRecord.payload -and $memberRecord.payload.member -and $memberRecord.payload.member.permissions) {
                if ($memberRecord.payload.member.permissions.push -eq $true -or $memberRecord.payload.member.permissions.admin -eq $true) { 'write' } else { 'read' }
            }
            else {
                'unknown'
            }

            $severity = 'Low'
            if ($action -eq 'added' -and $permission -eq 'write') { $severity = 'Medium' }
            elseif ($action -eq 'removed') { $severity = 'Info' }

            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentCollaboratorChange' `
                -Status 'Drift' `
                -Severity $severity `
                -Resource $target `
                -Detail "Collaborator drift detected: '$member' was $action (permission: $permission)." `
                -Remediation 'Validate change intent, enforce least privilege, and remove unexpected collaborator access immediately.' `
                -AttackMapping @('uber-credential-leak') `
                -Target $target `
                -Evidence @{
                    Source = 'events-api'
                    ChangedAt = $memberRecord.created_at
                    ChangedBy = if ($memberRecord.actor) { $memberRecord.actor.login } else { $null }
                    Action = $action
                    Collaborator = $member
                    Permission = $permission
                    EventId = $memberRecord.id
                } `
                -Mode 'Drift'))
        }

        return $results.ToArray()
    }

    $currentCollaborators = @()
    try {
        $collabResponse = @(Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/collaborators?per_page=100&affiliation=all" -Token $Token -AllPages)
        $currentCollaborators = @($collabResponse | ForEach-Object {
            [PSCustomObject]@{
                Login = [string]$_.login
                Permission = if ($_.permissions -and ($_.permissions.push -eq $true -or $_.permissions.admin -eq $true)) { 'write' } else { 'read' }
            }
        } | Sort-Object -Property Login)
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentCollaboratorChange' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed to collect collaborators for baseline diff: $($_.Exception.Message)" `
            -Remediation 'Verify token permission to read collaborators and rerun.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    if (-not $BaselinePath) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentCollaboratorChange' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No recent collaborator events found and no baseline provided. Captured current collaborator snapshot for a future diff.' `
            -Remediation 'Provide -BaselinePath from a previous scan to enable baseline-diff fallback.' `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                To = @{ Collaborators = $currentCollaborators }
                Fidelity = 'Baseline diff has no actor attribution; this run establishes state only.'
                StateSnapshot = @{ Collaborators = $currentCollaborators }
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    try {
        $comparison = Compare-FylgyrBaseline -BaselinePath $BaselinePath -CheckName 'RecentCollaboratorChange' -Resource $target -CurrentSnapshot @{ Collaborators = $currentCollaborators }
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentCollaboratorChange' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed baseline comparison for collaborator drift: $($_.Exception.Message)" `
            -Remediation 'Provide a valid baseline file generated by Invoke-Fylgyr.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $baselineCollaborators = @()
    if ($comparison.BaselineSnapshot -and $comparison.BaselineSnapshot.PSObject.Properties['Collaborators']) {
        $baselineCollaborators = @($comparison.BaselineSnapshot.Collaborators)
    }

    $baselineSet = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $baselineCollaborators) {
        if ($entry.Login) {
            $baselineSet[[string]$entry.Login] = [string]$entry.Permission
        }
    }

    $currentSet = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $currentCollaborators) {
        $currentSet[[string]$entry.Login] = [string]$entry.Permission
    }

    foreach ($login in $currentSet.Keys) {
        if (-not $baselineSet.ContainsKey($login)) {
            $severity = if ($currentSet[$login] -eq 'write') { 'Medium' } else { 'Low' }
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentCollaboratorChange' `
                -Status 'Drift' `
                -Severity $severity `
                -Resource $target `
                -Detail "Collaborator drift detected by baseline diff: '$login' was added with $($currentSet[$login]) access." `
                -Remediation 'Validate onboarding/change request and remove unexpected collaborator access.' `
                -AttackMapping @('uber-credential-leak') `
                -Target $target `
                -Evidence @{
                    Source = 'baseline-diff'
                    From = @{ Collaborators = $baselineCollaborators }
                    To = @{ Collaborators = $currentCollaborators }
                    Collaborator = $login
                    Permission = $currentSet[$login]
                    Fidelity = 'Baseline diff has no actor attribution; validate in GitHub audit logs.'
                    StateSnapshot = @{ Collaborators = $currentCollaborators }
                } `
                -Mode 'Drift'))
        }
    }

    foreach ($login in $baselineSet.Keys) {
        if (-not $currentSet.ContainsKey($login)) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentCollaboratorChange' `
                -Status 'Drift' `
                -Severity 'Info' `
                -Resource $target `
                -Detail "Collaborator drift detected by baseline diff: '$login' was removed." `
                -Remediation 'No action needed if this removal is expected; investigate if unexpected account churn occurred.' `
                -AttackMapping @('uber-credential-leak') `
                -Target $target `
                -Evidence @{
                    Source = 'baseline-diff'
                    From = @{ Collaborators = $baselineCollaborators }
                    To = @{ Collaborators = $currentCollaborators }
                    Collaborator = $login
                    Fidelity = 'Baseline diff has no actor attribution; validate in GitHub audit logs.'
                    StateSnapshot = @{ Collaborators = $currentCollaborators }
                } `
                -Mode 'Drift'))
        }
    }

    if ($results.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentCollaboratorChange' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No collaborator drift detected.' `
            -Remediation 'No action needed.' `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                From = @{ Collaborators = $baselineCollaborators }
                To = @{ Collaborators = $currentCollaborators }
                StateSnapshot = @{ Collaborators = $currentCollaborators }
            } `
            -Mode 'Drift'))
    }

    return $results.ToArray()
}
