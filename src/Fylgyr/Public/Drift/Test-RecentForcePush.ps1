function Test-RecentForcePush {
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
        [int]$SinceHours = 168
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $events = @(Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/events?per_page=100" -Token $Token)
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentForcePush' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $target `
            -Detail "Failed to read repository events for force-push drift detection: $($_.Exception.Message)" `
            -Remediation 'Verify the token has repository read access and rerun.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $repoInfo = $null
    $defaultBranch = 'main'
    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
        if ($repoInfo -and $repoInfo.default_branch) {
            $defaultBranch = [string]$repoInfo.default_branch
        }
    }
    catch {
        Write-Debug "Default branch lookup failed for '$target': $($_.Exception.Message)"
    }

    $since = [datetime]::UtcNow.AddHours(-1 * $SinceHours)
    $forcePushEvents = @($events | Where-Object {
        $_.type -eq 'PushEvent' -and
        $_.created_at -and
        ([datetime]$_.created_at) -ge $since -and
        $_.payload -and
        $_.payload.PSObject.Properties['forced'] -and
        $_.payload.forced -eq $true
    })

    if ($forcePushEvents.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentForcePush' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail "No force-push events detected in the last $SinceHours hour(s)." `
            -Remediation 'No action needed.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    foreach ($pushRecord in $forcePushEvents) {
        $ref = if ($pushRecord.payload -and $pushRecord.payload.ref) { [string]$pushRecord.payload.ref } else { '' }
        $branchName = if ($ref -match '^refs/heads/(.+)$') { $Matches[1] } else { $ref }
        $isDefaultBranch = $branchName -and $branchName -eq $defaultBranch
        $severity = if ($isDefaultBranch) { 'Critical' } else { 'High' }
        $detail = if ($isDefaultBranch) {
            "Force-push drift detected on default branch '$defaultBranch'."
        }
        else {
            "Force-push drift detected on branch '$branchName'."
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentForcePush' `
            -Status 'Drift' `
            -Severity $severity `
            -Resource $target `
            -Detail $detail `
            -Remediation 'Disable force-push on protected branches, inspect the rewritten commits, and validate release/tag integrity.' `
            -AttackMapping @('trivy-tag-poisoning', 'trivy-force-push-main') `
            -Target $target `
            -Evidence @{
                Source    = 'events-api'
                Branch    = $branchName
                ChangedAt = $pushRecord.created_at
                ChangedBy = if ($pushRecord.actor) { $pushRecord.actor.login } else { $null }
                EventId   = $pushRecord.id
            } `
            -Mode 'Drift'))
    }

    return $results.ToArray()
}
