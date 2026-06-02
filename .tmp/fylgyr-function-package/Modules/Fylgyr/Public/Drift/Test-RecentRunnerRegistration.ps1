function Test-RecentRunnerRegistration {
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

        [string]$BaselinePath,

        [PSCustomObject[]]$AuditEvents = @()
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $events = @($AuditEvents)
    $auditUsable = $false
    if ($events.Count -eq 0) {
        try {
            $events = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
            $auditUsable = $true
        }
        catch {
            Write-Debug "Audit log unavailable for runner registration drift: $($_.Exception.Message)"
        }
    }
    else {
        $auditUsable = $true
    }

    if ($auditUsable) {
        $runnerEvents = @($events | Where-Object {
            $_.action -match 'runner\.|self_hosted_runner\.|actions_runner\.' -and
            ($_.repo -eq $Repo -or -not $_.repo)
        })

        foreach ($runnerRecord in $runnerEvents) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentRunnerRegistration' `
                -Status 'Drift' `
                -Severity 'High' `
                -Resource $target `
                -Detail "Runner registration drift detected via audit log action '$($runnerRecord.action)'." `
                -Remediation 'Validate runner registration ownership, enforce ephemeral runners, and restrict runner groups to trusted repositories only.' `
                -AttackMapping @('shai-hulud-runner-backdoor', 'praetorian-runner-pivot', 'github-actions-cryptomining') `
                -Target $target `
                -Evidence @{
                    Source = 'audit-log'
                    ChangedAt = $runnerRecord.created_at
                    ChangedBy = if ($runnerRecord.actor) { $runnerRecord.actor } else { $null }
                    Action = $runnerRecord.action
                    Data = $runnerRecord.data
                } `
                -Mode 'Drift'))
        }

        if ($results.Count -gt 0) {
            return $results.ToArray()
        }
    }

    $repoRunners = @()
    $orgRunners = @()
    try {
        $repoRunnerResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/actions/runners" -Token $Token
        if ($repoRunnerResponse -and $repoRunnerResponse.PSObject.Properties['runners']) {
            $repoRunners = @($repoRunnerResponse.runners | ForEach-Object {
                [PSCustomObject]@{
                    Id = $_.id
                    Name = [string]$_.name
                    Ephemeral = if ($_.PSObject.Properties['ephemeral']) { [bool]$_.ephemeral } else { $null }
                    Scope = 'repo'
                }
            } | Sort-Object -Property Id)
        }
    }
    catch {
        Write-Debug "Repo runner snapshot unavailable for '$target': $($_.Exception.Message)"
    }

    try {
        $orgRunnerResponse = Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/runners" -Token $Token
        if ($orgRunnerResponse -and $orgRunnerResponse.PSObject.Properties['runners']) {
            $orgRunners = @($orgRunnerResponse.runners | ForEach-Object {
                [PSCustomObject]@{
                    Id = $_.id
                    Name = [string]$_.name
                    Ephemeral = if ($_.PSObject.Properties['ephemeral']) { [bool]$_.ephemeral } else { $null }
                    Scope = 'org'
                }
            } | Sort-Object -Property Id)
        }
    }
    catch {
        Write-Debug "Org runner snapshot unavailable for '$target': $($_.Exception.Message)"
    }

    $currentSnapshot = [PSCustomObject]@{
        RepoRunners = $repoRunners
        OrgRunners = $orgRunners
    }

    if (-not $BaselinePath) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentRunnerRegistration' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'Captured runner inventory for baseline drift comparison. Provide -BaselinePath to detect newly registered runners.' `
            -Remediation 'Run periodic drift scans with a baseline to detect runner additions promptly.' `
            -AttackMapping @('shai-hulud-runner-backdoor', 'praetorian-runner-pivot', 'github-actions-cryptomining') `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                To = $currentSnapshot
                Fidelity = 'Baseline diff has no actor attribution; rely on audit log where available.'
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    try {
        $comparison = Compare-FylgyrBaseline -BaselinePath $BaselinePath -CheckName 'RecentRunnerRegistration' -Resource $target -CurrentSnapshot $currentSnapshot
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentRunnerRegistration' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed baseline comparison for runner registration drift: $($_.Exception.Message)" `
            -Remediation 'Provide a valid baseline file generated by Invoke-Fylgyr.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $previousRepo = @()
    $previousOrg = @()
    if ($comparison.BaselineSnapshot) {
        if ($comparison.BaselineSnapshot.PSObject.Properties['RepoRunners']) {
            $previousRepo = @($comparison.BaselineSnapshot.RepoRunners)
        }
        if ($comparison.BaselineSnapshot.PSObject.Properties['OrgRunners']) {
            $previousOrg = @($comparison.BaselineSnapshot.OrgRunners)
        }
    }

    $previousIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($runner in @($previousRepo + $previousOrg)) {
        if ($runner -and $runner.PSObject.Properties['Id']) {
            $previousIds.Add([string]$runner.Id) | Out-Null
        }
    }

    $newRunners = @($repoRunners + $orgRunners | Where-Object { -not $previousIds.Contains([string]$_.Id) })
    if ($newRunners.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentRunnerRegistration' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No new runner registrations detected in baseline fallback mode.' `
            -Remediation 'No action needed.' `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                From = $comparison.BaselineSnapshot
                To = $currentSnapshot
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    foreach ($runner in $newRunners) {
        $isEphemeral = $runner.Ephemeral -eq $true
        $severity = if ($isEphemeral) { 'Medium' } else { 'High' }
        $ephemeralNote = if ($isEphemeral) { 'Runner is ephemeral.' } else { 'Runner is persistent (non-ephemeral).' }

        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentRunnerRegistration' `
            -Status 'Drift' `
            -Severity $severity `
            -Resource $target `
            -Detail "New $($runner.Scope)-scope runner detected: '$($runner.Name)'. $ephemeralNote" `
            -Remediation 'Validate runner registration request, isolate network egress, and enforce short-lived ephemeral runner strategy.' `
            -AttackMapping @('shai-hulud-runner-backdoor', 'praetorian-runner-pivot', 'github-actions-cryptomining') `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                From = $comparison.BaselineSnapshot
                To = $currentSnapshot
                RunnerId = $runner.Id
                RunnerName = $runner.Name
                RunnerScope = $runner.Scope
                Ephemeral = $runner.Ephemeral
                Fidelity = 'Baseline diff has no actor attribution; use audit log for identity context.'
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
    }

    return $results.ToArray()
}
