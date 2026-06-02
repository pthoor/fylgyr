function Test-RecentProtectionChange {
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

    $events = @($AuditEvents)
    $auditUsable = $false
    if ($events.Count -eq 0) {
        try {
            $events = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
            $auditUsable = $true
        }
        catch {
            Write-Debug "Audit log unavailable for '$target': $($_.Exception.Message)"
        }
    }
    else {
        $auditUsable = $true
    }

    if ($auditUsable) {
        $protectionEvents = @($events | Where-Object {
            $_.action -match 'protected_branch\.|branch_protection_rule\.|repository_ruleset\.' -and
            ($_.repo -eq $Repo -or -not $_.repo)
        })

        if ($protectionEvents.Count -gt 0) {
            foreach ($protectionRecord in $protectionEvents) {
                $isDefaultBranch = $false
                if ($protectionRecord.data) {
                    $eventData = ($protectionRecord.data | ConvertTo-Json -Depth 12 -Compress)
                    if ($eventData -match [regex]::Escape($defaultBranch) -or $eventData -match 'default') {
                        $isDefaultBranch = $true
                    }
                }

                $severity = if ($isDefaultBranch) { 'High' } else { 'Medium' }
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RecentProtectionChange' `
                    -Status 'Drift' `
                    -Severity $severity `
                    -Resource $target `
                    -Detail "Branch protection/ruleset drift detected from audit log action '$($protectionRecord.action)'." `
                    -Remediation 'Review branch protection and ruleset history, restore strict protection on default branch, and validate recent merges/tags.' `
                    -AttackMapping @('trivy-tag-poisoning', 'trivy-force-push-main') `
                    -Target $target `
                    -Evidence @{
                        Source = 'audit-log'
                        ChangedAt = $protectionRecord.created_at
                        ChangedBy = if ($protectionRecord.actor) { $protectionRecord.actor } else { $null }
                        Action = $protectionRecord.action
                        Data = $protectionRecord.data
                        DefaultBranch = $defaultBranch
                    } `
                    -Mode 'Drift'))
            }

            return $results.ToArray()
        }
    }

    $protection = $null
    $rulesets = @()
    try {
        $protection = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/branches/$defaultBranch/protection" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404') {
            $protection = [PSCustomObject]@{ Missing = $true }
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentProtectionChange' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $target `
                -Detail "Failed to fetch branch protection baseline snapshot: $($_.Exception.Message)" `
                -Remediation 'Verify token permissions (Administration:read or repo) and rerun.' `
                -Target $target `
                -Mode 'Drift'))
            return $results.ToArray()
        }
    }

    try {
        $rulesetResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets" -Token $Token
        if ($rulesetResponse -is [System.Array]) {
            $rulesets = @($rulesetResponse)
        }
        elseif ($rulesetResponse -and $rulesetResponse.PSObject.Properties['rulesets']) {
            $rulesets = @($rulesetResponse.rulesets)
        }
        elseif ($rulesetResponse) {
            $rulesets = @($rulesetResponse)
        }
    }
    catch {
        Write-Debug "Ruleset snapshot unavailable for '$target': $($_.Exception.Message)"
    }

    $currentSnapshot = [PSCustomObject]@{
        DefaultBranch = $defaultBranch
        BranchProtection = $protection
        Rulesets = $rulesets
    }

    if (-not $BaselinePath) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentProtectionChange' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'Audit log unavailable or no matching events. Captured protection snapshot for baseline drift comparison.' `
            -Remediation 'Provide -BaselinePath on subsequent runs to detect weakening via state diff.' `
            -Target $target `
            -Evidence @{
                Source = 'baseline-diff'
                To = $currentSnapshot
                Fidelity = 'Baseline diff has no actor attribution; use audit log for who/when context.'
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    try {
        $comparison = Compare-FylgyrBaseline -BaselinePath $BaselinePath -CheckName 'RecentProtectionChange' -Resource $target -CurrentSnapshot $currentSnapshot
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentProtectionChange' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed baseline comparison for branch protection drift: $($_.Exception.Message)" `
            -Remediation 'Provide a valid baseline file generated by Invoke-Fylgyr.' `
            -Target $target `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    if (-not $comparison.HasBaseline -or -not $comparison.IsChanged) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentProtectionChange' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No branch protection drift detected in baseline fallback mode.' `
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

    $results.Add((Format-FylgyrResult `
        -CheckName 'RecentProtectionChange' `
        -Status 'Drift' `
        -Severity 'High' `
        -Resource $target `
        -Detail "Branch protection drift detected by baseline comparison on default branch '$defaultBranch'." `
        -Remediation 'Review and restore required reviews, status checks, and force-push/deletion protections on the default branch.' `
        -AttackMapping @('trivy-tag-poisoning', 'trivy-force-push-main') `
        -Target $target `
        -Evidence @{
            Source = 'baseline-diff'
            From = $comparison.BaselineSnapshot
            To = $currentSnapshot
            DefaultBranch = $defaultBranch
            Fidelity = 'Baseline diff has no actor attribution; validate source of change in audit log where available.'
            StateSnapshot = $currentSnapshot
        } `
        -Mode 'Drift'))

    return $results.ToArray()
}
