function Test-RecentTokenExposure {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 168)]
        [int]$CorrelationWindowHours = 24,

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
            -CheckName 'RecentTokenExposure' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization token exposure correlation is not applicable." `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $events = @($AuditEvents)
    $auditUsable = $false
    if ($events.Count -eq 0) {
        try {
            $events = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
            $auditUsable = $true
        }
        catch {
            Write-Debug "Audit log unavailable for token exposure check: $($_.Exception.Message)"
        }
    }
    else {
        $auditUsable = $true
    }

    if ($auditUsable) {
        $tokenRiskEvents = @($events | Where-Object {
            $_.action -match 'org_credential_authorization\.|oauth_authorization\.|token\.|pat\.|integration_installation\.'
        })

        $repoAccessEvents = @($events | Where-Object {
            $_.action -match 'repo\.access|repo\.download|git\.clone|git\.archive|repo\.export|repo\.transfer'
        })

        if ($tokenRiskEvents.Count -eq 0 -and $repoAccessEvents.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentTokenExposure' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "No token-risk or correlated repository-access burst signals detected in the last $SinceHours hour(s)." `
                -Remediation 'No action needed.' `
                -Target $resource `
                -Evidence @{
                    Source = 'audit-log'
                    TokenEventCount = 0
                    RepoAccessBurstCount = 0
                    CorrelationWindowHours = $CorrelationWindowHours
                } `
                -Mode 'Drift'))
            return $results.ToArray()
        }

        $riskByActor = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($riskRecord in $tokenRiskEvents) {
            $actor = if ($riskRecord.actor) { [string]$riskRecord.actor } else { 'unknown' }
            if (-not $riskByActor.ContainsKey($actor)) {
                $riskByActor[$actor] = 0
            }
            $riskByActor[$actor]++
        }

        $burstByActor = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($accessRecord in $repoAccessEvents) {
            $actor = if ($accessRecord.actor) { [string]$accessRecord.actor } else { 'unknown' }
            if (-not $burstByActor.ContainsKey($actor)) {
                $burstByActor[$actor] = 0
            }
            $burstByActor[$actor]++
        }

        $allActors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($actor in $riskByActor.Keys) { $allActors.Add($actor) | Out-Null }
        foreach ($actor in $burstByActor.Keys) { $allActors.Add($actor) | Out-Null }

        foreach ($actor in $allActors) {
            $tokenCount = if ($riskByActor.ContainsKey($actor)) { $riskByActor[$actor] } else { 0 }
            $burstCount = if ($burstByActor.ContainsKey($actor)) { $burstByActor[$actor] } else { 0 }

            $severity = 'Medium'
            if ($tokenCount -gt 0 -and $burstCount -ge 5) {
                $severity = 'Critical'
            }
            elseif ($tokenCount -gt 0 -and $burstCount -gt 0) {
                $severity = 'High'
            }
            elseif ($tokenCount -ge 2) {
                $severity = 'High'
            }

            if ($tokenCount -eq 0 -and $burstCount -lt 8) {
                continue
            }

            $detail = if ($tokenCount -gt 0 -and $burstCount -gt 0) {
                "Token exposure drift chain detected for actor '$actor': $tokenCount token-risk event(s) and $burstCount repository-access event(s)."
            }
            elseif ($tokenCount -gt 0) {
                "Token-risk drift detected for actor '$actor': $tokenCount token-related event(s) without confirmed access burst."
            }
            else {
                "Repository access burst detected for actor '$actor' ($burstCount events). Correlated token-risk events were not observed in the same window."
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentTokenExposure' `
                -Status 'Drift' `
                -Severity $severity `
                -Resource $resource `
                -Detail $detail `
                -Remediation 'Investigate actor session history, revoke suspicious credentials, and rotate sensitive secrets/tokens across impacted repositories.' `
                -AttackMapping @('uber-credential-leak', 'github-device-code-phishing', 'committed-credentials-exposure') `
                -Target $resource `
                -Evidence @{
                    Source = 'audit-log'
                    Actor = $actor
                    TokenEventCount = $tokenCount
                    RepoAccessBurstCount = $burstCount
                    CorrelationWindowHours = $CorrelationWindowHours
                } `
                -Mode 'Drift'))
        }

        if ($results.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentTokenExposure' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Token-related events observed, but no correlation pattern met drift thresholds.' `
                -Remediation 'Continue monitoring and tune thresholds for your environment.' `
                -Target $resource `
                -Evidence @{
                    Source = 'audit-log'
                    TokenEventCount = $tokenRiskEvents.Count
                    RepoAccessBurstCount = $repoAccessEvents.Count
                    CorrelationWindowHours = $CorrelationWindowHours
                } `
                -Mode 'Drift'))
        }

        return $results.ToArray()
    }

    $patPolicy = $null
    $oauthPolicy = $null
    try {
        $patPolicy = Invoke-GitHubApi -Endpoint "orgs/$Owner/personal-access-token-requests" -Token $Token
    }
    catch {
        Write-Debug "PAT policy fallback endpoint unavailable: $($_.Exception.Message)"
    }

    try {
        $oauthPolicy = Invoke-GitHubApi -Endpoint "orgs/$Owner/settings/billing/actions" -Token $Token
    }
    catch {
        Write-Debug "OAuth policy fallback endpoint unavailable: $($_.Exception.Message)"
    }

    $currentSnapshot = [PSCustomObject]@{
        PatPolicy = $patPolicy
        OAuthPolicy = $oauthPolicy
    }

    if (-not $BaselinePath) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentTokenExposure' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Audit log unavailable. Captured current token-governance posture for baseline fallback comparison.' `
            -Remediation 'Provide -BaselinePath and enable org audit log access for full token exposure chain detection.' `
            -Target $resource `
            -Evidence @{
                Source = 'baseline-diff'
                To = $currentSnapshot
                Fidelity = 'Baseline fallback detects governance posture drift, not token usage events.'
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    try {
        $comparison = Compare-FylgyrBaseline -BaselinePath $BaselinePath -CheckName 'RecentTokenExposure' -Resource $resource -CurrentSnapshot $currentSnapshot
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentTokenExposure' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed baseline comparison for token-governance drift: $($_.Exception.Message)" `
            -Remediation 'Provide a valid baseline file generated by Invoke-Fylgyr.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    if (-not $comparison.HasBaseline -or -not $comparison.IsChanged) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentTokenExposure' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No token-governance drift detected in baseline fallback mode.' `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Evidence @{
                Source = 'baseline-diff'
                From = $comparison.BaselineSnapshot
                To = $currentSnapshot
                CorrelationWindowHours = $CorrelationWindowHours
                StateSnapshot = $currentSnapshot
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'RecentTokenExposure' `
        -Status 'Drift' `
        -Severity 'Medium' `
        -Resource $resource `
        -Detail 'Token-governance drift detected via baseline fallback (policy/configuration changed). Audit log correlation is unavailable.' `
        -Remediation 'Review PAT/OAuth policy changes, re-enable restrictive defaults, and enable audit log access for actor-level correlation.' `
        -AttackMapping @('uber-credential-leak', 'github-device-code-phishing', 'committed-credentials-exposure') `
        -Target $resource `
        -Evidence @{
            Source = 'baseline-diff'
            From = $comparison.BaselineSnapshot
            To = $currentSnapshot
            TokenEventCount = 0
            RepoAccessBurstCount = 0
            CorrelationWindowHours = $CorrelationWindowHours
            Fidelity = 'No actor attribution or usage burst correlation without audit log.'
            StateSnapshot = $currentSnapshot
        } `
        -Mode 'Drift'))

    return $results.ToArray()
}
