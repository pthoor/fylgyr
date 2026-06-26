function Test-TagProtection {
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
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $rulesets = @(Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets?per_page=100" -Token $Token -AllPages)
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'TagProtection' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail 'Insufficient permissions to read repository rulesets.' `
                -Remediation 'Use a fine-grained token with Administration:read, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'TagProtection' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed to read repository rulesets: $($_.Exception.Message)" `
            -Remediation 'Verify the repository and token, then rerun.' `
            -Target $target))
        return $results.ToArray()
    }

    $activeTagRulesets = @($rulesets | Where-Object {
        $_ -and $_.PSObject.Properties['target'] -and $_.target -eq 'tag' -and
        (-not $_.PSObject.Properties['enforcement'] -or -not $_.enforcement -or $_.enforcement -in @('active', 'evaluate'))
    })

    if ($activeTagRulesets.Count -eq 0) {
        # The absence case (no tag protection at all) is reported by Test-Rulesets /
        # branch-protection coverage; avoid emitting a duplicate failure here.
        $results.Add((Format-FylgyrResult `
            -CheckName 'TagProtection' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No active ruleset targets tags. Without tag protection, an attacker who can push can delete and recreate or force-move a release tag onto a malicious commit, the retagging primitive used in the Trivy tag-poisoning incident.' `
            -Remediation 'Add a ruleset targeting tags (Settings > Rules > Rulesets, target = Tags) that blocks deletion and non-fast-forward updates of release tags.' `
            -AttackMapping @('trivy-tag-poisoning') `
            -Target $target))
        return $results.ToArray()
    }

    # Union the rule types across all active tag rulesets.
    $ruleTypes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ruleset in $activeTagRulesets) {
        $resolved = $ruleset
        $hasRules = $ruleset.PSObject.Properties['rules'] -and $ruleset.rules -and @($ruleset.rules).Count -gt 0
        if (-not $hasRules -and $ruleset.PSObject.Properties['id'] -and $ruleset.id) {
            try {
                $rulesetId = ConvertTo-FylgyrEscapedPathSegment -Value ([string]$ruleset.id)
                $detail = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets/$rulesetId" -Token $Token
                if ($detail -and $detail.PSObject.Properties['rules'] -and $detail.rules) {
                    $resolved = $detail
                }
            }
            catch {
                Write-Debug "Unable to fetch tag ruleset details for id '$($ruleset.id)' on '$target': $($_.Exception.Message)"
            }
        }

        if ($resolved.PSObject.Properties['rules'] -and $resolved.rules) {
            foreach ($rule in @($resolved.rules)) {
                if ($rule -and $rule.PSObject.Properties['type'] -and $rule.type) {
                    [void]$ruleTypes.Add([string]$rule.type)
                }
            }
        }
    }

    $missing = @()
    if (-not $ruleTypes.Contains('deletion')) { $missing += 'deletion' }
    if (-not $ruleTypes.Contains('non_fast_forward')) { $missing += 'non_fast_forward' }

    if ($missing.Count -gt 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'TagProtection' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $target `
            -Detail "A tag ruleset exists but does not enforce: $($missing -join ', '). Tags can therefore still be deleted and recreated or force-moved onto attacker commits - the exact retagging primitive behind the Trivy tag-poisoning incident, where a mutable tag was repointed to a malicious image." `
            -Remediation 'Add both the "Restrict deletions" and "Block force pushes" (non_fast_forward) rules to the tag ruleset so release tags are immutable.' `
            -AttackMapping @('trivy-tag-poisoning', 'actions-cool-issues-helper-compromise') `
            -Target $target))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'TagProtection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'An active tag ruleset blocks tag deletion and non-fast-forward updates, so release tags cannot be silently repointed.' `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
