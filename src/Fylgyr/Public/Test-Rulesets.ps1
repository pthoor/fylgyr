function Test-Rulesets {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public check name follows project check contract.')]
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = if ($Repo) { "$Owner/$Repo" } else { "org/$Owner" }

    $isActiveRuleset = {
        param([object]$Ruleset)

        if (-not $Ruleset) { return $false }
        if (-not $Ruleset.PSObject.Properties['enforcement'] -or -not $Ruleset.enforcement) {
            return $true
        }

        return $Ruleset.enforcement -in @('active', 'evaluate')
    }

    $targetsDefaultBranch = {
        param([object]$Ruleset, [string]$DefaultBranch)

        if (-not $Ruleset -or -not $Ruleset.PSObject.Properties['conditions'] -or -not $Ruleset.conditions) {
            return $true
        }

        $conditionsJson = $Ruleset.conditions | ConvertTo-Json -Depth 8
        if ($conditionsJson -match 'DEFAULT_BRANCH' -or $conditionsJson -match [regex]::Escape($DefaultBranch)) {
            return $true
        }

        return $false
    }

    if (-not $Repo) {
        $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
        if ($ownerContext.Type -eq 'User') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "Owner '$Owner' is a personal account. Organization rulesets audit does not apply." `
                -Remediation 'No action needed. Run this check against an organization owner.' `
                -Target $resource))
            return $results.ToArray()
        }
    }

    $defaultBranch = 'main'
    if ($Repo) {
        try {
            $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
            if ($repoInfo -and $repoInfo.PSObject.Properties['default_branch'] -and $repoInfo.default_branch) {
                $defaultBranch = [string]$repoInfo.default_branch
            }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Failed to read repository default branch before ruleset evaluation: $($_.Exception.Message)" `
                -Remediation 'Verify repository access and token scope, then rerun.' `
                -Target $resource))
            return $results.ToArray()
        }
    }

    $endpoint = if ($Repo) { "repos/$Owner/$Repo/rulesets" } else { "orgs/$Owner/rulesets" }
    try {
        $rulesetsResponse = Invoke-GitHubApi -Endpoint $endpoint -Token $Token
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read rulesets.' `
                -Remediation 'Use a fine-grained token with repository/organization Administration:read, or a classic token with repo + read:org/admin:org scopes.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Rulesets endpoint returned not found. Modern branch/tag governance may not be configured.' `
                -Remediation 'Enable GitHub rulesets for branch and tag protection, and keep branch protection enabled as complementary control.' `
                -AttackMapping @('trivy-force-push-main') `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'Rulesets' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to evaluate rulesets: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and endpoint access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $rulesets = if ($rulesetsResponse -is [System.Array]) {
        @($rulesetsResponse)
    }
    elseif ($rulesetsResponse -and $rulesetsResponse.PSObject.Properties['rulesets']) {
        @($rulesetsResponse.rulesets)
    }
    elseif ($rulesetsResponse) {
        @($rulesetsResponse)
    }
    else {
        @()
    }

    $activeRulesets = @($rulesets | Where-Object { & $isActiveRuleset $_ })

    $hasBranchRuleset = $false
    foreach ($ruleset in $activeRulesets) {
        if ($ruleset.target -eq 'branch' -and (& $targetsDefaultBranch $ruleset $defaultBranch)) {
            $hasBranchRuleset = $true
            break
        }
    }

    $hasTagRuleset = @($activeRulesets | Where-Object { $_.target -eq 'tag' }).Count -gt 0

    $hasLegacyTagProtection = $false
    if ($Repo) {
        try {
            $tagProtection = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/tags/protection" -Token $Token
            if ($tagProtection -is [System.Array]) {
                $hasLegacyTagProtection = $tagProtection.Count -gt 0
            }
        }
        catch {
            $tagMsg = $_.Exception.Message
            if ($tagMsg -notmatch '404') {
                Write-Debug "Legacy tag protection check failed for '$resource': $tagMsg"
            }
        }
    }

    $hasTagProtection = $hasTagRuleset -or $hasLegacyTagProtection

    if ($hasBranchRuleset -and $hasTagProtection) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'Rulesets' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Active rulesets cover branch governance and tag protection.' `
            -Remediation 'No action needed. Keep branch protection and rulesets aligned.' `
            -Target $resource))
        return $results.ToArray()
    }

    if (-not $hasTagProtection) {
        $tagContextDetail = ''
        if ($Repo) {
            try {
                $repoTagsResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/tags?per_page=100" -Token $Token
                $repoTags = if ($repoTagsResponse -is [System.Array]) {
                    @($repoTagsResponse)
                }
                elseif ($repoTagsResponse) {
                    @($repoTagsResponse)
                }
                else {
                    @()
                }

                if ($repoTags.Count -gt 0) {
                    $sampleTagNames = [System.Collections.Generic.List[string]]::new()
                    foreach ($repoTag in $repoTags) {
                        if ($sampleTagNames.Count -ge 3) { break }
                        if ($repoTag -and $repoTag.PSObject.Properties['name'] -and $repoTag.name) {
                            $sampleTagNames.Add([string]$repoTag.name)
                        }
                    }

                    $sampleText = if ($sampleTagNames.Count -gt 0) {
                        " Sample tags: $($sampleTagNames -join ', ')."
                    }
                    else {
                        ''
                    }

                    $tagContextDetail = " Repository has tags (first-page sample from tags API).$sampleText"
                }
                else {
                    $tagContextDetail = ' Repository currently has no tags. Configure tag protection before creating release tags.'
                }
            }
            catch {
                Write-Debug "Failed to enumerate repository tags for '$resource': $($_.Exception.Message)"
            }
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'Rulesets' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "No active tag protection found (ruleset target: tag or legacy tag protection). Mutable release tags enable producer-side tag poisoning attacks.$tagContextDetail" `
            -Remediation 'Add an active tag-target ruleset (preferred) or legacy tag protection to prevent untrusted tag creation, deletion, and force-pushes. Protect release patterns such as v*.' `
            -AttackMapping @('trivy-tag-poisoning', 'actions-cool-issues-helper-compromise') `
            -Target $resource))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'Rulesets' `
        -Status 'Warning' `
        -Severity 'Medium' `
        -Resource $resource `
        -Detail 'Tag protection exists, but no active branch ruleset targeting the default branch was detected. Rulesets should complement branch protection for modern governance.' `
        -Remediation 'Add a branch-target ruleset for the default branch, and keep classic branch protection controls enabled.' `
        -AttackMapping @('trivy-force-push-main') `
        -Target $resource))

    $results.ToArray()
}
