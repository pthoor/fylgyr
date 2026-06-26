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
            if (-not $Repo) {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'Rulesets' `
                    -Status 'Info' `
                    -Severity 'Info' `
                    -Resource $resource `
                    -Detail 'Insufficient permission to read organization rulesets with the current token. This endpoint may require Organization Administration:write for fine-grained PATs.' `
                    -Remediation 'Treat this as advisory if you enforce least privilege. If you need org-level ruleset verification, use a dedicated audit token with Organization Administration:write, or rely on repository-level ruleset checks.' `
                    -Target $resource))
                return $results.ToArray()
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read rulesets.' `
                -Remediation 'Use a fine-grained token with repository Metadata:read for repository rulesets (and Administration:read if you also need legacy tag protection visibility). For organization rulesets, GitHub currently maps GET /orgs/{org}/rulesets to Organization Administration:write. If you use a classic token, include repo + read:org/admin:org scopes. In GitHub Actions, provide this token explicitly via -Token instead of relying on the default GITHUB_TOKEN.' `
                -Target $resource))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Rulesets endpoint returned not found (404). Governance could not be verified from this API response.' `
                -Remediation 'Verify repository/organization access and token permissions, then confirm rulesets support/availability in your GitHub plan and endpoint context.' `
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
    $bypassFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($ruleset in $activeRulesets) {
        if ($ruleset.target -eq 'branch' -and (& $targetsDefaultBranch $ruleset $defaultBranch)) {
            $hasBranchRuleset = $true

            # bypass_actors on an active ruleset lets specific actors skip all rules.
            # Any non-empty bypass list means at least one principal can push directly
            # to the default branch without going through the required controls.
            if ($ruleset.PSObject.Properties['bypass_actors'] -and
                $ruleset.bypass_actors -and
                @($ruleset.bypass_actors).Count -gt 0) {

                $bypassCount = @($ruleset.bypass_actors).Count
                $rulesetName = if ($ruleset.PSObject.Properties['name'] -and $ruleset.name) { [string]$ruleset.name } else { 'unnamed' }

                $bypassFindings.Add((Format-FylgyrResult `
                    -CheckName 'Rulesets' `
                    -Status 'Fail' `
                    -Severity 'High' `
                    -Resource $resource `
                    -Detail "Active branch ruleset '$rulesetName' has $bypassCount bypass actor(s) configured. Bypass actors can push directly to the default branch without satisfying the ruleset's required reviews, status checks, or other controls. A compromised account that holds bypass privilege can merge malicious code without the usual gatekeeping — the same escalation exploited in the xz-utils backdoor and Trivy force-push incidents." `
                    -Remediation "Remove all bypass actors from the '$rulesetName' ruleset in Settings → Rules → Rulesets unless there is a documented and time-limited operational need. Use environment protection rules with required reviewers instead of ruleset bypass for emergency deployments." `
                    -AttackMapping @('xz-utils-backdoor', 'trivy-force-push-main') `
                    -Target $resource))
            }
        }
    }

    if ($bypassFindings.Count -gt 0) {
        foreach ($bf in $bypassFindings) { $results.Add($bf) }
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
        if ($bypassFindings.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Rulesets' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Active rulesets cover branch governance and tag protection.' `
                -Remediation 'No action needed. Keep branch protection and rulesets aligned.' `
                -Target $resource))
        }
        return $results.ToArray()
    }

    if (-not $hasTagProtection) {
        $tagContextDetail = ''
        $repoHasTags = $null
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
                    $repoHasTags = $true
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
                    $repoHasTags = $false
                    $tagContextDetail = ' Repository currently has no tags. Configure tag protection before creating release tags.'
                }
            }
            catch {
                Write-Debug "Failed to enumerate repository tags for '$resource': $($_.Exception.Message)"
            }
        }

        $status = 'Fail'
        $severity = 'High'
        $detail = "No active tag protection found (ruleset target: tag or legacy tag protection). Mutable release tags enable producer-side tag poisoning attacks.$tagContextDetail"
        $remediation = 'Add an active tag-target ruleset (preferred) or legacy tag protection to prevent untrusted tag creation, deletion, and force-pushes. Protect release patterns such as v*.'
        $attackMapping = @('trivy-tag-poisoning', 'actions-cool-issues-helper-compromise')

        if (-not $Repo) {
            $status = 'Warning'
            $severity = 'Medium'
            $detail = 'No active organization-level tag protection ruleset was found. This is a governance gap, but repositories may still enforce tag protection at repo scope.'
            $remediation = 'Add an org-level tag-target ruleset for baseline governance, and verify each release repository has effective tag protection.'
        }

        if ($Repo -and $repoHasTags -eq $false) {
            $status = 'Warning'
            $severity = 'Medium'
            $detail = "No active tag protection found (ruleset target: tag or legacy tag protection). Repository currently has no tags, so immediate tag-poisoning exposure is lower, but the first release tag will be unprotected unless governance is added now."
            $remediation = 'Before creating your first release tag, add an active tag-target ruleset (preferred) or legacy tag protection for patterns such as v*.'
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'Rulesets' `
            -Status $status `
            -Severity $severity `
            -Resource $resource `
            -Detail $detail `
            -Remediation $remediation `
            -AttackMapping $attackMapping `
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
