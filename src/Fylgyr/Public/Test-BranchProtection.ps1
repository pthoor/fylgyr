function Test-BranchProtection {
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

    # Determine default branch
    $defaultBranch = 'main'
    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
        $defaultBranch = $repoInfo.default_branch
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $target `
            -Detail "Failed to retrieve repository info: $($_.Exception.Message)" `
            -Remediation 'Verify the repository exists and the token has contents:read access.' `
            -Target $target))
        return $results.ToArray()
    }

    $resource = "$target (branch: $defaultBranch)"

    $isActiveRuleset = {
        param([object]$Ruleset)

        if (-not $Ruleset) { return $false }
        if (-not $Ruleset.PSObject.Properties['enforcement'] -or -not $Ruleset.enforcement) {
            return $true
        }

        return $Ruleset.enforcement -in @('active', 'evaluate')
    }

    $targetsDefaultBranch = {
        param([object]$Ruleset, [string]$BranchName)

        if (-not $Ruleset -or -not $Ruleset.PSObject.Properties['conditions'] -or -not $Ruleset.conditions) {
            return $true
        }

        $conditionsJson = $Ruleset.conditions | ConvertTo-Json -Depth 8
        if ($conditionsJson -match 'DEFAULT_BRANCH' -or $conditionsJson -match [regex]::Escape("refs/heads/$BranchName") -or $conditionsJson -match [regex]::Escape($BranchName)) {
            return $true
        }

        return $false
    }

    $escapedBranch = ConvertTo-FylgyrEscapedPathSegment -Value $defaultBranch
    $protection = $null
    $classicProtectionState = 'Unknown'
    try {
        $protection = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/branches/$escapedBranch/protection" -Token $Token
        $classicProtectionState = 'Available'
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $classicProtectionState = 'NotFound'
        }
        elseif ($msg -match '403') {
            $classicProtectionState = 'Forbidden'
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Unexpected error reading classic branch protection: $($_.Exception.Message)" `
                -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
                -Target $target))
            return $results.ToArray()
        }
    }

    if ($classicProtectionState -ne 'Available') {
        $rulesetsResponse = $null
        try {
            $rulesetsResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets" -Token $Token
        }
        catch {
            $rulesetMessage = $_.Exception.Message
            if ($rulesetMessage -match '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'BranchProtection' `
                    -Status 'Error' `
                    -Severity 'High' `
                    -Resource $resource `
                    -Detail 'Insufficient permissions to read classic branch protection and branch rulesets.' `
                    -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                    -Target $target))
                return $results.ToArray()
            }

            if ($rulesetMessage -match '404') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'BranchProtection' `
                    -Status 'Fail' `
                    -Severity 'High' `
                    -Resource $resource `
                    -Detail "Branch '$defaultBranch' has no classic branch protection and no accessible branch rulesets." `
                    -Remediation 'Enable branch protection in Settings → Branches or add an active branch ruleset in Settings → Rules → Rulesets.' `
                    -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
                    -Target $target))
                return $results.ToArray()
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Unexpected error reading branch rulesets: $rulesetMessage" `
                -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
                -Target $target))
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

        $activeBranchRulesets = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($ruleset in $rulesets) {
            if ($ruleset.target -eq 'branch' -and (& $isActiveRuleset $ruleset) -and (& $targetsDefaultBranch $ruleset $defaultBranch)) {
                $activeBranchRulesets.Add($ruleset)
            }
        }

        if ($classicProtectionState -eq 'Forbidden') {
            $rulesetContext = if ($activeBranchRulesets.Count -gt 0) {
                "Detected $($activeBranchRulesets.Count) active branch ruleset(s) for '$defaultBranch', but classic branch protection could not be read."
            }
            else {
                "No active branch rulesets targeting '$defaultBranch' were readable."
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Insufficient permissions to fully evaluate branch protection (classic branch protection endpoint returned 403). $rulesetContext" `
                -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        if ($activeBranchRulesets.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' has no classic branch protection and no active branch ruleset targeting it." `
                -Remediation 'Enable branch protection in Settings → Branches or add an active branch ruleset targeting the default branch in Settings → Rules → Rulesets.' `
                -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
                -Target $target))
            return $results.ToArray()
        }

        $resolvedBranchRulesets = [System.Collections.Generic.List[PSCustomObject]]::new()
        $unresolvedRulesetCount = 0
        foreach ($ruleset in $activeBranchRulesets) {
            $resolvedRuleset = $ruleset
            $hasRulesOnListResponse = $ruleset.PSObject.Properties['rules'] -and $ruleset.rules -and @($ruleset.rules).Count -gt 0

            if (-not $hasRulesOnListResponse -and $ruleset.PSObject.Properties['id'] -and $ruleset.id) {
                try {
                    $rulesetId = ConvertTo-FylgyrEscapedPathSegment -Value ([string]$ruleset.id)
                    $rulesetDetail = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets/$rulesetId" -Token $Token
                    if ($rulesetDetail -and $rulesetDetail.PSObject.Properties['rules'] -and $rulesetDetail.rules -and @($rulesetDetail.rules).Count -gt 0) {
                        $resolvedRuleset = $rulesetDetail
                    }
                }
                catch {
                    Write-Debug "Unable to fetch ruleset details for id '$($ruleset.id)' on '$target': $($_.Exception.Message)"
                }
            }

            $hasResolvedRules = $resolvedRuleset.PSObject.Properties['rules'] -and $resolvedRuleset.rules -and @($resolvedRuleset.rules).Count -gt 0
            if (-not $hasResolvedRules) {
                $unresolvedRulesetCount++
            }

            $resolvedBranchRulesets.Add($resolvedRuleset)
        }

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $ruleTypes = [System.Collections.Generic.List[string]]::new()
        $pullRequestRules = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($ruleset in $resolvedBranchRulesets) {
            if (-not $ruleset.PSObject.Properties['rules'] -or $null -eq $ruleset.rules) {
                continue
            }

            foreach ($rule in @($ruleset.rules)) {
                if (-not $rule -or -not $rule.PSObject.Properties['type']) {
                    continue
                }

                $ruleTypes.Add([string]$rule.type)
                if ($rule.type -eq 'pull_request') {
                    $pullRequestRules.Add($rule)
                }
            }
        }

        if ($ruleTypes.Count -eq 0 -and $unresolvedRulesetCount -gt 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' was found, but its rule definitions could not be retrieved for evaluation." `
                -Remediation 'Ensure the token has Administration:read on the repository and rerun the scan.' `
                -Target $target))
            return $results.ToArray()
        }

        $hasNonFastForwardRule = $ruleTypes -contains 'non_fast_forward'
        if (-not $hasNonFastForwardRule) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' does not block non-fast-forward updates (force-push equivalent)." `
                -Remediation 'Add the non-fast-forward rule to the active branch ruleset.' `
                -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
                -Target $target))
        }

        $hasDeletionRule = $ruleTypes -contains 'deletion'
        if (-not $hasDeletionRule) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' does not block branch deletion." `
                -Remediation 'Add the deletion rule to the active branch ruleset.' `
                -AttackMapping @('trivy-force-push-main') `
                -Target $target))
        }

        if ($pullRequestRules.Count -eq 0) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' does not require pull requests before merging." `
                -Remediation 'Add a pull_request rule that requires pull request review before merge.' `
                -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
                -Target $target))
        }
        else {
            $requiresApprover = $false
            $dismissesStaleReviews = $false

            foreach ($pullRequestRule in $pullRequestRules) {
                if (-not $pullRequestRule.PSObject.Properties['parameters'] -or -not $pullRequestRule.parameters) {
                    continue
                }

                $pullRequestParameters = $pullRequestRule.parameters
                if ($pullRequestParameters.PSObject.Properties['required_approving_review_count']) {
                    $requiredApprovals = [int]$pullRequestParameters.required_approving_review_count
                    if ($requiredApprovals -ge 1) {
                        $requiresApprover = $true
                    }
                }

                if ($pullRequestParameters.PSObject.Properties['dismiss_stale_reviews_on_push'] -and $pullRequestParameters.dismiss_stale_reviews_on_push -eq $true) {
                    $dismissesStaleReviews = $true
                }
            }

            if (-not $requiresApprover) {
                $findings.Add((Format-FylgyrResult `
                    -CheckName 'BranchProtection' `
                    -Status 'Fail' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail "Active branch ruleset for '$defaultBranch' allows 0 approving reviews." `
                    -Remediation 'Set required approving review count to at least 1 in the pull_request ruleset configuration.' `
                    -AttackMapping @('trivy-force-push-main') `
                    -Target $target))
            }

            if (-not $dismissesStaleReviews) {
                $findings.Add((Format-FylgyrResult `
                    -CheckName 'BranchProtection' `
                    -Status 'Fail' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail "Active branch ruleset for '$defaultBranch' does not dismiss stale pull request reviews when new commits are pushed." `
                    -Remediation "Enable stale review dismissal (dismiss_stale_reviews_on_push) in the pull_request ruleset." `
                    -AttackMapping @('trivy-force-push-main') `
                    -Target $target))
            }
        }

        # Bypass actors that can skip the ruleset outside pull requests
        $alwaysBypassActorCount = 0
        foreach ($ruleset in $resolvedBranchRulesets) {
            if (-not $ruleset.PSObject.Properties['bypass_actors'] -or -not $ruleset.bypass_actors) {
                continue
            }

            foreach ($bypassActor in @($ruleset.bypass_actors)) {
                if (-not $bypassActor) {
                    continue
                }

                $bypassMode = if ($bypassActor.PSObject.Properties['bypass_mode'] -and $bypassActor.bypass_mode) {
                    [string]$bypassActor.bypass_mode
                }
                else {
                    'always'
                }

                if ($bypassMode -ne 'pull_request') {
                    $alwaysBypassActorCount++
                }
            }
        }

        if ($alwaysBypassActorCount -gt 0) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' grants $alwaysBypassActorCount bypass actor(s) the ability to bypass protections entirely (bypass_mode 'always'). Each bypass actor is an account, team, or app whose compromise defeats the whole ruleset with a direct push." `
                -Remediation "Remove bypass actors from the ruleset, or restrict them to bypass_mode 'pull_request' so a reviewed pull request is still required." `
                -AttackMapping @('trivy-force-push-main', 'dropbox-github-breach') `
                -Target $target))
        }

        $hasStatusChecksRule = $ruleTypes -contains 'required_status_checks'
        if (-not $hasStatusChecksRule) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Active branch ruleset for '$defaultBranch' does not require status checks before merge." `
                -Remediation 'Add a required_status_checks rule with CI contexts.' `
                -AttackMapping @('codecov-bash-uploader') `
                -Target $target))
        }

        if ($findings.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' is protected via active branch ruleset controls." `
                -Remediation 'No action needed.' `
                -Target $target))
        }
        else {
            foreach ($finding in $findings) { $results.Add($finding) }
        }

        return $results.ToArray()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Force push allowed
    if (-not $protection.PSObject.Properties['allow_force_pushes'] -or $null -eq $protection.allow_force_pushes) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' force-push setting could not be evaluated (property missing from API response)." `
            -Remediation 'Verify the branch protection rule exposes the force-push setting and that the token has sufficient access to read it.' `
            -Target $target))
    }
    elseif ($protection.allow_force_pushes.enabled -eq $true) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' allows force pushes." `
            -Remediation "Disable force pushes in Settings → Branches → Branch protection rules." `
            -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
            -Target $target))
    }

    # Admins exempt from protection
    if (-not $protection.PSObject.Properties['enforce_admins'] -or
        $null -eq $protection.enforce_admins -or
        $protection.enforce_admins.enabled -ne $true) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' does not apply protection rules to administrators (enforce_admins is disabled). A single compromised admin account can push directly to the default branch, bypassing every review and status-check requirement - the path attackers take after phishing or stealing maintainer credentials." `
            -Remediation "Enable 'Do not allow bypassing the above settings' in Settings → Branches so administrators are subject to the same protection rules." `
            -AttackMapping @('trivy-force-push-main', 'dropbox-github-breach') `
            -Target $target))
    }

    # Deletions allowed
    if ($protection.PSObject.Properties['allow_deletions'] -and $protection.allow_deletions.enabled -eq $true) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' allows deletion." `
            -Remediation "Disable branch deletion in Settings → Branches → Branch protection rules." `
            -AttackMapping @('trivy-force-push-main') `
            -Target $target))
    }

    # No required PR reviews
    if (-not $protection.PSObject.Properties['required_pull_request_reviews'] -or
        $null -eq $protection.required_pull_request_reviews) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' does not require pull request reviews before merging." `
            -Remediation "Enable required pull request reviews with at least 1 approver in Settings → Branches." `
            -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
            -Target $target))
    }
    else {
        $prReviews = $protection.required_pull_request_reviews
        if ($prReviews.required_approving_review_count -eq 0) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' requires pull request reviews but allows 0 approvers." `
                -Remediation "Set required approving review count to at least 1 in Settings → Branches." `
                -AttackMapping @('trivy-force-push-main') `
                -Target $target))
        }

        if (-not $prReviews.dismiss_stale_reviews) {
            $findings.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' does not dismiss stale pull request reviews when new commits are pushed." `
                -Remediation "Enable 'Dismiss stale pull request approvals when new commits are pushed' in Settings → Branches." `
                -AttackMapping @('trivy-force-push-main') `
                -Target $target))
        }
    }

    # No required status checks
    if (-not $protection.PSObject.Properties['required_status_checks'] -or
        $null -eq $protection.required_status_checks) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' does not require status checks to pass before merging." `
            -Remediation "Enable required status checks (e.g., CI) in Settings → Branches." `
            -AttackMapping @('codecov-bash-uploader') `
            -Target $target))
    }

    # Enforce admins: if admins can bypass branch protection, a single compromised
    # admin account can push directly to the default branch without review.
    if ($protection.PSObject.Properties['enforce_admins'] -and
        $protection.enforce_admins -and
        $protection.enforce_admins.PSObject.Properties['enabled'] -and
        $protection.enforce_admins.enabled -ne $true) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' does not enforce protection rules for administrators. A single compromised admin account can bypass all branch protection rules and push directly to the default branch without review — the exact escalation path in the xz-utils social-engineering attack and broad maintainer-account compromise patterns." `
            -Remediation "Enable 'Include administrators' (enforce_admins) in Settings → Branches → Branch protection rules. Alternatively, migrate to branch rulesets, which enforce protection consistently for all users including owners." `
            -AttackMapping @('xz-utils-backdoor', 'codecov-bash-uploader') `
            -Target $target))
    }

    if ($findings.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' has adequate protection rules configured." `
            -Remediation 'No action needed.' `
            -Target $target))
    }
    else {
        foreach ($finding in $findings) { $results.Add($finding) }
    }

    $results.ToArray()
}
