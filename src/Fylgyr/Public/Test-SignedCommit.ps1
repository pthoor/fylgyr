function Test-SignedCommit {
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

    $defaultBranch = 'main'
    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
        if ($repoInfo.default_branch) {
            $defaultBranch = $repoInfo.default_branch
        }
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommit' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed to retrieve repository info: $($_.Exception.Message)" `
            -Remediation 'Verify the repository exists and the token has contents:read access.' `
            -Target $target))
        return $results.ToArray()
    }

    $resource = "$target (branch: $defaultBranch)"
    $escapedBranch = ConvertTo-FylgyrEscapedPathSegment -Value $defaultBranch

    $signingRemediation = "Enforce signing via a branch ruleset (Settings > Rules > Rulesets, add the 'Require signed commits' rule) or classic branch protection. Low-friction maintainer setup: enable SSH commit signing (git config --global gpg.format ssh; git config --global user.signingkey <ssh-key>; git config --global commit.gpgsign true) and turn on Vigilant Mode so unsigned commits are flagged on your history. For published releases, also sign release tags. See: https://docs.github.com/authentication/managing-commit-signature-verification"

    # Signed-commit enforcement can come from classic branch protection
    # (required_signatures endpoint) OR from a modern branch ruleset carrying a
    # 'required_signatures' rule. This determines the ruleset side and returns
    # one of: 'Enabled', 'NotEnabled', 'Forbidden', 'Unknown'.
    $getRulesetSignatureState = {
        $rulesetsResponse = $null
        try {
            $rulesetsResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets" -Token $Token
        }
        catch {
            $rulesetMsg = $_.Exception.Message
            if ($rulesetMsg -match '403') { return 'Forbidden' }
            if ($rulesetMsg -match '404') { return 'NotEnabled' }
            Write-Debug "Unable to read rulesets for '$target': $rulesetMsg"
            return 'Unknown'
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

        foreach ($ruleset in $rulesets) {
            if (-not $ruleset -or $ruleset.target -ne 'branch') { continue }

            $isActive = (-not $ruleset.PSObject.Properties['enforcement']) -or
                (-not $ruleset.enforcement) -or
                ($ruleset.enforcement -in @('active', 'evaluate'))
            if (-not $isActive) { continue }

            $targetsBranch = $true
            if ($ruleset.PSObject.Properties['conditions'] -and $ruleset.conditions) {
                $conditionsJson = $ruleset.conditions | ConvertTo-Json -Depth 8
                $targetsBranch = ($conditionsJson -match 'DEFAULT_BRANCH') -or
                    ($conditionsJson -match [regex]::Escape("refs/heads/$defaultBranch")) -or
                    ($conditionsJson -match [regex]::Escape($defaultBranch))
            }
            if (-not $targetsBranch) { continue }

            $rules = $null
            if ($ruleset.PSObject.Properties['rules'] -and $ruleset.rules -and @($ruleset.rules).Count -gt 0) {
                $rules = @($ruleset.rules)
            }
            elseif ($ruleset.PSObject.Properties['id'] -and $ruleset.id) {
                try {
                    $rulesetId = ConvertTo-FylgyrEscapedPathSegment -Value ([string]$ruleset.id)
                    $rulesetDetail = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/rulesets/$rulesetId" -Token $Token
                    if ($rulesetDetail -and $rulesetDetail.PSObject.Properties['rules'] -and $rulesetDetail.rules) {
                        $rules = @($rulesetDetail.rules)
                    }
                }
                catch {
                    Write-Debug "Unable to fetch ruleset details for id '$($ruleset.id)' on '$target': $($_.Exception.Message)"
                }
            }

            if ($rules) {
                foreach ($rule in $rules) {
                    if ($rule -and $rule.PSObject.Properties['type'] -and $rule.type -eq 'required_signatures') {
                        return 'Enabled'
                    }
                }
            }
        }

        return 'NotEnabled'
    }

    # Emits the standard "not enforced" result. $rulesetState carries the ruleset
    # side so the wording stays honest when ruleset evaluation was incomplete.
    $addNotEnforced = {
        param([string]$RulesetState)

        $detail = "Branch '$defaultBranch' does not require signed commits. Neither classic branch protection nor an active branch ruleset enforces required_signatures. Signed commits make it harder for an attacker with a stolen credential to impersonate a maintainer, as in the xz-utils backdoor. Only a minority of projects enforce this today, so it is a recommendation rather than a hard failure."
        if ($RulesetState -eq 'Unknown') {
            $detail = "Branch '$defaultBranch' does not require signed commits via classic branch protection, and branch ruleset enforcement could not be fully evaluated. Signed commits make it harder for an attacker with a stolen credential to impersonate a maintainer, as in the xz-utils backdoor."
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommit' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail $detail `
            -Remediation $signingRemediation `
            -AttackMapping @('xz-utils-backdoor') `
            -Target $target))
    }

    $signatures = $null
    try {
        $signatures = Invoke-GitHubApi `
            -Endpoint "repos/$Owner/$Repo/branches/$escapedBranch/protection/required_signatures" `
            -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            # No classic required_signatures setting; fall back to ruleset evaluation.
            $rulesetState = & $getRulesetSignatureState

            if ($rulesetState -eq 'Enabled') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'SignedCommit' `
                    -Status 'Pass' `
                    -Severity 'Info' `
                    -Resource $resource `
                    -Detail "Branch '$defaultBranch' requires signed commits via an active branch ruleset." `
                    -Remediation 'No action needed.' `
                    -Target $target))
                return $results.ToArray()
            }

            if ($rulesetState -eq 'Forbidden') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'SignedCommit' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $resource `
                    -Detail 'Insufficient permissions to read classic required signatures and branch rulesets, so signed-commit enforcement could not be evaluated.' `
                    -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                    -Target $target))
                return $results.ToArray()
            }

            & $addNotEnforced $rulesetState
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SignedCommit' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read required signatures setting.' `
                -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommit' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Unexpected error reading required_signatures: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if ($signatures.PSObject.Properties['enabled'] -and $signatures.enabled -eq $true) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommit' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' requires signed commits." `
            -Remediation 'No action needed.' `
            -Target $target))
        return $results.ToArray()
    }

    # Classic branch protection exists but signing is off; a ruleset may still
    # enforce it, so check before warning.
    $rulesetState = & $getRulesetSignatureState
    if ($rulesetState -eq 'Enabled') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommit' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' requires signed commits via an active branch ruleset." `
            -Remediation 'No action needed.' `
            -Target $target))
        return $results.ToArray()
    }

    & $addNotEnforced $rulesetState
    $results.ToArray()
}
