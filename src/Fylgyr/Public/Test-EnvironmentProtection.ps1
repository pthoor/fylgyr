function Test-EnvironmentProtection {
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
        $response = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/environments" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'EnvironmentProtection' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'No deployment environments defined on this repository.' `
                -Remediation 'No action needed. If you later add deployment environments, configure required reviewers and wait timers.' `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'EnvironmentProtection' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail 'Insufficient permissions to list deployment environments.' `
                -Remediation 'Use a fine-grained token with Actions:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'EnvironmentProtection' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Unexpected error reading environments: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    $environments = @()
    if ($response -and $response.PSObject.Properties['environments'] -and $response.environments) {
        $environments = @($response.environments)
    }

    if ($environments.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'EnvironmentProtection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No deployment environments defined on this repository.' `
            -Remediation 'No action needed. If you later add deployment environments, configure required reviewers and wait timers.' `
            -Target $target))
        return $results.ToArray()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($env in $environments) {
        $envName = $env.name
        $envResource = "$target (environment: $envName)"

        $hasRequiredReviewers = $false
        $hasWaitTimer = $false
        $hasBranchPolicy = $false
        $reviewerCount = 0

        if ($env.protection_rules) {
            foreach ($rule in $env.protection_rules) {
                if ($rule.type -eq 'required_reviewers' -and $rule.reviewers -and $rule.reviewers.Count -gt 0) {
                    $hasRequiredReviewers = $true
                    $reviewerCount = $rule.reviewers.Count
                }
                if ($rule.type -eq 'wait_timer' -and $rule.wait_timer -gt 0) {
                    $hasWaitTimer = $true
                }
            }
        }

        if ($env.PSObject.Properties['deployment_branch_policy'] -and $env.deployment_branch_policy) {
            $hasBranchPolicy = $true
        }

        $preventSelfReview = $false
        if ($env.PSObject.Properties['prevent_self_review'] -and $env.prevent_self_review -eq $true) {
            $preventSelfReview = $true
        }

        if (-not $hasRequiredReviewers) {
            $severity = 'High'
            $detail = "Environment '$envName' has no required reviewers. Deployments can proceed without human approval, turning a compromised PR or workflow into a direct path to this environment."
            if (-not $hasWaitTimer) {
                $detail += ' No wait timer is configured either, so there is no delay window for manual intervention.'
            }
            if (-not $hasBranchPolicy) {
                $detail += ' No deployment branch policy is set - any ref can deploy to this environment.'
            }

            $findings.Add((Format-FylgyrResult `
                -CheckName 'EnvironmentProtection' `
                -Status 'Fail' `
                -Severity $severity `
                -Resource $envResource `
                -Detail $detail `
                -Remediation "Add at least one required reviewer to the '$envName' environment in Settings > Environments. For production, also configure a wait timer and a deployment branch policy restricting which refs can deploy." `
                -AttackMapping @('unauthorized-env-deployment', 'prt-scan-ai-automated') `
                -Target $target))
        }
        else {
            # Reviewer(s) are required. Now check self-review prevention. With
            # only one reviewer configured, that reviewer could plausibly be
            # whoever triggers the deployment, in which case enabling
            # prevent-self-review would deadlock it - so downgrade to Warning.
            # Two or more reviewers means the gate is achievable without that
            # risk, so keep it a hard Fail.
            if (-not $preventSelfReview) {
                $selfReviewStatus = if ($reviewerCount -le 1) { 'Warning' } else { 'Fail' }
                $selfReviewSeverity = if ($reviewerCount -le 1) { 'Medium' } else { 'High' }
                $singleReviewerNote = if ($reviewerCount -le 1) {
                    ' Only one reviewer is configured for this environment; if that reviewer is also whoever triggers the deployment, enabling prevent-self-review would leave no one else available to approve it.'
                }
                else { '' }

                $findings.Add((Format-FylgyrResult `
                    -CheckName 'EnvironmentProtection' `
                    -Status $selfReviewStatus `
                    -Severity $selfReviewSeverity `
                    -Resource $envResource `
                    -Detail "Environment '$envName' has required reviewers but does not prevent self-review. The person who triggers the deployment can also approve it, letting a single compromised or socially-engineered account bypass the reviewer gate.$singleReviewerNote" `
                    -Remediation "Enable 'Prevent self-review' in Settings > Environments > '$envName' so that the person who triggered the deployment cannot also approve it." `
                    -AttackMapping @('unauthorized-env-deployment', 'xz-utils-backdoor') `
                    -Target $target))
            }

            if (-not $hasBranchPolicy) {
                $findings.Add((Format-FylgyrResult `
                    -CheckName 'EnvironmentProtection' `
                    -Status 'Warning' `
                    -Severity 'Medium' `
                    -Resource $envResource `
                    -Detail "Environment '$envName' has required reviewers but no deployment branch policy. Any branch can trigger a deployment that (if approved) reaches this environment." `
                    -Remediation "Add a deployment branch policy in Settings > Environments to restrict deployments to protected or specific branches." `
                    -AttackMapping @('unauthorized-env-deployment') `
                    -Target $target))
            }
        }
    }

    if ($findings.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'EnvironmentProtection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail "$($environments.Count) environment(s) checked, all have required reviewers and deployment branch policies." `
            -Remediation 'No action needed.' `
            -Target $target))
    }
    else {
        foreach ($f in $findings) { $results.Add($f) }
    }

    $results.ToArray()
}
