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

    try {
        $protection = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/branches/$defaultBranch/protection" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' has no protection rules configured." `
                -Remediation 'Enable branch protection in repository Settings → Branches. Require pull request reviews and status checks.' `
                -AttackMapping @('trivy-force-push-main', 'codecov-bash-uploader') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BranchProtection' `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read branch protection.' `
                -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'BranchProtection' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Unexpected error reading branch protection: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
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
