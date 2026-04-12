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
            -CheckName 'SignedCommits' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed to retrieve repository info: $($_.Exception.Message)" `
            -Remediation 'Verify the repository exists and the token has contents:read access.' `
            -Target $target))
        return $results.ToArray()
    }

    $resource = "$target (branch: $defaultBranch)"

    try {
        $signatures = Invoke-GitHubApi `
            -Endpoint "repos/$Owner/$Repo/branches/$defaultBranch/protection/required_signatures" `
            -Token $Token
    }
    catch {
        $msg = $_.ToString()

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SignedCommits' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Branch '$defaultBranch' does not require signed commits (no branch protection or required_signatures is disabled). Signed commits make it harder for an attacker with a stolen credential to impersonate a maintainer, as in the xz-utils backdoor." `
                -Remediation "Enable 'Require signed commits' in Settings > Branches > Branch protection rules. As a lower-friction first step, adopt commit signoff (git commit -s) and document a GPG/SSH signing policy. See: https://docs.github.com/authentication/managing-commit-signature-verification" `
                -AttackMapping @('xz-utils-backdoor') `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'SignedCommits' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read required signatures setting.' `
                -Remediation 'Use a fine-grained token with Administration:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommits' `
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
            -CheckName 'SignedCommits' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' requires signed commits." `
            -Remediation 'No action needed.' `
            -Target $target))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'SignedCommits' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Branch '$defaultBranch' does not require signed commits. Only a small minority of projects enforce this today, so this is a recommendation rather than a hard failure, but it is a meaningful defense against maintainer-impersonation attacks such as xz-utils." `
            -Remediation "Enable 'Require signed commits' in Settings > Branches > Branch protection rules. Publish a GPG/SSH signing policy for maintainers. Commit signoff (git commit -s) is a lower-friction intermediate step." `
            -AttackMapping @('xz-utils-backdoor') `
            -Target $target))
    }

    $results.ToArray()
}
