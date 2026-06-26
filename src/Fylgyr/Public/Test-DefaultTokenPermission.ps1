function Test-DefaultTokenPermission {
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

    if ($Repo) {
        $endpoint = "repos/$Owner/$Repo/actions/permissions/workflow"
        $scopeNoun = 'Repository'
        $permsHint = 'Use a fine-grained token with Administration:read on the repository.'
    }
    else {
        $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
        if ($ownerContext.Type -eq 'User') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DefaultTokenPermission' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail "Owner '$Owner' is a personal account. Organization default workflow token permissions do not apply." `
                -Remediation 'No action needed. Run this check against an organization owner, or per-repository.' `
                -Target $resource))
            return $results.ToArray()
        }
        $endpoint = "orgs/$Owner/actions/permissions/workflow"
        $scopeNoun = 'Organization'
        $permsHint = 'Use a fine-grained token with organization Administration:read, or a classic token with admin:org scope.'
    }

    try {
        $perm = Invoke-GitHubApi -Endpoint $endpoint -Token $Token
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DefaultTokenPermission' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Default workflow permissions are not available (GitHub Actions may be disabled, or the endpoint is unsupported for this target).' `
                -Remediation 'No action needed if Actions is disabled.' `
                -Target $resource))
            return $results.ToArray()
        }
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DefaultTokenPermission' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read default workflow token permissions.' `
                -Remediation $permsHint `
                -Target $resource))
            return $results.ToArray()
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultTokenPermission' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Failed to read default workflow token permissions: $($_.Exception.Message)" `
            -Remediation 'Verify the owner/repo and token, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $defaultPerm = if ($perm -and $perm.PSObject.Properties['default_workflow_permissions']) {
        [string]$perm.default_workflow_permissions
    }
    else {
        ''
    }
    $canApprove = $perm -and $perm.PSObject.Properties['can_approve_pull_request_reviews'] -and $perm.can_approve_pull_request_reviews

    if ($defaultPerm -eq 'write') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultTokenPermission' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "$scopeNoun default GITHUB_TOKEN permission is 'write'. Every workflow job that does not declare its own permissions: block starts with write access across scopes (contents, packages, etc.), so any compromised action or injected step can push code or tamper with releases. This is the blast-radius enabler behind the tj-actions/changed-files compromise." `
            -Remediation "Set the default GITHUB_TOKEN permissions to 'read' (Settings > Actions > General > Workflow permissions) and grant write per-workflow via an explicit permissions: block." `
            -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request') `
            -Target $resource))
    }
    elseif ($canApprove) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultTokenPermission' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "$scopeNoun default workflow token permission is 'read', but workflows are allowed to approve pull requests. A workflow can then approve its own or attacker-authored PRs, defeating required-review protection." `
            -Remediation "Disable 'Allow GitHub Actions to create and approve pull requests' in Settings > Actions > General." `
            -AttackMapping @('prt-scan-ai-automated') `
            -Target $resource))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultTokenPermission' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "$scopeNoun default GITHUB_TOKEN permission is read-only and workflows cannot approve pull requests." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }

    $results.ToArray()
}
