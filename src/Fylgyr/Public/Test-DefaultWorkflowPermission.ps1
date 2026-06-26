function Test-DefaultWorkflowPermission {
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
        $response = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/actions/permissions/workflow" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DefaultWorkflowPermission' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail 'Insufficient permissions to read default workflow permissions. The endpoint requires Actions:read access.' `
                -Remediation 'Use a fine-grained token with Actions:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DefaultWorkflowPermission' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'Default workflow permissions setting is not available for this repository (404). The repository may not use GitHub Actions.' `
                -Remediation 'No action needed.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultWorkflowPermission' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Unexpected error reading default workflow permissions: $msg" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if (-not $response) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultWorkflowPermission' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail 'Default workflow permissions endpoint returned an empty response.' `
            -Remediation 'Verify token permissions and retry.' `
            -Target $target))
        return $results.ToArray()
    }

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $defaultPermissions = if ($response.PSObject.Properties['default_workflow_permissions'] -and $response.default_workflow_permissions) {
        [string]$response.default_workflow_permissions
    }
    else {
        $null
    }

    if ($defaultPermissions -eq 'write') {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'DefaultWorkflowPermission' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $target `
            -Detail "Repository default GITHUB_TOKEN permission is set to 'write'. Every workflow that does not explicitly declare a 'permissions:' block inherits write access across all scopes — exactly the ambient authority that was harvested in the tj-actions/changed-files Shai-Hulud incident and enabled the nx Pwn Request attack. Any compromised or malicious action in an unscoped workflow can modify code, create releases, and exfiltrate credentials without escalation." `
            -Remediation "Change the default workflow permission to 'Read repository contents and packages permissions' in Settings → Actions → General → Workflow permissions. This sets the default to read-only; individual workflows that need write access must declare it explicitly via a 'permissions:' block." `
            -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request') `
            -Target $target))
    }

    $canApprovePrs = if ($response.PSObject.Properties['can_approve_pull_request_reviews']) {
        $response.can_approve_pull_request_reviews -eq $true
    }
    else {
        $false
    }

    if ($canApprovePrs) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'DefaultWorkflowPermission' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "GitHub Actions is allowed to approve pull requests (can_approve_pull_request_reviews: true). A workflow — or an action it calls — can programmatically approve its own PR, bypassing the human review gate. This is a key control bypassed in automated Pwn Request campaigns where CI acts on behalf of the submitter." `
            -Remediation "Disable 'Allow GitHub Actions to create and approve pull requests' in Settings → Actions → General → Workflow permissions." `
            -AttackMapping @('nx-pwn-request', 'prt-scan-ai-automated') `
            -Target $target))
    }

    if ($findings.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DefaultWorkflowPermission' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail "Default GITHUB_TOKEN permission is read-only and Actions cannot self-approve pull requests." `
            -Remediation 'No action needed.' `
            -Target $target))
    }
    else {
        foreach ($f in $findings) { $results.Add($f) }
    }

    $results.ToArray()
}
