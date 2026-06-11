function Test-DeployKey {
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
        $keys = @(Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/keys?per_page=100" -Token $Token -AllPages)
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DeployKey' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'Deploy keys are not available for this repository.' `
                -Remediation 'No action needed.' `
                -Target $target))
            return $results.ToArray()
        }
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DeployKey' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail 'Insufficient permissions to list deploy keys.' `
                -Remediation 'Use a fine-grained token with Administration:read, or a classic token with repo/admin scope.' `
                -Target $target))
            return $results.ToArray()
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'DeployKey' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Failed to list deploy keys: $($_.Exception.Message)" `
            -Remediation 'Verify the repository and token, then rerun.' `
            -Target $target))
        return $results.ToArray()
    }

    $now = [datetime]::UtcNow
    $staleAfterDays = 365
    $findingCount = 0

    foreach ($key in $keys) {
        if (-not $key) { continue }
        $title = if ($key.PSObject.Properties['title'] -and $key.title) { [string]$key.title } else { "id $($key.id)" }
        $isReadOnly = $key.PSObject.Properties['read_only'] -and $key.read_only

        if (-not $isReadOnly) {
            $findingCount++
            $results.Add((Format-FylgyrResult `
                -CheckName 'DeployKey' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$target (deploy-key: $title)" `
                -Detail "Deploy key '$title' has write access (read_only = false). A write deploy key is a repository-scoped SSH credential with no MFA and no user attribution that can push to the repo and bypass review; a leaked or forgotten write key is a classic post-compromise persistence mechanism." `
                -Remediation 'Remove write deploy keys unless strictly required. Prefer a least-privilege GitHub App installation or a short-lived token; if a write key is unavoidable, rotate it regularly and scope deployments through a protected environment.' `
                -AttackMapping @('committed-credentials-exposure', 'codecov-bash-uploader') `
                -Target $target))
            continue
        }

        # Stale read-only key advisory (only when a creation date is available).
        if ($key.PSObject.Properties['created_at'] -and $key.created_at) {
            $createdAt = $null
            try {
                $createdAt = ([datetime]::Parse([string]$key.created_at)).ToUniversalTime()
            }
            catch {
                $createdAt = $null
            }

            if ($createdAt -and ($now - $createdAt).TotalDays -gt $staleAfterDays) {
                $findingCount++
                $ageDays = [int]($now - $createdAt).TotalDays
                $results.Add((Format-FylgyrResult `
                    -CheckName 'DeployKey' `
                    -Status 'Warning' `
                    -Severity 'Low' `
                    -Resource "$target (deploy-key: $title)" `
                    -Detail "Read-only deploy key '$title' is $ageDays days old. Long-lived keys widen the window for a leaked credential to be abused." `
                    -Remediation 'Review whether this deploy key is still needed and rotate or remove it.' `
                    -AttackMapping @('committed-credentials-exposure') `
                    -Target $target))
            }
        }
    }

    if ($findingCount -eq 0) {
        $detail = if ($keys.Count -eq 0) {
            'Repository has no deploy keys.'
        }
        else {
            "Repository has $($keys.Count) deploy key(s), all read-only and within the rotation window."
        }
        $results.Add((Format-FylgyrResult `
            -CheckName 'DeployKey' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail $detail `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
