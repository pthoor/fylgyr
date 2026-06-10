function Test-OutsideCollaborators {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Public check name follows project check contract.')]
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $resource = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'User') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OutsideCollaborators' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Outside collaborator policy does not apply." `
            -Remediation 'No action needed. Run this check against an organization owner.' `
            -Target $resource))
        return $results.ToArray()
    }

    # Rate-limit strategy: bound repo x collaborator permission lookups.
    # We cap permission checks to avoid N x M explosion on large organizations.
    $maxPermissionChecks = 500
    $permissionChecks = 0
    $limitReached = $false

    try {
        $outsideCollaborators = @(Invoke-GitHubApi -Endpoint "orgs/$Owner/outside_collaborators?filter=all&per_page=100" -Token $Token -AllPages)
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OutsideCollaborators' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Insufficient permissions to enumerate outside collaborators.' `
                -Remediation 'Use a fine-grained token with organization Members:read, or a classic token with read:org scope.' `
                -Target $resource))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OutsideCollaborators' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to enumerate outside collaborators: $($_.Exception.Message)" `
            -Remediation 'Verify token scope and organization access, then rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    if (-not $outsideCollaborators -or $outsideCollaborators.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OutsideCollaborators' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No outside collaborators found for this organization.' `
            -Remediation 'No action needed.' `
            -Target $resource))
        return $results.ToArray()
    }

    try {
        $orgRepos = @(Invoke-GitHubApi -Endpoint "orgs/$Owner/repos?type=all&per_page=100" -Token $Token -AllPages)
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'OutsideCollaborators' `
            -Status 'Error' `
            -Severity 'High' `
            -Resource $resource `
            -Detail "Failed to enumerate organization repositories: $($_.Exception.Message)" `
            -Remediation 'Use a token that can read organization repositories and rerun.' `
            -Target $resource))
        return $results.ToArray()
    }

    $risky = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($collaborator in $outsideCollaborators) {
        if ($limitReached) { break }

        $username = [string]$collaborator.login
        if (-not $username) { continue }

        foreach ($repo in $orgRepos) {
            if ($permissionChecks -ge $maxPermissionChecks) {
                $limitReached = $true
                break
            }

            if (-not $repo -or -not $repo.name) { continue }
            $repoName = [string]$repo.name

            $permissionChecks++
            try {
                $escapedRepoName = ConvertTo-FylgyrEscapedPathSegment -Value $repoName
                $escapedUsername = ConvertTo-FylgyrEscapedPathSegment -Value $username
                $perm = Invoke-GitHubApi -Endpoint "repos/$Owner/$escapedRepoName/collaborators/$escapedUsername/permission" -Token $Token
            }
            catch {
                $permMsg = $_.Exception.Message
                if ($permMsg -match '404') {
                    continue
                }

                if ($permMsg -match '403') {
                    $results.Add((Format-FylgyrResult `
                        -CheckName 'OutsideCollaborators' `
                        -Status 'Info' `
                        -Severity 'Info' `
                        -Resource $resource `
                        -Detail 'Token cannot read collaborator permission for one or more repositories. Outside collaborator analysis is partial.' `
                        -Remediation 'Use a fine-grained token with repository Metadata:read, or a classic token with repo + read:org scope.' `
                        -Target $resource))
                    return $results.ToArray()
                }

                continue
            }

            if ($perm -and $perm.PSObject.Properties['permission'] -and $perm.permission -in @('write', 'admin')) {
                $risky.Add([PSCustomObject]@{
                    User       = $username
                    Repo       = $repoName
                    Permission = [string]$perm.permission
                })
            }
        }
    }

    if ($risky.Count -eq 0) {
        $suffix = if ($limitReached) {
            " Analysis stopped after $maxPermissionChecks permission checks to stay within rate-limit budget."
        }
        else {
            ''
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OutsideCollaborators' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "No outside collaborators with write/admin permission detected.$suffix" `
            -Remediation 'No action needed.' `
            -Target $resource))

        return $results.ToArray()
    }

    $sample = @($risky | Select-Object -First 10 | ForEach-Object { "$($_.User) on $Owner/$($_.Repo) ($($_.Permission))" }) -join '; '
    $coverageNote = if ($limitReached) {
        " Analysis hit the $maxPermissionChecks permission-check cap, so findings may be incomplete."
    }
    else {
        ''
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'OutsideCollaborators' `
        -Status 'Fail' `
        -Severity 'High' `
        -Resource $resource `
        -Detail "$($risky.Count) outside collaborator write/admin grants detected. Examples: $sample.$coverageNote" `
        -Remediation 'Remove stale outside-collaborator access, downgrade to read/triage where possible, and use temporary team membership for contractors.' `
        -AttackMapping @('uber-credential-leak') `
        -Target $resource))

    $results.ToArray()
}
