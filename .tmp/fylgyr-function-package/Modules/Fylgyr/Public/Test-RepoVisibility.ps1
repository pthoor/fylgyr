function Test-RepoVisibility {
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
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RepoVisibility' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail 'Insufficient permissions to read repository metadata.' `
                -Remediation 'Use a fine-grained token with Metadata:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'RepoVisibility' `
            -Status 'Error' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Unexpected error reading repository metadata: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    $visibility = if ($repoInfo.PSObject.Properties['visibility'] -and $repoInfo.visibility) {
        $repoInfo.visibility
    }
    elseif ($repoInfo.private -eq $true) {
        'private'
    }
    else {
        'public'
    }

    # Naming heuristics for repos that probably should not be public
    $internalMarkers = @(
        '-internal$', '^internal-', '[-_]internal[-_]',
        '-private$', '^private-', '[-_]private[-_]',
        '-confidential$', '[-_]confidential[-_]',
        '-secret$', '[-_]secret[-_]',
        '-staging$', '[-_]staging[-_]',
        '-prod$', '^prod-', '[-_]prod[-_]',
        '-proprietary$'
    )

    $matchedMarker = $null
    foreach ($marker in $internalMarkers) {
        if ($Repo -match $marker) {
            $matchedMarker = $marker
            break
        }
    }

    if ($visibility -eq 'public' -and $matchedMarker) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RepoVisibility' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail "Repository is public but its name matches an internal/private naming pattern ('$matchedMarker'). This is the class of misconfiguration that caused the Toyota T-Connect source-code exposure, where a repository intended for internal use was publicly accessible for five years." `
            -Remediation "Confirm the repository is intentionally public. If not, change visibility to private in Settings > General > Danger Zone, audit the commit history for secrets, and rotate any exposed credentials." `
            -AttackMapping @('toyota-source-exposure') `
            -Target $target))
        return $results.ToArray()
    }

    $detail = if ($visibility -eq 'public') {
        'Repository is public and its name does not match internal/private naming heuristics.'
    }
    elseif ($visibility -eq 'internal') {
        'Repository visibility is internal.'
    }
    else {
        'Repository is private.'
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'RepoVisibility' `
        -Status 'Pass' `
        -Severity 'Info' `
        -Resource $target `
        -Detail $detail `
        -Remediation 'No action needed.' `
        -Target $target))

    $results.ToArray()
}
