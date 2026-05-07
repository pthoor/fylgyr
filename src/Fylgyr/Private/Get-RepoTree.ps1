function Get-RepoTree {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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

    # Confirm the repo exists and is not empty before fetching the tree
    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404') {
            return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
        }
        throw
    }

    if (-not $repoInfo.default_branch) {
        return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
    }

    # Use HEAD to avoid URL-encoding issues with branch names that contain slashes
    try {
        $tree = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/git/trees/HEAD?recursive=1" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404') {
            return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
        }
        throw
    }

    return $tree
}
