function Get-RepoTree {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    # Fetch the default branch SHA from the repo metadata
    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404') {
            return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
        }
        throw
    }

    $defaultBranch = $repoInfo.default_branch
    if (-not $defaultBranch) {
        $defaultBranch = 'HEAD'
    }

    # Fetch the recursive tree for the default branch
    try {
        $tree = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/git/trees/$defaultBranch`?recursive=1" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404') {
            return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
        }
        throw
    }

    return $tree
}
