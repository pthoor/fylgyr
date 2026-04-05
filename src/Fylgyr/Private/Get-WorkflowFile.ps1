function Get-WorkflowFile {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    # Use Git Trees API for efficient batch fetching (single call for all paths)
    try {
        $tree = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/git/trees/HEAD?recursive=1" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404' -or $_.Exception.Message -match 'Not Found') {
            return @()
        }
        throw
    }

    $workflowEntries = $tree.tree | Where-Object {
        $_.path -match '^\.github/workflows/.+\.(yml|yaml)$' -and $_.type -eq 'blob'
    }

    if (-not $workflowEntries -or $workflowEntries.Count -eq 0) {
        return @()
    }

    $workflowFiles = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($entry in $workflowEntries) {
        $blob = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/git/blobs/$($entry.sha)" -Token $Token
        $raw = [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String(($blob.content -replace '\s', ''))
        )

        $workflowFiles.Add([PSCustomObject]@{
            Name    = ($entry.path -split '/')[-1]
            Path    = $entry.path
            Content = $raw
        })
    }

    return $workflowFiles.ToArray()
}
