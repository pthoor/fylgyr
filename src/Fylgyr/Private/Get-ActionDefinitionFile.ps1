function Get-ActionDefinitionFile {
    <#
    .SYNOPSIS
        Fetches composite/JS action definition files (action.yml / action.yaml) from a repo.

    .DESCRIPTION
        Get-WorkflowFile only returns files under .github/workflows. Composite actions
        declare their own steps (including `uses:` references) in an action.yml at any
        path, so an unpinned dependency inside a composite action - the propagation
        vector in the tj-actions/Shai-Hulud incident - is invisible to a workflow-only
        scan. This helper enumerates action definition files via the Git Trees API and
        returns them in the same { Name, Path, Content } shape as Get-WorkflowFile.
    #>
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

    $tree = Get-RepoTree -Owner $Owner -Repo $Repo -Token $Token
    if (-not $tree -or -not $tree.tree) {
        return [PSCustomObject[]]@()
    }

    $actionEntries = @($tree.tree | Where-Object {
        $_.type -eq 'blob' -and $_.path -match '(^|/)action\.ya?ml$'
    })

    if ($actionEntries.Count -eq 0) {
        return [PSCustomObject[]]@()
    }

    # Bound the work so a pathological repo cannot drive unbounded API calls.
    $maxActionFiles = 50
    if ($actionEntries.Count -gt $maxActionFiles) {
        Write-Warning "Repository '$Owner/$Repo' has $($actionEntries.Count) action definition files; scanning the first $maxActionFiles."
        $actionEntries = $actionEntries[0..($maxActionFiles - 1)]
    }

    $actionFiles = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($entry in $actionEntries) {
        # Let API fetch errors bubble up - only catch Base64/UTF-8 decode failures.
        $escapedSha = ConvertTo-FylgyrEscapedPathSegment -Value ([string]$entry.sha)
        $blob = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/git/blobs/$escapedSha" -Token $Token
        try {
            $raw = [System.Text.Encoding]::UTF8.GetString(
                [System.Convert]::FromBase64String(($blob.content -replace '\s', ''))
            )
            $actionFiles.Add([PSCustomObject]@{
                Name    = ($entry.path -split '/')[-1]
                Path    = $entry.path
                Content = $raw
            })
        }
        catch {
            Write-Warning "Failed to decode action definition file '$($entry.path)': $($_.Exception.Message)"
        }
    }

    return $actionFiles.ToArray()
}
