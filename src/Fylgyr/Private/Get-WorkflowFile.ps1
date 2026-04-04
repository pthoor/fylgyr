function Get-WorkflowFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $listing = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/contents/.github/workflows" -Token $Token

    $workflowFiles = @()

    foreach ($item in $listing) {
        if ($item.type -ne 'file') { continue }
        if ($item.name -notmatch '\.(yml|yaml)$') { continue }

        $raw = Invoke-GitHubApi -Endpoint $item.download_url -Token $Token
        $workflowFiles += [PSCustomObject]@{
            Name    = $item.name
            Path    = $item.path
            Content = $raw
        }
    }

    return $workflowFiles
}
