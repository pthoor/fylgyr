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

    try {
        $listing = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/contents/.github/workflows" -Token $Token
    }
    catch {
        if ($_.Exception.Message -match '404' -or $_.Exception.Message -match 'Not Found') {
            return @()
        }
        throw
    }

    $workflowFiles = @()

    foreach ($item in $listing) {
        if ($item.type -ne 'file') { continue }
        if ($item.name -notmatch '\.(yml|yaml)$') { continue }

        $fileResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/contents/$($item.path)" -Token $Token
        $raw = [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String(($fileResponse.content -replace '\s', ''))
        )

        $workflowFiles += [PSCustomObject]@{
            Name    = $item.name
            Path    = $item.path
            Content = $raw
        }
    }

    return $workflowFiles
}
