function Add-FylgyrEvidence {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [PSCustomObject[]]$WorkflowFiles = @(),

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $scanTime = [datetime]::UtcNow
    $commitSha = $null

    try {
        $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
        $defaultBranch = if ($repoInfo -and $repoInfo.default_branch) { [string]$repoInfo.default_branch } else { 'main' }
        $headCommit = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/commits/$defaultBranch" -Token $Token
        if ($headCommit -and $headCommit.sha) {
            $commitSha = [string]$headCommit.sha
        }
    }
    catch {
        Write-Verbose "Unable to resolve commit SHA for evidence: $($_.Exception.Message)"
    }

    $workflowContentByPath = @{}
    foreach ($workflowFile in @($WorkflowFiles)) {
        if ($workflowFile -and $workflowFile.Path -and $workflowFile.Content) {
            $workflowContentByPath[[string]$workflowFile.Path] = [string]$workflowFile.Content
        }
    }

    foreach ($result in $Results) {
        if (-not $result) {
            continue
        }

        $resource = [string]$result.Resource
        $path = $null
        $line = $null

        if ($resource -match '^(.+):(\d+)$') {
            $path = [string]$Matches[1]
            $line = [int]$Matches[2]
        }
        elseif ($resource -like '.github/workflows/*') {
            $path = $resource
        }

        $yamlSnippet = $null
        if ($path -and $workflowContentByPath.ContainsKey($path)) {
            $yamlSnippet = Get-FylgyrYamlSnippet -Content $workflowContentByPath[$path] -Line $line
        }

        $permalink = $null
        if ($commitSha) {
            if ($path) {
                $permalink = "https://github.com/$Owner/$Repo/blob/$commitSha/$path"
                if ($line -and $line -gt 0) {
                    $permalink = "$permalink#L$line"
                }
            }
            else {
                $permalink = "https://github.com/$Owner/$Repo/tree/$commitSha"
            }
        }

        $evidence = [ordered]@{
            YamlSnippet = $yamlSnippet
            ApiResponse = $null
            CommitSha   = $commitSha
            ScanTime    = $scanTime
            Permalink   = $permalink
        }

        $result | Add-Member -NotePropertyName 'Evidence' -NotePropertyValue $evidence -Force
    }

    return $Results
}

function Get-FylgyrYamlSnippet {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Content,

        [int]$Line
    )

    $rawLines = @($Content -split "`n")
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($rawLine in $rawLines) {
        $lines.Add(($rawLine -replace "`r$", ''))
    }

    if ($lines.Count -eq 0) {
        return $null
    }

    if (-not $Line -or $Line -lt 1) {
        $startLine = 1
        $endLine = [Math]::Min(5, $lines.Count)
    }
    else {
        $startLine = [Math]::Max(1, $Line - 2)
        $endLine = [Math]::Min($lines.Count, $Line + 2)
    }

    $snippetLines = [System.Collections.Generic.List[string]]::new()
    for ($idx = $startLine; $idx -le $endLine; $idx++) {
        $snippetLines.Add(('{0:D4}: {1}' -f $idx, $lines[$idx - 1]))
    }

    return ($snippetLines -join "`n")
}
