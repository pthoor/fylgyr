function Get-FylgyrChangedWorkflowPath {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^(?!-)[a-zA-Z0-9._/-]+$')]
        [string]$SinceRef
    )

    $changed = & git diff --name-only $SinceRef HEAD 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to read changed files from git diff: $changed"
    }

    $workflowPathList = [System.Collections.Generic.List[string]]::new()
    foreach ($path in @($changed)) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }

        if ($path -match '^\.github/workflows/.*\.ya?ml$') {
            $workflowPathList.Add($path)
        }
    }

    $workflowPaths = [string[]]($workflowPathList | Sort-Object -Unique)

    return $workflowPaths
}
