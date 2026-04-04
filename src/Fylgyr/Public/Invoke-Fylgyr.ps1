function Invoke-Fylgyr {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [string]$Token = $env:GITHUB_TOKEN
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $workflowFiles = Get-WorkflowFile -Owner $Owner -Repo $Repo -Token $Token
    }
    catch {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowFileFetch' `
            -Status 'Error' `
            -Severity 'Critical' `
            -Resource "$Owner/$Repo" `
            -Detail "Failed to fetch workflow files: $_" `
            -Remediation 'Verify the repository exists and the token has contents:read access.'))
        return $results.ToArray()
    }

    if ($workflowFiles.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowFileFetch' `
            -Status 'Warning' `
            -Severity 'Info' `
            -Resource "$Owner/$Repo" `
            -Detail 'No workflow files found in .github/workflows.' `
            -Remediation 'No action needed if this repository does not use GitHub Actions.'))
        return $results.ToArray()
    }

    $checks = @(
        'Test-ActionPinning'
        'Test-DangerousTrigger'
        'Test-WorkflowPermission'
    )

    foreach ($check in $checks) {
        try {
            $checkResults = & $check -WorkflowFiles $workflowFiles
            foreach ($r in $checkResults) {
                $results.Add($r)
            }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName $check `
                -Status 'Error' `
                -Severity 'Critical' `
                -Resource "$Owner/$Repo" `
                -Detail "Check failed with error: $_" `
                -Remediation 'Review the error and re-run.'))
        }
    }

    return $results.ToArray()
}
