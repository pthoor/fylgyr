function Test-WorkflowPermission {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        # Check for a top-level permissions: block.
        # It must appear before the first "jobs:" key to be workflow-level.
        $hasTopLevelPermissions = $false

        $lines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        foreach ($line in $lines) {
            if ($line -match '^\s*jobs\s*:') {
                break
            }
            if ($line -match '^\s*permissions\s*:') {
                $hasTopLevelPermissions = $true
                break
            }
        }

        if ($hasTopLevelPermissions) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermissions' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail 'Workflow declares a top-level permissions block.' `
                -Remediation 'None.'))
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermissions' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail 'Workflow does not declare a top-level permissions block. Without an explicit permissions setting, the GITHUB_TOKEN uses the repository or organization default permissions, which may be broader than intended.' `
                -Remediation 'Add a top-level permissions: block (for example, permissions: read-all or permissions: { contents: read }) to explicitly define the token scope for this workflow.' `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
    }

    return $results.ToArray()
}
