function Test-WorkflowPermission {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $content = $wf.Content

        # Check for a top-level permissions: block.
        # It must appear before the first "jobs:" key to be workflow-level.
        $hasTopLevelPermissions = $false

        $lines = $content -split "`n"
        foreach ($line in $lines) {
            if ($line -match '^\s*jobs\s*:') {
                break
            }
            if ($line -match '^permissions\s*:') {
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
                -Detail 'Workflow does not declare a top-level permissions block. The GITHUB_TOKEN inherits broad default write permissions.' `
                -Remediation 'Add a top-level permissions: block (e.g., permissions: read-all or permissions: { contents: read }) to restrict the default token scope.' `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
    }

    return $results.ToArray()
}
