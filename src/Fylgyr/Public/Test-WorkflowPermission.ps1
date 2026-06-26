function Test-WorkflowPermission {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $lines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }

        $hasTopLevelPermissions = $false
        $topLevelIsWriteAll = $false
        $hasJobLevelWriteAll = $false
        $pastJobs = $false

        foreach ($line in $lines) {
            if ($line -match '^\s*jobs\s*:') {
                $pastJobs = $true
                continue
            }

            if (-not $pastJobs) {
                if ($line -match '^\s*permissions\s*:\s*write-all\s*(?:#.*)?$') {
                    $hasTopLevelPermissions = $true
                    $topLevelIsWriteAll = $true
                }
                elseif ($line -match '^\s*permissions\s*:') {
                    $hasTopLevelPermissions = $true
                }
            }
            else {
                if ($line -match '^\s*permissions\s*:\s*write-all\s*(?:#.*)?$') {
                    $hasJobLevelWriteAll = $true
                }
            }
        }

        if ($topLevelIsWriteAll) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermission' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' sets top-level permissions: write-all. This grants the GITHUB_TOKEN the maximum permission set across all scopes. Any compromised step or action in this workflow can write code, create releases, modify packages, and access all repository secrets — precisely the blast radius that enabled the tj-actions/changed-files Shai-Hulud incident." `
                -Remediation "Replace 'permissions: write-all' with the minimal set of scopes required. Use 'permissions: read-all' as a baseline and explicitly add write scopes only where needed (for example, 'contents: write' for release jobs)." `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
        elseif ($hasJobLevelWriteAll -and -not $hasTopLevelPermissions) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermission' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' sets 'permissions: write-all' at the job level and has no top-level permissions block. The GITHUB_TOKEN inherits the repository default (potentially write) for jobs that do not set write-all, and the job with write-all has maximum permissions — the exact ambient authority harvested in the tj-actions/changed-files Shai-Hulud incident." `
                -Remediation "Add 'permissions: read-all' at the top level to restrict the token default, and replace job-level 'permissions: write-all' with the minimal required scopes for that job (for example, 'contents: write' for a release job)." `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
        elseif (-not $hasTopLevelPermissions) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermission' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not declare a top-level permissions block. Without an explicit permissions setting, the GITHUB_TOKEN uses the repository or organization default permissions, which may be broader than intended." `
                -Remediation "Add a top-level 'permissions:' block (for example, 'permissions: read-all' or 'permissions: { contents: read }') to explicitly define the token scope for this workflow." `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
        elseif ($hasJobLevelWriteAll) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermission' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' sets 'permissions: write-all' at the job level. While a restrictive top-level block is present, write-all at the job level grants every step in that job maximum token permissions, expanding the blast radius of any compromised action or run step." `
                -Remediation "Replace job-level 'permissions: write-all' with the minimal required scopes for that job (for example, 'contents: write' for a release job)." `
                -AttackMapping @('tj-actions-shai-hulud', 'nx-pwn-request')))
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowPermission' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' declares a top-level permissions block without write-all." `
                -Remediation 'No action needed.'))
        }
    }

    return $results.ToArray()
}
