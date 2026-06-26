function Test-WorkflowConcurrency {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $stripped = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $jobBlocks = @(Get-WorkflowJobBlock -Content $stripped)

        $deployJobs = [System.Collections.Generic.List[string]]::new()
        foreach ($job in $jobBlocks) {
            if ($job.Content -match '(?m)^\s*environment\s*:') {
                $deployJobs.Add($job.Name)
            }
        }

        if ($deployJobs.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowConcurrency' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' has no jobs targeting a deployment environment." `
                -Remediation 'No action needed.'))
            continue
        }

        $strippedLines = $stripped -split "`n"
        $jobsLineIdx = -1
        for ($li = 0; $li -lt $strippedLines.Count; $li++) {
            if ($strippedLines[$li] -match '^\s*jobs\s*:') { $jobsLineIdx = $li; break }
        }
        $preJobsContent = if ($jobsLineIdx -gt 0) { ($strippedLines[0..($jobsLineIdx - 1)]) -join "`n" } else { '' }
        $hasWorkflowConcurrency = $preJobsContent -match '(?m)^\s*concurrency\s*:'

        $jobsMissingConcurrency = [System.Collections.Generic.List[string]]::new()
        foreach ($job in $jobBlocks) {
            if ($deployJobs -notcontains $job.Name) {
                continue
            }
            $jobHasConcurrency = $job.Content -match '(?m)^\s*concurrency\s*:'
            if (-not $hasWorkflowConcurrency -and -not $jobHasConcurrency) {
                $jobsMissingConcurrency.Add($job.Name)
            }
        }

        if ($jobsMissingConcurrency.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WorkflowConcurrency' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' has deployment job(s) with concurrency controls configured." `
                -Remediation 'No action needed.'))
            continue
        }

        $missingJobs = ($jobsMissingConcurrency | Sort-Object -Unique) -join ', '
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowConcurrency' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has deployment job(s) targeting an environment without a concurrency group: $missingJobs. Multiple concurrent workflow runs can deploy simultaneously, creating a race window where approval gates may be bypassed by a competing deployment that already holds the token." `
            -Remediation "Add a 'concurrency:' block with 'cancel-in-progress: true' at the workflow level or on each deployment job. Use a group key scoped to the environment (for example, 'group: deploy-production-`${{ github.ref }}'). This ensures only one deployment runs at a time per environment and ref." `
            -AttackMapping @('unauthorized-env-deployment')))
    }

    return $results.ToArray()
}
