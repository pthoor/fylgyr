function Test-DependencyReview {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $prTriggeredWorkflows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hasDependencyReview = $false

    foreach ($wf in $WorkflowFiles) {
        $content = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $hasPullRequestTrigger = $content -match '(?im)(^|\s)pull_request(\s|:|$)'
        if (-not $hasPullRequestTrigger) {
            continue
        }

        $prTriggeredWorkflows.Add($wf)
        if ($content -match '(?im)^\s*-\s*uses\s*:\s*actions/dependency-review-action@') {
            $hasDependencyReview = $true
        }
    }

    if ($prTriggeredWorkflows.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DependencyReview' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource '.github/workflows' `
            -Detail 'No pull_request workflow detected. Dependency review at PR time is not enforced.' `
            -Remediation 'Add a pull_request workflow on the default branch that runs actions/dependency-review-action to block vulnerable dependency introductions before merge.' `
            -AttackMapping @('event-stream-hijack')))
        return $results.ToArray()
    }

    if (-not $hasDependencyReview) {
        $workflowNames = @($prTriggeredWorkflows | ForEach-Object { $_.Name }) -join ', '
        $results.Add((Format-FylgyrResult `
            -CheckName 'DependencyReview' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource '.github/workflows' `
            -Detail "PR workflow(s) detected ($workflowNames), but none run actions/dependency-review-action. This leaves a post-merge detection gap where vulnerable transitive dependencies can land before alerts fire." `
            -Remediation 'Add actions/dependency-review-action to at least one pull_request workflow that protects the default branch.' `
            -AttackMapping @('event-stream-hijack')))
        return $results.ToArray()
    }

    $results.Add((Format-FylgyrResult `
        -CheckName 'DependencyReview' `
        -Status 'Pass' `
        -Severity 'Info' `
        -Resource '.github/workflows' `
        -Detail 'At least one pull_request workflow runs actions/dependency-review-action.' `
        -Remediation 'No action needed.'))

    return $results.ToArray()
}
