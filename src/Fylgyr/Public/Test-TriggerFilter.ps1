function Test-TriggerFilter {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $eventsRequiringTypes = @(
        'discussion',
        'issue_comment',
        'issues',
        'pull_request_review',
        'pull_request_review_comment',
        'project',
        'project_card',
        'project_column'
    )

    foreach ($wf in $WorkflowFiles) {
        $lines = @(($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' })
        $content = $lines -join "`n"
        $missingTypes = @(Get-MissingTypesEvent -WorkflowContent $content -Events $eventsRequiringTypes)

        if ($missingTypes.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'TriggerFilter' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' has no detected trigger events missing types filters." `
                -Remediation 'No action needed.'))
            continue
        }

        $selfHostedRunner = $content -match '(?im)^\s*runs-on\s*:\s*(\[[^\]]*self-hosted[^\]]*\]|.*self-hosted.*)$'
        $runBlocks = @(Get-RunBlock -Content $content)
        $hasUntrustedInterpolation = $false
        foreach ($block in $runBlocks) {
            if ($block.Content -match '(?i)\$\{\{\s*github\.event\.(discussion|issue|issue_comment|comment|review)\.') {
                $hasUntrustedInterpolation = $true
                break
            }
        }

        $escalated = $selfHostedRunner -or $hasUntrustedInterpolation
        $status = if ($escalated) { 'Fail' } else { 'Warning' }
        $severity = if ($escalated) { 'High' } else { 'Medium' }

        $detail = "Workflow '$($wf.Name)' defines trigger(s) without types filters: $($missingTypes -join ', ')."
        if ($escalated) {
            $detail += ' Combined with self-hosted execution or untrusted run interpolation, this increases exposure to obscure event-subtype trigger abuse.'
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'TriggerFilter' `
            -Status $status `
            -Severity $severity `
            -Resource $wf.Path `
            -Detail $detail `
            -Remediation 'Add explicit types: filters for discussion/comment/review/project events so only intended sub-actions trigger workflow execution.' `
            -AttackMapping @('shai-hulud-runner-backdoor')))
    }

    return $results.ToArray()
}
