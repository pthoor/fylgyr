function Test-ArtifactPoisoning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $sanitizedLines = @(($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' })
        $sanitizedContent = $sanitizedLines -join "`n"

        $hasDownloadArtifact = $sanitizedContent -match '(?im)^\s*-\s*uses\s*:\s*actions/download-artifact@'
        if (-not $hasDownloadArtifact) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ArtifactPoisoning' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not download artifacts." `
                -Remediation 'No action needed.'))
            continue
        }

        $hasWorkflowRunTrigger = $sanitizedContent -match '(?im)(^|\s)workflow_run(\s|:|$)'
        $artifactExecPatterns = @(
            '(?im)\bbash\s+[^`n#]*(artifact|download|dist|out|tmp|\./)'
            '(?im)\bsh\s+[^`n#]*(artifact|download|dist|out|tmp|\./)'
            '(?im)\bsource\s+[^`n#]*(artifact|download|dist|out|tmp|\./)'
            '(?im)\bpython\s+[^`n#]*(artifact|download|dist|out|tmp|\./)'
            '(?im)\b(pwsh|powershell)\s+[^`n#]*(artifact|download|dist|out|tmp|\./)'
            '(?im)\./[^`n#]*(artifact|download|dist|out|tmp)'
        )

        $runBlocks = @(Get-RunBlock -Content $sanitizedContent)
        $hasArtifactExecution = $false
        foreach ($block in $runBlocks) {
            foreach ($pattern in $artifactExecPatterns) {
                if ($block.Content -match $pattern) {
                    $hasArtifactExecution = $true
                    break
                }
            }

            if ($hasArtifactExecution) {
                break
            }
        }

        if ($hasArtifactExecution) {
            $severity = if ($hasWorkflowRunTrigger) { 'Critical' } else { 'High' }
            $detail = "Workflow '$($wf.Name)' downloads artifacts and appears to execute artifact content without integrity verification."
            if ($hasWorkflowRunTrigger) {
                $detail += ' It is also triggered by workflow_run, which can turn cross-workflow artifact consumption into an elevated artifact-poisoning path.'
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'ArtifactPoisoning' `
                -Status 'Fail' `
                -Severity $severity `
                -Resource $wf.Path `
                -Detail $detail `
                -Remediation 'Do not execute downloaded artifacts directly. Verify checksums/signatures and isolate untrusted artifacts. For workflow_run pipelines, enforce strict producer trust boundaries and integrity validation before execution.' `
                -AttackMapping @('artifact-poisoning-workflow-run')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ArtifactPoisoning' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' downloads artifacts but no direct artifact-execution pattern was detected." `
            -Remediation 'No action needed. Keep integrity validation in place for any future artifact execution.'))
    }

    return $results.ToArray()
}
