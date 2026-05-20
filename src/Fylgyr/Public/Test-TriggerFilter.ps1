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
        $missingTypes = [System.Collections.Generic.List[string]]::new()

        foreach ($eventName in $eventsRequiringTypes) {
            $inlineArrayPattern = '(?im)^\s*on\s*:\s*\[[^\]]*\b' + [regex]::Escape($eventName) + '\b[^\]]*\]'
            $inlineScalarPattern = '(?im)^\s*on\s*:\s*' + [regex]::Escape($eventName) + '\s*$'
            if ($content -match $inlineArrayPattern -or $content -match $inlineScalarPattern) {
                $missingTypes.Add($eventName)
                continue
            }

            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -notmatch '^\s*on\s*:\s*$') {
                    continue
                }

                $onIndent = ([regex]::Match($lines[$i], '^\s*')).Value.Length
                $j = $i + 1
                while ($j -lt $lines.Count) {
                    $candidate = $lines[$j]
                    if ($candidate -match '^\s*$') {
                        $j++
                        continue
                    }

                    $candidateIndent = ([regex]::Match($candidate, '^\s*')).Value.Length
                    if ($candidateIndent -le $onIndent) {
                        break
                    }

                    $eventHeaderPattern = '^\s{' + ($onIndent + 2) + '}' + [regex]::Escape($eventName) + '\s*:(?<tail>.*)$'
                    if ($candidate -match $eventHeaderPattern) {
                        $tail = $Matches.tail.Trim()
                        $hasTypes = $false

                        if ($tail -match '(?i)\btypes\b') {
                            $hasTypes = $true
                        }
                        else {
                            $eventIndent = $candidateIndent
                            $k = $j + 1
                            while ($k -lt $lines.Count) {
                                $eventLine = $lines[$k]
                                if ($eventLine -match '^\s*$') {
                                    $k++
                                    continue
                                }

                                $eventLineIndent = ([regex]::Match($eventLine, '^\s*')).Value.Length
                                if ($eventLineIndent -le $eventIndent) {
                                    break
                                }

                                if ($eventLine -match '^\s*types\s*:') {
                                    $hasTypes = $true
                                    break
                                }

                                $k++
                            }
                        }

                        if (-not $hasTypes) {
                            $missingTypes.Add($eventName)
                        }

                        break
                    }

                    $j++
                }
            }
        }

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

        $detail = "Workflow '$($wf.Name)' defines trigger(s) without types filters: $((@($missingTypes | Sort-Object -Unique)) -join ', ')."
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
