function Test-CacheIntegrity {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $unsafeKeyPatterns = @(
        'github\.event\.pull_request\.head\.ref'
        'github\.head_ref'
        'github\.event\.pull_request\.head\.label'
        'github\.event\.workflow_run\.head_branch'
    )

    foreach ($wf in $WorkflowFiles) {
        $lines = @(($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' })
        $content = $lines -join "`n"
        $hasPullRequestTrigger = $content -match '(?im)(^|\s)pull_request(\s|:|$)'

        $unsafeKeyHits = [System.Collections.Generic.List[string]]::new()

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -notmatch '(?i)^\s*-\s*uses\s*:\s*actions/(cache|setup-[a-z0-9._-]+)@') {
                continue
            }

            $j = $i + 1
            while ($j -lt $lines.Count) {
                $next = $lines[$j]
                if ($next -match '(?i)^\s*-\s*(uses|run)\s*:') {
                    break
                }

                if ($next -match '(?i)^\s*(key|cache-key)\s*:') {
                    foreach ($unsafePattern in $unsafeKeyPatterns) {
                        if ($next -match $unsafePattern) {
                            $unsafeKeyHits.Add($next.Trim())
                            break
                        }
                    }
                }

                $j++
            }

            $i = $j - 1
        }

        if ($unsafeKeyHits.Count -gt 0) {
            $severity = if ($hasPullRequestTrigger) { 'High' } else { 'Medium' }
            $status = if ($hasPullRequestTrigger) { 'Fail' } else { 'Warning' }

            $results.Add((Format-FylgyrResult `
                -CheckName 'CacheIntegrity' `
                -Status $status `
                -Severity $severity `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' uses cache keys derived from potentially attacker-controlled refs. Detected key lines: $((@($unsafeKeyHits | Select-Object -Unique)) -join ' | '). This can enable cache poisoning across branches/runs." `
                -Remediation 'Build cache keys from immutable inputs (lockfiles, dependency hashes, github.sha) rather than head_ref or PR branch refs. Scope cache restore keys to trusted branches only.' `
                -AttackMapping @('cache-poisoning-pr-branch')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'CacheIntegrity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has no detected unsafe cache key patterns." `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
