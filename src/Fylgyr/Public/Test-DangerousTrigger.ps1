function Test-DangerousTrigger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $dangerousTriggers = @('pull_request_target', 'workflow_run')

    # Patterns that indicate checkout of untrusted PR code
    $untrustedCheckoutPatterns = @(
        'github\.event\.pull_request\.head\.sha'
        'github\.event\.pull_request\.head\.ref'
        '\$\{\{\s*github\.head_ref\s*\}\}'
    )

    foreach ($wf in $WorkflowFiles) {
        $content = $wf.Content

        $foundTriggers = @()
        foreach ($trigger in $dangerousTriggers) {
            $escaped = [regex]::Escape($trigger)
            $triggerPatterns = @(
                "(?m)^\s*$escaped\s*:"
                "(?m)^\s*on\s*:\s*$escaped\s*(?:#.*)?$"
                "(?m)^\s*on\s*:\s*\[[^\]]*\b$escaped\b[^\]]*\]"
            )
            foreach ($tp in $triggerPatterns) {
                if ($content -match $tp) {
                    $foundTriggers += $trigger
                    break
                }
            }
        }

        if ($foundTriggers.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail 'No dangerous trigger patterns found.' `
                -Remediation 'None.'))
            continue
        }

        # Check if the workflow checks out untrusted code
        $checksOutUntrusted = $false
        foreach ($pattern in $untrustedCheckoutPatterns) {
            if ($content -match $pattern) {
                $checksOutUntrusted = $true
                break
            }
        }

        $triggerList = $foundTriggers -join ', '

        if ($checksOutUntrusted) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource $wf.Path `
                -Detail "Uses $triggerList and checks out untrusted PR code. This may allow attacker-controlled code to run with elevated permissions unless explicitly restricted." `
                -Remediation 'Do not checkout the PR head ref in pull_request_target workflows. Use pull_request trigger instead, or run untrusted code in a separate unprivileged workflow.' `
                -AttackMapping @('nx-pwn-request')))
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail "Uses $triggerList without apparent checkout of untrusted code. The workflow may still run with elevated permissions." `
                -Remediation 'Verify this workflow does not process untrusted input. Consider narrowing permissions or switching to pull_request trigger.' `
                -AttackMapping @('nx-pwn-request')))
        }
    }

    return $results.ToArray()
}
