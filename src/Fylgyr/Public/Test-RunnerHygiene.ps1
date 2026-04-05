function Test-RunnerHygiene {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [System.Object[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $hostedPattern = '^(ubuntu|windows|macos)-'
    $selfHostedPattern = '(?i)(self.hosted|self_hosted)'

    foreach ($wf in $WorkflowFiles) {
        $content = $wf.Content
        $name = $wf.Name
        $path = $wf.Path

        # Strip comment lines to avoid false positives
        $strippedLines = ($content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        $stripped = $strippedLines -join "`n"

        $hasPullRequestTarget = $stripped -match '(?m)pull_request_target'
        $hasPullRequest = $stripped -match '(?m)(^|\s)pull_request(\s|:|$)'
        $hasWorkflowRun = $stripped -match '(?m)workflow_run'

        # Find all runs-on values
        $runsOnMatches = [regex]::Matches($stripped, '(?m)^\s*runs-on:\s*(.+)$')

        $foundSelfHosted = $false

        foreach ($match in $runsOnMatches) {
            $runsOnValue = $match.Groups[1].Value.Trim()

            # Skip GitHub-hosted runners
            if ($runsOnValue -match $hostedPattern) {
                continue
            }

            # Check for self-hosted label or non-standard runner
            $isSelfHosted = $runsOnValue -match $selfHostedPattern -or
                            ($runsOnValue -notmatch $hostedPattern -and $runsOnValue -notmatch '^\$\{\{')

            if (-not $isSelfHosted) {
                continue
            }

            $foundSelfHosted = $true

            if ($hasPullRequestTarget -or $hasWorkflowRun) {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Fail' `
                    -Severity 'High' `
                    -Resource "$path" `
                    -Detail "Workflow '$name' uses a self-hosted runner ('$runsOnValue') with a dangerous trigger (pull_request_target or workflow_run). Attacker-controlled code from a fork could execute on your runner." `
                    -Remediation 'Move this job to a GitHub-hosted runner, or ensure the workflow never checks out untrusted code on a self-hosted runner. Consider using ephemeral runners.' `
                    -AttackMapping @('github-actions-cryptomining', 'nx-pwn-request') `
                    -Target $null))
            }
            elseif ($hasPullRequest) {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Warning' `
                    -Severity 'Medium' `
                    -Resource "$path" `
                    -Detail "Workflow '$name' uses a self-hosted runner ('$runsOnValue') with a pull_request trigger. Fork PRs can run arbitrary code on your self-hosted runner." `
                    -Remediation "If this repository is public, switch to GitHub-hosted runners for PR workflows. If private, verify fork PR access is restricted." `
                    -AttackMapping @('github-actions-cryptomining') `
                    -Target $null))
            }
            else {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Warning' `
                    -Severity 'Low' `
                    -Resource "$path" `
                    -Detail "Workflow '$name' uses a self-hosted runner ('$runsOnValue'). Self-hosted runners require careful hardening and access control." `
                    -Remediation 'Ensure self-hosted runners are ephemeral, run in isolated environments, and are not exposed to untrusted input. See: https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners' `
                    -AttackMapping @('github-actions-cryptomining') `
                    -Target $null))
            }
        }

        if (-not $foundSelfHosted) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RunnerHygiene' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource "$path" `
                -Detail "Workflow '$name' uses only GitHub-hosted runners." `
                -Remediation 'No action needed.' `
                -Target $null))
        }
    }

    $results.ToArray()
}
