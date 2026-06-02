function Test-ForkPullPolicy {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $prtPatterns = @(
        '(?m)^\s*pull_request_target\s*:'
        '(?m)^\s*on\s*:\s*pull_request_target\s*(?:#.*)?$'
        '(?m)^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]'
    )

    # Checkout of untrusted PR head (any of these = fork-supplied ref)
    $forkRefPatterns = @(
        '\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}'
        '\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}'
        '\$\{\{\s*github\.head_ref\s*\}\}'
    )

    foreach ($wf in $WorkflowFiles) {
        $stripped = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $hasPRT = $false
        foreach ($pattern in $prtPatterns) {
            if ($stripped -match $pattern) { $hasPRT = $true; break }
        }

        if (-not $hasPRT) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ForkPullPolicy' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not use pull_request_target." `
                -Remediation 'No action needed.'))
            continue
        }

        $forkRefMatch = $null
        foreach ($pattern in $forkRefPatterns) {
            if ($stripped -match $pattern) {
                $forkRefMatch = $Matches[0]
                break
            }
        }

        if (-not $forkRefMatch) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ForkPullPolicy' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' uses pull_request_target but does not check out the PR head ref. The fork trust boundary is preserved." `
                -Remediation 'No action needed. Continue to avoid checking out untrusted refs in pull_request_target workflows.'))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ForkPullPolicy' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' uses pull_request_target and checks out a fork-controlled ref ($forkRefMatch). This grants fork PRs access to repository secrets and a write-capable GITHUB_TOKEN, which is the exact primitive abused by the nx Pwn Request and tj-actions/changed-files (Shai-Hulud) incidents." `
            -Remediation 'Never combine pull_request_target with a checkout of github.event.pull_request.head.* or github.head_ref. Use the pull_request trigger for untrusted code, and split secret-dependent steps into a separate workflow_run workflow with environment protection.' `
            -AttackMapping @('nx-pwn-request', 'tj-actions-shai-hulud', 'prt-scan-ai-automated')))
    }

    $results.ToArray()
}
