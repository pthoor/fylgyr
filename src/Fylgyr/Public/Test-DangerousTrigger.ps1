function Test-DangerousTrigger {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [string]$Token
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $dangerousTriggers = @('pull_request_target', 'workflow_run')

    # Patterns that indicate checkout of untrusted PR code
    $untrustedCheckoutPatterns = @(
        'github\.event\.pull_request\.head\.sha'
        'github\.event\.pull_request\.head\.ref'
        '\$\{\{\s*github\.head_ref\s*\}\}'
    )

    # Patterns that indicate actor-restricted workflows
    $actorRestrictionPatterns = @(
        'github\.actor\s*[!=]'
        'github\.triggering_actor\s*[!=]'
        'contains\s*\([^)]*github\.actor'
        'github\.event\.pull_request\.author_association'
    )

    # Resolve fork PR contributor approval policy via the real API when possible.
    # Docs: https://docs.github.com/en/rest/actions/permissions#get-fork-pr-contributor-approval-permissions-for-a-repository
    # Valid approval_policy values (any of these means a gate is configured):
    #   first_time_contributors_new_to_github
    #   first_time_contributors
    #   all_external_contributors
    # State: 'present' | 'absent' | 'forbidden' | 'unknown'. Distinguishing 403
    # (token lacks permission to read the policy) from 404 (no policy => gate absent)
    # lets us flag "could not verify" instead of silently swallowing a 403.
    $approvalGateState = 'unknown'
    if ($Owner -and $Repo -and $Token) {
        try {
            $forkApproval = Invoke-GitHubApi `
                -Endpoint "repos/$Owner/$Repo/actions/permissions/fork-pr-contributor-approval" `
                -Token $Token
            if ($forkApproval -and $forkApproval.PSObject.Properties['approval_policy']) {
                $gateConfigured = $forkApproval.approval_policy -in @(
                    'first_time_contributors_new_to_github',
                    'first_time_contributors',
                    'all_external_contributors'
                )
                $approvalGateState = if ($gateConfigured) { 'present' } else { 'absent' }
            }
            else {
                $approvalGateState = 'absent'
            }
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -match '404') {
                # Repo has no explicit policy - GitHub default applies; treat as absent gate.
                $approvalGateState = 'absent'
            }
            elseif ($msg -match '403') {
                $approvalGateState = 'forbidden'
            }
            else {
                $approvalGateState = 'unknown'
            }
        }
    }
    $sawPullRequestTarget = $false

    foreach ($wf in $WorkflowFiles) {
        # Strip YAML comment lines to avoid false positives
        $content = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

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

        # Check if the workflow has actor restrictions
        $hasActorRestriction = $false
        foreach ($pattern in $actorRestrictionPatterns) {
            if ($content -match $pattern) {
                $hasActorRestriction = $true
                break
            }
        }

        # Check if secrets are referenced in a pull_request_target workflow
        $referencesSecrets = $content -match 'secrets\.'

        $triggerList = $foundTriggers -join ', '
        $hasPRT = $foundTriggers -contains 'pull_request_target'
        if ($hasPRT) { $sawPullRequestTarget = $true }

        if ($checksOutUntrusted) {
            $attackMappings = @('nx-pwn-request', 'prt-scan-ai-automated', 'trivy-supply-chain-2026', 'azure-karpenter-pwn-request')
            if ($foundTriggers -contains 'workflow_run') {
                $attackMappings += 'hackerbot-claw'
            }

            $detail = "Uses $triggerList and checks out untrusted PR code. This allows attacker-controlled code to run with elevated permissions, as exploited in the prt-scan campaign (475+ malicious PRs, ~10% success rate) and the Trivy supply chain worm."
            if (-not $hasActorRestriction) {
                $detail += ' No actor-restriction conditions detected to limit who can trigger this workflow.'
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource $wf.Path `
                -Detail $detail `
                -Remediation 'Do not checkout the PR head ref in pull_request_target workflows. Use pull_request trigger instead, or run untrusted code in a separate unprivileged workflow. Add actor-restriction conditions (e.g., check github.event.pull_request.author_association) to limit execution to trusted contributors.' `
                -AttackMapping $attackMappings))
        }
        elseif ($hasPRT -and $referencesSecrets) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Uses $triggerList and references secrets. Secrets are available to pull_request_target workflows even for fork PRs, enabling exfiltration if the workflow processes untrusted input." `
                -Remediation 'Move secret-dependent steps to a separate workflow triggered by workflow_run with appropriate isolation. Use environment protection rules with required reviewers for deployments.' `
                -AttackMapping @('prt-scan-ai-automated', 'hackerbot-claw', 'nx-pwn-request')))
        }
        else {
            $detail = "Uses $triggerList without apparent checkout of untrusted code. The workflow may still run with elevated permissions."
            if (-not $hasActorRestriction) {
                $detail += ' No actor-restriction conditions detected.'
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail $detail `
                -Remediation 'Verify this workflow does not process untrusted input. Consider narrowing permissions, adding actor-restriction conditions, or switching to pull_request trigger.' `
                -AttackMapping @('nx-pwn-request', 'prt-scan-ai-automated')))
        }

        # Advisory: check if first-time contributor approval is missing
        if ($hasPRT -and $approvalGateState -eq 'absent') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'DangerousTrigger' `
                -Status 'Info' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail 'Consider enabling first-time contributor approval gates for fork PRs. Repos that required approval (Sentry, NixOS, OpenSearch) successfully blocked the prt-scan campaign.' `
                -Remediation 'In Settings > Actions > General, set "Fork pull request workflows from outside collaborators" to "Require approval for first-time contributors" or stricter.' `
                -AttackMapping @('prt-scan-ai-automated')))
        }
    }

    # Once per repo: if pull_request_target workflows exist but the approval policy
    # could not be read (HTTP 403), say so rather than silently omitting the advisory.
    if ($sawPullRequestTarget -and $approvalGateState -eq 'forbidden' -and $Owner -and $Repo) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'DangerousTrigger' `
            -Status 'Info' `
            -Severity 'Low' `
            -Resource "$Owner/$Repo" `
            -Detail 'Could not verify the fork pull request contributor approval policy (insufficient permission, HTTP 403). pull_request_target workflows were found, so the approval gate that blocked the prt-scan campaign should be verified manually.' `
            -Remediation 'Grant the token repository Administration:read, or confirm "Require approval for fork pull request workflows" in Settings > Actions > General.' `
            -AttackMapping @('prt-scan-ai-automated') `
            -Target "$Owner/$Repo"))
    }

    $results.ToArray()
}
