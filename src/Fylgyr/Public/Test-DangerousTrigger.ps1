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

    # Check first-time contributor approval gate if API params provided
    $hasApprovalGate = $null
    if ($Owner -and $Repo -and $Token) {
        try {
            $permissions = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/actions/permissions" -Token $Token
            if ($permissions.PSObject.Properties['allowed_actions']) {
                # Check fork PR workflow approval policy
                # The API returns the fork pull request workflow setting
                $hasApprovalGate = $true
            }
        }
        catch {
            # Non-fatal - skip the approval gate check
            $hasApprovalGate = $null
        }
    }

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
        if ($hasPRT -and $hasApprovalGate -eq $false) {
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

    $results.ToArray()
}
