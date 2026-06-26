function Test-ForkSecretExposure {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check workflow files for pull_request_target + secrets references
    foreach ($wf in $WorkflowFiles) {
        # Strip YAML comment lines to avoid false positives
        $strippedLines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        $stripped = $strippedLines -join "`n"

        # Both pull_request_target and workflow_run run in the base-repo context with
        # access to secrets while being influenced by fork-controlled content.
        $triggerPatterns = [ordered]@{
            pull_request_target = @(
                '(?m)^\s*pull_request_target\s*:'
                '(?m)^\s*on\s*:\s*pull_request_target\s*(?:#.*)?$'
                '(?m)^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]'
            )
            workflow_run = @(
                '(?m)^\s*workflow_run\s*:'
                '(?m)^\s*on\s*:\s*workflow_run\s*(?:#.*)?$'
                '(?m)^\s*on\s*:\s*\[[^\]]*\bworkflow_run\b[^\]]*\]'
            )
        }

        $matchedTrigger = $null
        foreach ($triggerName in $triggerPatterns.Keys) {
            foreach ($pattern in $triggerPatterns[$triggerName]) {
                if ($stripped -match $pattern) {
                    $matchedTrigger = $triggerName
                    break
                }
            }
            if ($matchedTrigger) { break }
        }

        if (-not $matchedTrigger) {
            continue
        }

        # Check if secrets are referenced, in both dot and bracket notation.
        $secretRefs = [System.Collections.Generic.List[string]]::new()
        $secretPatterns = @(
            '(?i)\$\{\{\s*secrets\.([a-zA-Z0-9_]+)\s*\}\}'
            '(?i)\$\{\{\s*secrets\[\s*[''"]([a-zA-Z0-9_]+)[''"]\s*\]\s*\}\}'
        )
        foreach ($secretPattern in $secretPatterns) {
            foreach ($m in [regex]::Matches($stripped, $secretPattern)) {
                $secretName = $m.Groups[1].Value
                if ($secretName -ne 'GITHUB_TOKEN' -and -not $secretRefs.Contains($secretName)) {
                    $secretRefs.Add($secretName)
                }
            }
        }

        if ($secretRefs.Count -gt 0) {
            $secretList = $secretRefs -join ', '
            if ($matchedTrigger -eq 'pull_request_target') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'ForkSecretExposure' `
                    -Status 'Fail' `
                    -Severity 'Critical' `
                    -Resource $wf.Path `
                    -Detail "Workflow '$($wf.Name)' uses pull_request_target and references secrets ($secretList). These secrets are available to code from fork PRs in this trigger context, enabling exfiltration as demonstrated by prt-scan (475+ malicious PRs) and hackerbot-claw." `
                    -Remediation 'Move secret-dependent steps to a separate workflow using workflow_run trigger with environment protection. Use environment secrets with required reviewers instead of repository secrets in pull_request_target workflows.' `
                    -AttackMapping @('prt-scan-ai-automated', 'hackerbot-claw', 'nx-pwn-request', 'azure-karpenter-pwn-request') `
                    -Target $target))
            }
            else {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'ForkSecretExposure' `
                    -Status 'Fail' `
                    -Severity 'High' `
                    -Resource $wf.Path `
                    -Detail "Workflow '$($wf.Name)' uses the workflow_run trigger and references secrets ($secretList). workflow_run executes in the base-repo context with access to secrets; if it consumes artifacts or inputs produced by the triggering (fork) run, those secrets become an exfiltration path, as in the artifact-poisoning workflow_run pattern." `
                    -Remediation 'Treat artifacts and outputs from the triggering workflow as untrusted. Gate secret use behind an environment with required reviewers, and do not execute fork-controlled content in the workflow_run job.' `
                    -AttackMapping @('artifact-poisoning-workflow-run', 'hackerbot-claw', 'prt-scan-ai-automated') `
                    -Target $target))
            }
        }
    }

    # Check environment protection rules only when dangerous triggers exist in the
    # scanned workflow files. Unprotected environments are not a fork-secret-exposure
    # risk unless a pull_request_target or workflow_run trigger is present; general
    # environment protection is handled by Test-EnvironmentProtection.
    $hasDangerousTrigger = $false
    $allTriggerPatterns = @(
        '(?m)^\s*pull_request_target\s*:'
        '(?m)^\s*on\s*:\s*pull_request_target\s*(?:#.*)?$'
        '(?m)^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]'
        '(?m)^\s*workflow_run\s*:'
        '(?m)^\s*on\s*:\s*workflow_run\s*(?:#.*)?$'
        '(?m)^\s*on\s*:\s*\[[^\]]*\bworkflow_run\b[^\]]*\]'
    )
    foreach ($wf in $WorkflowFiles) {
        $strippedLines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        $wfStripped = $strippedLines -join "`n"
        foreach ($p in $allTriggerPatterns) {
            if ($wfStripped -match $p) {
                $hasDangerousTrigger = $true
                break
            }
        }
        if ($hasDangerousTrigger) { break }
    }

    if ($hasDangerousTrigger) {
        # Check environment protection rules
        try {
            $environments = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/environments" -Token $Token
            if ($environments.environments) {
                foreach ($env in $environments.environments) {
                    $envName = $env.name
                    $hasProtection = $false

                    # Check for required reviewers
                    if ($env.protection_rules) {
                        foreach ($rule in $env.protection_rules) {
                            if ($rule.type -eq 'required_reviewers' -and $rule.reviewers -and $rule.reviewers.Count -gt 0) {
                                $hasProtection = $true
                            }
                            if ($rule.type -eq 'wait_timer' -and $rule.wait_timer -gt 0) {
                                $hasProtection = $true
                            }
                        }
                    }

                    if (-not $hasProtection) {
                        $results.Add((Format-FylgyrResult `
                            -CheckName 'ForkSecretExposure' `
                            -Status 'Fail' `
                            -Severity 'High' `
                            -Resource "$target (environment: $envName)" `
                            -Detail "Environment '$envName' has no required reviewers or wait timers. Deployments to this environment can proceed without approval, bypassing human review of potentially malicious code." `
                            -Remediation "Add required reviewers to the '$envName' environment in Settings > Environments. For production environments, also add a wait timer to allow for review." `
                            -AttackMapping @('prt-scan-ai-automated', 'hackerbot-claw') `
                            -Target $target))
                    }
                }
            }
        }
        catch {
            $msg = $_.Exception.Message

            if ($msg -match '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'ForkSecretExposure' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $target `
                    -Detail 'Insufficient permissions to list deployment environments; cannot evaluate environment protection rules.' `
                    -Remediation 'Use a token with permission to read environment settings (Actions:read for fine-grained tokens, or repo scope for classic tokens).' `
                    -Target $target))
            }
            elseif ($msg -notmatch '404') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'ForkSecretExposure' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $target `
                    -Detail "Failed to check environment protection rules: $msg" `
                    -Remediation 'Verify the token has access to read environment settings.' `
                    -Target $target))
            }
        }
    } # end if ($hasDangerousTrigger)

    # Org-level secret visibility is evaluated once per org by Test-OrgSecretVisibility
    # (an org-scoped check), not re-evaluated here for every repository.

    if ($results.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'ForkSecretExposure' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No fork secret exposure risks detected in workflow files or environment configuration.' `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
