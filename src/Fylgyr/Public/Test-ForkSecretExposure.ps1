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

        $hasPRT = $false
        $prtPatterns = @(
            '(?m)^\s*pull_request_target\s*:'
            '(?m)^\s*on\s*:\s*pull_request_target\s*(?:#.*)?$'
            '(?m)^\s*on\s*:\s*\[[^\]]*\bpull_request_target\b[^\]]*\]'
        )
        foreach ($pattern in $prtPatterns) {
            if ($stripped -match $pattern) {
                $hasPRT = $true
                break
            }
        }

        if (-not $hasPRT) {
            continue
        }

        # Check if secrets are referenced
        $secretRefs = [System.Collections.Generic.List[string]]::new()
        $secretPattern = '(?i)\$\{\{\s*secrets\.([a-zA-Z0-9_]+)\s*\}\}'
        $secretMatches = [regex]::Matches($stripped, $secretPattern)
        foreach ($m in $secretMatches) {
            $secretName = $m.Groups[1].Value
            if ($secretName -ne 'GITHUB_TOKEN' -and -not $secretRefs.Contains($secretName)) {
                $secretRefs.Add($secretName)
            }
        }

        if ($secretRefs.Count -gt 0) {
            $secretList = $secretRefs -join ', '
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
    }

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
        if ($msg -notmatch '404' -and $msg -notmatch '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ForkSecretExposure' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail "Failed to check environment protection rules: $($_.Exception.Message)" `
                -Remediation 'Verify the token has access to read environment settings.' `
                -Target $target))
        }
    }

    # Check org-level secrets without repository restrictions
    try {
        $orgSecrets = Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/secrets" -Token $Token
        if ($orgSecrets.secrets) {
            foreach ($secret in $orgSecrets.secrets) {
                if ($secret.visibility -eq 'all') {
                    $results.Add((Format-FylgyrResult `
                        -CheckName 'ForkSecretExposure' `
                        -Status 'Fail' `
                        -Severity 'High' `
                        -Resource "$Owner (org-secret: $($secret.name))" `
                        -Detail "Org-level secret '$($secret.name)' is available to all repositories. Any repository with a pull_request_target workflow can expose this secret to fork PRs." `
                        -Remediation "Restrict this secret to specific repositories in Settings > Secrets and variables > Actions. Use the 'Selected repositories' visibility option." `
                        -AttackMapping @('prt-scan-ai-automated', 'hackerbot-claw') `
                        -Target $Owner))
                }
            }
        }
    }
    catch {
        Write-Debug "Org secret listing skipped: $($_.Exception.Message)"
    }

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
