function Test-RunnerHygiene {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [System.Object[]]$WorkflowFiles,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [string]$Token
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
        $runsOnValues = [System.Collections.Generic.List[string]]::new()

        $lines = $stripped -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match '(?i)^\s*runs-on:\s*(.+)$') {
                $runsOnValues.Add($Matches[1].Trim())
            }
            elseif ($line -match '(?i)^\s*runs-on:\s*$') {
                $labels = [System.Collections.Generic.List[string]]::new()
                $j = $i + 1
                while ($j -lt $lines.Count -and $lines[$j] -match '^\s+-\s+(.+)$') {
                    $labels.Add($Matches[1].Trim())
                    $j++
                }
                if ($labels.Count -gt 0) {
                    $runsOnValues.Add($labels -join ', ')
                }
            }
        }

        $foundSelfHosted = $false

        foreach ($runsOnValue in $runsOnValues) {
            # Skip GitHub-hosted runners
            if ($runsOnValue -match $hostedPattern) {
                continue
            }

            # Matrix/expression - cannot determine at analysis time; warn conservatively
            if ($runsOnValue -match '^\$\{\{') {
                $foundSelfHosted = $true
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Warning' `
                    -Severity 'Low' `
                    -Resource "$path" `
                    -Detail "Workflow '$name' uses a dynamic runner expression ('$runsOnValue'). If this resolves to a self-hosted runner, review the security hardening guidance." `
                    -Remediation 'Verify the expression never resolves to a self-hosted runner in untrusted contexts. See: https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners' `
                    -AttackMapping @('github-actions-cryptomining', 'praetorian-runner-pivot') `
                    -Target $null))
                continue
            }

            # Check for self-hosted label or non-standard runner
            $isSelfHosted = $runsOnValue -match $selfHostedPattern -or
                            $runsOnValue -notmatch $hostedPattern

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
                    -Detail "Workflow '$name' uses a self-hosted runner ('$runsOnValue') with a dangerous trigger (pull_request_target or workflow_run). Attacker-controlled code from a fork could execute on your runner, as demonstrated in the Praetorian lateral movement attack." `
                    -Remediation 'Move this job to a GitHub-hosted runner, or ensure the workflow never checks out untrusted code on a self-hosted runner. Use ephemeral runners and restrict runner groups to specific repositories.' `
                    -AttackMapping @('github-actions-cryptomining', 'nx-pwn-request', 'praetorian-runner-pivot') `
                    -Target $null))
            }
            elseif ($hasPullRequest) {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Warning' `
                    -Severity 'Medium' `
                    -Resource "$path" `
                    -Detail "Workflow '$name' uses a self-hosted runner ('$runsOnValue') with a pull_request trigger. Fork PRs can run arbitrary code on your self-hosted runner." `
                    -Remediation "If this repository is public, switch to GitHub-hosted runners for PR workflows. If private, verify fork PR access is restricted. Consider ephemeral runners to limit persistence." `
                    -AttackMapping @('github-actions-cryptomining', 'praetorian-runner-pivot') `
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
                    -AttackMapping @('github-actions-cryptomining', 'praetorian-runner-pivot') `
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

    # Org-level runner checks (require API access).
    # These hit `orgs/{Owner}/...` and must not re-fire once per repository on an org-wide scan.
    # Invoke-Fylgyr resets $script:FylgyrOwnerRunnerGroupsChecked in its begin block;
    # we suppress the org block here if this owner was already checked in the current run.
    $orgAlreadyChecked = $false
    if ($script:FylgyrOwnerRunnerGroupsChecked -is [hashtable] -and $Owner) {
        if ($script:FylgyrOwnerRunnerGroupsChecked.ContainsKey($Owner)) {
            $orgAlreadyChecked = $true
        }
        else {
            $script:FylgyrOwnerRunnerGroupsChecked[$Owner] = $true
        }
    }

    if ($Owner -and $Token -and -not $orgAlreadyChecked) {
        $target = if ($Repo) { "$Owner/$Repo" } else { $Owner }

        # Check org-wide runner groups
        try {
            $runnerGroups = Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/runner-groups" -Token $Token
            if ($runnerGroups.runner_groups) {
                foreach ($group in $runnerGroups.runner_groups) {
                    # Flag runner groups available to all repos
                    if ($group.visibility -eq 'all' -or $group.allows_public_repositories -eq $true) {
                        $detail = "Runner group '$($group.name)' is available to all repositories in the organization."
                        if ($group.allows_public_repositories -eq $true) {
                            $detail += ' Public repositories can use these runners, enabling fork PR abuse.'
                        }

                        $results.Add((Format-FylgyrResult `
                            -CheckName 'RunnerHygiene' `
                            -Status 'Fail' `
                            -Severity 'High' `
                            -Resource "$target (runner-group: $($group.name))" `
                            -Detail $detail `
                            -Remediation "Restrict this runner group to specific repositories in Settings > Actions > Runner groups. Disable 'Allow public repositories' to prevent fork PR abuse. This was the exact attack path in the Praetorian lateral movement demonstration." `
                            -AttackMapping @('praetorian-runner-pivot', 'github-actions-cryptomining') `
                            -Target $target))
                    }
                }
            }
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -notmatch '404' -and $msg -notmatch '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'RunnerHygiene' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $target `
                    -Detail "Failed to check org runner groups: $($_.Exception.Message)" `
                    -Remediation 'Verify the token has org admin access to read runner group configuration.' `
                    -Target $target))
            }
        }

        # Check for non-ephemeral self-hosted runners at org level
        try {
            $orgRunners = Invoke-GitHubApi -Endpoint "orgs/$Owner/actions/runners" -Token $Token
            if ($orgRunners.runners) {
                foreach ($runner in $orgRunners.runners) {
                    # Check if runner is not ephemeral (persistent runners = persistence for attackers)
                    if ($runner.PSObject.Properties['ephemeral'] -and $runner.ephemeral -eq $false) {
                        $results.Add((Format-FylgyrResult `
                            -CheckName 'RunnerHygiene' `
                            -Status 'Warning' `
                            -Severity 'Medium' `
                            -Resource "$target (runner: $($runner.name))" `
                            -Detail "Self-hosted runner '$($runner.name)' is not configured as ephemeral. Persistent runners allow attackers to maintain access across workflow runs." `
                            -Remediation 'Configure runners with --ephemeral flag so they are automatically de-registered after each job. This limits persistence for attackers who gain runner access.' `
                            -AttackMapping @('praetorian-runner-pivot', 'github-actions-cryptomining') `
                            -Target $target))
                    }
                }
            }
        }
        catch {
            Write-Debug "Org runner listing skipped: $($_.Exception.Message)"
        }
    }

    # Repo-level runner listing always runs per-repo (not cached at owner level).
    if ($Owner -and $Token -and $Repo) {
        $target = "$Owner/$Repo"
        try {
            $repoRunners = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/actions/runners" -Token $Token
            if ($repoRunners.runners -and $repoRunners.runners.Count -gt 0) {
                $isPublic = $false
                try {
                    $repoInfo = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo" -Token $Token
                    $isPublic = -not $repoInfo.private
                }
                catch {
                    Write-Debug "Repo info lookup skipped: $($_.Exception.Message)"
                }

                if ($isPublic) {
                    $results.Add((Format-FylgyrResult `
                        -CheckName 'RunnerHygiene' `
                        -Status 'Fail' `
                        -Severity 'Critical' `
                        -Resource "$target" `
                        -Detail "$($repoRunners.runners.Count) self-hosted runner(s) registered on a public repository. Anyone who forks this repo can potentially execute code on your runners." `
                        -Remediation 'Remove self-hosted runners from public repositories or switch to GitHub-hosted runners. If self-hosted runners are required, use ephemeral runners with strict network isolation.' `
                        -AttackMapping @('github-actions-cryptomining', 'praetorian-runner-pivot') `
                        -Target $target))
                }

                foreach ($runner in $repoRunners.runners) {
                    if ($runner.PSObject.Properties['ephemeral'] -and $runner.ephemeral -eq $false) {
                        $results.Add((Format-FylgyrResult `
                            -CheckName 'RunnerHygiene' `
                            -Status 'Warning' `
                            -Severity 'Medium' `
                            -Resource "$target (runner: $($runner.name))" `
                            -Detail "Self-hosted runner '$($runner.name)' is not ephemeral. Persistent runners allow attackers to maintain access across workflow runs." `
                            -Remediation 'Configure runners with --ephemeral flag. This limits persistence for attackers.' `
                            -AttackMapping @('praetorian-runner-pivot') `
                            -Target $target))
                    }
                }
            }
        }
        catch {
            Write-Debug "Repo runner listing skipped: $($_.Exception.Message)"
        }
    }

    $results.ToArray()
}
