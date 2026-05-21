function Write-FylgyrConsole {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output requires Write-Host for colored formatting')]
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$Target = '',

        [int]$ScannedRepoCount = -1
    )

    Write-Host ''
    Write-Host "  Fylgyr Supply-Chain Audit: $Target" -ForegroundColor Cyan
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray

    # Separate repos with no workflows from repos with actual check results
    $noWorkflowResults = $Results | Where-Object { $_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Warning' }
    $checkResults = $Results | Where-Object { -not ($_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Warning') }

    # Build a consolidated recommendation set so users get actionable next steps
    # in addition to per-finding remediation text.
    $recommendationItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $recommendationKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $addRecommendation = {
        param(
            [int]$Priority,
            [string]$Key,
            [string]$Text
        )

        if (-not $recommendationKeys.Contains($Key)) {
            $recommendationKeys.Add($Key) | Out-Null
            $recommendationItems.Add([PSCustomObject]@{
                    Priority = $Priority
                    Text     = $Text
                })
        }
    }

    $nonPassResults = @($checkResults | Where-Object { $_.Status -in @('Fail', 'Warning', 'Error') })

    if (@($nonPassResults | Where-Object { $_.Status -eq 'Error' }).Count -gt 0) {
        & $addRecommendation 0 'errors' 'P0 Resolve API/token scope errors first so coverage is complete.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'OrgMfaPolicy' -and $_.Status -eq 'Fail' }).Count -gt 0) {
        & $addRecommendation 0 'org-mfa' 'P0 Enforce organization-wide MFA immediately to reduce account takeover risk from stolen passwords.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'OrgActionRestrictions' -and $_.Status -eq 'Fail' }).Count -gt 0) {
        & $addRecommendation 1 'org-actions' "P1 Restrict organization actions to 'selected' and maintain an explicit allowlist of trusted sources."
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'ActionPinning' -and $_.Status -eq 'Fail' }).Count -gt 0) {
        & $addRecommendation 1 'action-pinning' 'P1 Pin third-party actions to full 40-character commit SHAs to prevent mutable-tag supply chain attacks.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'Rulesets' -and $_.Detail -match 'tag protection' }).Count -gt 0) {
        & $addRecommendation 1 'tag-protection' 'P1 Protect release tags with a tag ruleset (for example v*) to prevent mutable tag poisoning.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'BranchProtection' -and $_.Detail -match '0 approving reviews' }).Count -gt 0) {
        & $addRecommendation 1 'approvals' 'P1 Set at least 1 required approval on the default branch, or explicitly document solo-maintainer exception with compensating controls.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'BranchProtection' -and $_.Detail -match 'status checks|pull requests|non-fast-forward|deletion' }).Count -gt 0) {
        & $addRecommendation 1 'branch-baseline' 'P1 Keep default branch baseline: PR-required, strict status checks, force-push blocked, and deletion blocked.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'BranchProtection' -and $_.Detail -match 'no classic branch protection|no active branch ruleset targeting it' }).Count -gt 0) {
        & $addRecommendation 1 'branch-protection' 'P1 Add active branch protection for the default branch (classic branch protection or branch-target ruleset).'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'SignedCommit' }).Count -gt 0) {
        & $addRecommendation 2 'signed-commits' 'P2 Require signed commits on the default branch to reduce maintainer impersonation risk.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'EgressControl' }).Count -gt 0) {
        & $addRecommendation 2 'egress' 'P2 Add CI egress controls to limit outbound traffic from compromised actions or injected workflow code.'
    }

    if (@($nonPassResults | Where-Object { $_.CheckName -eq 'CodeOwner' }).Count -gt 0) {
        & $addRecommendation 3 'codeowner' 'P3 Add a trusted co-owner in CODEOWNERS (or migrate to an organization team) to reduce single-maintainer risk.'
    }

    # Group by Target (Owner/Repo)
    if ($checkResults.Count -gt 0) {
        $repoGroups = $checkResults | Group-Object -Property Target

        foreach ($repoGroup in $repoGroups) {
            Write-Host ''
            Write-Host "  [$($repoGroup.Name)]" -ForegroundColor Cyan

            $checkGroups = @($repoGroup.Group | Group-Object -Property CheckName)

            for ($i = 0; $i -lt $checkGroups.Count; $i++) {
                $checkGroup = $checkGroups[$i]
                $passes = @($checkGroup.Group | Where-Object { $_.Status -eq 'Pass' })
                $failures = @($checkGroup.Group | Where-Object { $_.Status -ne 'Pass' })

                if ($i -gt 0) { Write-Host '' }

                Write-Host "    > $($checkGroup.Name)  " -ForegroundColor White -NoNewline

                if ($failures.Count -eq 0) {
                    $passDetail = $passes[0].Detail
                    if ($passes.Count -gt 1) {
                        Write-Host "[PASS]" -ForegroundColor Green
                        Write-Host "        $passDetail ($($passes.Count) files)" -ForegroundColor DarkGray
                    }
                    else {
                        Write-Host "[PASS]" -ForegroundColor Green
                        Write-Host "        $passDetail" -ForegroundColor DarkGray
                    }
                }
                else {
                    $onlyInfo = @($failures | Where-Object { $_.Status -notin @('Info', 'Suppressed') }).Count -eq 0
                    if ($passes.Count -gt 0) {
                        Write-Host "[$($passes.Count) passed, $($failures.Count) finding(s)]" -ForegroundColor Yellow
                    }
                    elseif ($onlyInfo) {
                        Write-Host "[$($failures.Count) info]" -ForegroundColor Cyan
                    }
                    else {
                        Write-Host "[$($failures.Count) finding(s)]" -ForegroundColor Red
                    }

                    foreach ($r in $failures) {
                        $icon = switch ($r.Status) {
                            'Fail'    { '[FAIL]' }
                            'Warning' { '[WARN]' }
                            'Error'   { '[ERR]' }
                            'Info'    { '[INFO]' }
                            'Suppressed' { '[SUPP]' }
                            default   { '[?]' }
                        }
                        $color = switch ($r.Status) {
                            'Fail'    { 'Red' }
                            'Warning' { 'Yellow' }
                            'Error'   { 'Magenta' }
                            'Info'    { 'Cyan' }
                            'Suppressed' { 'DarkCyan' }
                            default   { 'Gray' }
                        }

                        Write-Host "      $icon " -ForegroundColor $color -NoNewline
                        Write-Host "$($r.Detail)" -ForegroundColor $color
                        Write-Host "        Resource:    $($r.Resource)" -ForegroundColor DarkGray
                        Write-Host "        Severity:    $($r.Severity)" -ForegroundColor DarkGray
                        Write-Host "        Remediation: $($r.Remediation)" -ForegroundColor DarkGray

                        if ($r.AttackMapping.Count -gt 0) {
                            Write-Host "        Attacks:     $($r.AttackMapping -join ', ')" -ForegroundColor DarkGray
                        }

                        if ($r.PSObject.Properties.Name -contains 'Evidence' -and $r.Evidence -and $VerbosePreference -ne 'SilentlyContinue') {
                            Write-Host '        Evidence:' -ForegroundColor DarkGray

                            if ($r.Evidence.CommitSha) {
                                Write-Host "          CommitSha: $($r.Evidence.CommitSha)" -ForegroundColor DarkGray
                            }
                            if ($r.Evidence.ScanTime) {
                                Write-Host "          ScanTime:  $(([datetime]$r.Evidence.ScanTime).ToString('o'))" -ForegroundColor DarkGray
                            }
                            if ($r.Evidence.Permalink) {
                                Write-Host "          Permalink: $($r.Evidence.Permalink)" -ForegroundColor DarkGray
                            }
                            if ($r.Evidence.YamlSnippet) {
                                Write-Host '          YamlSnippet:' -ForegroundColor DarkGray
                                foreach ($snippetLine in @([string]$r.Evidence.YamlSnippet -split "`n")) {
                                    Write-Host "            $snippetLine" -ForegroundColor DarkGray
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Show repos with no workflows as a compact list at the end
    if ($noWorkflowResults.Count -gt 0) {
        Write-Host ''
        Write-Host "  Repos with no workflow files ($($noWorkflowResults.Count)):" -ForegroundColor DarkGray
        foreach ($nw in $noWorkflowResults) {
            Write-Host "    - $($nw.Target)" -ForegroundColor DarkGray
        }
    }

    # Summary - prefer explicit scan count from the orchestrator; fall back to
    # grouping by Target only when the caller did not provide one.
    $totalRepos = if ($ScannedRepoCount -ge 0) {
        $ScannedRepoCount
    }
    else {
        @($Results.Target | Where-Object { $_ } | Sort-Object -Unique).Count
    }
    $passCount    = ($Results | Where-Object Status -EQ 'Pass').Count
    $failCount    = ($Results | Where-Object Status -EQ 'Fail').Count
    $warnCount    = ($Results | Where-Object Status -EQ 'Warning').Count
    $errorCount   = ($Results | Where-Object Status -EQ 'Error').Count
    $suppressedCount = ($Results | Where-Object Status -EQ 'Suppressed').Count

    Write-Host ''
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
    Write-Host "  $totalRepos repo(s) scanned | " -ForegroundColor White -NoNewline
    Write-Host "$passCount passed" -ForegroundColor Green -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$failCount failed" -ForegroundColor Red -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$warnCount warnings" -ForegroundColor Yellow -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$errorCount errors" -ForegroundColor Magenta -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$suppressedCount suppressed" -ForegroundColor DarkCyan

    if ($recommendationItems.Count -gt 0) {
        Write-Host ''
        Write-Host '  Prioritized Recommendations:' -ForegroundColor White
        foreach ($recommendation in @($recommendationItems | Sort-Object -Property Priority, Text)) {
            Write-Host "    - $($recommendation.Text)" -ForegroundColor DarkGray
        }
    }

    Write-Host ''
}
