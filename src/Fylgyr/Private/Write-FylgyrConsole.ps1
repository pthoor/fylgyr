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
                    $onlyInfo = @($failures | Where-Object { $_.Status -ne 'Info' }).Count -eq 0
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
                            default   { '[?]' }
                        }
                        $color = switch ($r.Status) {
                            'Fail'    { 'Red' }
                            'Warning' { 'Yellow' }
                            'Error'   { 'Magenta' }
                            'Info'    { 'Cyan' }
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

    Write-Host ''
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray
    Write-Host "  $totalRepos repo(s) scanned | " -ForegroundColor White -NoNewline
    Write-Host "$passCount passed" -ForegroundColor Green -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$failCount failed" -ForegroundColor Red -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$warnCount warnings" -ForegroundColor Yellow -NoNewline
    Write-Host ', ' -NoNewline
    Write-Host "$errorCount errors" -ForegroundColor Magenta
    Write-Host ''
}
