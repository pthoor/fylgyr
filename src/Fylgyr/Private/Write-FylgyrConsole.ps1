function Write-FylgyrConsole {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output requires Write-Host for colored formatting')]
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$Owner,

        [string]$Repo
    )

    $target = if ($Repo) { "$Owner/$Repo" } else { $Owner }

    Write-Host ''
    Write-Host "  Fylgyr Supply-Chain Audit: $target" -ForegroundColor Cyan
    Write-Host "  $('-' * 60)" -ForegroundColor DarkGray

    # Separate repos with no workflows from repos with actual check results
    $noWorkflowResults = $Results | Where-Object { $_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Warning' }
    $checkResults = $Results | Where-Object { -not ($_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Warning') }

    # Extract repo from Resource (format: Owner/Repo/path) for grouping
    if ($checkResults.Count -gt 0) {
        $repoGroups = $checkResults | Group-Object -Property {
            if ($_.Resource -match '^([^/]+/[^/]+)') { $Matches[1] } else { $_.Resource }
        }

        foreach ($repoGroup in $repoGroups) {
            Write-Host ''
            Write-Host "  [$($repoGroup.Name)]" -ForegroundColor Cyan

            $checkGroups = $repoGroup.Group | Group-Object -Property CheckName

            foreach ($checkGroup in $checkGroups) {
                $passes = @($checkGroup.Group | Where-Object { $_.Status -eq 'Pass' })
                $failures = @($checkGroup.Group | Where-Object { $_.Status -ne 'Pass' })

                Write-Host "    $($checkGroup.Name): " -ForegroundColor White -NoNewline

                if ($failures.Count -eq 0) {
                    # Show the detail from the first pass to explain what was verified
                    $passDetail = $passes[0].Detail
                    if ($passes.Count -gt 1) {
                        Write-Host "[PASS] $passDetail ($($passes.Count) files)" -ForegroundColor Green
                    }
                    else {
                        Write-Host "[PASS] $passDetail" -ForegroundColor Green
                    }
                }
                else {
                    if ($passes.Count -gt 0) {
                        Write-Host "$($passes.Count) passed, $($failures.Count) finding(s):" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "$($failures.Count) finding(s):" -ForegroundColor Red
                    }

                    foreach ($r in $failures) {
                        $icon = switch ($r.Status) {
                            'Fail'    { '[FAIL]' }
                            'Warning' { '[WARN]' }
                            'Error'   { '[ERR]' }
                            default   { '[?]' }
                        }
                        $color = switch ($r.Status) {
                            'Fail'    { 'Red' }
                            'Warning' { 'Yellow' }
                            'Error'   { 'Magenta' }
                            default   { 'Gray' }
                        }

                        # Show just the file path portion (strip Owner/Repo/ prefix for readability)
                        $displayResource = $r.Resource
                        if ($displayResource -match '^[^/]+/[^/]+/(.+)$') {
                            $displayResource = $Matches[1]
                        }

                        Write-Host "      $icon " -ForegroundColor $color -NoNewline
                        Write-Host "$($r.Detail)" -ForegroundColor $color
                        Write-Host "        Resource:    $displayResource" -ForegroundColor DarkGray
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
            Write-Host "    - $($nw.Resource)" -ForegroundColor DarkGray
        }
    }

    # Summary
    $totalRepos   = ($Results | Group-Object -Property {
        if ($_.Resource -match '^([^/]+/[^/]+)') { $Matches[1] } else { $_.Resource }
    }).Count
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
