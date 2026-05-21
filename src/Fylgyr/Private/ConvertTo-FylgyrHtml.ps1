function ConvertTo-FylgyrHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$Target = '',

        [string[]]$ScannedTargets = @(),

        [string]$OutputPath
    )

    $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
    $version = if ($module -and $module.Version) { $module.Version.ToString() } else { '0.0.0' }
    if ($version -match '^0(\.0)+$') {
        $manifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'Fylgyr.psd1'
        if (Test-Path -Path $manifestPath -PathType Leaf) {
            try {
                $manifestData = Import-PowerShellDataFile -Path $manifestPath
                if ($manifestData -and $manifestData.ModuleVersion) {
                    $version = [string]$manifestData.ModuleVersion
                }
            }
            catch {
                Write-Verbose "Unable to resolve module version from manifest: $($_.Exception.Message)"
            }
        }
    }

    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'Data' | Join-Path -ChildPath 'report-template.html'
    if (-not (Test-Path -Path $templatePath -PathType Leaf)) {
        throw "HTML template not found at '$templatePath'."
    }

    $coveragePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath '..' | Join-Path -ChildPath '..' | Join-Path -ChildPath 'docs' | Join-Path -ChildPath 'COVERAGE.md'
    $coverageSummaryHtml = '<div class="coverage-card"><h3>Coverage Map</h3><p>Coverage summary unavailable.</p></div>'
    $openGapIds = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -Path $coveragePath -PathType Leaf) {
        $coverageText = Get-Content -Path $coveragePath -Raw
        $coverageLineRaw = [regex]::Match($coverageText, '(?m)^\s*\*{0,2}\s*Coverage:[^\n]+').Value
        $openGapsLineRaw = [regex]::Match($coverageText, '(?m)^\s*\*{0,2}\s*Open gaps:\s*[^\n]+').Value

        $coverageLine = if ($coverageLineRaw) { (($coverageLineRaw -replace '^\s*\*{0,2}\s*', '') -replace '\*{0,2}\s*$', '').Trim() } else { '' }
        $openGapsLine = if ($openGapsLineRaw) { (($openGapsLineRaw -replace '^\s*\*{0,2}\s*', '') -replace '\*{0,2}\s*$', '').Trim() } else { '' }

        if ($coverageLine -match 'Open gaps:') {
            $parts = $coverageLine -split 'Open gaps:', 2
            $coverageLine = ($parts[0]).Trim()
            if ($parts.Count -gt 1 -and [string]::IsNullOrWhiteSpace($openGapsLine)) {
                $gapsText = ($parts[1]).Trim().TrimEnd('.')
                if (-not [string]::IsNullOrWhiteSpace($gapsText)) {
                    $openGapsLine = "Open gaps: $gapsText."
                }
            }
        }

        $coverageLine = $coverageLine.Trim().TrimEnd('.')
        if (-not [string]::IsNullOrWhiteSpace($coverageLine)) {
            $coverageLine = "$coverageLine."
        }

        $openGapsLine = $openGapsLine.Trim().TrimEnd('.')
        if (-not [string]::IsNullOrWhiteSpace($openGapsLine) -and $openGapsLine -notmatch '^Open gaps:') {
            $openGapsLine = "Open gaps: $openGapsLine"
        }
        if (-not [string]::IsNullOrWhiteSpace($openGapsLine)) {
            $openGapsLine = "$openGapsLine."
        }

        $owaspText = if ($coverageLine) { [System.Net.WebUtility]::HtmlEncode($coverageLine) } else { 'Coverage summary not found.' }
        $openGapsText = if ($openGapsLine) { [System.Net.WebUtility]::HtmlEncode($openGapsLine) } else { 'Open gaps summary not found.' }

        if ($openGapsLine -match '^Open gaps:\s*(.+)\.$') {
            foreach ($gapId in @($Matches[1] -split ',')) {
                $normalizedGapId = ([string]$gapId).Trim()
                if (-not [string]::IsNullOrWhiteSpace($normalizedGapId)) {
                    $openGapIds.Add($normalizedGapId)
                }
            }
        }

$coverageSummaryHtml = @"
<div class="coverage-card">
  <h3>Coverage Dashboard</h3>
  <p>$owaspText</p>
  <p>$openGapsText</p>
</div>
"@
    }

    $summary = [ordered]@{
        total      = $Results.Count
        pass       = ($Results | Where-Object Status -EQ 'Pass').Count
        fail       = ($Results | Where-Object Status -EQ 'Fail').Count
        warning    = ($Results | Where-Object Status -EQ 'Warning').Count
        error      = ($Results | Where-Object Status -EQ 'Error').Count
        info       = ($Results | Where-Object Status -EQ 'Info').Count
        suppressed = ($Results | Where-Object Status -EQ 'Suppressed').Count
    }

    $scannedRepoSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($scanTarget in @($ScannedTargets)) {
        if ([string]::IsNullOrWhiteSpace($scanTarget)) {
            continue
        }

        $normalizedTarget = [string]$scanTarget
        if ($normalizedTarget -match '^org/') {
            continue
        }

        if ($normalizedTarget -match '^[^/]+/[^/]+$') {
            $scannedRepoSet.Add($normalizedTarget) | Out-Null
        }
    }

    $orgSections = [System.Collections.Generic.List[string]]::new()
    $repoSections = [System.Collections.Generic.List[string]]::new()
    $otherSections = [System.Collections.Generic.List[string]]::new()
    $orgTocItems = [System.Collections.Generic.List[string]]::new()
    $repoTocItems = [System.Collections.Generic.List[string]]::new()
    $otherTocItems = [System.Collections.Generic.List[string]]::new()
    $repoTargetSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $groupIndex = 0
    $resultGroups = @($Results | Group-Object -Property Target | Sort-Object -Property Name)
    foreach ($resultGroup in $resultGroups) {
        $groupIndex++
        $rawGroupName = [string]$resultGroup.Name
        if ([string]::IsNullOrWhiteSpace($rawGroupName)) {
            $rawGroupName = 'unknown'
        }

        $groupTitle = [System.Net.WebUtility]::HtmlEncode($rawGroupName)
        $groupId = "target-$groupIndex"
        $groupCheckCount = @($resultGroup.Group).Count
        $groupNonPassCount = @($resultGroup.Group | Where-Object { $_.Status -ne 'Pass' }).Count

        $checkGroups = @($resultGroup.Group | Group-Object -Property CheckName)
        $checkHtml = [System.Collections.Generic.List[string]]::new()
        foreach ($checkGroup in $checkGroups) {
            $checkName = [System.Net.WebUtility]::HtmlEncode([string]$checkGroup.Name)
            $findingHtml = [System.Collections.Generic.List[string]]::new()

            foreach ($result in @($checkGroup.Group)) {
                $status = [string]$result.Status
                $statusClass = switch ($status) {
                    'Fail' { 'status-fail' }
                    'Warning' { 'status-warning' }
                    'Error' { 'status-error' }
                    'Info' { 'status-info' }
                    'Suppressed' { 'status-suppressed' }
                    default { 'status-pass' }
                }

                $detail = [System.Net.WebUtility]::HtmlEncode([string]$result.Detail)
                $resource = [System.Net.WebUtility]::HtmlEncode([string]$result.Resource)
                $severity = [System.Net.WebUtility]::HtmlEncode([string]$result.Severity)
                $remediation = [System.Net.WebUtility]::HtmlEncode([string]$result.Remediation)

                $attacksHtml = ''
                $attackText = @($result.AttackMapping) -join ', '
                if (-not [string]::IsNullOrWhiteSpace($attackText)) {
                    $attacksHtml = "<p><strong>Attacks:</strong> $([System.Net.WebUtility]::HtmlEncode($attackText))</p>"
                }

                $evidenceHtml = ''
                if ($result.PSObject.Properties.Name -contains 'Evidence' -and $result.Evidence) {
                    $evidence = $result.Evidence
                    $yamlSnippet = if ($evidence.YamlSnippet) { [System.Net.WebUtility]::HtmlEncode([string]$evidence.YamlSnippet) } else { '' }
                    $commitSha = if ($evidence.CommitSha) { [System.Net.WebUtility]::HtmlEncode([string]$evidence.CommitSha) } else { '' }
                    $scanTime = if ($evidence.ScanTime) { [System.Net.WebUtility]::HtmlEncode(([datetime]$evidence.ScanTime).ToString('o')) } else { '' }
                    $permalink = if ($evidence.Permalink) { [System.Net.WebUtility]::HtmlEncode([string]$evidence.Permalink) } else { '' }

                    $yamlBlock = if ($yamlSnippet) { "<h5>YamlSnippet</h5><pre>$yamlSnippet</pre>" } else { '' }
                    $commitBlock = if ($commitSha) { "<p><strong>CommitSha:</strong> $commitSha</p>" } else { '' }
                    $timeBlock = if ($scanTime) { "<p><strong>ScanTime:</strong> $scanTime</p>" } else { '' }
                    $linkBlock = if ($permalink) { "<p><strong>Permalink:</strong> <a href='$permalink'>$permalink</a></p>" } else { '' }

$evidenceHtml = @"
<details class="evidence-block">
  <summary>Evidence</summary>
  $commitBlock
  $timeBlock
  $linkBlock
  $yamlBlock
</details>
"@
                }

$findingHtml.Add(@"
<div class="finding $statusClass">
  <div class="finding-header">
    <span class="status">$status</span>
    <span class="severity">$severity</span>
  </div>
  <p class="detail">$detail</p>
  <p><strong>Resource:</strong> $resource</p>
  <p><strong>Remediation:</strong> $remediation</p>
  $attacksHtml
  $evidenceHtml
</div>
"@)
            }

$checkHtml.Add(@"
<section class="check-group">
  <h4>$checkName</h4>
  $($findingHtml -join "`n")
</section>
"@)
        }

$groupHtml = @"
<section class="repo-group">
  <h3 id="$groupId">$groupTitle</h3>
  <p class="group-meta">$groupNonPassCount non-pass result(s) across $groupCheckCount check result(s).</p>
  $($checkHtml -join "`n")
</section>
"@

        $tocItem = "<li><a href='#$groupId'>$groupTitle</a><span class='toc-count'>$groupNonPassCount non-pass / $groupCheckCount checks</span></li>"
        if ($rawGroupName -match '^org/') {
            $orgSections.Add($groupHtml)
            $orgTocItems.Add($tocItem)
        }
        elseif ($rawGroupName -match '^[^/]+/[^/]+$') {
            $repoSections.Add($groupHtml)
            $repoTocItems.Add($tocItem)
            $repoTargetSet.Add($rawGroupName) | Out-Null
        }
        else {
            $otherSections.Add($groupHtml)
            $otherTocItems.Add($tocItem)
        }
    }

    $repoScannedCount = if ($scannedRepoSet.Count -gt 0) { $scannedRepoSet.Count } else { $repoTargetSet.Count }
    $repoMissingCount = 0
    if ($scannedRepoSet.Count -gt 0) {
        foreach ($scannedRepo in $scannedRepoSet) {
            if (-not $repoTargetSet.Contains($scannedRepo)) {
                $repoMissingCount++
            }
        }
    }
    $repoWithResultsCount = if ($repoScannedCount -gt 0) { [Math]::Max(0, $repoScannedCount - $repoMissingCount) } else { $repoTargetSet.Count }

        $scanScopeHtml = @(
                '<h2>Scan Scope</h2>'
                '<div class="summary-grid">'
            "  <div class=""summary-item""><h3>$repoScannedCount</h3><p>Repositories Scanned</p></div>"
            "  <div class=""summary-item""><h3>$repoWithResultsCount</h3><p>Repositories With Results</p></div>"
            "  <div class=""summary-item""><h3>$repoMissingCount</h3><p>Repositories Without Results</p></div>"
            "  <div class=""summary-item""><h3>$($orgSections.Count)</h3><p>Organization Targets</p></div>"
            "  <div class=""summary-item""><h3>$($repoSections.Count)</h3><p>Repository Targets</p></div>"
                '</div>'
        ) -join "`n"

    $tocBlocks = [System.Collections.Generic.List[string]]::new()
    if ($orgTocItems.Count -gt 0) {
        $orgTocBlock = @(
            '<h3><a href="#scope-org">Organization Scope</a></h3>'
            '<ul class="toc-list">'
            "  $($orgTocItems -join "`n  ")"
            '</ul>'
        ) -join "`n"
        $tocBlocks.Add($orgTocBlock)
    }
    if ($repoTocItems.Count -gt 0) {
        $repoTocBlock = @(
            '<h3><a href="#scope-repo">Repository Scope</a></h3>'
            '<ul class="toc-list">'
            "  $($repoTocItems -join "`n  ")"
            '</ul>'
        ) -join "`n"
        $tocBlocks.Add($repoTocBlock)
    }
    if ($otherTocItems.Count -gt 0) {
        $otherTocBlock = @(
            '<h3><a href="#scope-other">Other Scope</a></h3>'
            '<ul class="toc-list">'
            "  $($otherTocItems -join "`n  ")"
            '</ul>'
        ) -join "`n"
        $tocBlocks.Add($otherTocBlock)
    }
    $tableOfContentsHtml = if ($tocBlocks.Count -gt 0) { $tocBlocks -join "`n" } else { '<p>No targets were included in this report.</p>' }

    $riskCandidates = @($Results | Where-Object { $_.Status -in @('Fail', 'Warning', 'Error') })
    $severityRank = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
    $statusRank = @{ Warning = 1; Fail = 2; Error = 3 }

    $orderedRiskCandidates = @($riskCandidates | Sort-Object -Property @(
        @{ Expression = { if ($severityRank.ContainsKey([string]$_.Severity)) { $severityRank[[string]$_.Severity] } else { -1 } }; Descending = $true },
        @{ Expression = { if ($statusRank.ContainsKey([string]$_.Status)) { $statusRank[[string]$_.Status] } else { -1 } }; Descending = $true },
        @{ Expression = { [string]$_.CheckName }; Descending = $false }
    ))

    $prioritizedRiskItems = [System.Collections.Generic.List[string]]::new()
    $riskLimit = [Math]::Min(10, $orderedRiskCandidates.Count)
    for ($riskIndex = 0; $riskIndex -lt $riskLimit; $riskIndex++) {
        $riskResult = $orderedRiskCandidates[$riskIndex]
        $riskCheckName = [System.Net.WebUtility]::HtmlEncode([string]$riskResult.CheckName)
        $riskSeverity = [System.Net.WebUtility]::HtmlEncode([string]$riskResult.Severity)
        $riskStatus = [System.Net.WebUtility]::HtmlEncode([string]$riskResult.Status)
        $riskTarget = [System.Net.WebUtility]::HtmlEncode([string]$riskResult.Target)
        $riskResource = [System.Net.WebUtility]::HtmlEncode([string]$riskResult.Resource)
        $prioritizedRiskItems.Add("<li><strong>$riskCheckName</strong><span class='risk-meta'>$riskSeverity / $riskStatus</span><span class='risk-meta'>target: $riskTarget</span><span class='risk-meta'>resource: $riskResource</span></li>")
    }

    $criticalHighCount = @($riskCandidates | Where-Object { $_.Severity -in @('Critical', 'High') }).Count
    $mediumCount = @($riskCandidates | Where-Object { $_.Severity -eq 'Medium' }).Count

    $openGapPills = [System.Collections.Generic.List[string]]::new()
    foreach ($gapId in $openGapIds) {
        $openGapPills.Add("<span class='pill'>$([System.Net.WebUtility]::HtmlEncode($gapId))</span>")
    }

    $prioritizedRiskListHtml = if ($prioritizedRiskItems.Count -gt 0) {
@"
<h3>Prioritized Findings</h3>
<ul class="risk-list">
  $($prioritizedRiskItems -join "`n  ")
</ul>
"@
    }
    else {
        '<p>No fail/warning/error findings in this report.</p>'
    }

    $missingRiskHtml = if ($openGapPills.Count -gt 0) {
@"
<h3>Missing OWASP Coverage</h3>
<p>$($openGapPills -join ' ')</p>
"@
    }
    else {
        '<h3>Missing OWASP Coverage</h3><p>No open OWASP gaps listed in coverage metadata.</p>'
    }

$riskPrioritizationHtml = @"
<div class="summary-grid">
  <div class="summary-item"><h3>$criticalHighCount</h3><p>Critical/High Findings</p></div>
  <div class="summary-item"><h3>$mediumCount</h3><p>Medium Findings</p></div>
  <div class="summary-item"><h3>$($riskCandidates.Count)</h3><p>Total Prioritized Findings</p></div>
</div>
$prioritizedRiskListHtml
$missingRiskHtml
"@

    $scopeSections = [System.Collections.Generic.List[string]]::new()
    if ($orgSections.Count -gt 0) {
        $orgScopeSection = @(
            '<section class="scope-block" id="scope-org">'
            "  <h3>Organization Scope ($($orgSections.Count) target(s))</h3>"
            "  $($orgSections -join "`n")"
            '</section>'
        ) -join "`n"
        $scopeSections.Add($orgScopeSection)
    }
    if ($repoSections.Count -gt 0) {
        $repoScopeSection = @(
            '<section class="scope-block" id="scope-repo">'
            "  <h3>Repository Scope ($($repoSections.Count) target(s))</h3>"
            "  $($repoSections -join "`n")"
            '</section>'
        ) -join "`n"
        $scopeSections.Add($repoScopeSection)
    }
    if ($otherSections.Count -gt 0) {
        $otherScopeSection = @(
            '<section class="scope-block" id="scope-other">'
            "  <h3>Other Scope ($($otherSections.Count) target(s))</h3>"
            "  $($otherSections -join "`n")"
            '</section>'
        ) -join "`n"
        $scopeSections.Add($otherScopeSection)
    }
    $resultSectionsHtml = if ($scopeSections.Count -gt 0) { $scopeSections -join "`n" } else { '<p>No findings were produced for this run.</p>' }

    $template = Get-Content -Path $templatePath -Raw
    $html = $template
    $html = $html.Replace('{{TITLE}}', 'Fylgyr HTML Report')
    $html = $html.Replace('{{GENERATED_AT}}', [System.Net.WebUtility]::HtmlEncode((Get-Date -Format 'o')))
    $html = $html.Replace('{{TARGET}}', [System.Net.WebUtility]::HtmlEncode($Target))
    $html = $html.Replace('{{VERSION}}', [System.Net.WebUtility]::HtmlEncode($version))
    $html = $html.Replace('{{SUMMARY_TOTAL}}', [string]$summary.total)
    $html = $html.Replace('{{SUMMARY_PASS}}', [string]$summary.pass)
    $html = $html.Replace('{{SUMMARY_FAIL}}', [string]$summary.fail)
    $html = $html.Replace('{{SUMMARY_WARNING}}', [string]$summary.warning)
    $html = $html.Replace('{{SUMMARY_ERROR}}', [string]$summary.error)
    $html = $html.Replace('{{SUMMARY_INFO}}', [string]$summary.info)
    $html = $html.Replace('{{SUMMARY_SUPPRESSED}}', [string]$summary.suppressed)
    $html = $html.Replace('{{SCAN_SCOPE}}', $scanScopeHtml)
    $html = $html.Replace('{{TABLE_OF_CONTENTS}}', $tableOfContentsHtml)
    $html = $html.Replace('{{RISK_PRIORITIES}}', $riskPrioritizationHtml)
    $html = $html.Replace('{{COVERAGE_DASHBOARD}}', $coverageSummaryHtml)
    $html = $html.Replace('{{RESULT_SECTIONS}}', $resultSectionsHtml)

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $html -Encoding UTF8
        return
    }

    return $html
}
