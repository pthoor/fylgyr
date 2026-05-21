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

    $manifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'Fylgyr.psd1'
    $version = ''
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

    if ([string]::IsNullOrWhiteSpace($version) -or $version -match '^0(\.0)+$') {
        $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
        if ($module -and $module.Version) {
            $version = $module.Version.ToString()
        }
    }

    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = '0.0.0'
    }

    $templatePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'Data' | Join-Path -ChildPath 'report-template.html'
    if (-not (Test-Path -Path $templatePath -PathType Leaf)) {
        throw "HTML template not found at '$templatePath'."
    }

    $coveragePath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath '..' | Join-Path -ChildPath '..' | Join-Path -ChildPath 'docs' | Join-Path -ChildPath 'COVERAGE.md'
    $coverageSummaryHtml = '<div class="coverage-card"><h3>Coverage Map</h3><p>Coverage summary unavailable.</p></div>'
    $owaspTop10BaseUrl = 'https://owasp.org/www-project-top-10-ci-cd-security-risks'
    $owaspControlUrlMap = @{
        'CICD-SEC-1'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms'
        'CICD-SEC-2'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management'
        'CICD-SEC-3'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse'
        'CICD-SEC-4'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution'
        'CICD-SEC-5'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC'
        'CICD-SEC-6'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene'
        'CICD-SEC-7'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration'
        'CICD-SEC-8'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services'
        'CICD-SEC-9'  = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation'
        'CICD-SEC-10' = 'https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-And-Visibility'
    }
    $buildOwaspControlUrl = {
        param(
            [string]$ControlId
        )

        if ($ControlId -match '^CICD-SEC-(\d+)$') {
            $normalizedControlId = "CICD-SEC-$([int]$Matches[1])"
            if ($owaspControlUrlMap.ContainsKey($normalizedControlId)) {
                return [string]$owaspControlUrlMap[$normalizedControlId]
            }
        }

        return "$owaspTop10BaseUrl/"
    }

    $openGapIds = [System.Collections.Generic.List[string]]::new()
    $coveredOwaspRisks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $missingOwaspRisks = [System.Collections.Generic.List[PSCustomObject]]::new()
    $owaspRiskNamesById = @{}
    $owaspTotalRiskCount = 0
    if (Test-Path -Path $coveragePath -PathType Leaf) {
        $coverageText = Get-Content -Path $coveragePath -Raw
        $coverageLineRaw = [regex]::Match($coverageText, '(?m)^\s*\*{0,2}\s*Coverage:[^\n]+').Value
        $openGapsLineRaw = [regex]::Match($coverageText, '(?m)^\s*\*{0,2}\s*Open gaps:\s*[^\n]+').Value

        $owaspIdSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($owaspRow in [regex]::Matches($coverageText, '(?m)^\|\s*(CICD-SEC-\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]*?)\s*\|')) {
            $owaspId = [string]$owaspRow.Groups[1].Value.Trim()
            if ([string]::IsNullOrWhiteSpace($owaspId) -or -not $owaspIdSet.Add($owaspId)) {
                continue
            }

            $owaspName = [string]$owaspRow.Groups[2].Value.Trim()
            $coveringChecks = [string]$owaspRow.Groups[4].Value.Trim()
            $owaspTotalRiskCount++
            $owaspRiskNamesById[$owaspId] = $owaspName

            $isEmDashPlaceholder = ($coveringChecks.Length -eq 1 -and [int][char]$coveringChecks[0] -eq 8212)
            $isMissingCoverage = [string]::IsNullOrWhiteSpace($coveringChecks) -or $coveringChecks -in @('-', '--', '---', '----', '-----', '------') -or $isEmDashPlaceholder
            if ($isMissingCoverage) {
                $missingOwaspRisks.Add([PSCustomObject]@{
                        Id   = $owaspId
                        Name = $owaspName
                    })
            }
            else {
                $coveredOwaspRisks.Add([PSCustomObject]@{
                        Id   = $owaspId
                        Name = $owaspName
                    })
            }
        }

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
        $gapName = ''
        if ($owaspRiskNamesById.ContainsKey([string]$gapId)) {
            $gapName = [string]$owaspRiskNamesById[[string]$gapId]
        }

        $gapLabel = if ([string]::IsNullOrWhiteSpace($gapName)) { [string]$gapId } else { "$gapId - $gapName" }
        $gapUrl = & $buildOwaspControlUrl ([string]$gapId)
        $openGapPills.Add("<a class='pill' href='$([System.Net.WebUtility]::HtmlEncode($gapUrl))' target='_blank' rel='noopener noreferrer'>$([System.Net.WebUtility]::HtmlEncode($gapLabel))</a>")
    }

    $coveredOwaspPills = [System.Collections.Generic.List[string]]::new()
    foreach ($coveredOwaspRisk in $coveredOwaspRisks) {
        $coveredLabel = if ([string]::IsNullOrWhiteSpace([string]$coveredOwaspRisk.Name)) {
            [string]$coveredOwaspRisk.Id
        }
        else {
            "$($coveredOwaspRisk.Id) - $($coveredOwaspRisk.Name)"
        }
        $coveredUrl = & $buildOwaspControlUrl ([string]$coveredOwaspRisk.Id)
        $coveredOwaspPills.Add("<a class='pill' href='$([System.Net.WebUtility]::HtmlEncode($coveredUrl))' target='_blank' rel='noopener noreferrer'>$([System.Net.WebUtility]::HtmlEncode($coveredLabel))</a>")
    }

    if ($openGapPills.Count -eq 0 -and $missingOwaspRisks.Count -gt 0) {
        foreach ($missingOwaspRisk in $missingOwaspRisks) {
            $missingLabel = if ([string]::IsNullOrWhiteSpace([string]$missingOwaspRisk.Name)) {
                [string]$missingOwaspRisk.Id
            }
            else {
                "$($missingOwaspRisk.Id) - $($missingOwaspRisk.Name)"
            }
            $missingUrl = & $buildOwaspControlUrl ([string]$missingOwaspRisk.Id)
            $openGapPills.Add("<a class='pill' href='$([System.Net.WebUtility]::HtmlEncode($missingUrl))' target='_blank' rel='noopener noreferrer'>$([System.Net.WebUtility]::HtmlEncode($missingLabel))</a>")
        }
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
<h3>OWASP CI/CD Coverage Context</h3>
<p><strong>Missing means:</strong> this OWASP CI/CD Top 10 risk currently has no mapped Fylgyr check in coverage metadata.</p>
<p><strong>Covered OWASP CI/CD risks ($($coveredOwaspRisks.Count)/$owaspTotalRiskCount):</strong></p>
<p>$($coveredOwaspPills -join ' ')</p>
<h3>Missing OWASP Coverage</h3>
<p>$($openGapPills -join ' ')</p>
"@
    }
    elseif ($coveredOwaspPills.Count -gt 0) {
@"
<h3>OWASP CI/CD Coverage Context</h3>
<p><strong>Missing means:</strong> this OWASP CI/CD Top 10 risk currently has no mapped Fylgyr check in coverage metadata.</p>
<p><strong>Covered OWASP CI/CD risks ($($coveredOwaspRisks.Count)/$owaspTotalRiskCount):</strong></p>
<p>$($coveredOwaspPills -join ' ')</p>
<h3>Missing OWASP Coverage</h3><p>No open OWASP gaps listed in coverage metadata.</p>
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

    $overallRecommendationItems = [System.Collections.Generic.List[PSCustomObject]]::new()
    $overallRecommendationKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $addOverallRecommendation = {
        param(
            [int]$Priority,
            [string]$Key,
            [string]$Text
        )

        if (-not $overallRecommendationKeys.Contains($Key)) {
            $overallRecommendationKeys.Add($Key) | Out-Null
            $overallRecommendationItems.Add([PSCustomObject]@{
                    Priority = $Priority
                    Text     = $Text
                }) | Out-Null
        }
    }

    if (@($riskCandidates | Where-Object { $_.Status -eq 'Error' }).Count -gt 0) {
        & $addOverallRecommendation 0 'resolve-errors' 'P0 Resolve API and token scope errors first so scan coverage is complete before triage decisions.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -eq 'OrgMfaPolicy' -and $_.Status -eq 'Fail' }).Count -gt 0) {
        & $addOverallRecommendation 0 'org-mfa' 'P0 Enforce organization-wide MFA immediately to reduce account takeover risk from stolen credentials.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -in @('PatPolicy', 'OAuthAppPolicy', 'GitHubAppSecurity') }).Count -gt 0) {
        & $addOverallRecommendation 0 'token-governance' 'P0 Tighten token and app governance: least privilege, approval gates, and short-lived credentials where possible.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -eq 'ActionPinning' -and $_.Status -eq 'Fail' }).Count -gt 0) {
        & $addOverallRecommendation 1 'action-pinning' 'P1 Pin all third-party actions to full commit SHAs to reduce mutable-tag supply chain exposure.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -eq 'EgressControl' }).Count -gt 0) {
        & $addOverallRecommendation 1 'egress-control' 'P1 Enforce workflow egress controls in block mode to limit secret exfiltration and attacker callouts.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -eq 'RunnerHygiene' }).Count -gt 0) {
        & $addOverallRecommendation 1 'runner-isolation' 'P1 Isolate runners with ephemeral execution and segmented network paths; avoid long-lived shared runners.'
    }

    if (@($riskCandidates | Where-Object { $_.CheckName -eq 'BranchProtection' -or $_.CheckName -eq 'Rulesets' }).Count -gt 0) {
        & $addOverallRecommendation 1 'branch-rulesets' 'P1 Keep strict default branch and tag protection baselines so stolen maintainer sessions cannot silently tamper with release paths.'
    }

    $orderedOverallRecommendations = @($overallRecommendationItems | Sort-Object -Property Priority, Text)
    $overallRecommendationListItems = [System.Collections.Generic.List[string]]::new()
    foreach ($recommendation in $orderedOverallRecommendations) {
        $overallRecommendationListItems.Add("<li>$([System.Net.WebUtility]::HtmlEncode([string]$recommendation.Text))</li>") | Out-Null
    }

    $overallRecommendationListHtml = if ($overallRecommendationListItems.Count -gt 0) {
@"
<h3>Prioritized From This Scan</h3>
<ul class="recommendation-list">
  $($overallRecommendationListItems -join "`n  ")
</ul>
"@
    }
    else {
        '<h3>Prioritized From This Scan</h3><p>No fail/warning/error findings detected.</p>'
    }

    $companionControlHtml = @"
<div class="note-box">
  <strong>Scope note:</strong> Controls in this section are companion recommendations for endpoint and network hardening. They are not directly validated by this scan unless a corresponding GitHub finding exists.
</div>
<h3>Recommended Companion Controls</h3>
<ul class="recommendation-list">
  <li>Extension governance: enforce publisher allowlists via Intune or Group Policy and use staged extension update rings for sensitive developer populations.</li>
  <li>Endpoint protection: deploy Microsoft Defender XDR (or equivalent EDR), enable tamper protection, and maintain host isolation runbooks.</li>
  <li>Network telemetry: keep DNS and outbound HTTPS visibility so unusual exfiltration behavior can be investigated quickly.</li>
  <li>Runner isolation: keep CI runners ephemeral and in segmented network zones; integrate private networking where supported.</li>
  <li>Identity and token resilience: prefer short-lived and least-privilege credentials, and require app approval workflows.</li>
    <li>Emergency credential response: include GitHub Credential Revocation API in playbooks to rapidly revoke exposed classic and fine-grained PATs.</li>
    <li>Dependency hardening on workstations: use package-manager cooldown controls to reduce exposure to freshly compromised package versions.</li>
    <li>Workstation posture scanners (for example Bagel) can complement Fylgyr by inventorying local credential and configuration risk on developer endpoints.</li>
</ul>
"@

    $overallRecommendationsHtml = @"
$overallRecommendationListHtml
$companionControlHtml
"@

    $defenderXdrRulesHtml = @"
<div class="note-box">
  <strong>Telemetry assumptions:</strong> Custom detections below require Defender for Endpoint data in Microsoft Defender XDR. GitHub identity and OAuth visibility may additionally require Defender for Cloud Apps integration and GitHub connector coverage.
</div>
<h3>Recommended Custom Detections</h3>
<ul class="recommendation-list">
    <li>Inventory VS Code extensions across endpoints and alert on known compromised versions.</li>
  <li>Suspicious extension-driven command execution from developer tools.</li>
  <li>Outbound connections to high-risk endpoints or unusual GitHub API usage patterns from developer workstations.</li>
  <li>Persistence artifact creation in known post-compromise paths.</li>
  <li>Potential credential-harvesting process patterns across shells and package managers.</li>
</ul>
<p class="code-title">Query 0: VS Code extension inventory in Defender XDR (MDE)</p>
<pre>DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessCommandLine has "\\.vscode\\extensions\\"
| where InitiatingProcessCommandLine has "code.exe"
| extend ExtensionName = extract(@"extensions\\([^\\]+)", 1, InitiatingProcessCommandLine)
| distinct DeviceName, ExtensionName
| sort by DeviceName asc</pre>
<p class="code-title">Query 1: Suspicious npx GitHub install command</p>
<pre>DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "npx -y github:"
| where ProcessCommandLine has "#"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName</pre>
<p class="code-title">Query 1b: Potential PAT material in process command line</p>
<pre>DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("ghp_", "github_pat_")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName</pre>
<p class="code-title">Query 2: Potential exfiltration-related network activity</p>
<pre>DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("api.github.com/search/commits", "fulcio.sigstore.dev", "rekor.sigstore.dev")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort</pre>
<p class="code-title">Query 3: Persistence indicators on developer endpoints</p>
<pre>DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any (".local/share/kitty", "Library/LaunchAgents", "/var/tmp")
| where FileName has_any ("cat.py", "com.user.kitty-monitor.plist", ".gh_update_state")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName</pre>
<p class="code-title">Query 4: GitHub cloud activity pivot (when CloudAppEvents is available)</p>
<pre>CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "GitHub"
| where ActionType has_any ("OAuth", "Token", "Repository")
| project Timestamp, AccountDisplayName, ActionType, ActivityObjects, IPAddress, UserAgent</pre>
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
    $html = $html.Replace('{{OVERALL_RECOMMENDATIONS}}', $overallRecommendationsHtml)
    $html = $html.Replace('{{DEFENDER_XDR_RULES}}', $defenderXdrRulesHtml)
    $html = $html.Replace('{{COVERAGE_DASHBOARD}}', $coverageSummaryHtml)
    $html = $html.Replace('{{RESULT_SECTIONS}}', $resultSectionsHtml)

    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $html -Encoding UTF8
        return
    }

    return $html
}
