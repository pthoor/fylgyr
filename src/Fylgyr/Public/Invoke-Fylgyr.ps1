function Invoke-Fylgyr {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]], [string])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [ValidateSet('Object', 'JSON', 'SARIF', 'Console', 'NDJSON', 'HTML')]
        [string]$OutputFormat = 'Object',

        [switch]$IncludeOrgChecks,

        [ValidateRange(1, 20)]
        [int]$ThrottleLimit = 5,

        [string[]]$ReusableWorkflowAllowlist = @(),

        [switch]$ChangedOnly,

        [ValidatePattern('^(?!-)[a-zA-Z0-9._/-]+$')]
        [string]$SinceRef = 'origin/main',

        [string]$BaselinePath,

        [switch]$IncludeEvidence,

        [switch]$IgnoreConfig,

        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$FailOn,

        [string]$OutputPath,

        [string]$Token = $env:GITHUB_TOKEN
    )

    begin {
        if (-not $Token) {
            throw 'GitHub token not provided. Use -Token or set $env:GITHUB_TOKEN.'
        }

        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $scannedTargets = [System.Collections.Generic.List[string]]::new()
        $scanId = [Guid]::NewGuid().ToString()
        $scanStartTime = [datetime]::UtcNow
        $changedWorkflowPaths = $null

        # Owner-level check caches. Reset every run so repeated Invoke-Fylgyr calls
        # inside the same session do not reuse stale data.
        # - FylgyrOwnerRunnerGroupsChecked: Test-RunnerHygiene consults this to skip the
        #   `orgs/{Owner}/...` block on second and later repos in an org-wide scan.
        # - FylgyrOwnerContextCache: owner type/token-owner/plan cache used by
        #   Get-FylgyrOwnerContext to avoid repeated users/{owner} and user calls.
        $script:FylgyrOwnerRunnerGroupsChecked = @{}
        $script:FylgyrOwnerContextCache = @{}
    }

    process {
        # If no Repo specified, enumerate all repos for the Owner (org-wide scan)
        if (-not $Repo) {
            if ($ChangedOnly) {
                $allResults.Add((Format-FylgyrResult `
                    -CheckName 'ChangedOnly' `
                    -Status 'Error' `
                    -Severity 'Low' `
                    -Resource $Owner `
                    -Detail 'ChangedOnly mode requires -Repo. Org-wide scans are not supported in ChangedOnly mode.' `
                    -Remediation 'Provide -Repo for ChangedOnly scans, or run without ChangedOnly for org-wide coverage.' `
                    -Target $Owner))
                return
            }

            $repos = [System.Collections.Generic.List[string]]::new()

            try {
                $orgRepos = Invoke-GitHubApi -Endpoint "orgs/$Owner/repos?per_page=100" -Token $Token -AllPages
            }
            catch {
                try {
                    $orgRepos = Invoke-GitHubApi -Endpoint "users/$Owner/repos?per_page=100" -Token $Token -AllPages
                }
                catch {
                    $allResults.Add((Format-FylgyrResult `
                        -CheckName 'OrgRepoList' `
                        -Status 'Error' `
                        -Severity 'Critical' `
                        -Resource $Owner `
                        -Detail "Failed to list repositories for '$Owner': $($_.Exception.Message)" `
                        -Remediation 'Verify the owner exists and the token has repo access.' `
                        -Target $Owner))
                    return
                }
            }

            foreach ($r in $orgRepos) {
                $repos.Add($r.name)
            }

            if ($IncludeOrgChecks) {
                $orgResults = Invoke-FylgyrOrgScan -Owner $Owner -Token $Token
                foreach ($result in $orgResults) { $allResults.Add($result) }
            }

            if ($repos.Count -eq 0) {
                $allResults.Add((Format-FylgyrResult `
                    -CheckName 'OrgRepoList' `
                    -Status 'Warning' `
                    -Severity 'Info' `
                    -Resource $Owner `
                    -Detail "No repositories found for '$Owner'." `
                    -Remediation 'Verify the owner name and token permissions.' `
                    -Target $Owner))
                return
            }

            $repoTotal = $repos.Count
            $effectiveThrottle = Get-FylgyrOrgScanThrottle -RequestedThrottle $ThrottleLimit -RepoTotal $repoTotal -Token $Token

            $isPesterRun = $null -ne (Get-Variable -Name PesterPreference -Scope Global -ErrorAction SilentlyContinue)
            $useParallel = ($effectiveThrottle -gt 1) -and ($repoTotal -gt 1) -and (-not $isPesterRun)

            if ($useParallel) {
                $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
                $modulePath = Join-Path -Path $moduleRoot -ChildPath 'Fylgyr.psm1'
                $scanOwner = $Owner
                $scanToken = $Token
                $scanAllowlist = $ReusableWorkflowAllowlist
                $scanIgnoreConfig = $IgnoreConfig.IsPresent
                $scanIncludeEvidence = $IncludeEvidence.IsPresent
                $repoInputs = for ($i = 0; $i -lt $repoTotal; $i++) {
                    [PSCustomObject]@{
                        Index = $i
                        Repo = $repos[$i]
                    }
                }

                $parallelBatches = $repoInputs | ForEach-Object -Parallel {
                    $repoIndex = [int]$_.Index
                    $repoName = [string]$_.Repo
                    Import-Module -Name $using:modulePath -Force

                    try {
                        $scanResults = @(
                            Invoke-FylgyrScan -Owner $using:scanOwner -Repo $repoName -Token $using:scanToken -ReusableWorkflowAllowlist $using:scanAllowlist -ChangedOnly:$false -ChangedWorkflowPaths @() -IgnoreConfig:$using:scanIgnoreConfig -IncludeEvidence:$using:scanIncludeEvidence
                        )
                    }
                    catch {
                        $target = "$($using:scanOwner)/$repoName"
                        $scanResults = @(
                            (Format-FylgyrResult `
                                -CheckName 'OrgParallelScan' `
                                -Status 'Error' `
                                -Severity 'Critical' `
                                -Resource $target `
                                -Detail "Parallel scan failed: $($_.Exception.Message)" `
                                -Remediation 'Retry with -ThrottleLimit 1 and verify token/repository access.' `
                                -Target $target)
                        )
                    }

                    [PSCustomObject]@{
                        Index = $repoIndex
                        Repo = $repoName
                        Results = $scanResults
                    }
                } -ThrottleLimit $effectiveThrottle

                foreach ($batch in @($parallelBatches | Sort-Object -Property Index)) {
                    foreach ($result in @($batch.Results)) {
                        $allResults.Add($result)
                    }
                    $scannedTargets.Add("$Owner/$($batch.Repo)")
                }
            }
            else {
                for ($i = 0; $i -lt $repoTotal; $i++) {
                    $repoName = $repos[$i]
                    $pct = [math]::Floor(($i / $repoTotal) * 100)
                    Write-Progress -Activity "Scanning $Owner" `
                        -Status "Repo $($i + 1) of $repoTotal : $repoName" `
                        -PercentComplete $pct `
                        -Id 1

                    $repoResults = Invoke-FylgyrScan -Owner $Owner -Repo $repoName -Token $Token -ReusableWorkflowAllowlist $ReusableWorkflowAllowlist -ChangedOnly:$ChangedOnly -ChangedWorkflowPaths $changedWorkflowPaths -IgnoreConfig:$IgnoreConfig -IncludeEvidence:$IncludeEvidence
                    foreach ($result in $repoResults) { $allResults.Add($result) }
                    $scannedTargets.Add("$Owner/$repoName")
                }

                Write-Progress -Activity "Scanning $Owner" -Id 1 -Completed
            }
        }
        else {
            if ($ChangedOnly) {
                try {
                    $changedWorkflowPaths = Get-FylgyrChangedWorkflowPath -SinceRef $SinceRef
                }
                catch {
                    $allResults.Add((Format-FylgyrResult `
                        -CheckName 'ChangedOnly' `
                        -Status 'Error' `
                        -Severity 'Low' `
                        -Resource "$Owner/$Repo" `
                        -Detail "Failed to collect changed files from '$SinceRef': $($_.Exception.Message)" `
                        -Remediation 'Verify SinceRef exists (for example origin/main) and rerun.' `
                        -Target "$Owner/$Repo"))
                }
            }

            $repoResults = Invoke-FylgyrScan -Owner $Owner -Repo $Repo -Token $Token -ReusableWorkflowAllowlist $ReusableWorkflowAllowlist -ChangedOnly:$ChangedOnly -ChangedWorkflowPaths $changedWorkflowPaths -IgnoreConfig:$IgnoreConfig -IncludeEvidence:$IncludeEvidence
            foreach ($result in $repoResults) { $allResults.Add($result) }
            $scannedTargets.Add("$Owner/$Repo")
        }
    }

    end {
        if ($allResults.Count -eq 0) {
            return
        }

        $resultsArray = $allResults.ToArray()

        # Derive display target from scanned targets
        $displayTarget = if ($scannedTargets.Count -eq 1) {
            $scannedTargets[0]
        }
        elseif ($scannedTargets.Count -gt 1) {
            $owners = @($scannedTargets | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique)
            if ($owners.Count -eq 1) { $owners[0] } else { "$($scannedTargets.Count) repositories" }
        }
        else {
            'unknown'
        }

        if ($BaselinePath) {
            try {
                $baselineFingerprints = Get-FylgyrBaselineFingerprintSet -BaselinePath $BaselinePath
                foreach ($result in $resultsArray) {
                    # Baselines are intended for actionable findings only.
                    # Keep scan errors and informational telemetry visible.
                    if ($result.Status -notin @('Fail', 'Warning')) {
                        continue
                    }

                    $fingerprint = Get-FylgyrFingerprint -Result $result
                    if ($baselineFingerprints.Contains($fingerprint)) {
                        $result.Status = 'Suppressed'
                    }
                }
            }
            catch {
                $allResults.Add((Format-FylgyrResult `
                    -CheckName 'BaselineDiff' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $displayTarget `
                    -Detail "Failed to apply baseline diff from '$BaselinePath': $($_.Exception.Message)" `
                    -Remediation 'Provide a valid JSON baseline path (Invoke-Fylgyr JSON output or array of result objects).' `
                    -Target $displayTarget))
                $resultsArray = $allResults.ToArray()
            }
        }

        if ($FailOn) {
            $severityOrder = @{
                Info = 0
                Low = 1
                Medium = 2
                High = 3
                Critical = 4
            }

            $threshold = $severityOrder[$FailOn]
            $hasBlockingFindings = @($resultsArray | Where-Object {
                $_.Status -notin @('Pass', 'Suppressed') -and $severityOrder[$_.Severity] -ge $threshold
            }).Count -gt 0

            $global:LASTEXITCODE = if ($hasBlockingFindings) { 1 } else { 0 }
        }

        if ($OutputFormat -eq 'JSON') {
            ConvertTo-FylgyrJson -Results $resultsArray -Target $displayTarget
        }
        elseif ($OutputFormat -eq 'SARIF') {
            ConvertTo-FylgyrSarif -Results $resultsArray
        }
        elseif ($OutputFormat -eq 'NDJSON') {
            ConvertTo-FylgyrNdjson -Results $resultsArray -ScanId $scanId -ScanStartTime $scanStartTime -OutputPath $OutputPath
        }
        elseif ($OutputFormat -eq 'HTML') {
            ConvertTo-FylgyrHtml -Results $resultsArray -Target $displayTarget -ScannedTargets $scannedTargets.ToArray() -OutputPath $OutputPath
        }
        elseif ($OutputFormat -eq 'Console') {
            Write-FylgyrConsole -Results $resultsArray -Target $displayTarget -ScannedRepoCount $scannedTargets.Count
        }
        else {
            $resultsArray
        }
    }
}

function Invoke-FylgyrScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token,

        [string[]]$ReusableWorkflowAllowlist = @(),

        [switch]$ChangedOnly,

        [string[]]$ChangedWorkflowPaths = @(),

        [switch]$IgnoreConfig,

        [switch]$IncludeEvidence
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $configContext = Get-FylgyrConfigSuppression -IgnoreConfig:$IgnoreConfig
    $configSuppressions = @($configContext.Rules)
    $configDiagnostics = @($configContext.Diagnostics)

    foreach ($configDiagnostic in $configDiagnostics) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'ConfigSuppression' `
            -Status $configDiagnostic.Status `
            -Severity $configDiagnostic.Severity `
            -Resource $target `
            -Detail $configDiagnostic.Detail `
            -Remediation $configDiagnostic.Remediation `
            -Target $target))
    }

    Write-Progress -Activity $target -Status 'Fetching workflow files...' -Id 2 -ParentId 1

    $workflowFiles = $null
    $fetchFailed = $false
    try {
        $workflowFiles = @(Get-WorkflowFile -Owner $Owner -Repo $Repo -Token $Token)
    }
    catch {
        $fetchFailed = $true
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowFileFetch' `
            -Status 'Error' `
            -Severity 'Critical' `
            -Resource $target `
            -Detail "Failed to fetch workflow files: $($_.Exception.Message)" `
            -Remediation 'Verify the repository exists and the token has contents:read access.' `
            -Target $target))
    }

    if ($fetchFailed) {
        # Error already recorded above
    }
    elseif ($ChangedOnly) {
        if (-not $ChangedWorkflowPaths -or $ChangedWorkflowPaths.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ChangedOnly' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'ChangedOnly mode found no changed workflow files under .github/workflows.' `
                -Remediation 'No action needed.' `
                -Target $target))
            $resultArray = $results.ToArray()
            if ($IncludeEvidence) {
                $resultArray = Add-FylgyrEvidence -Results $resultArray -WorkflowFiles @() -Owner $Owner -Repo $Repo -Token $Token
            }
            return (Resolve-FylgyrSuppressionStatus -Results $resultArray -Suppressions $configSuppressions)
        }

        $workflowFiles = @($workflowFiles | Where-Object { $ChangedWorkflowPaths -contains $_.Path })
        if ($workflowFiles.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ChangedOnly' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $target `
                -Detail 'ChangedOnly mode detected workflow changes, but none are present in the current repository scan context.' `
                -Remediation 'Ensure changed workflow paths exist in the target repository and rerun.' `
                -Target $target))
            $resultArray = $results.ToArray()
            if ($IncludeEvidence) {
                $resultArray = Add-FylgyrEvidence -Results $resultArray -WorkflowFiles @() -Owner $Owner -Repo $Repo -Token $Token
            }
            return (Resolve-FylgyrSuppressionStatus -Results $resultArray -Suppressions $configSuppressions)
        }
    }
    elseif ($workflowFiles.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowFileFetch' `
            -Status 'Warning' `
            -Severity 'Info' `
            -Resource $target `
            -Detail 'No workflow files found in .github/workflows.' `
            -Remediation 'No action needed if this repository does not use GitHub Actions.' `
            -Target $target))
    }
    else {
        $workflowChecks = @(
            @{ Name = 'Test-ActionPinning';      Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-DangerousTrigger';   Params = @{ WorkflowFiles = $workflowFiles; Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-ScriptInjection';    Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-ArtifactPoisoning';  Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-OidcTrust';          Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-CacheIntegrity';     Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-TriggerFilter';      Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-DependencyReview';   Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-ArtifactAttestation'; Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-ReusableWorkflowTrust'; Params = @{ WorkflowFiles = $workflowFiles; Owner = $Owner; ReusableWorkflowAllowlist = $ReusableWorkflowAllowlist } }
            @{ Name = 'Test-WorkflowPermission'; Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-RunnerHygiene';      Params = @{ WorkflowFiles = $workflowFiles; Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-EgressControl';      Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-PublishIntegrity';   Params = @{ WorkflowFiles = $workflowFiles } }
            @{ Name = 'Test-ForkPullPolicy';     Params = @{ WorkflowFiles = $workflowFiles } }
        )

        for ($c = 0; $c -lt $workflowChecks.Count; $c++) {
            $check = $workflowChecks[$c]
            $checkPct = [math]::Floor(($c / $workflowChecks.Count) * 100)
            Write-Progress -Activity $target `
                -Status "Running $($check.Name) ($($workflowFiles.Count) workflow files)" `
                -PercentComplete $checkPct `
                -Id 2 -ParentId 1

            try {
                $checkParams = $check.Params
                $checkResults = & $check.Name @checkParams
                foreach ($r in $checkResults) {
                    $r.Target = $target
                    $results.Add($r)
                }
            }
            catch {
                $results.Add((Format-FylgyrResult `
                    -CheckName $check.Name `
                    -Status 'Error' `
                    -Severity 'Critical' `
                    -Resource $target `
                    -Detail "Check failed with error: $($_.Exception.Message)" `
                    -Remediation 'Review the error and re-run.' `
                    -Target $target))
            }
        }
    }

    # Fork secret exposure check (needs workflow files + API params)
    if (-not $fetchFailed -and $workflowFiles -and $workflowFiles.Count -gt 0) {
        Write-Progress -Activity $target -Status 'Running Test-ForkSecretExposure' -Id 2 -ParentId 1
        try {
            $checkResults = Test-ForkSecretExposure -WorkflowFiles $workflowFiles -Owner $Owner -Repo $Repo -Token $Token
            foreach ($r in $checkResults) {
                $r.Target = $target
                $results.Add($r)
            }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName 'Test-ForkSecretExposure' `
                -Status 'Error' `
                -Severity 'Critical' `
                -Resource $target `
                -Detail "Check failed with error: $($_.Exception.Message)" `
                -Remediation 'Review the error and re-run.' `
                -Target $target))
        }
    }

    if (-not $ChangedOnly) {
        # Repo-level checks (always run, regardless of workflow files)
        $repoChecks = @(
            @{ Name = 'Test-BranchProtection';     Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-SecretScanning';       Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-DependabotAlert';      Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-CodeScanning';         Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-CodeOwner';            Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-SignedCommit';         Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-EnvironmentProtection'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-RepoVisibility';       Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-WebhookSecurity';      Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-Rulesets';             Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-BinaryArtifact';       Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
            @{ Name = 'Test-PrivateVulnReporting'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
        )

        foreach ($entry in $repoChecks) {
            Write-Progress -Activity $target -Status "Running $($entry.Name)" -Id 2 -ParentId 1

            try {
                $checkParams = $entry.Params
                $checkResults = & $entry.Name @checkParams
                foreach ($r in $checkResults) {
                    $r.Target = $target
                    $results.Add($r)
                }
            }
            catch {
                $results.Add((Format-FylgyrResult `
                    -CheckName $entry.Name `
                    -Status 'Error' `
                    -Severity 'Critical' `
                    -Resource $target `
                    -Detail "Check failed with error: $($_.Exception.Message)" `
                    -Remediation 'Review the error and re-run.' `
                    -Target $target))
            }
        }
    }

    Write-Progress -Activity $target -Id 2 -Completed

    $resultArray = $results.ToArray()
    if ($IncludeEvidence) {
        $resultArray = Add-FylgyrEvidence -Results $resultArray -WorkflowFiles $workflowFiles -Owner $Owner -Repo $Repo -Token $Token
    }

    Resolve-FylgyrSuppressionStatus -Results $resultArray -Suppressions $configSuppressions
}

function Invoke-FylgyrOrgScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $orgChecks = @(
        @{ Name = 'Test-OrgMfaPolicy';          Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-OrgDefaultPermissions'; Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-IpAllowlist';           Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-AuditLogStreaming';     Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-OAuthAppPolicy';        Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-OrgActionRestrictions'; Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-OutsideCollaborators';  Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-PatPolicy';             Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-GitHubAppSecurity';     Params = @{ Owner = $Owner; Token = $Token } }
        @{ Name = 'Test-Rulesets';              Params = @{ Owner = $Owner; Token = $Token } }
    )

    foreach ($entry in $orgChecks) {
        Write-Progress -Activity $target -Status "Running $($entry.Name)" -Id 3 -ParentId 1

        try {
            $checkParams = $entry.Params
            $checkResults = & $entry.Name @checkParams
            foreach ($r in $checkResults) {
                $r.Target = $target
                $results.Add($r)
            }
        }
        catch {
            $normalizedCheckName = $entry.Name -replace '^Test-', ''
            $results.Add((Format-FylgyrResult `
                -CheckName $normalizedCheckName `
                -Status 'Error' `
                -Severity 'Critical' `
                -Resource $target `
                -Detail "Check failed with error: $($_.Exception.Message)" `
                -Remediation 'Review the error and re-run.' `
                -Target $target))
        }
    }

    Write-Progress -Activity $target -Id 3 -Completed

    $results.ToArray()
}
