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

        [ValidateSet('Object', 'JSON', 'SARIF', 'Console')]
        [string]$OutputFormat = 'Object',

        [string]$Token = $env:GITHUB_TOKEN
    )

    begin {
        if (-not $Token) {
            throw 'GitHub token not provided. Use -Token or set $env:GITHUB_TOKEN.'
        }

        $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
        $scannedTargets = [System.Collections.Generic.List[string]]::new()
    }

    process {
        # If no Repo specified, enumerate all repos for the Owner (org-wide scan)
        if (-not $Repo) {
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
            for ($i = 0; $i -lt $repoTotal; $i++) {
                $repoName = $repos[$i]
                $pct = [math]::Floor(($i / $repoTotal) * 100)
                Write-Progress -Activity "Scanning $Owner" `
                    -Status "Repo $($i + 1) of $repoTotal : $repoName" `
                    -PercentComplete $pct `
                    -Id 1

                $repoResults = Invoke-FylgyrScan -Owner $Owner -Repo $repoName -Token $Token
                foreach ($result in $repoResults) { $allResults.Add($result) }
                $scannedTargets.Add("$Owner/$repoName")
            }

            Write-Progress -Activity "Scanning $Owner" -Id 1 -Completed
        }
        else {
            $repoResults = Invoke-FylgyrScan -Owner $Owner -Repo $Repo -Token $Token
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
            $owners = $scannedTargets | ForEach-Object { ($_ -split '/')[0] } | Sort-Object -Unique
            if ($owners.Count -eq 1) { $owners[0] } else { "$($scannedTargets.Count) repositories" }
        }
        else {
            'unknown'
        }

        if ($OutputFormat -eq 'JSON') {
            ConvertTo-FylgyrJson -Results $resultsArray -Target $displayTarget
        }
        elseif ($OutputFormat -eq 'SARIF') {
            ConvertTo-FylgyrSarif -Results $resultsArray
        }
        elseif ($OutputFormat -eq 'Console') {
            Write-FylgyrConsole -Results $resultsArray -Target $displayTarget
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
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

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
        $checks = @(
            'Test-ActionPinning'
            'Test-DangerousTrigger'
            'Test-WorkflowPermission'
            'Test-RunnerHygiene'
        )

        for ($c = 0; $c -lt $checks.Count; $c++) {
            $check = $checks[$c]
            $checkPct = [math]::Floor(($c / $checks.Count) * 100)
            Write-Progress -Activity $target `
                -Status "Running $check ($($workflowFiles.Count) workflow files)" `
                -PercentComplete $checkPct `
                -Id 2 -ParentId 1

            try {
                $checkResults = & $check -WorkflowFiles $workflowFiles
                foreach ($r in $checkResults) {
                    $r.Target = $target
                    $results.Add($r)
                }
            }
            catch {
                $results.Add((Format-FylgyrResult `
                    -CheckName $check `
                    -Status 'Error' `
                    -Severity 'Critical' `
                    -Resource $target `
                    -Detail "Check failed with error: $($_.Exception.Message)" `
                    -Remediation 'Review the error and re-run.' `
                    -Target $target))
            }
        }
    }

    # Repo-level checks (always run, regardless of workflow files)
    $repoChecks = @(
        @{ Name = 'Test-BranchProtection'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
        @{ Name = 'Test-SecretScanning';   Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
        @{ Name = 'Test-DependabotAlert';  Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
        @{ Name = 'Test-CodeScanning';     Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token } }
    )

    foreach ($entry in $repoChecks) {
        Write-Progress -Activity $target -Status "Running $($entry.Name)" -Id 2 -ParentId 1

        try {
            $checkParams = $entry.Params
            $checkResults = & $entry.Name @checkParams
            foreach ($r in $checkResults) { $results.Add($r) }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName $entry.Name `
                -Status 'Error' `
                -Severity 'Critical' `
                -Resource $target `
                -Detail "Check failed with error: $_" `
                -Remediation 'Review the error and re-run.' `
                -Target $target))
        }
    }

    Write-Progress -Activity $target -Id 2 -Completed

    $results.ToArray()
}
