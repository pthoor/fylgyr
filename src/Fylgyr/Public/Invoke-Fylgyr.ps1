function Invoke-Fylgyr {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]], [string])]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$Owner,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
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
                        -Detail "Failed to list repositories for '$Owner': $_" `
                        -Remediation 'Verify the owner exists and the token has repo access.'))
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
                    -Remediation 'Verify the owner name and token permissions.'))
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
            }

            Write-Progress -Activity "Scanning $Owner" -Id 1 -Completed
        }
        else {
            $repoResults = Invoke-FylgyrScan -Owner $Owner -Repo $Repo -Token $Token
            foreach ($result in $repoResults) { $allResults.Add($result) }
        }
    }

    end {
        if ($allResults.Count -eq 0) {
            return
        }

        $resultsArray = $allResults.ToArray()

        if ($OutputFormat -eq 'JSON') {
            ConvertTo-FylgyrJson -Results $resultsArray -Owner $Owner -Repo $Repo
        }
        elseif ($OutputFormat -eq 'SARIF') {
            ConvertTo-FylgyrSarif -Results $resultsArray
        }
        elseif ($OutputFormat -eq 'Console') {
            Write-FylgyrConsole -Results $resultsArray -Owner $Owner -Repo $Repo
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
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Progress -Activity "$Owner/$Repo" -Status 'Fetching workflow files...' -Id 2 -ParentId 1

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
            -Resource "$Owner/$Repo" `
            -Detail "Failed to fetch workflow files: $_" `
            -Remediation 'Verify the repository exists and the token has contents:read access.'))
    }

    if ($fetchFailed) {
        # Error already recorded above
    }
    elseif ($workflowFiles.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WorkflowFileFetch' `
            -Status 'Warning' `
            -Severity 'Info' `
            -Resource "$Owner/$Repo" `
            -Detail 'No workflow files found in .github/workflows.' `
            -Remediation 'No action needed if this repository does not use GitHub Actions.'))
    }
    else {
        $checks = @(
            'Test-ActionPinning'
            'Test-DangerousTrigger'
            'Test-WorkflowPermission'
        )

        for ($c = 0; $c -lt $checks.Count; $c++) {
            $check = $checks[$c]
            $checkPct = [math]::Floor(($c / $checks.Count) * 100)
            Write-Progress -Activity "$Owner/$Repo" `
                -Status "Running $check ($($workflowFiles.Count) workflow files)" `
                -PercentComplete $checkPct `
                -Id 2 -ParentId 1

            try {
                $checkResults = & $check -WorkflowFiles $workflowFiles
                foreach ($r in $checkResults) {
                    $r.Resource = "$Owner/$Repo/$($r.Resource)"
                    $results.Add($r)
                }
            }
            catch {
                $results.Add((Format-FylgyrResult `
                    -CheckName $check `
                    -Status 'Error' `
                    -Severity 'Critical' `
                    -Resource "$Owner/$Repo" `
                    -Detail "Check failed with error: $_" `
                    -Remediation 'Review the error and re-run.'))
            }
        }
    }

    Write-Progress -Activity "$Owner/$Repo" -Id 2 -Completed

    $results.ToArray()
}
