function Test-CodeOwner {
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

    $candidatePaths = @('CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS')
    $codeownersContent = $null
    $foundPath = $null

    foreach ($path in $candidatePaths) {
        try {
            $file = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/contents/$path" -Token $Token
            if ($file -and $file.content) {
                try {
                    $codeownersContent = [System.Text.Encoding]::UTF8.GetString(
                        [System.Convert]::FromBase64String(($file.content -replace '\s', ''))
                    )
                    $foundPath = $path
                    break
                }
                catch {
                    Write-Debug "Failed to decode CODEOWNERS at ${path}: $($_.Exception.Message)"
                }
            }
        }
        catch {
            $msg = $_.ToString()
            if ($msg -match '404') {
                continue
            }
            if ($msg -match '403') {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'CodeOwners' `
                    -Status 'Error' `
                    -Severity 'Medium' `
                    -Resource $target `
                    -Detail 'Insufficient permissions to read repository contents for CODEOWNERS.' `
                    -Remediation 'Use a fine-grained token with contents:read permission, or a classic token with repo scope.' `
                    -Target $target))
                return $results.ToArray()
            }
            $results.Add((Format-FylgyrResult `
                -CheckName 'CodeOwners' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $target `
                -Detail "Unexpected error reading CODEOWNERS candidate '${path}': $($_.Exception.Message)" `
                -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
                -Target $target))
            return $results.ToArray()
        }
    }

    if (-not $codeownersContent) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'CodeOwners' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource $target `
            -Detail 'No CODEOWNERS file found at CODEOWNERS, .github/CODEOWNERS, or docs/CODEOWNERS. Without code owners, a single compromised maintainer can merge unreviewed changes - the exact pattern exploited in the xz-utils backdoor.' `
            -Remediation 'Create a CODEOWNERS file under .github/CODEOWNERS that assigns at least two distinct owners to security-sensitive paths. See: https://docs.github.com/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners' `
            -AttackMapping @('xz-utils-backdoor') `
            -Target $target))
        return $results.ToArray()
    }

    # Parse rules: skip comments and blank lines. Rule = pattern + one-or-more owners.
    $rules = foreach ($line in ($codeownersContent -split "`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
        $tokens = -split $trimmed
        if ($tokens.Count -lt 2) { continue }
        $owners = @($tokens | Select-Object -Skip 1 | Where-Object { $_ -match '^@' -or $_ -match '@' })
        [PSCustomObject]@{
            Pattern = $tokens[0]
            Owners  = $owners
        }
    }

    $distinctOwners = @($rules.Owners | Sort-Object -Unique)
    $catchAllRules = @($rules | Where-Object { $_.Pattern -eq '*' })

    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($rules.Count -eq 0) {
        $findings.Add((Format-FylgyrResult `
            -CheckName 'CodeOwners' `
            -Status 'Fail' `
            -Severity 'Medium' `
            -Resource "$target ($foundPath)" `
            -Detail "CODEOWNERS file exists at '$foundPath' but contains no rules." `
            -Remediation 'Add at least one pattern with two or more distinct owners.' `
            -AttackMapping @('xz-utils-backdoor') `
            -Target $target))
    }
    else {
        if ($distinctOwners.Count -lt 2) {
            $onlyOwner = if ($distinctOwners.Count -eq 1) { $distinctOwners[0] } else { '(none)' }
            $findings.Add((Format-FylgyrResult `
                -CheckName 'CodeOwners' `
                -Status 'Fail' `
                -Severity 'Medium' `
                -Resource "$target ($foundPath)" `
                -Detail "CODEOWNERS assigns ownership to only $($distinctOwners.Count) distinct owner ($onlyOwner). A single compromised or socially-engineered maintainer can merge malicious code, as in the xz-utils backdoor." `
                -Remediation 'Assign at least two distinct owners (users or teams) in CODEOWNERS so every change requires review by someone other than the author.' `
                -AttackMapping @('xz-utils-backdoor') `
                -Target $target))
        }

        foreach ($rule in $catchAllRules) {
            if ($rule.Owners.Count -le 1) {
                $soleOwner = if ($rule.Owners.Count -eq 1) { $rule.Owners[0] } else { '(none)' }
                $findings.Add((Format-FylgyrResult `
                    -CheckName 'CodeOwners' `
                    -Status 'Fail' `
                    -Severity 'Medium' `
                    -Resource "$target ($foundPath)" `
                    -Detail "Catch-all pattern '*' is assigned to a single owner ($soleOwner). Any change in the repository can be approved by that one account." `
                    -Remediation "Replace the catch-all rule with multiple reviewers (e.g. '* @org/security @org/maintainers') or scope ownership by directory." `
                    -AttackMapping @('xz-utils-backdoor') `
                    -Target $target))
            }
        }
    }

    if ($findings.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'CodeOwners' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource "$target ($foundPath)" `
            -Detail "CODEOWNERS found with $($rules.Count) rule(s) and $($distinctOwners.Count) distinct owner(s). No single-owner catch-all detected." `
            -Remediation 'No action needed.' `
            -Target $target))
    }
    else {
        foreach ($f in $findings) { $results.Add($f) }
    }

    $results.ToArray()
}
