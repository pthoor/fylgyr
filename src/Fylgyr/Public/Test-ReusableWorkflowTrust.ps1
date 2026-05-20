function Test-ReusableWorkflowTrust {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [string[]]$ReusableWorkflowAllowlist = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $normalizedAllowlist = [System.Collections.Generic.List[string]]::new()
    $normalizedAllowlist.Add('actions/*')
    $normalizedAllowlist.Add('github/*')

    foreach ($entry in $ReusableWorkflowAllowlist) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }

        $normalizedAllowlist.Add($entry.Trim().ToLowerInvariant())
    }

    foreach ($wf in $WorkflowFiles) {
        $lines = @(($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' })
        $findings = [System.Collections.Generic.List[string]]::new()

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -notmatch '(?i)^\s*-?\s*uses\s*:\s*(?<ref>[^\s#]+)') {
                continue
            }

            $reference = $Matches.ref.Trim().Trim("'").Trim('"')
            if ($reference -notmatch '/\.github/workflows/') {
                continue
            }

            if ($reference -notmatch '^(?<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/\.github/workflows/.+@(?<version>.+)$') {
                $findings.Add("line $($i + 1): reusable workflow reference is malformed: $reference")
                continue
            }

            $sourceRepo = $Matches.repo.ToLowerInvariant()
            $sourceOwner = ($sourceRepo -split '/')[0]
            $versionRef = $Matches.version

            $isShaPinned = $versionRef -match '^[0-9a-fA-F]{40}$'
            if (-not $isShaPinned) {
                $findings.Add("line $($i + 1): reusable workflow is not SHA pinned: $reference")
            }

            $isAllowedSource = $false
            if ($Owner -and ($sourceOwner -eq $Owner.ToLowerInvariant())) {
                $isAllowedSource = $true
            }
            else {
                foreach ($allowEntry in $normalizedAllowlist) {
                    if ($allowEntry -match '/\*$') {
                        $allowOwner = ($allowEntry -split '/')[0]
                        if ($sourceOwner -eq $allowOwner) {
                            $isAllowedSource = $true
                            break
                        }
                    }
                    elseif ($sourceRepo -eq $allowEntry) {
                        $isAllowedSource = $true
                        break
                    }
                }
            }

            if (-not $isAllowedSource) {
                $findings.Add("line $($i + 1): reusable workflow source is outside trusted allowlist: $sourceRepo")
            }
        }

        if ($findings.Count -gt 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ReusableWorkflowTrust' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' has reusable workflow trust issues: $((@($findings | Select-Object -Unique)) -join ' | ')." `
                -Remediation 'Pin reusable workflow refs to full 40-character SHAs and limit sources to trusted repositories (same owner, actions/*, github/*, or explicit allowlist entries).' `
                -AttackMapping @('tj-actions-shai-hulud')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ReusableWorkflowTrust' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has no detected reusable-workflow trust issues." `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
