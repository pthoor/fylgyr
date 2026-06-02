function Test-OidcTrust {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $sanitizedContent = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $jobBlocks = @(Get-WorkflowJobBlock -Content $sanitizedContent)
        $hasWorkflowLevelIdToken = $false

        $lines = $sanitizedContent -split "`n"
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]

            if ($line -match '^permissions\s*:\s*\{[^}]*id-token\s*:\s*write') {
                $hasWorkflowLevelIdToken = $true
                break
            }

            if ($line -notmatch '^permissions\s*:\s*$') {
                continue
            }

            $j = $i + 1
            while ($j -lt $lines.Count) {
                $next = $lines[$j]
                if ($next -match '^\s*$') {
                    $j++
                    continue
                }

                if ($next -match '^\S') {
                    break
                }

                if ($next -match '^\s+id-token\s*:\s*write\s*$') {
                    $hasWorkflowLevelIdToken = $true
                    break
                }

                $j++
            }

            if ($hasWorkflowLevelIdToken) {
                break
            }
        }

        $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
        $anyIdToken = $hasWorkflowLevelIdToken

        foreach ($job in $jobBlocks) {
            $jobText = $job.Content
            $jobHasIdToken = $hasWorkflowLevelIdToken -or ($jobText -match '(?im)^\s*id-token\s*:\s*write\s*$')
            if (-not $jobHasIdToken) {
                continue
            }

            $anyIdToken = $true
            $jobHasEnvironment = $jobText -match '(?im)^\s*environment\s*:'

            if ($jobHasEnvironment) {
                continue
            }

            $hasDockerPush = $jobText -match '(?im)^\s*-\s*uses\s*:\s*docker/build-push-action@' -and $jobText -match '(?im)^\s*push\s*:\s*true\s*$'
            $isPublishAdjacent = ($jobText -match '(?i)\bnpm\s+publish\b') -or
                                 ($jobText -match '(?i)\bpypa/gh-action-pypi-publish@') -or
                                 ($jobText -match '(?i)\bgh\s+release\s+create\b') -or
                                 ($jobText -match '(?i)\bsoftprops/action-gh-release@') -or
                                 $hasDockerPush

            $findings.Add([PSCustomObject]@{
                    JobName           = $job.Name
                    IsPublishAdjacent = $isPublishAdjacent
                })
        }

        if (-not $anyIdToken) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OidcTrust' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not request OIDC tokens (id-token: write)." `
                -Remediation 'No action needed.'))
            continue
        }

        if ($findings.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OidcTrust' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' requests OIDC tokens and declares environment scoping for analyzed jobs." `
                -Remediation 'No action needed. Keep cloud IAM trust policies scoped to expected repos/refs/environments.'))
            continue
        }

        $publishAdjacentFindings = @($findings | Where-Object { $_.IsPublishAdjacent })
        $affectedJobs = @($findings | ForEach-Object { $_.JobName } | Sort-Object -Unique)

        if ($publishAdjacentFindings.Count -gt 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'OidcTrust' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' requests OIDC tokens without environment scoping in publish-adjacent job(s): $($affectedJobs -join ', '). This matches the Bitwarden CLI 2026-04 primitive (OIDC trusted publishing without environment gating). Cross-check this job with PublishIntegrity controls to ensure both provenance and trust gating are enforced." `
                -Remediation 'Workflow requests OIDC id-token without environment scoping. Verify cloud IAM trust policies are properly restricted. If this job publishes packages, add environment: with required reviewers - OIDC trusted publishing without environment gating is the primitive exploited in the Bitwarden CLI 2026-04 compromise.' `
                -AttackMapping @('oidc-trust-abuse', 'bitwarden-cli-2026-04')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'OidcTrust' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' requests OIDC tokens without environment scoping in job(s): $($affectedJobs -join ', '). Cloud-side trust policies cannot be verified from workflow YAML alone, so this should be reviewed manually." `
            -Remediation 'Workflow requests OIDC id-token without environment scoping. Verify cloud IAM trust policies are properly restricted. Add environment protection with required reviewers for sensitive jobs.' `
            -AttackMapping @('oidc-trust-abuse')))
    }

    return $results.ToArray()
}
