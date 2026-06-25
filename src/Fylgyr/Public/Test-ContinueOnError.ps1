function Test-ContinueOnError {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Job name patterns that indicate security gates
    $securityJobPattern = '(?i)(scan|security|sast|dast|lint|test|validate|audit|check|gitleaks|trivy|codeql|semgrep|snyk)'

    # Action references associated with security scanning
    $securityActionPattern = '(?i)(aquasecurity/trivy|github/codeql-action|securecodewarrior/|snyk/actions|returntocorp/semgrep|gitleaks/|trufflesecurity/|anchore/scan|step-security/|dependency-review|ossf/scorecard)'

    foreach ($wf in $WorkflowFiles) {
        $stripped = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $jobBlocks = @(Get-WorkflowJobBlock -Content $stripped)

        $violatingJobs = [System.Collections.Generic.List[string]]::new()

        foreach ($job in $jobBlocks) {
            $isSecurityJob = $job.Name -match $securityJobPattern -or $job.Content -match $securityActionPattern

            if (-not $isSecurityJob) {
                continue
            }

            if ($job.Content -match '(?m)^\s*continue-on-error\s*:\s*true\s*(?:#.*)?$') {
                $violatingJobs.Add($job.Name)
            }
        }

        if ($violatingJobs.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ContinueOnError' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' has no security gate jobs with 'continue-on-error: true'." `
                -Remediation 'No action needed.'))
            continue
        }

        $jobList = ($violatingJobs | Sort-Object -Unique) -join ', '
        $results.Add((Format-FylgyrResult `
            -CheckName 'ContinueOnError' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $wf.Path `
            -Detail "Security gate job(s) in workflow '$($wf.Name)' use 'continue-on-error: true': $jobList. A step or action failure in these jobs is silenced and the workflow continues to subsequent steps including publishing or deployment. This allows a compromised security tool to exit non-zero — or a real vulnerability to fire an alert — without blocking the pipeline, replicating the integrity gap that made the SolarWinds build compromise go undetected." `
            -Remediation "Remove 'continue-on-error: true' from security scanning steps. If a tool is flaky, fix the tool configuration rather than masking its failures. If a step genuinely must not block the build, extract it into a separate informational workflow that runs in parallel." `
            -AttackMapping @('solarwinds-orion', 'codecov-bash-uploader')))
    }

    return $results.ToArray()
}
