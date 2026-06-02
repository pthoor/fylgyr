function Test-ArtifactAttestation {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $content = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $jobBlocks = @(Get-WorkflowJobBlock -Content $content)

        $releaseJobsMissingAttestation = [System.Collections.Generic.List[string]]::new()
        $foundReleaseJob = $false

        foreach ($job in $jobBlocks) {
            $jobText = $job.Content
            $hasDockerPush = $jobText -match '(?im)^\s*-\s*uses\s*:\s*docker/build-push-action@' -and $jobText -match '(?im)^\s*push\s*:\s*true\s*$'
            $isReleaseJob = ($jobText -match '(?i)\bnpm\s+publish\b') -or
                            ($jobText -match '(?i)\bpypa/gh-action-pypi-publish@') -or
                            ($jobText -match '(?i)\bsoftprops/action-gh-release@') -or
                            ($jobText -match '(?i)\bactions/upload-release-asset@') -or
                            ($jobText -match '(?i)\bgh\s+release\s+create\b') -or
                            $hasDockerPush

            if (-not $isReleaseJob) {
                continue
            }

            $foundReleaseJob = $true

            $hasAttestationStep = ($jobText -match '(?im)^\s*-\s*uses\s*:\s*actions/attest-build-provenance@') -or
                                  ($jobText -match '(?im)^\s*-\s*uses\s*:\s*actions/attest@')
            $hasIdTokenWrite = $jobText -match '(?im)^\s*id-token\s*:\s*write\s*$'
            $hasAttestationsWrite = $jobText -match '(?im)^\s*attestations\s*:\s*write\s*$'

            if (-not $hasAttestationStep -or -not $hasIdTokenWrite -or -not $hasAttestationsWrite) {
                $releaseJobsMissingAttestation.Add($job.Name)
            }
        }

        if (-not $foundReleaseJob) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ArtifactAttestation' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not appear to produce release artifacts." `
                -Remediation 'No action needed.'))
            continue
        }

        if ($releaseJobsMissingAttestation.Count -gt 0) {
            $missingJobs = @($releaseJobsMissingAttestation | Sort-Object -Unique) -join ', '
            $results.Add((Format-FylgyrResult `
                -CheckName 'ArtifactAttestation' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail "Release-producing job(s) in workflow '$($wf.Name)' are missing full provenance attestation controls (actions/attest-build-provenance or actions/attest with id-token: write + attestations: write): $missingJobs. Cross-check with PublishIntegrity; passing publish controls without provenance attestation still leaves integrity blind spots." `
                -Remediation 'For each release-producing job, add actions/attest-build-provenance (or actions/attest) and grant id-token: write plus attestations: write in permissions.' `
                -AttackMapping @('solarwinds-orion', 'codecov-bash-uploader')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ArtifactAttestation' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "All release-producing jobs in workflow '$($wf.Name)' include provenance attestation signals." `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
