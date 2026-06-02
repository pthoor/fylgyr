function Test-PublishIntegrity {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        # Strip YAML comment lines before pattern matching to reduce false positives.
        $lines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        $normalized = $lines -join "`n"

        $hasIdTokenWrite = $normalized -match '(?im)^\s*id-token\s*:\s*write\s*$'
        $hasNpmTokenEnv = $normalized -match '(?i)\b(NPM_TOKEN|NODE_AUTH_TOKEN)\b'

        $npmPublishLines = @($lines | Where-Object { $_ -match '(?i)\bnpm\s+publish\b' })
        $hasNpmPublish = $npmPublishLines.Count -gt 0
        $hasNpmProvenance = @($npmPublishLines | Where-Object { $_ -match '(?i)\bnpm\s+publish\b.*--provenance\b' }).Count -gt 0

        $hasPypiPublish = $false
        $pypiUsesPassword = $false

        $dockerPushSteps = 0
        $hasReleasePublish = $false

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]

            if ($line -match '(?i)\buses\s*:\s*pypa/gh-action-pypi-publish@') {
                $hasPypiPublish = $true
                for ($j = $i + 1; $j -lt $lines.Count -and $j -le ($i + 18); $j++) {
                    if ($lines[$j] -match '^\s*-\s*uses\s*:') {
                        break
                    }

                    if ($lines[$j] -match '^\s*password\s*:') {
                        $pypiUsesPassword = $true
                        break
                    }
                }
            }

            if ($line -match '(?i)\buses\s*:\s*docker/build-push-action@') {
                $stepPushEnabled = $false
                for ($j = $i + 1; $j -lt $lines.Count -and $j -le ($i + 18); $j++) {
                    if ($lines[$j] -match '^\s*-\s*uses\s*:') {
                        break
                    }

                    if ($lines[$j] -match '(?i)^\s*push\s*:\s*true\s*$') {
                        $stepPushEnabled = $true
                        break
                    }
                }

                if ($stepPushEnabled) {
                    $dockerPushSteps++
                }
            }

            if ($line -match '(?i)\bgh\s+release\s+create\b' -or
                $line -match '(?i)\buses\s*:\s*softprops/action-gh-release@') {
                $hasReleasePublish = $true
            }
        }

        $hasContainerAttestation = $normalized -match '(?i)\bcosign\s+sign\b' -or
                                   $normalized -match '(?i)\buses\s*:\s*actions/attest-build-provenance@'

        $hasReleaseAttestation = $normalized -match '(?i)\bgh\s+attestation\b' -or
                                 $normalized -match '(?i)\buses\s*:\s*actions/attest-build-provenance@'

        $hasPublishStep = $hasNpmPublish -or $hasPypiPublish -or ($dockerPushSteps -gt 0) -or $hasReleasePublish

        $findings = [System.Collections.Generic.List[string]]::new()

        if ($hasNpmPublish -and -not $hasNpmProvenance) {
            if ($hasNpmTokenEnv) {
                $findings.Add('Detected npm publish using token-based auth without --provenance. Long-lived npm tokens are a primary compromise path in incidents like Shai-Hulud and lottie-player.')
            }
            elseif ($hasIdTokenWrite) {
                $findings.Add('Detected npm publish with id-token: write but missing --provenance. Trusted publishing to npm must use npm publish --provenance to emit verifiable provenance.')
            }
            else {
                $findings.Add('Detected npm publish without --provenance and without evidence of trusted publishing. This weakens publish-chain integrity and incident response confidence.')
            }
        }

        if ($hasPypiPublish -and $pypiUsesPassword) {
            $findings.Add('Detected pypa/gh-action-pypi-publish with password input. Prefer PyPI Trusted Publishing (OIDC) with no password field.')
        }

        if ($dockerPushSteps -gt 0 -and -not $hasContainerAttestation) {
            $findings.Add('Detected docker/build-push-action push without cosign signing or actions/attest-build-provenance. Published containers are missing a verifiable integrity signal.')
        }

        if ($hasReleasePublish -and -not $hasReleaseAttestation) {
            $findings.Add('Detected GitHub Release publishing without an attestation step. Release artifacts should include provenance or attestations for downstream verification.')
        }

        if ($findings.Count -gt 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PublishIntegrity' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail ($findings -join ' ') `
                -Remediation 'For npm, use npm publish --provenance with OIDC trusted publishing. For PyPI, remove password and use Trusted Publishing. For containers and releases, add cosign signing or actions/attest-build-provenance.' `
                -AttackMapping @('shai-hulud-npm-worm', 'lottie-player-npm-compromise', 'ua-parser-js-npm-compromise', 'bitwarden-cli-2026-04', 'event-stream-hijack')))
            continue
        }

        if (-not $hasPublishStep) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'PublishIntegrity' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not appear to publish packages, container images, or releases." `
                -Remediation 'No action needed.'))
            continue
        }

        $crossCheckNote = ''
        if ($hasNpmPublish -and $hasNpmProvenance -and $hasIdTokenWrite) {
            $crossCheckNote = ' npm publish uses OIDC-oriented provenance controls. Also verify OIDC trust hardening on publish jobs: use protected environments with required reviewers and trusted ref restrictions; OIDC without environment gating was exploited in the Bitwarden CLI 2026-04 compromise.'
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'PublishIntegrity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Publish-related steps in workflow '$($wf.Name)' include provenance/OIDC/signing signals.$crossCheckNote" `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
