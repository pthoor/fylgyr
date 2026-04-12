function Test-EgressControl {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known egress control actions
    $egressActions = @(
        @{ Pattern = 'step-security/harden-runner'; Name = 'StepSecurity Harden-Runner' }
        @{ Pattern = 'code-cargo/cargowall-action'; Name = 'CargoWall Action' }
        @{ Pattern = 'bullfrogsec/bullfrog'; Name = 'BullFrog' }
    )

    # Patterns indicating network calls in run steps
    $networkCallPatterns = @(
        '(?m)^\s*-?\s*run:.*\b(curl|wget)\b'
        '(?m)^\s*(curl|wget)\s'
        '(?m)\bInvoke-WebRequest\b'
        '(?m)\bInvoke-RestMethod\b'
        '(?m)\biwr\b\s'
    )

    foreach ($wf in $WorkflowFiles) {
        # Strip YAML comment lines to avoid false positives
        $strippedLines = ($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }
        $stripped = $strippedLines -join "`n"

        $foundControls = [System.Collections.Generic.List[string]]::new()
        $hasAuditOnly = $false
        $hasBullfrog = $false

        foreach ($action in $egressActions) {
            if ($stripped -match [regex]::Escape($action.Pattern)) {
                $foundControls.Add($action.Name)

                if ($action.Pattern -eq 'bullfrogsec/bullfrog') {
                    $hasBullfrog = $true
                }
            }
        }

        # Check egress-policy setting
        if ($stripped -match '(?i)egress-policy:\s*audit') {
            $hasAuditOnly = $true
        }
        $hasBlockPolicy = $stripped -match '(?i)egress-policy:\s*block'

        # Check for network calls without egress controls
        $hasNetworkCalls = $false
        foreach ($pattern in $networkCallPatterns) {
            if ($stripped -match $pattern) {
                $hasNetworkCalls = $true
                break
            }
        }

        if ($foundControls.Count -gt 0) {
            $controlList = $foundControls -join ', '

            if ($hasBlockPolicy) {
                $detail = "Workflow '$($wf.Name)' has egress controls ($controlList) with block enforcement."
                $status = 'Pass'
                $severity = 'Info'

                if ($hasBullfrog) {
                    $detail += ' Note: BullFrog has a known DNS-over-TCP bypass disclosed Feb 2026 (see https://devansh.bearblog.dev/bullfrog-dns-pipelining/). Consider layering with additional controls.'
                }

                $results.Add((Format-FylgyrResult `
                    -CheckName 'EgressControl' `
                    -Status $status `
                    -Severity $severity `
                    -Resource $wf.Path `
                    -Detail $detail `
                    -Remediation 'No action needed. Continue monitoring egress control effectiveness.' `
                    -Target $null))
            }
            elseif ($hasAuditOnly) {
                $detail = "Workflow '$($wf.Name)' has egress controls ($controlList) in audit-only mode. This provides visibility into network calls but does not block unauthorized egress."

                if ($hasBullfrog) {
                    $detail += ' Note: BullFrog has a known DNS-over-TCP bypass disclosed Feb 2026.'
                }

                $results.Add((Format-FylgyrResult `
                    -CheckName 'EgressControl' `
                    -Status 'Info' `
                    -Severity 'Low' `
                    -Resource $wf.Path `
                    -Detail $detail `
                    -Remediation "Switch egress-policy from 'audit' to 'block' to enforce network restrictions. Audit mode is a good first step but does not prevent exfiltration." `
                    -AttackMapping @('tj-actions-shai-hulud', 'codecov-bash-uploader') `
                    -Target $null))
            }
            else {
                $results.Add((Format-FylgyrResult `
                    -CheckName 'EgressControl' `
                    -Status 'Pass' `
                    -Severity 'Info' `
                    -Resource $wf.Path `
                    -Detail "Workflow '$($wf.Name)' has egress controls ($controlList)." `
                    -Remediation 'No action needed.' `
                    -Target $null))
            }
        }
        else {
            $severity = 'Medium'
            $detail = "Workflow '$($wf.Name)' has no egress controls. Compromised actions or injected code can freely exfiltrate secrets over the network, as seen in the tj-actions/changed-files and Trivy supply chain attacks."

            if ($hasNetworkCalls) {
                $detail += ' This workflow contains network calls (curl, wget, Invoke-WebRequest, or Invoke-RestMethod) that could be exploited without egress filtering.'
            }

            $results.Add((Format-FylgyrResult `
                -CheckName 'EgressControl' `
                -Status 'Warning' `
                -Severity $severity `
                -Resource $wf.Path `
                -Detail $detail `
                -Remediation "Add step-security/harden-runner with egress-policy: block as the first step in each job. Free for public repos, trusted by 11,000+ projects including Microsoft and Google. GitHub's 2026 roadmap includes a native Layer 7 egress firewall (public preview in 3-6 months). Azure VNet integration is available now for Enterprise Cloud customers." `
                -AttackMapping @('tj-actions-shai-hulud', 'trivy-supply-chain-2026', 'codecov-bash-uploader') `
                -Target $null))
        }
    }

    $results.ToArray()
}
