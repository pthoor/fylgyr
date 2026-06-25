function Test-RunnerPinning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $stripped = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        # Match runs-on values that end in -latest, excluding matrix variable expressions.
        # Handles: scalar (runs-on: ubuntu-latest), array items, and quoted values.
        $latestMatches = [System.Collections.Generic.List[string]]::new()
        $lines = $stripped -split "`n"

        foreach ($line in $lines) {
            if ($line -notmatch '^\s*runs-on\s*:') {
                continue
            }

            # Skip matrix variable expressions - these are dynamic and not pinnable here
            if ($line -match '\$\{\{') {
                continue
            }

            $runsOnMatches = [regex]::Matches($line, "[\w.-]+-latest\b")
            foreach ($m in $runsOnMatches) {
                $latestMatches.Add([string]$m.Value)
            }
        }

        if ($latestMatches.Count -eq 0) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RunnerPinning' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' does not use any '-latest' runner labels." `
                -Remediation 'No action needed.'))
            continue
        }

        $uniqueLabels = @($latestMatches | Sort-Object -Unique)
        $labelList = $uniqueLabels -join ', '

        $results.Add((Format-FylgyrResult `
            -CheckName 'RunnerPinning' `
            -Status 'Warning' `
            -Severity 'Medium' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' uses mutable runner label(s): $labelList. GitHub-hosted runner images update automatically when a new major OS version is adopted under the '-latest' alias. An unexpected image update can change installed tool versions, shell behavior, or available binaries mid-build — the same class of uncontrolled environment drift that contributed to the detection gap in the SolarWinds Orion build compromise and the Trivy supply chain worm." `
            -Remediation "Pin runner labels to a specific OS version (for example, 'ubuntu-24.04' instead of 'ubuntu-latest') to eliminate silent environment drift. Review GitHub's runner changelog before manually updating the pinned version." `
            -AttackMapping @('trivy-supply-chain-2026', 'solarwinds-orion')))
    }

    return $results.ToArray()
}
