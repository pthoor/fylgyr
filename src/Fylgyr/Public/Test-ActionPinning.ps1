function Test-ActionPinning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [AllowEmptyCollection()]
        [PSCustomObject[]]$WorkflowFiles = @(),

        # Composite/JS action definition files (action.yml). Their `uses:` steps are
        # scanned with the same rules so an unpinned dependency inside a local action
        # is not missed.
        [AllowEmptyCollection()]
        [PSCustomObject[]]$ActionFiles = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-PinningResultsForFile {
        param(
            [PSCustomObject]$File,
            [bool]$IsComposite
        )

        $lines = $File.Content -split "`n"
        $unpinnedFound = $false

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]

            # Skip YAML comment lines
            if ($line -match '^\s*#') { continue }

            if ($line -notmatch '^\s*-?\s*uses:\s*(.+)$') { continue }

            $target = $Matches[1].Trim().Trim("'").Trim('"')

            # Strip trailing YAML inline comments (e.g., "actions/checkout@sha # v4.2.2")
            if ($target -match '^([^#]+)\s+#') {
                $target = $Matches[1].Trim()
            }

            # Skip local actions and Docker references
            if ($target -match '^\./' -or $target -match '^\.\.' -or $target -match '^docker://') {
                continue
            }

            # Third-party action: expect owner/repo@40-hex-char SHA
            if ($target -match '@[0-9a-fA-F]{40}$') {
                continue
            }

            $unpinnedFound = $true
            $lineNum = $i + 1
            $detail = if ($IsComposite) {
                "Unpinned action reference in composite action file: $target"
            }
            else {
                "Unpinned action reference: $target"
            }
            $results.Add((Format-FylgyrResult `
                -CheckName 'ActionPinning' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$($File.Path):$lineNum" `
                -Detail $detail `
                -Remediation 'Pin this action to a full 40-character commit SHA instead of a tag or branch.' `
                -AttackMapping @('trivy-tag-poisoning', 'tj-actions-shai-hulud', 'actions-cool-issues-helper-compromise')))
        }

        if (-not $unpinnedFound) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ActionPinning' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $File.Path `
                -Detail 'All action references are SHA-pinned.' `
                -Remediation 'None.'))
        }
    }

    foreach ($wf in @($WorkflowFiles)) {
        Add-PinningResultsForFile -File $wf -IsComposite $false
    }

    foreach ($af in @($ActionFiles)) {
        Add-PinningResultsForFile -File $af -IsComposite $true
    }

    return $results.ToArray()
}
