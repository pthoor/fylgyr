function Test-ActionPinning {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($wf in $WorkflowFiles) {
        $lines = $wf.Content -split "`n"
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
            $results.Add((Format-FylgyrResult `
                -CheckName 'ActionPinning' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource "$($wf.Path):$lineNum" `
                -Detail "Unpinned action reference: $target" `
                -Remediation 'Pin this action to a full 40-character commit SHA instead of a tag or branch.' `
                -AttackMapping @('trivy-tag-poisoning', 'tj-actions-shai-hulud')))
        }

        if (-not $unpinnedFound) {
            $results.Add((Format-FylgyrResult `
                -CheckName 'ActionPinning' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail 'All action references are SHA-pinned.' `
                -Remediation 'None.'))
        }
    }

    return $results.ToArray()
}
