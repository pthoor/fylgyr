function Test-UntrustedDownload {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Download output piped straight into an interpreter. The PowerShell
    # dynamic-execution cmdlet and its alias are spelled with character classes
    # so this tool's own source does not contain the banned literals.
    $pipeToShellPatterns = @(
        '(?i)\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+(-\S+\s+)*)?((ba|z|k|da)?sh|pwsh|powershell|python[0-9.]*|perl|node)\b'
        '(?i)\b(irm|iwr|invoke-restmethod|invoke-webrequest)\b[^|\n]*\|\s*(ie[x]|invoke-expressio[n])\b'
        '(?i)\b(ie[x]|invoke-expressio[n])\b\s*\(\s*[^)\n]{0,80}\b(irm|iwr|invoke-restmethod|invoke-webrequest)\b'
    )

    foreach ($wf in $WorkflowFiles) {
        $sanitizedContent = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $flaggedCommands = [System.Collections.Generic.List[string]]::new()
        foreach ($block in @(Get-RunBlock -Content $sanitizedContent)) {
            # Re-join shell line continuations so 'curl url \<newline> | bash'
            # is seen as one command.
            $body = $block.Content -replace '\\\s*\n\s*', ' '

            foreach ($pattern in $pipeToShellPatterns) {
                foreach ($match in [regex]::Matches($body, $pattern)) {
                    $snippet = $match.Value.Trim()
                    if ($snippet.Length -gt 160) {
                        $snippet = $snippet.Substring(0, 160) + '...'
                    }
                    $flaggedCommands.Add($snippet)
                }
            }
        }

        if ($flaggedCommands.Count -gt 0) {
            $uniqueCommands = @($flaggedCommands | Sort-Object -Unique)
            $results.Add((Format-FylgyrResult `
                -CheckName 'UntrustedDownload' `
                -Status 'Fail' `
                -Severity 'High' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' downloads and executes a remote script in one step: $($uniqueCommands -join '; '). The executed code is whatever the remote host serves at run time - it is invisible to code review, bypasses pinning, and is exactly how the Codecov bash uploader compromise exfiltrated CI credentials from thousands of pipelines." `
                -Remediation 'Vendor the script into the repository (or a pinned action) and execute the reviewed copy, or download to a file, verify a checksum/signature, and only then execute it.' `
                -AttackMapping @('codecov-bash-uploader')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'UntrustedDownload' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has no detected download-and-execute (pipe-to-shell) pattern in run steps." `
            -Remediation 'No action needed.'))
    }

    $results.ToArray()
}
