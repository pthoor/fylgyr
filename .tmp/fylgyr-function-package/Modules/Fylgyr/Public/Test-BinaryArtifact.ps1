function Test-BinaryArtifact {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = $target

    try {
        $treeResult = Get-RepoTree -Owner $Owner -Repo $Repo -Token $Token
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'BinaryArtifact' `
                -Status 'Error' `
                -Severity 'Low' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read repository tree.' `
                -Remediation 'Use a fine-grained token with Contents:read permission, or a classic token with repo scope.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'BinaryArtifact' `
            -Status 'Error' `
            -Severity 'Low' `
            -Resource $resource `
            -Detail "Unexpected error reading repository tree: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if ($treeResult.PSObject.Properties['empty'] -and $treeResult.empty) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'BinaryArtifact' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'Repository is empty or has no committed files.' `
            -Remediation 'No action needed.' `
            -Target $target))
        return $results.ToArray()
    }

    # Handle truncated tree — large repos may exceed the 100,000-entry API limit
    if ($treeResult.truncated -eq $true) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'BinaryArtifact' `
            -Status 'Info' `
            -Severity 'Low' `
            -Resource $resource `
            -Detail 'Repository tree was truncated by the GitHub API (exceeds 100,000 entries). Binary artifact check is incomplete — not all files could be inspected.' `
            -Remediation 'Use the GitHub web UI or git CLI to manually audit for committed binaries. Run git ls-files locally and filter for .exe, .dll, .so, .dylib, .bin, .jar, .war, .a, .o, .pyc, or .class extensions.' `
            -Target $target))
        return $results.ToArray()
    }

    $binaryExtensions = @('.exe', '.dll', '.so', '.dylib', '.bin', '.jar', '.war', '.a', '.o', '.pyc', '.class')
    $treeEntries = if ($treeResult.tree) { $treeResult.tree } else { @() }

    $binaryFiles = [System.Collections.Generic.List[string]]::new()

    foreach ($entry in $treeEntries) {
        if ($entry.type -ne 'blob') {
            continue
        }
        $ext = [System.IO.Path]::GetExtension($entry.path).ToLowerInvariant()
        if ($binaryExtensions -contains $ext) {
            $binaryFiles.Add($entry.path)
        }
    }

    if ($binaryFiles.Count -gt 0) {
        $sample = ($binaryFiles | Select-Object -First 10) -join ', '
        $detail = "$($binaryFiles.Count) binary file(s) found in the default branch tree. Committed binaries hide backdoors that source-level review cannot catch — this is the pattern behind the SolarWinds Orion SUNBURST attack, where injected compiled code in build artifacts went undetected for months. Files (first 10): $sample."
        if ($binaryFiles.Count -gt 10) {
            $detail = "$($binaryFiles.Count) binary file(s) found in the default branch tree. Committed binaries hide backdoors that source-level review cannot catch — this is the pattern behind the SolarWinds Orion SUNBURST attack, where injected compiled code in build artifacts went undetected for months. First 10 of $($binaryFiles.Count) files: $sample."
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'BinaryArtifact' `
            -Status 'Fail' `
            -Severity 'Low' `
            -Resource $resource `
            -Detail $detail `
            -Remediation 'Remove committed binaries from the repository. Store build artifacts in GitHub Releases or a package registry. Add binary extensions to .gitignore. If vendored binaries are required as test fixtures, document them and verify their integrity with checksums.' `
            -AttackMapping @('solarwinds-orion') `
            -Target $target))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'BinaryArtifact' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No binary files with known risk extensions found in the default branch tree.' `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
