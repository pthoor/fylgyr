function Test-LifecycleScript {
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
        [string]$Token,

        [AllowEmptyCollection()]
        [PSCustomObject[]]$WorkflowFiles = @()
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $attackMap = @('shai-hulud-npm-worm', 'event-stream-hijack', 'ua-parser-js-npm-compromise')

    # --- Part 1: package-manager installs in CI without --ignore-scripts ---
    # Any compromised (transitive) dependency executes arbitrary code at install
    # time via lifecycle scripts, inside a runner that holds tokens and secrets.
    $installPattern = '(?i)\b(npm\s+(ci|install|i)\b|yarn\s+install\b|pnpm\s+(install|i)\b)'

    foreach ($wf in @($WorkflowFiles)) {
        $sanitizedContent = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

        $unprotectedInstalls = [System.Collections.Generic.List[string]]::new()
        $installCount = 0

        foreach ($block in @(Get-RunBlock -Content $sanitizedContent)) {
            foreach ($line in ($block.Content -split "`n")) {
                if ($line -notmatch $installPattern) {
                    continue
                }

                $installCount++
                if ($line -notmatch '--ignore-scripts') {
                    $command = $line.Trim()
                    if ($command.Length -gt 120) {
                        $command = $command.Substring(0, 120) + '...'
                    }
                    $unprotectedInstalls.Add($command)
                }
            }
        }

        if ($installCount -eq 0) {
            continue
        }

        if ($unprotectedInstalls.Count -gt 0) {
            $uniqueInstalls = @($unprotectedInstalls | Sort-Object -Unique)
            $results.Add((Format-FylgyrResult `
                -CheckName 'LifecycleScript' `
                -Status 'Warning' `
                -Severity 'Medium' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' runs dependency install(s) without --ignore-scripts: $($uniqueInstalls -join '; '). Install-time lifecycle scripts of any compromised transitive dependency execute arbitrary code on the runner - the delivery mechanism used by event-stream, ua-parser-js, and the Shai-Hulud npm worm." `
                -Remediation 'Add --ignore-scripts to CI installs (or set ignore-scripts=true in .npmrc) and run required build scripts explicitly. If a dependency genuinely needs its install script, allowlist it deliberately.' `
                -AttackMapping $attackMap))
        }
        else {
            $results.Add((Format-FylgyrResult `
                -CheckName 'LifecycleScript' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' runs all detected dependency installs with --ignore-scripts." `
                -Remediation 'No action needed.'))
        }
    }

    # --- Part 2: the repository's own package.json lifecycle scripts ---
    # Best effort: repos without a root package.json (or without contents access)
    # are skipped silently.
    $packageJson = $null
    try {
        $contentResponse = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/contents/package.json" -Token $Token
        if ($contentResponse -and $contentResponse.PSObject.Properties['content'] -and $contentResponse.content) {
            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((([string]$contentResponse.content) -replace '\s', '')))
            $packageJson = $decoded | ConvertFrom-Json
        }
    }
    catch {
        Write-Debug "package.json was not scanned for '$target': $($_.Exception.Message)"
    }

    if (-not $packageJson) {
        return $results.ToArray()
    }

    $lifecycleKeys = @('preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepublishOnly')
    # Network fetches, encoding tricks, and dynamic execution inside an
    # install-time script are the signature of npm-worm payloads. The dynamic
    # execution names use character classes to keep the literals out of source.
    $suspiciousPattern = '(?i)(\bcurl\b|\bwget\b|https?://|base64|child_process|\bnode\s+-e\b|\beva[l]\b|\bie[x]\b|invoke-webrequest|invoke-restmethod|\|\s*(ba)?sh\b)'

    $declaredLifecycle = [System.Collections.Generic.List[string]]::new()
    $suspiciousLifecycle = [System.Collections.Generic.List[string]]::new()

    if ($packageJson.PSObject.Properties['scripts'] -and $packageJson.scripts) {
        foreach ($key in $lifecycleKeys) {
            if (-not $packageJson.scripts.PSObject.Properties[$key]) {
                continue
            }

            $scriptBody = [string]$packageJson.scripts.$key
            if ([string]::IsNullOrWhiteSpace($scriptBody)) {
                continue
            }

            $declaredLifecycle.Add($key)
            if ($scriptBody -match $suspiciousPattern) {
                $suspiciousLifecycle.Add($key)
            }
        }
    }

    if ($suspiciousLifecycle.Count -gt 0) {
        # Script bodies are untrusted repo data; report key names only.
        $results.Add((Format-FylgyrResult `
            -CheckName 'LifecycleScript' `
            -Status 'Fail' `
            -Severity 'High' `
            -Resource "$target/package.json" `
            -Detail "package.json declares install-time lifecycle script(s) ($($suspiciousLifecycle -join ', ')) that invoke network download, encoding, or dynamic-execution primitives. This is the exact payload shape of the event-stream, ua-parser-js, and Shai-Hulud npm compromises: code that runs automatically on every install of the package." `
            -Remediation 'Review the flagged lifecycle scripts. Remove network fetches and dynamic execution from install-time scripts, or move that logic to an explicit, documented build step that consumers opt into.' `
            -AttackMapping $attackMap `
            -Target $target))
    }
    elseif ($declaredLifecycle.Count -gt 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'LifecycleScript' `
            -Status 'Info' `
            -Severity 'Low' `
            -Resource "$target/package.json" `
            -Detail "package.json declares install-time lifecycle script(s): $($declaredLifecycle -join ', '). Nothing suspicious detected, but install-time scripts run automatically for every consumer, so keep them minimal and reviewed - they are the execution vehicle npm supply-chain attacks rely on." `
            -Remediation 'Confirm each lifecycle script is intentional and does not fetch or execute remote content.' `
            -AttackMapping $attackMap `
            -Target $target))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'LifecycleScript' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource "$target/package.json" `
            -Detail 'package.json declares no install-time lifecycle scripts.' `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
