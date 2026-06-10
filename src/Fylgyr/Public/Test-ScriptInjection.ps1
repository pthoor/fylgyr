function Test-ScriptInjection {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$WorkflowFiles
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $safeExpressions = @(
        '^github\.event\.number$'
        '^github\.sha$'
        '^github\.ref$'
        '^github\.run_id$'
        '^github\.run_number$'
        '^github\.actor$'
        '^github\.repository$'
    )

    $userControlledPatterns = @(
        'github\.event\.issue\.(title|body)'
        'github\.event\.pull_request\.(title|body)'
        'github\.event\.comment\.body'
        'github\.event\.review\.body'
        'github\.event\.pull_request_review_comment\.body'
        'github\.event\.discussion\.(body|title)'
        'github\.event\.pages\.[^.]+\.page_name'
        'github\.event\.commits\.[^.]+\.message'
        'github\.event\.head_commit\.message'
        'github\.head_ref'
        'github\.event\.workflow_run\.head_branch'
        'github\.event\.workflow_run\.pull_requests'
        'github\.event\.pull_request\.head\.label'
        'github\.event\.pull_request\.head\.repo\.default_branch'
    )

    # Normalizes a GitHub Actions expression for pattern matching: lowercases and
    # rewrites bracket access (event['issue']['title']) into dot form so it cannot
    # be used to slip an untrusted context past the patterns above.
    function Get-NormalizedExpr {
        param([string]$Raw)
        $e = $Raw.Trim().ToLowerInvariant()
        $e = $e -replace "\[\s*'([^']+)'\s*\]", '.$1'
        $e = $e -replace '\[\s*"([^"]+)"\s*\]', '.$1'
        return $e
    }

    function Test-UnsafeExpr {
        param([string]$Expr)
        foreach ($safePattern in $safeExpressions) {
            if ($Expr -match $safePattern) { return $false }
        }
        foreach ($unsafePattern in $userControlledPatterns) {
            if ($Expr -match $unsafePattern) { return $true }
        }
        return $false
    }

    foreach ($wf in $WorkflowFiles) {
        $sanitizedContent = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $lines = $sanitizedContent -split "`n"

        # Pass 1: find env vars (at workflow/job/step level) whose value embeds an
        # untrusted expression. Using such a var later in a run/script step is the
        # indirection form of the injection - the dangerous case the previous
        # version explicitly did not cover.
        $taintedEnvVars = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        for ($li = 0; $li -lt $lines.Count; $li++) {
            if ($lines[$li] -notmatch '^(?<indent>\s*)(?<dash>-\s*)?env\s*:\s*$') { continue }
            # Indent of the env key itself - for a list-item form ("- env:") that is
            # past the dash, so a sibling key (run:) is correctly seen as <= and ends the block.
            $envIndent = $Matches.indent.Length + $Matches.dash.Length

            for ($lj = $li + 1; $lj -lt $lines.Count; $lj++) {
                $child = $lines[$lj]
                if ($child -match '^\s*$') { continue }
                $childIndent = ([regex]::Match($child, '^\s*')).Value.Length
                if ($childIndent -le $envIndent) { break }

                if ($child -match '^\s*(?<name>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?<value>.+)$') {
                    $envName = $Matches.name
                    $envValue = $Matches.value
                    foreach ($m in [regex]::Matches($envValue, '\$\{\{\s*(?<expr>[^}]+?)\s*\}\}')) {
                        if (Test-UnsafeExpr -Expr (Get-NormalizedExpr -Raw $m.Groups['expr'].Value)) {
                            [void]$taintedEnvVars.Add($envName)
                            break
                        }
                    }
                }
            }
        }

        # Pass 2: scan executable bodies - both run: steps and actions/github-script
        # script: inputs - for direct untrusted interpolation or use of a tainted env var.
        $scanBlocks = @(Get-RunBlock -Content $sanitizedContent) + @(Get-RunBlock -Content $sanitizedContent -Key 'script')
        $riskyExpressions = [System.Collections.Generic.List[string]]::new()

        foreach ($block in $scanBlocks) {
            $expressionMatches = [regex]::Matches($block.Content, '\$\{\{\s*(?<expr>[^}]+?)\s*\}\}')
            foreach ($match in $expressionMatches) {
                $expr = Get-NormalizedExpr -Raw $match.Groups['expr'].Value
                if ([string]::IsNullOrWhiteSpace($expr)) {
                    continue
                }

                if (Test-UnsafeExpr -Expr $expr) {
                    $riskyExpressions.Add($expr)
                    continue
                }

                if ($expr -match '^env\.(?<name>[a-z0-9_-]+)$' -and $taintedEnvVars.Contains($Matches.name)) {
                    $riskyExpressions.Add("$expr (assigned from untrusted event data)")
                }
            }
        }

        if ($riskyExpressions.Count -gt 0) {
            $uniqueExpr = @($riskyExpressions | Sort-Object -Unique)
            $results.Add((Format-FylgyrResult `
                -CheckName 'ScriptInjection' `
                -Status 'Fail' `
                -Severity 'Critical' `
                -Resource $wf.Path `
                -Detail "Workflow '$($wf.Name)' interpolates untrusted GitHub event data inside an executable step (run/script): $($uniqueExpr -join ', '). This creates command-injection risk in shell execution context and matches real-world GitHub Actions script-injection campaigns." `
                -Remediation 'Never interpolate untrusted event data directly in run/script steps, and do not route it through an env var that is later interpolated. Bind it to an intermediate environment variable and reference it as a shell variable ("$FOO"), or validate it before use.' `
                -AttackMapping @('github-actions-script-injection')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ScriptInjection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has no detected untrusted event expression interpolation inside run/script blocks." `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
