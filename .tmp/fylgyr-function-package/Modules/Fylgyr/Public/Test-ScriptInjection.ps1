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
        'github\.event\.discussion\.(body|title)'
        'github\.event\.pages\.[^.]+\.page_name'
        'github\.event\.commits\.[^.]+\.message'
        'github\.event\.head_commit\.message'
        'github\.head_ref'
        'github\.event\.workflow_run\.head_branch'
        'github\.event\.pull_request\.head\.label'
        'github\.event\.pull_request\.head\.repo\.default_branch'
    )

    foreach ($wf in $WorkflowFiles) {
        $sanitizedContent = (($wf.Content -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $runBlocks = @(Get-RunBlock -Content $sanitizedContent)

        $riskyExpressions = [System.Collections.Generic.List[string]]::new()

        foreach ($block in $runBlocks) {
            $expressionMatches = [regex]::Matches($block.Content, '\$\{\{\s*(?<expr>[^}]+?)\s*\}\}')
            foreach ($match in $expressionMatches) {
                $expr = $match.Groups['expr'].Value.Trim().ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($expr)) {
                    continue
                }

                $isSafeExpression = $false
                foreach ($safePattern in $safeExpressions) {
                    if ($expr -match $safePattern) {
                        $isSafeExpression = $true
                        break
                    }
                }

                if ($isSafeExpression) {
                    continue
                }

                foreach ($unsafePattern in $userControlledPatterns) {
                    if ($expr -match $unsafePattern) {
                        $riskyExpressions.Add($expr)
                        break
                    }
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
                -Detail "Workflow '$($wf.Name)' interpolates untrusted GitHub event fields inside run steps: $($uniqueExpr -join ', '). This creates command-injection risk in shell execution context and matches real-world GitHub Actions script-injection campaigns." `
                -Remediation 'Never interpolate untrusted event fields directly in run steps. Move untrusted values into validated inputs or sanitize them before use. Known limitation: this check only evaluates run: blocks and does not currently inspect env: interpolation paths.' `
                -AttackMapping @('github-actions-script-injection')))
            continue
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'ScriptInjection' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $wf.Path `
            -Detail "Workflow '$($wf.Name)' has no detected untrusted event expression interpolation inside run blocks." `
            -Remediation 'No action needed.'))
    }

    return $results.ToArray()
}
