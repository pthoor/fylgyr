function Get-RunBlock {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Content,

        # YAML key whose scalar value is the executable body. Defaults to 'run';
        # pass 'script' to capture actions/github-script inline scripts.
        [string]$Key = 'run'
    )

    $blocks = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $blocks.ToArray()
    }

    $lines = $Content -split "`n"
    $keyPattern = '^(?<indent>\s*)(?:-\s*)?' + [regex]::Escape($Key) + '\s*:\s*(?<value>.*)$'

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*#') {
            continue
        }

        if ($line -notmatch $keyPattern) {
            continue
        }

        $baseIndent = $Matches.indent.Length
        $value = $Matches.value.Trim()
        $startLine = $i + 1

        $isBlockScalar = $value -match '^[|>][+-]?$'
        $isImplicitMultiline = [string]::IsNullOrWhiteSpace($value)

        if ($isBlockScalar -or $isImplicitMultiline) {
            $blockLines = [System.Collections.Generic.List[string]]::new()
            $j = $i + 1

            while ($j -lt $lines.Count) {
                $nextLine = $lines[$j]

                if ($nextLine -match '^\s*$') {
                    $blockLines.Add('')
                    $j++
                    continue
                }

                $nextIndent = ([regex]::Match($nextLine, '^\s*')).Value.Length
                if ($nextIndent -le $baseIndent) {
                    break
                }

                $trimCount = [Math]::Min($nextLine.Length, $baseIndent + 2)
                $blockLines.Add($nextLine.Substring($trimCount))
                $j++
            }

            $blocks.Add([PSCustomObject]@{
                    StartLine = $startLine
                    EndLine   = if ($j -gt $startLine) { $j } else { $startLine }
                    Content   = $blockLines -join "`n"
                })

            $i = $j - 1
            continue
        }

        $blocks.Add([PSCustomObject]@{
                StartLine = $startLine
                EndLine   = $startLine
                Content   = $value
            })
    }

    $blocks.ToArray()
}
