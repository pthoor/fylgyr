function Get-MissingTypesEvent {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$WorkflowContent,

        [Parameter(Mandatory)]
        [string[]]$Events
    )

    $missing = [System.Collections.Generic.List[string]]::new()
    $lines = $WorkflowContent -split "`n"

    foreach ($eventName in $Events) {
        $inlineArrayPattern = '(?im)^\s*on\s*:\s*\[[^\]]*\b' + [regex]::Escape($eventName) + '\b[^\]]*\]'
        $inlineScalarPattern = '(?im)^\s*on\s*:\s*' + [regex]::Escape($eventName) + '\s*$'
        if ($WorkflowContent -match $inlineArrayPattern -or $WorkflowContent -match $inlineScalarPattern) {
            $missing.Add($eventName)
            continue
        }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch '^\s*on\s*:\s*$') {
                continue
            }

            $onIndent = ([regex]::Match($lines[$i], '^\s*')).Value.Length
            $j = $i + 1
            while ($j -lt $lines.Count) {
                $candidate = $lines[$j]
                if ($candidate -match '^\s*$') {
                    $j++
                    continue
                }

                $candidateIndent = ([regex]::Match($candidate, '^\s*')).Value.Length
                if ($candidateIndent -le $onIndent) {
                    break
                }

                $eventHeaderPattern = '^\s{' + ($onIndent + 2) + '}' + [regex]::Escape($eventName) + '\s*:(?<tail>.*)$'
                if ($candidate -match $eventHeaderPattern) {
                    $tail = $Matches.tail.Trim()
                    $hasTypes = $false

                    if ($tail -match '(?i)\btypes\b') {
                        $hasTypes = $true
                    }
                    else {
                        $eventIndent = $candidateIndent
                        $k = $j + 1
                        while ($k -lt $lines.Count) {
                            $eventLine = $lines[$k]
                            if ($eventLine -match '^\s*$') {
                                $k++
                                continue
                            }

                            $eventLineIndent = ([regex]::Match($eventLine, '^\s*')).Value.Length
                            if ($eventLineIndent -le $eventIndent) {
                                break
                            }

                            if ($eventLine -match '^\s*types\s*:') {
                                $hasTypes = $true
                                break
                            }

                            $k++
                        }
                    }

                    if (-not $hasTypes) {
                        $missing.Add($eventName)
                    }

                    break
                }

                $j++
            }
        }
    }

    @($missing | Sort-Object -Unique)
}
