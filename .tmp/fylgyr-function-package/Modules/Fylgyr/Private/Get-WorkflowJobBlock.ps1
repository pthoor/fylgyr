function Get-WorkflowJobBlock {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Content
    )

    $jobBlocks = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ([string]::IsNullOrWhiteSpace($Content)) {
        return $jobBlocks.ToArray()
    }

    $lines = $Content -split "`n"
    $jobsStart = -1

    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*jobs\s*:\s*$') {
            $jobsStart = $i
            break
        }
    }

    if ($jobsStart -lt 0) {
        return $jobBlocks.ToArray()
    }

    $jobsIndent = ([regex]::Match($lines[$jobsStart], '^\s*')).Value.Length

    for ($i = $jobsStart + 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]

        if ($line -match '^\s*$') {
            continue
        }

        $indent = ([regex]::Match($line, '^\s*')).Value.Length
        if ($indent -le $jobsIndent) {
            break
        }

        $jobHeaderPattern = '^\s{' + ($jobsIndent + 2) + '}(?<name>[A-Za-z0-9._-]+)\s*:\s*$'
        if ($line -notmatch $jobHeaderPattern) {
            continue
        }

        $jobName = $Matches.name
        $jobStart = $i
        $j = $i + 1

        while ($j -lt $lines.Count) {
            $nextLine = $lines[$j]
            if ($nextLine -match '^\s*$') {
                $j++
                continue
            }

            $nextIndent = ([regex]::Match($nextLine, '^\s*')).Value.Length
            if ($nextIndent -le $jobsIndent) {
                break
            }

            if ($nextIndent -eq ($jobsIndent + 2) -and $nextLine -match '^\s{' + ($jobsIndent + 2) + '}[A-Za-z0-9._-]+\s*:\s*$') {
                break
            }

            $j++
        }

        $jobContent = ($lines[$jobStart..([Math]::Max($jobStart, $j - 1))]) -join "`n"
        $jobBlocks.Add([PSCustomObject]@{
                Name      = $jobName
                StartLine = $jobStart + 1
                EndLine   = [Math]::Max($jobStart + 1, $j)
                Content   = $jobContent
            })

        $i = $j - 1
    }

    $jobBlocks.ToArray()
}
