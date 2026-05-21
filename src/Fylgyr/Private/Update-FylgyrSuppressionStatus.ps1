function Resolve-FylgyrSuppressionStatus {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [PSCustomObject[]]$Suppressions = @()
    )

    if (-not $Suppressions -or $Suppressions.Count -eq 0) {
        return $Results
    }

    $utcNow = [datetime]::UtcNow
    foreach ($result in $Results) {
        if (-not $result) {
            continue
        }

        if ($result.Status -in @('Pass', 'Error')) {
            continue
        }

        $normalizedResultCheck = ([string]$result.CheckName) -replace '^Test-', ''
        $resourceValue = [string]$result.Resource
        $resourceWithoutLine = if ($resourceValue -match '^(.+):(\d+)$') {
            $Matches[1]
        }
        else {
            $resourceValue
        }

        $matchingRules = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($suppression in $Suppressions) {
            if (-not $suppression) {
                continue
            }

            $normalizedSuppressionCheck = ([string]$suppression.Check) -replace '^Test-', ''
            if ($normalizedSuppressionCheck -ine $normalizedResultCheck) {
                continue
            }

            $suppressionResource = [string]$suppression.Resource
            $resourceMatches = $false
            if ($suppressionResource -ieq $resourceValue) {
                $resourceMatches = $true
            }
            elseif ($suppressionResource -ieq $resourceWithoutLine) {
                $resourceMatches = $true
            }

            if ($resourceMatches) {
                $matchingRules.Add($suppression)
            }
        }

        if ($matchingRules.Count -eq 0) {
            continue
        }

        $activeRule = $null
        $expiredRule = $null
        foreach ($matchingRule in $matchingRules) {
            if (-not $matchingRule.ExpiresUtc -or $matchingRule.ExpiresUtc -ge $utcNow) {
                $activeRule = $matchingRule
                break
            }

            if (-not $expiredRule) {
                $expiredRule = $matchingRule
            }
        }

        if ($activeRule) {
            $result.Status = 'Suppressed'

            $suppressionNote = "Suppressed by .fylgyr.yml: $($activeRule.Reason)"
            if ($result.Detail -notmatch 'Suppressed by \.fylgyr\.yml:') {
                $result.Detail = "$($result.Detail) $suppressionNote"
            }
            continue
        }

        if ($expiredRule) {
            $expiredNote = "Suppression expired on $(([datetime]$expiredRule.ExpiresUtc).ToString('yyyy-MM-dd')): $($expiredRule.Reason)"
            if ($result.Detail -notmatch 'Suppression expired on') {
                $result.Detail = "$($result.Detail) $expiredNote"
            }
        }
    }

    return $Results
}
