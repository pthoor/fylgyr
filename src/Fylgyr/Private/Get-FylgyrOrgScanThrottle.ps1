function Get-FylgyrOrgScanThrottle {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1, 20)]
        [int]$RequestedThrottle,

        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$RepoTotal,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $effectiveThrottle = [Math]::Min($RequestedThrottle, $RepoTotal)

    # Conservative rate-limit-aware throttle clamp for org-wide scans.
    try {
        $rateLimitInfo = Invoke-GitHubApi -Endpoint 'rate_limit' -Token $Token
        $remainingCore = 0
        if ($rateLimitInfo -and $rateLimitInfo.resources -and $rateLimitInfo.resources.core -and $null -ne $rateLimitInfo.resources.core.remaining) {
            $remainingCore = [int]$rateLimitInfo.resources.core.remaining
        }

        if ($remainingCore -le 0) {
            $effectiveThrottle = 1
        }
        else {
            # Assume a heavy scan can burst up to ~200 core requests per worker.
            $maxSafeThrottle = [Math]::Max(1, [Math]::Floor($remainingCore / 200))
            if ($maxSafeThrottle -lt $effectiveThrottle) {
                $effectiveThrottle = $maxSafeThrottle
            }
        }
    }
    catch {
        Write-Verbose "Rate limit metadata unavailable; using requested throttle. $($_.Exception.Message)"
    }

    return [int]$effectiveThrottle
}
