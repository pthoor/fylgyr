function Get-OrgAuditLog {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168
    )

    if (-not $script:FylgyrOrgAuditLogCache) {
        $script:FylgyrOrgAuditLogCache = @{}
    }

    $tokenHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Token))
    $tokenHash = ([System.BitConverter]::ToString($tokenHashBytes) -replace '-', '')
    $cacheKey = "$Owner|$SinceHours|$tokenHash"
    if ($script:FylgyrOrgAuditLogCache.ContainsKey($cacheKey)) {
        return @($script:FylgyrOrgAuditLogCache[$cacheKey])
    }

    $sinceIso = [datetime]::UtcNow.AddHours(-1 * $SinceHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $phrase = [uri]::EscapeDataString("created:>=$sinceIso")
    $endpoint = "orgs/$Owner/audit-log?include=all&per_page=100&phrase=$phrase"

    $events = @(Invoke-GitHubApi -Endpoint $endpoint -Token $Token -AllPages)
    $script:FylgyrOrgAuditLogCache[$cacheKey] = $events
    return $events
}
