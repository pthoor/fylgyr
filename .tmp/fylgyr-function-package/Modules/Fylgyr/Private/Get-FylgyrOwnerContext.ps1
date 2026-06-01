function Get-FylgyrOwnerContext {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    if (-not ($script:FylgyrOwnerContextCache -is [hashtable])) {
        $script:FylgyrOwnerContextCache = @{}
    }

    $tokenHashBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Token))
    $tokenHash = ([System.BitConverter]::ToString($tokenHashBytes)).Replace('-', '')
    $cacheKey = "$Owner::$tokenHash"

    if ($script:FylgyrOwnerContextCache.ContainsKey($cacheKey)) {
        return $script:FylgyrOwnerContextCache[$cacheKey]
    }

    $normalizePlan = {
        param([object]$Name)
        $raw = [string]$Name
        if (-not $raw) {
            return 'unknown'
        }

        $lower = $raw.ToLowerInvariant()
        if ($lower -match '^enterprise') { return 'enterprise' }
        if ($lower -match '^team')       { return 'team' }
        if ($lower -match '^pro')        { return 'pro' }
        if ($lower -match '^free')       { return 'free' }
        return 'unknown'
    }

    $context = [PSCustomObject]@{
        Type             = 'Unknown'
        Login            = $Owner
        PlanName         = 'unknown'
        TokenOwner       = 'unknown'
        TokenMatchesOwner = $false
    }

    $ownerInfo = $null
    $authedUser = $null

    try {
        $ownerInfo = Invoke-GitHubApi -Endpoint "users/$Owner" -Token $Token

        if ($ownerInfo -and $ownerInfo.PSObject.Properties['type'] -and
            $ownerInfo.type -in @('User', 'Organization')) {
            $context.Type = $ownerInfo.type
        }

        if ($ownerInfo -and $ownerInfo.PSObject.Properties['login'] -and $ownerInfo.login) {
            $context.Login = [string]$ownerInfo.login
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -notmatch '403' -and $msg -notmatch '404') {
            Write-Debug "Owner context fallback for '$Owner': $msg"
        }

        $script:FylgyrOwnerContextCache[$cacheKey] = $context
        return $context
    }

    try {
        $authedUser = Invoke-GitHubApi -Endpoint 'user' -Token $Token
        if ($authedUser -and $authedUser.PSObject.Properties['login'] -and $authedUser.login) {
            $context.TokenOwner = [string]$authedUser.login
        }
    }
    catch {
        Write-Debug "Could not resolve token owner for '$Owner': $($_.Exception.Message)"
    }

    if ($context.TokenOwner -and $context.TokenOwner -ne 'unknown' -and $context.Login) {
        $context.TokenMatchesOwner = $context.TokenOwner.Equals($context.Login, [System.StringComparison]::OrdinalIgnoreCase)
    }

    if ($context.Type -eq 'User') {
        if ($authedUser -and $context.TokenMatchesOwner -and $authedUser.PSObject.Properties['plan']) {
            $context.PlanName = & $normalizePlan $authedUser.plan.name
        }
        elseif ($ownerInfo -and $ownerInfo.PSObject.Properties['plan']) {
            $context.PlanName = & $normalizePlan $ownerInfo.plan.name
        }
    }
    elseif ($context.Type -eq 'Organization') {
        try {
            $orgInfo = Invoke-GitHubApi -Endpoint "orgs/$Owner" -Token $Token
            if ($orgInfo -and $orgInfo.PSObject.Properties['plan']) {
                $context.PlanName = & $normalizePlan $orgInfo.plan.name
            }
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -notmatch '403' -and $msg -notmatch '404') {
                Write-Debug "Could not resolve organization plan for '$Owner': $msg"
            }
        }
    }

    $script:FylgyrOwnerContextCache[$cacheKey] = $context
    return $context
}
