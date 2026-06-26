function Test-AccountKey {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $resource = "user/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Run once per owner across an org-wide repo scan (cache reset by Invoke-Fylgyr).
    $cacheKey = "$Owner::keys"
    if ($script:FylgyrOwnerAccountChecked -is [hashtable]) {
        if ($script:FylgyrOwnerAccountChecked.ContainsKey($cacheKey)) {
            return $results.ToArray()
        }
        $script:FylgyrOwnerAccountChecked[$cacheKey] = $true
    }

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'Organization') {
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountKey' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is an organization. Account key hygiene targets personal accounts." `
            -Remediation 'No action needed.' `
            -Target $resource))
        return $results.ToArray()
    }

    $isSelf = $ownerContext.TokenMatchesOwner

    # Prefer the authenticated endpoints when the token owns the account (they carry
    # titles and created_at); fall back to the public endpoints otherwise.
    $sshEndpoint = if ($isSelf) { 'user/keys' } else { "users/$Owner/keys" }
    $gpgEndpoint = if ($isSelf) { 'user/gpg_keys' } else { "users/$Owner/gpg_keys" }

    $now = [datetime]::UtcNow
    $staleAfterDays = 730
    $findingCount = 0

    $sshKeys = @()
    try {
        $sshKeys = @(Invoke-GitHubApi -Endpoint $sshEndpoint -Token $Token -AllPages)
    }
    catch {
        Write-Debug "Could not list SSH keys for '$Owner': $($_.Exception.Message)"
    }

    foreach ($key in $sshKeys) {
        if (-not $key) { continue }
        $title = if ($key.PSObject.Properties['title'] -and $key.title) { [string]$key.title } else { "id $($key.id)" }
        if ($key.PSObject.Properties['created_at'] -and $key.created_at) {
            $createdAt = $null
            try { $createdAt = ([datetime]::Parse([string]$key.created_at)).ToUniversalTime() } catch { $createdAt = $null }
            if ($createdAt -and ($now - $createdAt).TotalDays -gt $staleAfterDays) {
                $findingCount++
                $ageDays = [int]($now - $createdAt).TotalDays
                $results.Add((Format-FylgyrResult `
                    -CheckName 'AccountKey' `
                    -Status 'Warning' `
                    -Severity 'Low' `
                    -Resource "$resource (ssh-key: $title)" `
                    -Detail "SSH key '$title' is $ageDays days old. Long-lived account keys widen the window for a leaked or stolen key to be used to push as the maintainer, a vector in maintainer-account compromises such as the Gentoo GitHub incident." `
                    -Remediation 'Review and rotate old SSH keys; remove any you no longer recognize.' `
                    -AttackMapping @('gentoo-github-compromise', 'xz-utils-backdoor') `
                    -Target $resource))
            }
        }
    }

    $gpgKeys = @()
    try {
        $gpgKeys = @(Invoke-GitHubApi -Endpoint $gpgEndpoint -Token $Token -AllPages)
    }
    catch {
        Write-Debug "Could not list GPG keys for '$Owner': $($_.Exception.Message)"
    }

    foreach ($key in $gpgKeys) {
        if (-not $key) { continue }
        $keyId = if ($key.PSObject.Properties['key_id'] -and $key.key_id) { [string]$key.key_id } else { "id $($key.id)" }
        if ($key.PSObject.Properties['expires_at'] -and $key.expires_at) {
            $expiresAt = $null
            try { $expiresAt = ([datetime]::Parse([string]$key.expires_at)).ToUniversalTime() } catch { $expiresAt = $null }
            if ($expiresAt -and $expiresAt -lt $now) {
                $findingCount++
                $results.Add((Format-FylgyrResult `
                    -CheckName 'AccountKey' `
                    -Status 'Warning' `
                    -Severity 'Low' `
                    -Resource "$resource (gpg-key: $keyId)" `
                    -Detail "GPG signing key '$keyId' expired on $($expiresAt.ToString('yyyy-MM-dd')). Commits signed with an expired key no longer verify, eroding the signing signal that helps detect maintainer impersonation." `
                    -Remediation 'Rotate the expired GPG key and update your signing configuration; remove unused keys.' `
                    -AttackMapping @('xz-utils-backdoor') `
                    -Target $resource))
            }
        }
    }

    if ($findingCount -eq 0) {
        $note = if (-not $isSelf) { ' (key dates are only available for the token owner, so staleness was not assessed)' } else { '' }
        $results.Add((Format-FylgyrResult `
            -CheckName 'AccountKey' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Account '$Owner' has $($sshKeys.Count) SSH key(s) and $($gpgKeys.Count) GPG key(s); no expired or stale keys detected$note." `
            -Remediation 'No action needed.' `
            -Target $resource))
    }

    $results.ToArray()
}
