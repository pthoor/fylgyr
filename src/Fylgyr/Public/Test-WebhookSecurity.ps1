function Test-WebhookSecurity {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [Parameter(Mandatory)]
        [string]$Token
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resource = $target

    try {
        $hooks = Invoke-GitHubApi -Endpoint "repos/$Owner/$Repo/hooks?per_page=100" -Token $Token -AllPages
    }
    catch {
        $msg = $_.Exception.Message

        if ($msg -match '404') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WebhookSecurity' `
                -Status 'Pass' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'No webhooks configured on this repository.' `
                -Remediation 'No action needed.' `
                -Target $target))
            return $results.ToArray()
        }

        if ($msg -match '403') {
            $results.Add((Format-FylgyrResult `
                -CheckName 'WebhookSecurity' `
                -Status 'Info' `
                -Severity 'Info' `
                -Resource $resource `
                -Detail 'Insufficient permissions to read webhook configuration. Requires admin:repo_hook scope.' `
                -Remediation 'Use a fine-grained token with Webhooks:read permission, or a classic token with admin:repo_hook scope, to audit webhook secrets.' `
                -Target $target))
            return $results.ToArray()
        }

        $results.Add((Format-FylgyrResult `
            -CheckName 'WebhookSecurity' `
            -Status 'Error' `
            -Severity 'Low' `
            -Resource $resource `
            -Detail "Unexpected error reading webhook configuration: $($_.Exception.Message)" `
            -Remediation 'Re-run with a valid token and verify network access to api.github.com.' `
            -Target $target))
        return $results.ToArray()
    }

    if (-not $hooks -or $hooks.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WebhookSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail 'No webhooks configured on this repository.' `
            -Remediation 'No action needed.' `
            -Target $target))
        return $results.ToArray()
    }

    $unsecured = [System.Collections.Generic.List[string]]::new()

    foreach ($hook in $hooks) {
        $hasSecret = $hook.config.PSObject.Properties['secret'] -and
                     $null -ne $hook.config.secret -and
                     $hook.config.secret -ne ''
        if (-not $hasSecret) {
            $unsecured.Add($hook.config.url)
        }
    }

    if ($unsecured.Count -gt 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WebhookSecurity' `
            -Status 'Fail' `
            -Severity 'Low' `
            -Resource $resource `
            -Detail "$($unsecured.Count) webhook(s) have no secret token configured. Without a shared secret, receivers cannot verify that payloads originate from GitHub — an attacker who discovers the webhook URL can forge or replay events to trigger downstream CI, deploy, or chat automation, as in the Codecov bash uploader integrity gap. Unsecured endpoints: $($unsecured -join ', ')." `
            -Remediation 'Set a webhook secret in Settings → Webhooks → Edit, then validate the X-Hub-Signature-256 header in the receiving service. See https://docs.github.com/webhooks/using-webhooks/validating-webhook-deliveries.' `
            -AttackMapping @('codecov-bash-uploader') `
            -Target $target))
    }
    else {
        $results.Add((Format-FylgyrResult `
            -CheckName 'WebhookSecurity' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "All $($hooks.Count) webhook(s) have a secret token configured." `
            -Remediation 'No action needed.' `
            -Target $target))
    }

    $results.ToArray()
}
