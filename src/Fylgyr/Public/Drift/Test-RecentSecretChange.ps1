function Test-RecentSecretChange {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Repo,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168,

        [PSCustomObject[]]$AuditEvents = @()
    )

    $resource = if ($Repo) { "$Owner/$Repo" } else { "org/$Owner" }
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $ownerContext = Get-FylgyrOwnerContext -Owner $Owner -Token $Token
    if ($ownerContext.Type -eq 'User' -and -not $Repo) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentSecretChange' `
            -Status 'Info' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "Owner '$Owner' is a personal account. Organization secret drift is not applicable." `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    $events = @($AuditEvents)
    if ($events.Count -eq 0) {
        try {
            $events = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName 'RecentSecretChange' `
                -Status 'Error' `
                -Severity 'Medium' `
                -Resource $resource `
                -Detail "Secret-change drift requires org audit log access: $($_.Exception.Message)" `
                -Remediation 'Grant admin:org for audit-log access, then rerun drift mode.' `
                -Target $resource `
                -Mode 'Drift'))
            return $results.ToArray()
        }
    }

    $secretEvents = @($events | Where-Object {
        $_.action -match '^(org|repo)\.secret\.(create|update|delete|remove)$'
    })

    if ($Repo) {
        $secretEvents = @($secretEvents | Where-Object { $_.repo -eq "$Owner/$Repo" })
    }

    if ($secretEvents.Count -eq 0) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentSecretChange' `
            -Status 'Pass' `
            -Severity 'Info' `
            -Resource $resource `
            -Detail "No secret create/update/delete events detected in the last $SinceHours hour(s)." `
            -Remediation 'No action needed.' `
            -Target $resource `
            -Evidence @{
                Source = 'audit-log'
                EventCount = 0
            } `
            -Mode 'Drift'))
        return $results.ToArray()
    }

    foreach ($secretRecord in $secretEvents) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'RecentSecretChange' `
            -Status 'Drift' `
            -Severity 'Medium' `
            -Resource $resource `
            -Detail "Secret metadata drift detected: action '$($secretRecord.action)'." `
            -Remediation 'Validate secret lifecycle activity, confirm authorized actor intent, and review related workflow executions for abuse.' `
            -AttackMapping @('committed-credentials-exposure', 'github-app-token-theft') `
            -Target $resource `
            -Evidence @{
                Source = 'audit-log'
                ChangedAt = $secretRecord.created_at
                ChangedBy = if ($secretRecord.actor) { $secretRecord.actor } else { $null }
                Action = $secretRecord.action
                Repo = $secretRecord.repo
            } `
            -Mode 'Drift'))
    }

    return $results.ToArray()
}
