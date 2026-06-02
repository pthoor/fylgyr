function Invoke-FylgyrDriftScan {
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
        [string]$Token,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168,

        [string]$BaselinePath,

        [switch]$IgnoreConfig
    )

    $target = "$Owner/$Repo"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $configContext = Get-FylgyrConfigSuppression -IgnoreConfig:$IgnoreConfig
    $configSuppressions = @($configContext.Rules)
    $configDiagnostics = @($configContext.Diagnostics)

    foreach ($configDiagnostic in $configDiagnostics) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'ConfigSuppression' `
            -Status $configDiagnostic.Status `
            -Severity $configDiagnostic.Severity `
            -Resource $target `
            -Detail $configDiagnostic.Detail `
            -Remediation $configDiagnostic.Remediation `
            -Target $target `
            -Mode 'Drift'))
    }

    $auditEvents = @()
    try {
        $auditEvents = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
    }
    catch {
        Write-Debug "Audit log cache warmup failed for '$target': $($_.Exception.Message)"
    }

    $driftChecks = @(
        @{ Name = 'Test-RecentCollaboratorChange'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; SinceHours = $SinceHours; BaselinePath = $BaselinePath } }
        @{ Name = 'Test-RecentProtectionChange'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; SinceHours = $SinceHours; BaselinePath = $BaselinePath; AuditEvents = $auditEvents } }
        @{ Name = 'Test-RecentForcePush'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; SinceHours = $SinceHours } }
        @{ Name = 'Test-RecentRunnerRegistration'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; SinceHours = $SinceHours; BaselinePath = $BaselinePath; AuditEvents = $auditEvents } }
        @{ Name = 'Test-RecentSecretChange'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; SinceHours = $SinceHours; AuditEvents = $auditEvents } }
        @{ Name = 'Test-RecentWorkflowAdd'; Params = @{ Owner = $Owner; Repo = $Repo; Token = $Token; BaselinePath = $BaselinePath } }
    )

    foreach ($entry in $driftChecks) {
        Write-Progress -Activity $target -Status "Running $($entry.Name)" -Id 4 -ParentId 1

        try {
            $checkResults = & $entry.Name @($entry.Params)
            foreach ($checkResult in $checkResults) {
                $checkResult.Target = $target
                if (-not $checkResult.PSObject.Properties['Mode']) {
                    $checkResult | Add-Member -NotePropertyName Mode -NotePropertyValue 'Drift'
                }
                $results.Add($checkResult)
            }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName ($entry.Name -replace '^Test-', '') `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $target `
                -Detail "Drift check failed with error: $($_.Exception.Message)" `
                -Remediation 'Review the check failure and rerun drift mode.' `
                -Target $target `
                -Mode 'Drift'))
        }
    }

    Write-Progress -Activity $target -Id 4 -Completed
    return (Resolve-FylgyrSuppressionStatus -Results $results.ToArray() -Suppressions $configSuppressions)
}

function Invoke-FylgyrOrgDriftScan {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9._-]+$')]
        [string]$Owner,

        [Parameter(Mandatory)]
        [string]$Token,

        [ValidateRange(1, 720)]
        [int]$SinceHours = 168,

        [string]$BaselinePath,

        [switch]$IgnoreConfig
    )

    $target = "org/$Owner"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $configContext = Get-FylgyrConfigSuppression -IgnoreConfig:$IgnoreConfig
    $configSuppressions = @($configContext.Rules)
    $configDiagnostics = @($configContext.Diagnostics)

    foreach ($configDiagnostic in $configDiagnostics) {
        $results.Add((Format-FylgyrResult `
            -CheckName 'ConfigSuppression' `
            -Status $configDiagnostic.Status `
            -Severity $configDiagnostic.Severity `
            -Resource $target `
            -Detail $configDiagnostic.Detail `
            -Remediation $configDiagnostic.Remediation `
            -Target $target `
            -Mode 'Drift'))
    }

    $auditEvents = @()
    try {
        $auditEvents = @(Get-OrgAuditLog -Owner $Owner -Token $Token -SinceHours $SinceHours)
    }
    catch {
        Write-Debug "Org audit log unavailable for '$target': $($_.Exception.Message)"
    }

    $orgDriftChecks = @(
        @{ Name = 'Test-RecentAppAuthorization'; Params = @{ Owner = $Owner; Token = $Token; SinceHours = $SinceHours; BaselinePath = $BaselinePath; AuditEvents = $auditEvents } }
        @{ Name = 'Test-RecentSecretChange'; Params = @{ Owner = $Owner; Token = $Token; SinceHours = $SinceHours; AuditEvents = $auditEvents } }
        @{ Name = 'Test-RecentTokenExposure'; Params = @{ Owner = $Owner; Token = $Token; SinceHours = $SinceHours; BaselinePath = $BaselinePath; AuditEvents = $auditEvents } }
    )

    foreach ($entry in $orgDriftChecks) {
        Write-Progress -Activity $target -Status "Running $($entry.Name)" -Id 5 -ParentId 1

        try {
            $checkResults = & $entry.Name @($entry.Params)
            foreach ($checkResult in $checkResults) {
                $checkResult.Target = $target
                if (-not $checkResult.PSObject.Properties['Mode']) {
                    $checkResult | Add-Member -NotePropertyName Mode -NotePropertyValue 'Drift'
                }
                $results.Add($checkResult)
            }
        }
        catch {
            $results.Add((Format-FylgyrResult `
                -CheckName ($entry.Name -replace '^Test-', '') `
                -Status 'Error' `
                -Severity 'High' `
                -Resource $target `
                -Detail "Org drift check failed with error: $($_.Exception.Message)" `
                -Remediation 'Review org drift check failure and rerun.' `
                -Target $target `
                -Mode 'Drift'))
        }
    }

    Write-Progress -Activity $target -Id 5 -Completed
    return (Resolve-FylgyrSuppressionStatus -Results $results.ToArray() -Suppressions $configSuppressions)
}
