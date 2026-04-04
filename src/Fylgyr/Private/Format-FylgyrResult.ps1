function Format-FylgyrResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Error')]
        [string]$Status,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [string]$Resource,

        [Parameter(Mandatory)]
        [string]$Detail,

        [Parameter(Mandatory)]
        [string]$Remediation,

        [string[]]$AttackMapping = @()
    )

    [PSCustomObject]@{
        CheckName = $CheckName
        Status = $Status
        Severity = $Severity
        Resource = $Resource
        Detail = $Detail
        Remediation = $Remediation
        AttackMapping = $AttackMapping
    }
}
