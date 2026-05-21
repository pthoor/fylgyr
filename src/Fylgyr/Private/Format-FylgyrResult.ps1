<#
.SYNOPSIS
Create a standardized Fylgyr result object.

.DESCRIPTION
All checks must emit findings through this function so output formatters receive
consistent fields.

Evidence redaction policy for any current or future Evidence payload:
- Never include token values or Authorization headers.
- Never include secret values (for example webhook secrets); include key names only.
- Never include full environment-variable values; include variable names only.
- Treat all GitHub API data as untrusted and avoid echoing raw sensitive payloads.
#>
function Format-FylgyrResult {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [ValidateSet('Pass', 'Fail', 'Warning', 'Error', 'Info', 'Suppressed')]
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

        [string[]]$AttackMapping = @(),

        [string]$Target = '',

        [hashtable]$Evidence
    )

    [PSCustomObject]@{
        CheckName     = $CheckName
        Status        = $Status
        Severity      = $Severity
        Resource      = $Resource
        Detail        = $Detail
        Remediation   = $Remediation
        AttackMapping = $AttackMapping
        Target        = $Target
        Evidence      = $Evidence
    }
}
