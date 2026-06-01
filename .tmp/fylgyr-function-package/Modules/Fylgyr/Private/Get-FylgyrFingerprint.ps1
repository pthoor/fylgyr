function Get-FylgyrFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result
    )

    $ruleId = "fylgyr/$($Result.CheckName)"
    $resource = if ($Result.PSObject.Properties['Resource'] -and $null -ne $Result.Resource) {
        [string]$Result.Resource
    }
    else {
        ''
    }
    $detail = if ($Result.PSObject.Properties['Detail'] -and $null -ne $Result.Detail) {
        [string]$Result.Detail
    }
    else {
        ''
    }

    $fingerprintInput = "$ruleId|$resource|$detail"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fingerprintInput))
    }
    finally {
        $sha256.Dispose()
    }

    $hashHex = ($hashBytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join ''
    return "${hashHex}:1"
}
