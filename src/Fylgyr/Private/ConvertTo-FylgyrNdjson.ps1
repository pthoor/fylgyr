function ConvertTo-FylgyrNdjson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [datetime]$ScanStartTime,

        [string]$OutputPath
    )

    $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
    $version = if ($module -and $module.Version) { $module.Version.ToString() } else { '0.0.0' }

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($result in $Results) {
        $lineObject = [ordered]@{}
        foreach ($property in $result.PSObject.Properties) {
            $lineObject[$property.Name] = $property.Value
        }

        $lineObject['_meta'] = [ordered]@{
            scanId        = $ScanId
            scanStartTime = $ScanStartTime.ToString('o')
            fylgyrVersion = $version
        }

        $lines.Add(($lineObject | ConvertTo-Json -Depth 12 -Compress))
    }

    $ndjson = $lines -join [Environment]::NewLine
    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $ndjson -Encoding UTF8
        return
    }

    return $ndjson
}
