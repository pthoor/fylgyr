function ConvertTo-FylgyrJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$Target = ''
    )

    $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
    $version = if ($module -and $module.Version) { $module.Version.ToString() } else { '0.0.0' }

    $output = [PSCustomObject]@{
        tool     = 'Fylgyr'
        version  = $version
        scanDate = (Get-Date -Format 'o')
        target   = $Target
        summary  = [PSCustomObject]@{
            total   = $Results.Count
            pass    = ($Results | Where-Object Status -EQ 'Pass').Count
            fail    = ($Results | Where-Object Status -EQ 'Fail').Count
            warning = ($Results | Where-Object Status -EQ 'Warning').Count
            error   = ($Results | Where-Object Status -EQ 'Error').Count
        }
        results = $Results
    }

    $output | ConvertTo-Json -Depth 10
}
