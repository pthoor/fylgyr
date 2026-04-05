function ConvertTo-FylgyrJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [string]$Owner,

        [string]$Repo
    )

    $output = [PSCustomObject]@{
        tool    = 'Fylgyr'
        version = (Get-Module -Name Fylgyr -ErrorAction SilentlyContinue).Version.ToString()
        scanDate = (Get-Date -Format 'o')
        target  = if ($Repo) { "$Owner/$Repo" } else { $Owner }
        summary = [PSCustomObject]@{
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
