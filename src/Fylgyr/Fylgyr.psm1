$publicPath = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$privatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'

$publicFunctions = @(Get-ChildItem -Path $publicPath -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue)
$privateFunctions = @(Get-ChildItem -Path $privatePath -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue)

foreach ($file in $privateFunctions + $publicFunctions) {
    . $file.FullName
}

if ($publicFunctions.Count -gt 0) {
    Export-ModuleMember -Function $publicFunctions.BaseName
}
