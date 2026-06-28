function Resolve-FylgyrIngestionBaseUri {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$UriValue,

        [Parameter(Mandatory)]
        [string]$ParameterName
    )

    $candidateUri = $UriValue.Trim()
    if (-not $candidateUri) {
        throw "$ParameterName cannot be empty."
    }

    try {
        $parsedBaseUri = [System.Uri]$candidateUri
    }
    catch {
        $errorMessage = $_.Exception.Message
        throw "$ParameterName is not a valid URI. $errorMessage"
    }

    if ($parsedBaseUri.Scheme -ne 'https') {
        throw "$ParameterName must use HTTPS."
    }

    $targetHost = $parsedBaseUri.Host
    if ($targetHost -in @('localhost', '0.0.0.0')) {
        throw "$ParameterName must not target localhost or link-local addresses."
    }

    if (Test-FylgyrPrivateOrLinkLocalIpAddress -TargetHost $targetHost) {
        throw "$ParameterName must not target private or link-local addresses."
    }

    return $parsedBaseUri.AbsoluteUri.TrimEnd('/')
}
