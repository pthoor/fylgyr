function Invoke-GitHubApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [hashtable]$Body,

        [string]$Token = $env:GITHUB_TOKEN,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 30,

        [switch]$GraphQL
    )

    if (-not $Token) {
        throw 'GitHub token not provided. Use -Token or set GITHUB_TOKEN.'
    }

    $headers = @{
        Authorization = "Bearer $Token"
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    if ($GraphQL) {
        $uri = 'https://api.github.com/graphql'
        $Method = 'POST'

        if (-not $Body) {
            $Body = @{ query = $Endpoint }
        }
    }
    else {
        if ($Endpoint -match '^https?://') {
            $uri = $Endpoint
        }
        else {
            $trimmedEndpoint = $Endpoint.TrimStart('/')
            $uri = "https://api.github.com/$trimmedEndpoint"
        }
    }

    $invokeParams = @{
        Uri = $uri
        Method = $Method
        Headers = $headers
        ErrorAction = 'Stop'
        ResponseHeadersVariable = 'responseHeaders'
        TimeoutSec = $TimeoutSec
    }

    if ($Body) {
        $invokeParams['ContentType'] = 'application/json'
        $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 20)
    }

    try {
        $response = Invoke-RestMethod @invokeParams

        $remaining = $null
        if ($responseHeaders.ContainsKey('X-RateLimit-Remaining')) {
            $remaining = [int]($responseHeaders['X-RateLimit-Remaining'][0])
        }
        elseif ($responseHeaders.ContainsKey('x-ratelimit-remaining')) {
            $remaining = [int]($responseHeaders['x-ratelimit-remaining'][0])
        }

        if ($null -ne $remaining -and $remaining -le 10) {
            $resetEpoch = $null
            if ($responseHeaders.ContainsKey('X-RateLimit-Reset')) {
                $resetEpoch = [long]($responseHeaders['X-RateLimit-Reset'][0])
            }
            elseif ($responseHeaders.ContainsKey('x-ratelimit-reset')) {
                $resetEpoch = [long]($responseHeaders['x-ratelimit-reset'][0])
            }

            if ($remaining -eq 0 -and $null -ne $resetEpoch) {
                $resetTime = [DateTimeOffset]::FromUnixTimeSeconds($resetEpoch).UtcDateTime
                throw "GitHub API rate limit exhausted. Resets at $resetTime UTC."
            }

            Write-Warning "GitHub API rate limit is low: $remaining requests remaining."
        }

        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message

        # PS7 (.NET 5+): Invoke-RestMethod throws HttpResponseException; the
        # response body is pre-populated in ErrorDetails.Message by PowerShell.
        if ($_.ErrorDetails.Message) {
            $errorMessage = "$errorMessage`nGitHub response: $($_.ErrorDetails.Message)"
        }

        throw "GitHub API call failed for '$uri' using method '$Method'. $errorMessage"
    }
}
