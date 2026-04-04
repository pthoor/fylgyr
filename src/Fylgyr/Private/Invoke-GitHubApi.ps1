function Invoke-GitHubApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [hashtable]$Body,

        [string]$Token = $env:GITHUB_TOKEN,

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
    }

    if ($Body) {
        $invokeParams['ContentType'] = 'application/json'
        $invokeParams['Body'] = ($Body | ConvertTo-Json -Depth 20)
    }

    try {
        $response = Invoke-RestMethod @invokeParams

        $remaining = $null
        if ($responseHeaders.ContainsKey('X-RateLimit-Remaining')) {
            $remaining = [int]$responseHeaders['X-RateLimit-Remaining']
        }
        elseif ($responseHeaders.ContainsKey('x-ratelimit-remaining')) {
            $remaining = [int]$responseHeaders['x-ratelimit-remaining']
        }

        if ($null -ne $remaining -and $remaining -le 10) {
            $resetEpoch = $null
            if ($responseHeaders.ContainsKey('X-RateLimit-Reset')) {
                $resetEpoch = [long]$responseHeaders['X-RateLimit-Reset']
            }
            elseif ($responseHeaders.ContainsKey('x-ratelimit-reset')) {
                $resetEpoch = [long]$responseHeaders['x-ratelimit-reset']
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

        if ($_.Exception.Response) {
            $responseStream = $_.Exception.Response.GetResponseStream()
            if ($responseStream) {
                $reader = [System.IO.StreamReader]::new($responseStream)
                try {
                    $responseBody = $reader.ReadToEnd()
                }
                finally {
                    $reader.Dispose()
                }

                if ($responseBody) {
                    $errorMessage = "$errorMessage`nGitHub response: $responseBody"
                }
            }
        }

        throw "GitHub API call failed for '$uri' using method '$Method'. $errorMessage"
    }
}
