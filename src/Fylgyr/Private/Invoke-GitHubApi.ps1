function Invoke-GitHubApi {
    [CmdletBinding()]
    [OutputType([PSCustomObject], [PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$Method = 'GET',

        [hashtable]$Body,

        [string]$Token = $env:GITHUB_TOKEN,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 30,

        [switch]$GraphQL,

        [switch]$AllPages
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
        if ($Endpoint -match '^https://') {
            $uri = $Endpoint
        }
        elseif ($Endpoint -match '^http://') {
            throw 'HTTP endpoints are not allowed. Use HTTPS only.'
        }
        else {
            $trimmedEndpoint = $Endpoint.TrimStart('/')
            $uri = "https://api.github.com/$trimmedEndpoint"
        }
    }

    $maxPages = 100
    $pageCount = 0
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nextUri = $uri

    do {
        $pageCount++
        if ($pageCount -gt $maxPages) {
            Write-Warning "Pagination limit reached ($maxPages pages). Results may be incomplete."
            break
        }

        $invokeParams = @{
            Uri = $nextUri
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
        }
        catch {
            $errorMessage = $_.Exception.Message

            if ($_.ErrorDetails.Message) {
                try {
                    $ghError = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($ghError.message) {
                        $errorMessage = "$errorMessage`nGitHub response: $($ghError.message)"
                    }
                }
                catch {
                    Write-Debug "Could not parse GitHub error response as JSON: $($_.Exception.Message)"
                }
            }

            # Sanitize: strip any token fragments that might appear in error output
            $sanitizedUri = $nextUri -replace '[?&]access_token=[^&]+', '?access_token=***'
            throw "GitHub API call failed for '$sanitizedUri' using method '$Method'. $errorMessage"
        }

        if ($AllPages) {
            if ($response -is [System.Array]) {
                foreach ($item in $response) { $allResults.Add($item) }
            }
            else {
                $allResults.Add($response)
            }

            # Parse Link header for next page
            $nextUri = $null
            $linkHeader = $null
            if ($responseHeaders.ContainsKey('Link')) {
                $linkHeader = $responseHeaders['Link'][0]
            }
            elseif ($responseHeaders.ContainsKey('link')) {
                $linkHeader = $responseHeaders['link'][0]
            }

            if ($linkHeader -and $linkHeader -match '<([^>]+)>;\s*rel="next"') {
                $nextUri = $Matches[1]
            }
        }
        else {
            return $response
        }
    } while ($null -ne $nextUri)

    return $allResults.ToArray()
}
