function Send-FylgyrToLogAnalytics {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'LogAnalytics matches Azure product naming.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'StreamName', Justification = 'StreamName is consumed in ingestion endpoint construction.')]
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$InputObject,

        [Parameter(Mandatory)]
        [ValidatePattern('^dcr-[a-zA-Z0-9-]+$')]
        [string]$DcrImmutableId,

        [string]$DceUri,

        [string]$DcrEndpointUri,

        [Parameter(Mandatory)]
        [ValidatePattern('^Custom-[A-Za-z0-9_]+$')]
        [string]$StreamName,

        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$ClientId,

        [ValidatePattern('^[0-9a-fA-F-]{36}$')]
        [string]$TenantId,

        [SecureString]$ClientSecret,

        [switch]$UseManagedIdentity,

        [string]$FederatedToken,

        [string]$FederatedTokenFile,

        [ValidateRange(1, 5000)]
        [int]$BatchSize = 500,

        [ValidateRange(1, 10)]
        [int]$MaxRetries = 5
    )

    begin {
        $lines = [System.Collections.Generic.List[string]]::new()
    }

    process {
        foreach ($line in @($InputObject)) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                continue
            }

            # Accept both NDJSON-as-single-string and pre-split line arrays.
            foreach ($ndjsonLine in @([string]$line -split "`r?`n")) {
                if (-not [string]::IsNullOrWhiteSpace($ndjsonLine)) {
                    $lines.Add($ndjsonLine)
                }
            }
        }
    }

    end {
        if ($lines.Count -eq 0) {
            return [PSCustomObject]@{
                SentBatches = 0
                SentRecords = 0
                Endpoint = $null
            }
        }

        $baseIngestionUri = $null
        if ($DcrEndpointUri) {
            $baseIngestionUri = Resolve-FylgyrIngestionBaseUri -UriValue $DcrEndpointUri -ParameterName 'DcrEndpointUri'
        }
        elseif ($DceUri) {
            $baseIngestionUri = Resolve-FylgyrIngestionBaseUri -UriValue $DceUri -ParameterName 'DceUri'
        }
        else {
            throw 'Provide either -DcrEndpointUri or -DceUri.'
        }

        $token = $null
        if ($UseManagedIdentity) {
            try {
                if (-not [string]::IsNullOrWhiteSpace($env:IDENTITY_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:IDENTITY_HEADER)) {
                    # App Service managed identity endpoint.
                    $msiUri = '{0}?api-version=2019-08-01&resource={1}' -f $env:IDENTITY_ENDPOINT, [System.Uri]::EscapeDataString('https://monitor.azure.com/')
                    if ($ClientId) {
                        $msiUri = "$msiUri&client_id=$ClientId"
                    }

                    $msiResponse = Invoke-RestMethod -Method GET -Uri $msiUri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER } -ErrorAction Stop
                }
                elseif (-not [string]::IsNullOrWhiteSpace($env:MSI_ENDPOINT) -and -not [string]::IsNullOrWhiteSpace($env:MSI_SECRET)) {
                    # Legacy App Service managed identity endpoint.
                    $msiUri = '{0}?api-version=2017-09-01&resource={1}' -f $env:MSI_ENDPOINT, [System.Uri]::EscapeDataString('https://monitor.azure.com/')
                    if ($ClientId) {
                        $msiUri = "$msiUri&clientid=$ClientId"
                    }

                    $msiResponse = Invoke-RestMethod -Method GET -Uri $msiUri -Headers @{ Secret = $env:MSI_SECRET } -ErrorAction Stop
                }
                else {
                    throw 'Managed identity IMDS fallback is not supported because it requires an HTTP endpoint. Configure IDENTITY_ENDPOINT/IDENTITY_HEADER or MSI_ENDPOINT/MSI_SECRET to use a supported managed identity flow.'
                }

                $token = [string]$msiResponse.access_token
            }
            catch {
                throw "Managed identity token acquisition failed: $($_.Exception.Message)"
            }
        }
        else {
            if (-not $TenantId -or -not $ClientId) {
                throw 'ClientId and TenantId are required for non-managed-identity authentication.'
            }

            if (-not $FederatedToken -and $FederatedTokenFile -and (Test-Path -Path $FederatedTokenFile -PathType Leaf)) {
                $FederatedToken = Get-Content -Path $FederatedTokenFile -Raw
            }

            if (-not $FederatedToken -and $env:AZURE_FEDERATED_TOKEN_FILE -and (Test-Path -Path $env:AZURE_FEDERATED_TOKEN_FILE -PathType Leaf)) {
                $FederatedToken = Get-Content -Path $env:AZURE_FEDERATED_TOKEN_FILE -Raw
            }

            try {
                if ($FederatedToken) {
                    $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                        client_id = $ClientId
                        scope = 'https://monitor.azure.com//.default'
                        grant_type = 'client_credentials'
                        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                        client_assertion = $FederatedToken.Trim()
                    } -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                    $token = [string]$tokenResponse.access_token
                }
                else {
                    if (-not $ClientSecret) {
                        throw 'ClientSecret is required when no managed identity or federated token is provided.'
                    }

                    $plainSecret = $null
                    try {
                        $plainSecret = [System.Net.NetworkCredential]::new('', $ClientSecret).Password
                        $tokenResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body @{
                            client_id = $ClientId
                            client_secret = $plainSecret
                            scope = 'https://monitor.azure.com//.default'
                            grant_type = 'client_credentials'
                        } -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
                        $token = [string]$tokenResponse.access_token
                    }
                    finally {
                        # .NET strings are immutable so the value cannot be zeroed in place;
                        # drop the reference so it is no longer reachable from session state.
                        $plainSecret = $null
                        Remove-Variable -Name plainSecret -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                throw "Service principal token acquisition failed: $($_.Exception.Message)"
            }
        }

        if (-not $token) {
            throw 'Failed to obtain access token for Logs Ingestion API.'
        }

        $ingestionUri = '{0}/dataCollectionRules/{1}/streams/{2}?api-version=2023-01-01' -f $baseIngestionUri, $DcrImmutableId, $StreamName
        $headers = @{ Authorization = "Bearer $token" }

        $sentBatches = 0
        $sentRecords = 0
        for ($offset = 0; $offset -lt $lines.Count; $offset += $BatchSize) {
            $count = [Math]::Min($BatchSize, $lines.Count - $offset)
            $batchRecords = [System.Collections.Generic.List[object]]::new()

            for ($i = 0; $i -lt $count; $i++) {
                $line = $lines[$offset + $i]
                try {
                    $batchRecords.Add(($line | ConvertFrom-Json -Depth 25))
                }
                catch {
                    throw "Invalid NDJSON record at position $($offset + $i + 1): $($_.Exception.Message)"
                }
            }

            $payload = $batchRecords.ToArray() | ConvertTo-Json -Depth 25 -AsArray
            $attempt = 0
            $sent = $false
            while (-not $sent -and $attempt -lt $MaxRetries) {
                $attempt++
                try {
                    Invoke-RestMethod -Method POST -Uri $ingestionUri -Headers $headers -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
                    $sent = $true
                }
                catch {
                    $message = $_.Exception.Message
                    $isTransient = $message -match '429|500|502|503|504|temporar|timeout'
                    if (-not $isTransient -or $attempt -ge $MaxRetries) {
                        throw "Log ingestion batch failed after $attempt attempt(s): $message"
                    }

                    $delay = [Math]::Pow(2, $attempt)
                    Start-Sleep -Seconds $delay
                }
            }

            $sentBatches++
            $sentRecords += $count
        }

        return [PSCustomObject]@{
            SentBatches = $sentBatches
            SentRecords = $sentRecords
            Endpoint = $ingestionUri
        }
    }
}
