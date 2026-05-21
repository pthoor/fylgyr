function Get-FylgyrConfigSuppression {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$IgnoreConfig
    )

    $rules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $diagnostics = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($IgnoreConfig) {
        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    $configPath = Join-Path -Path (Get-Location) -ChildPath '.fylgyr.yml'
    if (-not (Test-Path -Path $configPath -PathType Leaf)) {
        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    $configText = Get-Content -Path $configPath -Raw
    if ([string]::IsNullOrWhiteSpace($configText)) {
        $diagnostics.Add([PSCustomObject]@{
            Status = 'Warning'
            Severity = 'Low'
            Detail = "Suppression config file '$configPath' is empty."
            Remediation = 'Add a suppressions array or remove the empty file.'
        })

        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    try {
        Import-Module -Name powershell-yaml -ErrorAction Stop
    }
    catch {
        $diagnostics.Add([PSCustomObject]@{
            Status = 'Warning'
            Severity = 'Low'
            Detail = "Unable to load powershell-yaml while reading '$configPath': $($_.Exception.Message)"
            Remediation = "Install the 'powershell-yaml' module and rerun."
        })

        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    try {
        $parsed = ConvertFrom-Yaml -Yaml $configText -ErrorAction Stop
    }
    catch {
        $diagnostics.Add([PSCustomObject]@{
            Status = 'Warning'
            Severity = 'Low'
            Detail = "Failed to parse suppression config '$configPath': $($_.Exception.Message)"
            Remediation = 'Fix YAML syntax. Expected top-level key: suppressions.'
        })

        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    $suppressionEntries = @()
    if ($parsed -is [System.Collections.IDictionary] -and $parsed.Contains('suppressions')) {
        $suppressionEntries = @($parsed['suppressions'])
    }
    elseif ($parsed -and $parsed.PSObject.Properties['suppressions']) {
        $suppressionEntries = @($parsed.suppressions)
    }
    else {
        $diagnostics.Add([PSCustomObject]@{
            Status = 'Warning'
            Severity = 'Low'
            Detail = "Suppression config '$configPath' is missing top-level 'suppressions'."
            Remediation = "Define suppressions under 'suppressions:' as a YAML array."
        })

        return [PSCustomObject]@{
            Rules = $rules.ToArray()
            Diagnostics = $diagnostics.ToArray()
        }
    }

    for ($index = 0; $index -lt $suppressionEntries.Count; $index++) {
        $entry = $suppressionEntries[$index]
        $position = $index + 1

        if (-not $entry) {
            $diagnostics.Add([PSCustomObject]@{
                Status = 'Warning'
                Severity = 'Low'
                Detail = "Suppression entry #$position is null."
                Remediation = 'Provide check, resource, and reason fields.'
            })
            continue
        }

        $checkValue = ''
        $resourceValue = ''
        $reasonValue = ''
        $expiresValue = ''

        if ($entry -is [System.Collections.IDictionary]) {
            foreach ($key in $entry.Keys) {
                $keyName = [string]$key
                if ($keyName -ieq 'check') {
                    $checkValue = [string]$entry[$key]
                    continue
                }

                if ($keyName -ieq 'resource') {
                    $resourceValue = [string]$entry[$key]
                    continue
                }

                if ($keyName -ieq 'reason') {
                    $reasonValue = [string]$entry[$key]
                    continue
                }

                if ($keyName -ieq 'expires') {
                    $expiresValue = [string]$entry[$key]
                    continue
                }
            }
        }
        else {
            $checkValue = if ($entry.PSObject.Properties['check']) { [string]$entry.check } else { '' }
            $resourceValue = if ($entry.PSObject.Properties['resource']) { [string]$entry.resource } else { '' }
            $reasonValue = if ($entry.PSObject.Properties['reason']) { [string]$entry.reason } else { '' }
            $expiresValue = if ($entry.PSObject.Properties['expires']) { [string]$entry.expires } else { '' }
        }

        if ([string]::IsNullOrWhiteSpace($checkValue) -or [string]::IsNullOrWhiteSpace($resourceValue) -or [string]::IsNullOrWhiteSpace($reasonValue)) {
            $diagnostics.Add([PSCustomObject]@{
                Status = 'Warning'
                Severity = 'Low'
                Detail = "Suppression entry #$position is invalid: check/resource/reason are required."
                Remediation = 'Set check, resource, and reason for each suppression entry.'
            })
            continue
        }

        $expiresUtc = $null
        if (-not [string]::IsNullOrWhiteSpace($expiresValue)) {
            [datetime]$parsedExpiry = [datetime]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
            if (-not [datetime]::TryParse($expiresValue, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsedExpiry)) {
                $diagnostics.Add([PSCustomObject]@{
                    Status = 'Warning'
                    Severity = 'Low'
                    Detail = "Suppression entry #$position has invalid expires value '$expiresValue'."
                    Remediation = 'Use an ISO date value, for example 2026-07-01.'
                })
                continue
            }

            $expiresUtc = $parsedExpiry.ToUniversalTime()
        }

        $rules.Add([PSCustomObject]@{
            Check = $checkValue
            Resource = $resourceValue
            Reason = $reasonValue
            ExpiresUtc = $expiresUtc
        })
    }

    return [PSCustomObject]@{
        Rules = $rules.ToArray()
        Diagnostics = $diagnostics.ToArray()
    }
}
