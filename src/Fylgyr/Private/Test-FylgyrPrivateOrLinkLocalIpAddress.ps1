function Test-FylgyrPrivateOrLinkLocalIpAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$TargetHost
    )

    $ipAddress = $null
    if ([System.Net.IPAddress]::TryParse($TargetHost, [ref]$ipAddress)) {
        if ($ipAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
            $octets = $ipAddress.GetAddressBytes()
            $is10Network = $octets[0] -eq 10
            $is172Network = ($octets[0] -eq 172) -and ($octets[1] -ge 16) -and ($octets[1] -le 31)
            $is192Network = ($octets[0] -eq 192) -and ($octets[1] -eq 168)
            $isLoopback = $octets[0] -eq 127
            $isLinkLocal = ($octets[0] -eq 169) -and ($octets[1] -eq 254)
            return $is10Network -or $is172Network -or $is192Network -or $isLoopback -or $isLinkLocal
        }

        if ($ipAddress.IsIPv4MappedToIPv6) {
            return Test-FylgyrPrivateOrLinkLocalIpAddress -TargetHost ($ipAddress.MapToIPv4().ToString())
        }

        $ipv6Bytes = $ipAddress.GetAddressBytes()
        $isIpv6UniqueLocal = ($ipv6Bytes[0] -band 0xFE) -eq 0xFC
        $isIpv6Loopback = $ipAddress.Equals([System.Net.IPAddress]::IPv6Loopback)
        $isIpv6Unspecified = $ipAddress.Equals([System.Net.IPAddress]::IPv6None)

        return $ipAddress.IsIPv6LinkLocal -or $ipAddress.IsIPv6SiteLocal -or $isIpv6UniqueLocal -or $isIpv6Loopback -or $isIpv6Unspecified
    }

    try {
        $resolvedAddresses = [System.Net.Dns]::GetHostAddresses($TargetHost)
        foreach ($resolvedAddress in $resolvedAddresses) {
            if (Test-FylgyrPrivateOrLinkLocalIpAddress -TargetHost ([string]$resolvedAddress)) {
                return $true
            }
        }
    }
    catch {
        return $false
    }

    return $false
}
