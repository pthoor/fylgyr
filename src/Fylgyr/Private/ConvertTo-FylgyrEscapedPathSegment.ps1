function ConvertTo-FylgyrEscapedPathSegment {
    <#
    .SYNOPSIS
        Percent-encodes a single URL path segment sourced from the GitHub API.

    .DESCRIPTION
        Values returned by the GitHub API (branch names, ruleset ids, repo and
        collaborator names) are untrusted and may legitimately contain characters
        that are significant in a URL path - most notably '/', which appears in
        branch names like 'release/v1'. Interpolating such a value straight into
        an -Endpoint template both breaks the request (the slash is read as a path
        separator, so the call 404s) and lets a hostile value steer the request to
        a different API path.

        Callers escape each variable segment individually, so literal '/'
        separators in the endpoint template are preserved while a '/' inside the
        value becomes '%2F' - which is exactly what segment-scoped endpoints such
        as repos/{o}/{r}/branches/{branch}/protection require.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    [System.Uri]::EscapeDataString($Value)
}
