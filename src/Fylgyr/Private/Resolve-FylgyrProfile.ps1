<#
.SYNOPSIS
Recalibrate findings for a maintainer profile.

.DESCRIPTION
Some controls structurally require a second person (a reviewer or a second code
owner) and cannot be satisfied by a solo maintainer no matter what they
configure. Left as Fail/Warning they train a solo maintainer to ignore Fylgyr
output. The SoloMaintainer profile re-ranks exactly those findings to an
informational, non-blocking status and appends the compensating-control
guidance, leaving every solo-achievable guardrail untouched.

This is a pure post-processing pass over already-collected result objects.
#>
function Resolve-FylgyrProfile {
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [ValidateSet('SoloMaintainer')]
        [string]$ProfileName
    )

    if (-not $Results -or $Results.Count -eq 0) {
        return $Results
    }

    if ($ProfileName -ne 'SoloMaintainer') {
        return $Results
    }

    $compensatingNote = 'Solo-maintainer profile: re-ranked to Info. This control requires a second person (a distinct reviewer or co-owner) and cannot be satisfied by a one-person project. Recommended compensating controls: required status checks (a CI gate is your machine reviewer), signed commits, and hardware-backed 2FA. See docs/SOLO-MAINTAINER.md.'

    # Findings that inherently require more than one human. Matched on check name
    # plus a distinctive detail fragment so solo-achievable findings from the same
    # check (for example a missing CODEOWNERS file, which one person can add) are
    # left as-is.
    foreach ($result in $Results) {
        if (-not $result -or $result.Status -notin @('Fail', 'Warning')) {
            continue
        }

        $check = ([string]$result.CheckName) -replace '^Test-', ''
        $detail = [string]$result.Detail
        $requiresSecondPerson = $false

        if ($check -eq 'BranchProtection' -and $detail -match '0 approving reviews|0 approvers') {
            $requiresSecondPerson = $true
        }
        elseif ($check -eq 'CodeOwner' -and $detail -match 'distinct owner|single owner') {
            $requiresSecondPerson = $true
        }

        if (-not $requiresSecondPerson) {
            continue
        }

        $result.Status = 'Info'
        $result.Severity = 'Info'
        if ($result.Detail -notmatch 'Solo-maintainer profile:') {
            $result.Detail = "$($result.Detail) $compensatingNote"
        }
    }

    return $Results
}
