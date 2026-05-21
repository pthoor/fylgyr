function ConvertTo-FylgyrSarif {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results
    )

    # SARIF results represent findings — filter out passes
    $findings = @($Results | Where-Object { $_.Status -ne 'Pass' })

    $severityToLevel = @{
        Critical = 'error'
        High     = 'error'
        Medium   = 'warning'
        Low      = 'note'
        Info     = 'note'
    }

    # GitHub treats results as security findings when security-severity is set (0.0-10.0)
    $severityToScore = @{
        Critical = '9.5'
        High     = '8.0'
        Medium   = '5.5'
        Low      = '2.0'
        Info     = '0.0'
    }

    $attacksPath = Join-Path -Path $PSScriptRoot -ChildPath '..' | Join-Path -ChildPath 'Data' | Join-Path -ChildPath 'attacks.json'
    $attackCatalog = @{}
    if (Test-Path $attacksPath) {
        $attacks = Get-Content -Path $attacksPath -Raw | ConvertFrom-Json
        foreach ($a in $attacks) {
            $attackCatalog[$a.id] = $a
        }
    }

    $rules = [System.Collections.Generic.Dictionary[string, PSCustomObject]]::new()
    $sarifResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($r in $findings) {
        $ruleId = "fylgyr/$($r.CheckName)"

        if (-not $rules.ContainsKey($ruleId)) {
            $helpText = $r.Remediation
            if ($r.AttackMapping.Count -gt 0) {
                $attackNames = $r.AttackMapping | ForEach-Object {
                    if ($attackCatalog.ContainsKey($PSItem)) { $attackCatalog[$PSItem].name } else { $PSItem }
                }
                $helpText += "`n`nRelated attacks: $($attackNames -join ', ')"
            }

            $ruleTags = [System.Collections.Generic.List[string]]::new()
            $ruleTags.Add('security')
            $ruleTags.Add('supply-chain')

            $rules[$ruleId] = [PSCustomObject]@{
                id                   = $ruleId
                name                 = $r.CheckName
                shortDescription     = [PSCustomObject]@{ text = $r.CheckName }
                fullDescription      = [PSCustomObject]@{ text = $r.Detail }
                helpUri              = 'https://github.com/pthoor/Fylgyr'
                help                 = [PSCustomObject]@{
                    text     = $helpText
                    markdown = $helpText
                }
                defaultConfiguration = [PSCustomObject]@{
                    level = $severityToLevel[$r.Severity]
                }
                properties           = [PSCustomObject]@{
                    tags                = $ruleTags.ToArray()
                    precision           = 'high'
                    'security-severity' = $severityToScore[$r.Severity]
                }
            }
        }

        # Determine whether Resource is a repo-level identifier or a file path.
        # Repo-level resources look like "owner/repo" or
        # "owner/repo (branch: main)". Everything else is treated as a file
        # path, with an optional trailing ":line" suffix parsed below.
        $orgCheckNames = @(
            'OrgMfaPolicy'
            'OrgDefaultPermissions'
            'IpAllowlist'
            'AuditLogStreaming'
            'OAuthAppPolicy'
            'OrgActionRestrictions'
            'OutsideCollaborators'
            'PatPolicy'
            'GitHubAppSecurity'
            'Rulesets'
        )
        $isOrgLevelResource = $orgCheckNames -contains $r.CheckName
        $isRepoLevelResource = $r.Resource -match '^[^/\s]+/[^/\s]+(?: \(.+\))?$'
        $isFilePath = -not $isRepoLevelResource

        $sarifResult = [PSCustomObject]@{
            ruleId  = $ruleId
            level   = $severityToLevel[$r.Severity]
            message = [PSCustomObject]@{ text = $r.Detail }
        }

        if ($isFilePath) {
            $filePath = $r.Resource
            $startLine = 1
            if ($r.Resource -match '^(.+):(\d+)$') {
                $filePath = $Matches[1]
                $startLine = [int]$Matches[2]
            }
            $sarifResult | Add-Member -NotePropertyName 'locations' -NotePropertyValue @(
                [PSCustomObject]@{
                    physicalLocation = [PSCustomObject]@{
                        artifactLocation = [PSCustomObject]@{
                            uri       = $filePath
                            uriBaseId = '%SRCROOT%'
                        }
                        region = [PSCustomObject]@{
                            startLine = $startLine
                        }
                    }
                }
            )
        } else {
            # GitHub code scanning requires physicalLocation on every result.
            # Repo-level findings point to a sentinel path with the detail in the message.
            $sarifResult | Add-Member -NotePropertyName 'locations' -NotePropertyValue @(
                [PSCustomObject]@{
                    physicalLocation = [PSCustomObject]@{
                        artifactLocation = [PSCustomObject]@{
                            uri       = 'SECURITY.md'
                            uriBaseId = '%SRCROOT%'
                        }
                        region = [PSCustomObject]@{
                            startLine = 1
                        }
                    }
                    message = [PSCustomObject]@{
                        text = if ($isOrgLevelResource) {
                            "Organization setting: $($r.Resource)"
                        }
                        else {
                            "Repository setting: $($r.Resource)"
                        }
                    }
                }
            )
        }

        # Generate a stable fingerprint from rule + resource + detail to prevent
        # duplicate alerts across runs (required by GitHub code scanning).
        $hashHex = Get-FylgyrFingerprint -Result $r
        $sarifResult | Add-Member -NotePropertyName 'partialFingerprints' -NotePropertyValue ([PSCustomObject]@{
            primaryLocationLineHash = $hashHex
        })

        if ($r.Status -eq 'Suppressed') {
            $sarifResult | Add-Member -NotePropertyName 'suppressions' -NotePropertyValue @(
                [PSCustomObject]@{
                    kind          = 'external'
                    status        = 'accepted'
                    justification = 'Matched baseline fingerprint.'
                }
            )
        }

        $resultProperties = [ordered]@{}
        if ($r.AttackMapping.Count -gt 0) {
            $tags = [System.Collections.Generic.List[string]]::new()
            foreach ($attackId in $r.AttackMapping) {
                $tags.Add("attack:$attackId")
            }
            $resultProperties.tags = $tags.ToArray()
        }

        if ($r.PSObject.Properties.Name -contains 'Evidence' -and $r.Evidence) {
            $resultProperties.evidence = [PSCustomObject]@{
                commitSha = $r.Evidence.CommitSha
                scanTime  = if ($r.Evidence.ScanTime) { ([datetime]$r.Evidence.ScanTime).ToString('o') } else { $null }
                permalink = $r.Evidence.Permalink
            }
        }

        if ($resultProperties.Count -gt 0) {
            $sarifResult | Add-Member -NotePropertyName 'properties' -NotePropertyValue ([PSCustomObject]$resultProperties)
        }

        $sarifResults.Add($sarifResult)
    }

    $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
    $versionStr = if ($module -and $module.Version) { $module.Version.ToString() } else { '0.1.0' }

    $sarif = [PSCustomObject]@{
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        version = '2.1.0'
        runs = @(
            [PSCustomObject]@{
                tool = [PSCustomObject]@{
                    driver = [PSCustomObject]@{
                        name            = 'Fylgyr'
                        informationUri  = 'https://github.com/pthoor/Fylgyr'
                        semanticVersion = $versionStr
                        rules           = @($rules.Values)
                    }
                }
                results = $sarifResults.ToArray()
            }
        )
    }

    $sarif | ConvertTo-Json -Depth 20
}
