function ConvertTo-FylgyrSarif {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results
    )

    $severityToLevel = @{
        Critical = 'error'
        High     = 'error'
        Medium   = 'warning'
        Low      = 'note'
        Info     = 'note'
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

    foreach ($r in $Results) {
        $ruleId = "fylgyr/$($r.CheckName)"

        if (-not $rules.ContainsKey($ruleId)) {
            $helpText = $r.Remediation
            if ($r.AttackMapping.Count -gt 0) {
                $attackNames = $r.AttackMapping | ForEach-Object {
                    if ($attackCatalog.ContainsKey($_)) { $attackCatalog[$_].name } else { $_ }
                }
                $helpText += "`n`nRelated attacks: $($attackNames -join ', ')"
            }

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
            }
        }

        # Parse file path and line number from Resource (format: path:line or just path)
        $filePath = $r.Resource
        $startLine = 1
        if ($r.Resource -match '^(.+):(\d+)$') {
            $filePath = $Matches[1]
            $startLine = [int]$Matches[2]
        }

        $sarifResult = [PSCustomObject]@{
            ruleId  = $ruleId
            level   = $severityToLevel[$r.Severity]
            message = [PSCustomObject]@{ text = $r.Detail }
            locations = @(
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
        }

        if ($r.AttackMapping.Count -gt 0) {
            $tags = [System.Collections.Generic.List[string]]::new()
            foreach ($attackId in $r.AttackMapping) {
                $tags.Add("attack:$attackId")
            }
            $sarifResult | Add-Member -NotePropertyName 'properties' -NotePropertyValue ([PSCustomObject]@{
                tags = $tags.ToArray()
            })
        }

        $sarifResults.Add($sarifResult)
    }

    $moduleVersion = (Get-Module -Name Fylgyr -ErrorAction SilentlyContinue).Version
    $versionStr = if ($moduleVersion) { $moduleVersion.ToString() } else { '0.1.0' }

    $sarif = [PSCustomObject]@{
        '$schema' = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json'
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
