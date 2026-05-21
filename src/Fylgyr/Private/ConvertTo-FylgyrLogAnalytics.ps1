function ConvertTo-FylgyrLogAnalytics {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'LogAnalytics matches Azure product naming.')]
    [CmdletBinding()]
    [OutputType([string], [void])]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Results,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [datetime]$ScanStartTime,

        [string]$OutputPath
    )

    $module = Get-Module -Name Fylgyr -ErrorAction SilentlyContinue
    $version = if ($module -and $module.Version) { $module.Version.ToString() } else { '0.0.0' }

    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($result in $Results) {
        $mode = if ($result.PSObject.Properties['Mode'] -and $result.Mode) { [string]$result.Mode } else { 'Audit' }
        $eventSchema = if ($mode -eq 'Drift') { 'ChangeEvent' } else { 'AuditEvent' }

        $timeGenerated = $ScanStartTime.ToString('o')
        if ($result.PSObject.Properties['Evidence'] -and $result.Evidence) {
            if ($result.Evidence.PSObject.Properties['ChangedAt'] -and $result.Evidence.ChangedAt) {
                try {
                    $timeGenerated = ([datetime]$result.Evidence.ChangedAt).ToString('o')
                }
                catch {
                    $timeGenerated = $ScanStartTime.ToString('o')
                }
            }
            elseif ($result.Evidence.PSObject.Properties['ScanTime'] -and $result.Evidence.ScanTime) {
                try {
                    $timeGenerated = ([datetime]$result.Evidence.ScanTime).ToString('o')
                }
                catch {
                    $timeGenerated = $ScanStartTime.ToString('o')
                }
            }
        }

        $attackMapping = ''
        if ($result.PSObject.Properties['AttackMapping'] -and $result.AttackMapping) {
            $attackMapping = (@($result.AttackMapping) -join ';')
        }

        $evidenceYaml = $null
        $evidenceCommitSha = $null
        $evidencePermalink = $null
        $driftFrom = $null
        $driftTo = $null

        if ($result.PSObject.Properties['Evidence'] -and $result.Evidence) {
            if ($result.Evidence.PSObject.Properties['YamlSnippet']) {
                $evidenceYaml = [string]$result.Evidence.YamlSnippet
            }
            if ($result.Evidence.PSObject.Properties['CommitSha']) {
                $evidenceCommitSha = [string]$result.Evidence.CommitSha
            }
            if ($result.Evidence.PSObject.Properties['Permalink']) {
                $evidencePermalink = [string]$result.Evidence.Permalink
            }
            if ($result.Evidence.PSObject.Properties['From']) {
                $driftFrom = ($result.Evidence.From | ConvertTo-Json -Depth 20 -Compress)
            }
            if ($result.Evidence.PSObject.Properties['To']) {
                $driftTo = ($result.Evidence.To | ConvertTo-Json -Depth 20 -Compress)
            }
        }

        $lineObject = [ordered]@{
            TimeGenerated = $timeGenerated
            Type = 'Fylgyr_CL'
            EventVendor = 'Fylgyr'
            EventProduct = 'Fylgyr'
            EventSchema = $eventSchema
            EventType = if ($mode -eq 'Drift') { 'ConfigurationDrift' } else { 'SecurityFinding' }
            ScanId_g = $ScanId
            ScanStartTime_dt = $ScanStartTime.ToString('o')
            FylgyrVersion_s = $version
            CheckName_s = [string]$result.CheckName
            Severity_s = [string]$result.Severity
            Status_s = [string]$result.Status
            Mode_s = $mode
            Resource_s = [string]$result.Resource
            Detail_s = ([string]$result.Detail -replace "`r?`n", ' ')
            Remediation_s = ([string]$result.Remediation -replace "`r?`n", ' ')
            AttackMapping_s = $attackMapping
            DriftFrom_s = $driftFrom
            DriftTo_s = $driftTo
            EvidenceYaml_s = $evidenceYaml
            EvidenceCommitSha_s = $evidenceCommitSha
            EvidencePermalink_s = $evidencePermalink
        }

        $lines.Add(($lineObject | ConvertTo-Json -Depth 12 -Compress))
    }

    $ndjson = $lines -join [Environment]::NewLine
    if ($OutputPath) {
        Set-Content -Path $OutputPath -Value $ndjson -Encoding UTF8
        return
    }

    return $ndjson
}
