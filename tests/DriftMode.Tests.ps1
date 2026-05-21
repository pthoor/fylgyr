Describe 'Drift mode orchestration' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    BeforeEach {
        $auditResult = [PSCustomObject]@{
            CheckName = 'BranchProtection'
            Status = 'Pass'
            Severity = 'Info'
            Resource = 'acme/repo'
            Detail = 'ok'
            Remediation = 'none'
            AttackMapping = @()
            Target = 'acme/repo'
            Mode = 'Audit'
        }

        $driftResult = [PSCustomObject]@{
            CheckName = 'RecentForcePush'
            Status = 'Drift'
            Severity = 'High'
            Resource = 'acme/repo'
            Detail = 'force push'
            Remediation = 'investigate'
            AttackMapping = @('trivy-tag-poisoning')
            Target = 'acme/repo'
            Mode = 'Drift'
        }

        Mock -ModuleName Fylgyr Invoke-FylgyrScan { return @($auditResult) }
        Mock -ModuleName Fylgyr Invoke-FylgyrDriftScan { return @($driftResult) }
        Mock -ModuleName Fylgyr Get-OrgAuditLog { return @() }
    }

    It 'runs only drift checks when Mode is Drift' {
        $results = Invoke-Fylgyr -Owner 'acme' -Repo 'repo' -Token 'fake-token' -Mode Drift
        $results | Should -HaveCount 1
        $results[0].Mode | Should -Be 'Drift'
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrDriftScan -Times 1 -Exactly
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrScan -Times 0 -Exactly
    }

    It 'runs both audit and drift checks when Mode is Both' {
        $results = Invoke-Fylgyr -Owner 'acme' -Repo 'repo' -Token 'fake-token' -Mode Both
        $results.Count | Should -Be 2
        @($results.Mode) | Should -Contain 'Audit'
        @($results.Mode) | Should -Contain 'Drift'
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrDriftScan -Times 1 -Exactly
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrScan -Times 1 -Exactly
    }
}

Describe 'Drift checks' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'Test-RecentForcePush reports drift for forced push events' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/acme/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }

            return @(
                [PSCustomObject]@{
                    id = '1'
                    type = 'PushEvent'
                    created_at = [datetime]::UtcNow.ToString('o')
                    actor = [PSCustomObject]@{ login = 'attacker' }
                    payload = [PSCustomObject]@{ forced = $true; ref = 'refs/heads/main' }
                }
            )
        }

        $results = Test-RecentForcePush -Owner 'acme' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Drift'
        $results[0].Severity | Should -Be 'Critical'
    }

    It 'Test-RecentWorkflowAdd reports drift when baseline misses a workflow path' {
        Mock -ModuleName Fylgyr Get-WorkflowFile {
            return @(
                [PSCustomObject]@{ Name = 'a.yml'; Path = '.github/workflows/a.yml'; Content = 'name: a' }
            )
        }

        Mock -ModuleName Fylgyr Compare-FylgyrBaseline {
            return [PSCustomObject]@{
                HasBaseline = $true
                IsChanged = $true
                BaselineSnapshot = @{ Paths = @() }
                CurrentSnapshot = @{ Paths = @('.github/workflows/a.yml') }
            }
        }

        $results = Test-RecentWorkflowAdd -Owner 'acme' -Repo 'repo' -Token 'fake-token' -BaselinePath '/tmp/base.json'
        $results[0].Status | Should -Be 'Drift'
    }

    It 'Test-RecentAppAuthorization reports drift from audit events' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }

        $results = Test-RecentAppAuthorization -Owner 'acme' -Token 'fake-token' -AuditEvents @(
            [PSCustomObject]@{
                action = 'org_credential_authorization.grant'
                created_at = [datetime]::UtcNow.ToString('o')
                actor = 'attacker'
                data = @{ scope = 'contents:write' }
                programmatic_access_type = 'oauth_app'
            }
        )

        $results[0].Status | Should -Be 'Drift'
    }

    It 'Test-RecentProtectionChange reports baseline drift when snapshot changes' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/acme/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            if ($Endpoint -eq 'repos/acme/repo/branches/main/protection') {
                return [PSCustomObject]@{ allow_force_pushes = @{ enabled = $false } }
            }
            if ($Endpoint -eq 'repos/acme/repo/rulesets') {
                return @()
            }
            throw 'unexpected endpoint'
        }

        Mock -ModuleName Fylgyr Compare-FylgyrBaseline {
            return [PSCustomObject]@{
                HasBaseline = $true
                IsChanged = $true
                BaselineSnapshot = @{ BranchProtection = @{ allow_force_pushes = @{ enabled = $true } } }
                CurrentSnapshot = @{ BranchProtection = @{ allow_force_pushes = @{ enabled = $false } } }
            }
        }

        $results = Test-RecentProtectionChange -Owner 'acme' -Repo 'repo' -Token 'fake-token' -BaselinePath '/tmp/base.json'
        $results[0].Status | Should -Be 'Drift'
    }
}

Describe 'Log Analytics output' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'formats ASIM-oriented NDJSON for Log Analytics' {
        $line = InModuleScope Fylgyr {
            $results = @(
                (Format-FylgyrResult -CheckName 'RecentProtectionChange' -Status 'Drift' -Severity 'High' -Resource 'acme/repo' -Detail 'changed' -Remediation 'fix' -Mode 'Drift' -Evidence @{ From = @{ a = 1 }; To = @{ a = 2 } })
            )
            ConvertTo-FylgyrLogAnalytics -Results $results -ScanId ([guid]::NewGuid().ToString()) -ScanStartTime ([datetime]::UtcNow)
        }

        $parsed = ($line -split [Environment]::NewLine)[0] | ConvertFrom-Json
        $parsed.EventVendor | Should -Be 'Fylgyr'
        $parsed.EventSchema | Should -Be 'ChangeEvent'
        $parsed.Mode_s | Should -Be 'Drift'
    }
}
