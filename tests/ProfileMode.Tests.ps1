Describe 'Solo-maintainer profile' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    Describe 'Resolve-FylgyrProfile' {
        It 're-ranks the 0-approvers BranchProtection finding to Info with a compensating note' {
            $results = @(
                [PSCustomObject]@{
                    CheckName = 'BranchProtection'; Status = 'Fail'; Severity = 'Medium'
                    Resource = 'org/repo (branch: main)'
                    Detail = "Active branch ruleset for 'main' allows 0 approving reviews."
                    Remediation = 'x'; AttackMapping = @(); Target = 'org/repo'; Mode = 'Audit'
                }
            )

            $out = InModuleScope Fylgyr -Parameters @{ Results = $results } {
                param($Results)
                Resolve-FylgyrProfile -Results $Results -ProfileName 'SoloMaintainer'
            }

            $out[0].Status | Should -Be 'Info'
            $out[0].Severity | Should -Be 'Info'
            $out[0].Detail | Should -Match 'Solo-maintainer profile:'
            $out[0].Detail | Should -Match 'docs/SOLO-MAINTAINER.md'
        }

        It 're-ranks single-owner CODEOWNERS findings to Info' {
            $results = @(
                [PSCustomObject]@{
                    CheckName = 'CodeOwner'; Status = 'Warning'; Severity = 'Medium'
                    Resource = 'org/repo (.github/CODEOWNERS)'
                    Detail = 'CODEOWNERS assigns ownership to only 1 distinct owner (@solo).'
                    Remediation = 'x'; AttackMapping = @('xz-utils-backdoor'); Target = 'org/repo'; Mode = 'Audit'
                }
            )

            $out = InModuleScope Fylgyr -Parameters @{ Results = $results } {
                param($Results)
                Resolve-FylgyrProfile -Results $Results -ProfileName 'SoloMaintainer'
            }

            $out[0].Status | Should -Be 'Info'
        }

        It 'leaves solo-achievable findings untouched' {
            $results = @(
                [PSCustomObject]@{
                    CheckName = 'ActionPinning'; Status = 'Fail'; Severity = 'High'
                    Resource = '.github/workflows/ci.yml'
                    Detail = 'Action referenced by tag instead of SHA.'
                    Remediation = 'x'; AttackMapping = @(); Target = 'org/repo'; Mode = 'Audit'
                },
                [PSCustomObject]@{
                    CheckName = 'CodeOwner'; Status = 'Warning'; Severity = 'Medium'
                    Resource = 'org/repo (.github/CODEOWNERS)'
                    Detail = 'No CODEOWNERS file found in the repository.'
                    Remediation = 'x'; AttackMapping = @(); Target = 'org/repo'; Mode = 'Audit'
                }
            )

            $out = InModuleScope Fylgyr -Parameters @{ Results = $results } {
                param($Results)
                Resolve-FylgyrProfile -Results $Results -ProfileName 'SoloMaintainer'
            }

            ($out | Where-Object CheckName -EQ 'ActionPinning').Status | Should -Be 'Fail'
            # "missing CODEOWNERS file" is fixable by one person, so it stays.
            ($out | Where-Object CheckName -EQ 'CodeOwner').Status | Should -Be 'Warning'
        }

        It 'does not touch Pass or Error results' {
            $results = @(
                [PSCustomObject]@{
                    CheckName = 'BranchProtection'; Status = 'Error'; Severity = 'High'
                    Resource = 'org/repo'; Detail = 'allows 0 approving reviews'
                    Remediation = 'x'; AttackMapping = @(); Target = 'org/repo'; Mode = 'Audit'
                }
            )

            $out = InModuleScope Fylgyr -Parameters @{ Results = $results } {
                param($Results)
                Resolve-FylgyrProfile -Results $Results -ProfileName 'SoloMaintainer'
            }

            $out[0].Status | Should -Be 'Error'
        }

        It 'is idempotent (does not append the note twice)' {
            $results = @(
                [PSCustomObject]@{
                    CheckName = 'BranchProtection'; Status = 'Fail'; Severity = 'Medium'
                    Resource = 'org/repo (branch: main)'
                    Detail = 'Branch allows 0 approvers.'
                    Remediation = 'x'; AttackMapping = @(); Target = 'org/repo'; Mode = 'Audit'
                }
            )

            $out = InModuleScope Fylgyr -Parameters @{ Results = $results } {
                param($Results)
                $once = Resolve-FylgyrProfile -Results $Results -ProfileName 'SoloMaintainer'
                Resolve-FylgyrProfile -Results $once -ProfileName 'SoloMaintainer'
            }

            ([regex]::Matches($out[0].Detail, 'Solo-maintainer profile:')).Count | Should -Be 1
        }
    }

    Describe 'Invoke-Fylgyr -SoloMaintainer' {
        BeforeEach {
            $stubResult = [PSCustomObject]@{
                CheckName = 'Stub'; Status = 'Pass'; Severity = 'Info'; Resource = 'test/repo'
                Detail = 'Stubbed.'; Remediation = 'None.'; AttackMapping = @(); Target = 'test/repo'
            }
            Mock -ModuleName Fylgyr Test-SecretScanning       { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-DependabotAlert      { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-CodeScanning         { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-SignedCommit         { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-EnvironmentProtection { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-RepoVisibility       { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-ForkSecretExposure   { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-GitHubAppSecurity    { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-Rulesets             { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-WebhookSecurity      { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-BinaryArtifact       { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-PrivateVulnReporting { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-DefaultTokenPermission { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-DeployKey            { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-TagProtection        { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-AccountSecurity      { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-AccountKey           { return @($stubResult) }
            Mock -ModuleName Fylgyr Test-LifecycleScript      { return @($stubResult) }
            Mock -ModuleName Fylgyr Get-ActionDefinitionFile  { return @() }
            Mock -ModuleName Fylgyr Get-WorkflowFile          { return @() }

            Mock -ModuleName Fylgyr Test-BranchProtection {
                return @([PSCustomObject]@{
                    CheckName = 'BranchProtection'; Status = 'Fail'; Severity = 'Medium'
                    Resource = 'test/repo (branch: main)'
                    Detail = "Active branch ruleset for 'main' allows 0 approving reviews."
                    Remediation = 'x'; AttackMapping = @(); Target = 'test/repo'; Mode = 'Audit'
                })
            }
            Mock -ModuleName Fylgyr Test-CodeOwner {
                return @([PSCustomObject]@{
                    CheckName = 'CodeOwner'; Status = 'Warning'; Severity = 'Medium'
                    Resource = 'test/repo (.github/CODEOWNERS)'
                    Detail = 'CODEOWNERS assigns ownership to only 1 distinct owner (@solo).'
                    Remediation = 'x'; AttackMapping = @(); Target = 'test/repo'; Mode = 'Audit'
                })
            }
        }

        It 're-ranks impossible-solo findings to Info when -SoloMaintainer is set' {
            $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -SoloMaintainer

            $bp = $results | Where-Object CheckName -EQ 'BranchProtection'
            $co = $results | Where-Object CheckName -EQ 'CodeOwner'
            $bp.Status | Should -Be 'Info'
            $co.Status | Should -Be 'Info'
            $bp.Detail | Should -Match 'Solo-maintainer profile:'
        }

        It 'leaves the findings as Fail/Warning without the switch' {
            $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'

            ($results | Where-Object CheckName -EQ 'BranchProtection').Status | Should -Be 'Fail'
            ($results | Where-Object CheckName -EQ 'CodeOwner').Status | Should -Be 'Warning'
        }

        It 'keeps the impossible-solo finding from tripping -FailOn Medium' {
            $null = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -SoloMaintainer -FailOn Medium
            $LASTEXITCODE | Should -Be 0
        }
    }
}
