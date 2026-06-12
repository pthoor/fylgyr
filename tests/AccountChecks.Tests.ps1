Describe 'Phase 4 personal-account checks' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    BeforeEach {
        # The account checks run once per owner per scan; reset the cache so each
        # test starts clean.
        InModuleScope Fylgyr {
            $script:FylgyrOwnerAccountChecked = @{}
        }
    }

    Describe 'Test-AccountSecurity' {
        It 'fails with Critical severity when 2FA is disabled' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{ login = 'alice'; two_factor_authentication = $false }
            }

            $results = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].AttackMapping | Should -Contain 'dropbox-github-breach'
        }

        It 'passes when 2FA is enabled' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{ login = 'alice'; two_factor_authentication = $true }
            }

            $results = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'returns Info when the token belongs to a different user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $false }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw 'should not be called' }

            $results = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -Match 'different user'
        }

        It 'returns Info when the token type omits the 2FA field' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{ login = 'alice' }
            }

            $results = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -Match 'could not be verified'
        }

        It 'returns Info when the owner is an organization' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'Organization'; TokenMatchesOwner = $false }
            }

            $results = Test-AccountSecurity -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -Match 'Test-OrgMfaPolicy'
        }

        It 'returns Info when the owner type cannot be determined' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'Unknown'; TokenMatchesOwner = $false }
            }

            $results = Test-AccountSecurity -Owner 'ghost' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'runs once per owner and returns nothing on the second call' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{ login = 'alice'; two_factor_authentication = $true }
            }

            $first = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $second = Test-AccountSecurity -Owner 'alice' -Token 'fake'
            $first | Should -HaveCount 1
            $second | Should -BeNullOrEmpty
        }
    }

    Describe 'Test-AccountKey' {
        It 'warns on a stale SSH key without echoing key material' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'user/keys') {
                    return @([PSCustomObject]@{
                        id         = 1
                        title      = 'old-laptop'
                        key        = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyMaterial'
                        created_at = ([datetime]::UtcNow.AddDays(-1000)).ToString('o')
                    })
                }
                return @()
            }

            $results = Test-AccountKey -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Low'
            $results[0].AttackMapping | Should -Contain 'gentoo-github-compromise'
            ($results | ConvertTo-Json -Depth 5) | Should -Not -Match 'AAAAC3NzaC1lZDI1NTE5'
        }

        It 'warns on an expired GPG key' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'user/gpg_keys') {
                    return @([PSCustomObject]@{
                        id         = 2
                        key_id     = 'ABCDEF1234567890'
                        expires_at = ([datetime]::UtcNow.AddDays(-30)).ToString('o')
                    })
                }
                return @()
            }

            $results = Test-AccountKey -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
            $results[0].AttackMapping | Should -Contain 'xz-utils-backdoor'
        }

        It 'passes when keys are recent and unexpired' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'user/keys') {
                    return @([PSCustomObject]@{
                        id         = 1
                        title      = 'new-laptop'
                        created_at = ([datetime]::UtcNow.AddDays(-30)).ToString('o')
                    })
                }
                if ($Endpoint -eq 'user/gpg_keys') {
                    return @([PSCustomObject]@{
                        id         = 2
                        key_id     = 'ABCDEF1234567890'
                        expires_at = ([datetime]::UtcNow.AddDays(365)).ToString('o')
                    })
                }
                return @()
            }

            $results = Test-AccountKey -Owner 'alice' -Token 'fake'
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }

        It 'uses public endpoints and notes reduced fidelity when the token is not the owner' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $false }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'users/alice/keys') {
                    # Public endpoint returns only id + key — no created_at.
                    return @([PSCustomObject]@{ id = 1; key = 'ssh-ed25519 AAAApublic' })
                }
                return @()
            }

            $results = Test-AccountKey -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
            $results[0].Detail | Should -Match 'staleness was not assessed'
            Assert-MockCalled -ModuleName Fylgyr Invoke-GitHubApi -ParameterFilter { $Endpoint -eq 'users/alice/keys' }
        }

        It 'returns Info when the owner is an organization' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'Organization'; TokenMatchesOwner = $false }
            }

            $results = Test-AccountKey -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'still passes when key listing fails' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-AccountKey -Owner 'alice' -Token 'fake'
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Describe 'Invoke-FylgyrOrgScan personal-account consolidation' {
        It 'emits one consolidated skip notice plus account checks for a personal account' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Test-OrgMfaPolicy { throw 'org checks should be skipped' }
            Mock -ModuleName Fylgyr Test-AccountSecurity {
                @([PSCustomObject]@{
                    CheckName = 'AccountSecurity'; Status = 'Pass'; Severity = 'Info'
                    Resource = 'user/alice'; Detail = 'ok'; Remediation = 'none'
                    AttackMapping = @(); Target = 'user/alice'
                })
            }
            Mock -ModuleName Fylgyr Test-AccountKey {
                @([PSCustomObject]@{
                    CheckName = 'AccountKey'; Status = 'Pass'; Severity = 'Info'
                    Resource = 'user/alice'; Detail = 'ok'; Remediation = 'none'
                    AttackMapping = @(); Target = 'user/alice'
                })
            }

            $results = InModuleScope Fylgyr {
                Invoke-FylgyrOrgScan -Owner 'alice' -Token 'fake'
            }

            $skipNotices = @($results | Where-Object CheckName -EQ 'OrgChecks')
            $skipNotices | Should -HaveCount 1
            $skipNotices[0].Status | Should -Be 'Info'
            $skipNotices[0].Detail | Should -Match 'personal account'
            ($results | Where-Object CheckName -EQ 'AccountSecurity') | Should -HaveCount 1
            ($results | Where-Object CheckName -EQ 'AccountKey') | Should -HaveCount 1
            Assert-MockCalled -ModuleName Fylgyr Test-OrgMfaPolicy -Times 0
        }

        It 'records an Error result when an account check throws during consolidation' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'User'; TokenMatchesOwner = $true }
            }
            Mock -ModuleName Fylgyr Test-AccountSecurity { throw 'boom' }
            Mock -ModuleName Fylgyr Test-AccountKey { @() }

            $results = InModuleScope Fylgyr {
                Invoke-FylgyrOrgScan -Owner 'alice' -Token 'fake'
            }

            $errorResult = @($results | Where-Object { $_.Status -eq 'Error' })
            $errorResult | Should -HaveCount 1
            $errorResult[0].CheckName | Should -Be 'AccountSecurity'
        }

        It 'still runs the org loop when the owner type is Unknown' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext {
                [PSCustomObject]@{ Type = 'Unknown'; TokenMatchesOwner = $false }
            }
            Mock -ModuleName Fylgyr Test-OrgMfaPolicy { @() }
            Mock -ModuleName Fylgyr Test-OrgDefaultPermissions { @() }
            Mock -ModuleName Fylgyr Test-IpAllowlist { @() }
            Mock -ModuleName Fylgyr Test-AuditLogStreaming { @() }
            Mock -ModuleName Fylgyr Test-OAuthAppPolicy { @() }
            Mock -ModuleName Fylgyr Test-OrgActionRestrictions { @() }
            Mock -ModuleName Fylgyr Test-OutsideCollaborators { @() }
            Mock -ModuleName Fylgyr Test-PatPolicy { @() }
            Mock -ModuleName Fylgyr Test-GitHubAppSecurity { @() }
            Mock -ModuleName Fylgyr Test-Rulesets { @() }
            Mock -ModuleName Fylgyr Test-DefaultTokenPermission { @() }
            Mock -ModuleName Fylgyr Test-OrgSecretVisibility { @() }

            $null = InModuleScope Fylgyr {
                Invoke-FylgyrOrgScan -Owner 'mystery' -Token 'fake'
            }

            Assert-MockCalled -ModuleName Fylgyr Test-OrgMfaPolicy -Times 1
        }
    }
}
