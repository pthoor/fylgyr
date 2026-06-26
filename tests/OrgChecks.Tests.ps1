Describe 'Phase 7 org-level checks' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    Describe 'Test-OrgMfaPolicy' {
        It 'passes when MFA is required' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ two_factor_requirement_enabled = $true } }

            $results = Test-OrgMfaPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails when MFA is not required' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ two_factor_requirement_enabled = $false } }

            $results = Test-OrgMfaPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].AttackMapping | Should -Contain 'dropbox-github-breach'
        }

        It 'returns Error on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-OrgMfaPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Error'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-OrgMfaPolicy -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-OrgDefaultPermissions' {
        It 'passes for read default permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ default_repository_permission = 'read' } }

            $results = Test-OrgDefaultPermissions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails for write default permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ default_repository_permission = 'write' } }

            $results = Test-OrgDefaultPermissions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].AttackMapping | Should -Contain 'gentoo-github-compromise'
        }

        It 'returns Error on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-OrgDefaultPermissions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Error'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-OrgDefaultPermissions -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-IpAllowlist' {
        It 'passes when allowlist has entries' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{
                    data = [PSCustomObject]@{
                        organization = [PSCustomObject]@{
                            ipAllowListEntries = [PSCustomObject]@{ totalCount = 1 }
                        }
                    }
                }
            }

            $results = Test-IpAllowlist -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'warns when allowlist has zero entries' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                [PSCustomObject]@{
                    data = [PSCustomObject]@{
                        organization = [PSCustomObject]@{
                            ipAllowListEntries = [PSCustomObject]@{ totalCount = 0 }
                        }
                    }
                }
            }

            $results = Test-IpAllowlist -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
        }

        It 'returns Info on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-IpAllowlist -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'returns Info when GraphQL reports PAT field-level access denied' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw 'GraphQL query failed. GitHub response: Resource not accessible by personal access token' }

            $results = Test-IpAllowlist -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Info'
        }

        It 'returns Info on unexpected GraphQL failures as advisory' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw 'timeout contacting GraphQL endpoint' }

            $results = Test-IpAllowlist -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Info'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-IpAllowlist -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-AuditLogStreaming' {
        It 'passes when stream key is present' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ stream_key = 'abc' } }

            $results = Test-AuditLogStreaming -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'warns when stream key is missing' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{} }

            $results = Test-AuditLogStreaming -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
        }

        It 'returns Info on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-AuditLogStreaming -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-AuditLogStreaming -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-OAuthAppPolicy' {
        It 'passes when restrictions are enabled' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ enabled_for_organization = $true } }

            $results = Test-OAuthAppPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails when restrictions are disabled' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ enabled_for_organization = $false } }

            $results = Test-OAuthAppPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].AttackMapping | Should -Contain 'github-device-code-phishing'
        }

        It 'returns Error on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-OAuthAppPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Error'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-OAuthAppPolicy -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-OrgActionRestrictions' {
        It 'passes when allowed_actions is selected' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ allowed_actions = 'selected' } }

            $results = Test-OrgActionRestrictions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails when actions are unrestricted' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { [PSCustomObject]@{ allowed_actions = 'all' } }

            $results = Test-OrgActionRestrictions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].AttackMapping | Should -Contain 'tj-actions-shai-hulud'
        }

        It 'returns Error on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

            $results = Test-OrgActionRestrictions -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Error'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-OrgActionRestrictions -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-OutsideCollaborators' {
        It 'passes when no outside collaborators are present' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -like 'orgs/acme/outside_collaborators*') { return @() }
                throw 'unexpected endpoint'
            }

            $results = Test-OutsideCollaborators -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails when outside collaborator has write/admin permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -like 'orgs/acme/outside_collaborators*') {
                    return @([PSCustomObject]@{ login = 'contractor1' })
                }
                if ($Endpoint -like 'orgs/acme/repos*') {
                    return @([PSCustomObject]@{ name = 'repo1' })
                }
                if ($Endpoint -eq 'repos/acme/repo1/collaborators/contractor1/permission') {
                    return [PSCustomObject]@{ permission = 'write' }
                }
                throw 'unexpected endpoint'
            }

            $results = Test-OutsideCollaborators -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].AttackMapping | Should -Contain 'uber-credential-leak'
        }

        It 'returns Info on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -like 'orgs/acme/outside_collaborators*') { throw '403 Forbidden' }
                throw 'unexpected endpoint'
            }

            $results = Test-OutsideCollaborators -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-OutsideCollaborators -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-PatPolicy' {
        It 'passes when PAT policy endpoints are active and requests exist' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/personal-access-token-requests?per_page=100') {
                    return @([PSCustomObject]@{ id = 1 })
                }
                if ($Endpoint -eq 'orgs/acme/personal-access-tokens?per_page=1') {
                    return @()
                }
                throw 'unexpected endpoint'
            }

            $results = Test-PatPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'returns Info when requests endpoint is reachable but tokens endpoint is unavailable (404)' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/personal-access-token-requests?per_page=100') {
                    return @([PSCustomObject]@{ id = 1 })
                }
                if ($Endpoint -eq 'orgs/acme/personal-access-tokens?per_page=1') {
                    throw '404 Not Found'
                }
                throw 'unexpected endpoint'
            }

            $results = Test-PatPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -BeLike '*endpoint is unavailable (404)*'
        }

        It 'returns Info on insufficient permission' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/personal-access-token-requests?per_page=100') {
                    throw '403 Forbidden'
                }
                throw 'unexpected endpoint'
            }

            $results = Test-PatPolicy -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-PatPolicy -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }
    }

    Describe 'Test-Rulesets' {
        It 'passes when branch and tag protections are present for org mode' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/rulesets') {
                    return @(
                        [PSCustomObject]@{ target = 'branch'; enforcement = 'active' }
                        [PSCustomObject]@{ target = 'tag'; enforcement = 'active' }
                    )
                }
                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'warns when tag protection is missing at org scope' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/rulesets') {
                    return @([PSCustomObject]@{ target = 'branch'; enforcement = 'active' })
                }
                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
            $results[0].AttackMapping | Should -Contain 'trivy-tag-poisoning'
            $results[0].AttackMapping | Should -Contain 'actions-cool-issues-helper-compromise'
        }

        It 'returns Info on insufficient permission for org rulesets' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/rulesets') { throw '403 Forbidden' }
                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -BeLike '*Administration:write*'
        }

        It 'returns Info when rulesets endpoint is unavailable (404)' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'orgs/acme/rulesets') { throw '404 Not Found' }
                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -BeLike '*could not be verified*'
        }

        It 'returns Info when owner is a user' {
            Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

            $results = Test-Rulesets -Owner 'alice' -Token 'fake'
            $results[0].Status | Should -Be 'Info'
        }

        It 'includes tag context when repo tags exist and tag protection is missing' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)

                if ($Endpoint -eq 'repos/acme/repo') {
                    return [PSCustomObject]@{ default_branch = 'main' }
                }

                if ($Endpoint -eq 'repos/acme/repo/rulesets') {
                    return @(
                        [PSCustomObject]@{
                            target = 'branch'
                            enforcement = 'active'
                            conditions = [PSCustomObject]@{
                                ref_name = [PSCustomObject]@{
                                    include = @('refs/heads/main')
                                }
                            }
                        }
                    )
                }

                if ($Endpoint -eq 'repos/acme/repo/tags/protection') {
                    return @()
                }

                if ($Endpoint -eq 'repos/acme/repo/tags?per_page=100') {
                    return @(
                        [PSCustomObject]@{ name = 'v1.0.0' }
                        [PSCustomObject]@{ name = 'v1.1.0' }
                    )
                }

                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Repo 'repo' -Token 'fake'
            $results[0].Status | Should -Be 'Fail'
            $results[0].Detail | Should -BeLike '*first-page sample*'
            $results[0].Detail | Should -BeLike '*v1.0.0*'
        }

        It 'warns when repo has no tags and tag protection is missing' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)

                if ($Endpoint -eq 'repos/acme/repo') {
                    return [PSCustomObject]@{ default_branch = 'main' }
                }

                if ($Endpoint -eq 'repos/acme/repo/rulesets') {
                    return @(
                        [PSCustomObject]@{
                            target = 'branch'
                            enforcement = 'active'
                            conditions = [PSCustomObject]@{
                                ref_name = [PSCustomObject]@{
                                    include = @('refs/heads/main')
                                }
                            }
                        }
                    )
                }

                if ($Endpoint -eq 'repos/acme/repo/tags/protection') {
                    return @()
                }

                if ($Endpoint -eq 'repos/acme/repo/tags?per_page=100') {
                    return @()
                }

                throw 'unexpected endpoint'
            }

            $results = Test-Rulesets -Owner 'acme' -Repo 'repo' -Token 'fake'
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Detail | Should -BeLike '*currently has no tags*'
        }
    }
}

Describe 'Test-DefaultTokenPermission (org scope)' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'returns Info when owner is a personal account' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

        $results = Test-DefaultTokenPermission -Owner 'alice' -Token 'fake'
        $results[0].Status | Should -Be 'Info'
    }

    It 'fails when the org default token permission is write' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            [PSCustomObject]@{ default_workflow_permissions = 'write'; can_approve_pull_request_reviews = $true }
        }

        $results = Test-DefaultTokenPermission -Owner 'acme' -Token 'fake'
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
        $results[0].Resource | Should -Be 'org/acme'
    }
}

Describe 'Test-OrgSecretVisibility' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'returns Info when owner is a personal account' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'User' } }

        $results = Test-OrgSecretVisibility -Owner 'alice' -Token 'fake'
        $results[0].Status | Should -Be 'Info'
    }

    It 'fails for a secret visible to all repositories' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            @(
                [PSCustomObject]@{ name = 'NPM_TOKEN'; visibility = 'all' }
                [PSCustomObject]@{ name = 'SCOPED'; visibility = 'selected' }
            )
        }

        $results = Test-OrgSecretVisibility -Owner 'acme' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
        $fail[0].Severity | Should -Be 'High'
        $fail[0].Resource | Should -BeLike '*NPM_TOKEN*'
        $fail[0].AttackMapping | Should -Contain 'prt-scan-ai-automated'
    }

    It 'passes when no secret is visible to all repositories' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            @([PSCustomObject]@{ name = 'SCOPED'; visibility = 'selected' })
        }

        $results = Test-OrgSecretVisibility -Owner 'acme' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'returns Error on 403' {
        Mock -ModuleName Fylgyr Get-FylgyrOwnerContext { [PSCustomObject]@{ Type = 'Organization' } }
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

        $results = Test-OrgSecretVisibility -Owner 'acme' -Token 'fake'
        $results[0].Status | Should -Be 'Error'
    }
}
