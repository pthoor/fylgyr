Describe 'Test-BranchProtection' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when branch has full protection with required reviews and status checks' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            return [PSCustomObject]@{
                allow_force_pushes            = [PSCustomObject]@{ enabled = $false }
                allow_deletions               = [PSCustomObject]@{ enabled = $false }
                required_pull_request_reviews = [PSCustomObject]@{
                    required_approving_review_count = 1
                    dismiss_stale_reviews           = $true
                }
                required_status_checks        = [PSCustomObject]@{ strict = $true; contexts = @('ci') }
            }
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when classic protection is absent but branch ruleset provides equivalent controls' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/org/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }

            if ($Endpoint -eq 'repos/org/repo/branches/main/protection') {
                throw '404 Not Found'
            }

            if ($Endpoint -eq 'repos/org/repo/rulesets') {
                return @(
                    [PSCustomObject]@{
                        target = 'branch'
                        enforcement = 'active'
                        conditions = [PSCustomObject]@{
                            ref_name = [PSCustomObject]@{
                                include = @('refs/heads/main')
                            }
                        }
                        rules = @(
                            [PSCustomObject]@{ type = 'non_fast_forward' }
                            [PSCustomObject]@{ type = 'deletion' }
                            [PSCustomObject]@{
                                type = 'pull_request'
                                parameters = [PSCustomObject]@{
                                    required_approving_review_count = 1
                                    dismiss_stale_reviews_on_push = $true
                                }
                            }
                            [PSCustomObject]@{ type = 'required_status_checks' }
                        )
                    }
                )
            }

            throw 'unexpected endpoint'
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
        $results[0].Detail | Should -BeLike '*ruleset*'
    }

    It 'passes when ruleset list omits rules but detail endpoint contains required controls' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/org/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }

            if ($Endpoint -eq 'repos/org/repo/branches/main/protection') {
                throw '404 Not Found'
            }

            if ($Endpoint -eq 'repos/org/repo/rulesets') {
                return @(
                    [PSCustomObject]@{
                        id = 42
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

            if ($Endpoint -eq 'repos/org/repo/rulesets/42') {
                return [PSCustomObject]@{
                    id = 42
                    target = 'branch'
                    enforcement = 'active'
                    conditions = [PSCustomObject]@{
                        ref_name = [PSCustomObject]@{
                            include = @('refs/heads/main')
                        }
                    }
                    rules = @(
                        [PSCustomObject]@{ type = 'non_fast_forward' }
                        [PSCustomObject]@{ type = 'deletion' }
                        [PSCustomObject]@{
                            type = 'pull_request'
                            parameters = [PSCustomObject]@{
                                required_approving_review_count = 1
                                dismiss_stale_reviews_on_push = $true
                            }
                        }
                        [PSCustomObject]@{ type = 'required_status_checks' }
                    )
                }
            }

            throw 'unexpected endpoint'
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when no branch protection exists (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            throw '404 Not Found'
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
        $results[0].AttackMapping | Should -Contain 'trivy-force-push-main'
    }

    It 'returns Error when access is forbidden (403)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            throw '403 Forbidden'
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
    }

    It 'fails when force pushes are allowed' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            return [PSCustomObject]@{
                allow_force_pushes            = [PSCustomObject]@{ enabled = $true }
                allow_deletions               = [PSCustomObject]@{ enabled = $false }
                required_pull_request_reviews = [PSCustomObject]@{
                    required_approving_review_count = 1
                    dismiss_stale_reviews           = $true
                }
                required_status_checks        = [PSCustomObject]@{ strict = $true }
            }
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
        $fail[0].Detail | Should -BeLike '*force push*'
        $fail[0].AttackMapping | Should -Contain 'trivy-force-push-main'
    }

    It 'returns Error when force-push setting is missing from API response' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            # allow_force_pushes deliberately absent
            return [PSCustomObject]@{
                allow_deletions               = [PSCustomObject]@{ enabled = $false }
                required_pull_request_reviews = [PSCustomObject]@{
                    required_approving_review_count = 1
                    dismiss_stale_reviews           = $true
                }
                required_status_checks        = [PSCustomObject]@{ strict = $true }
            }
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $errorResult = $results | Where-Object { $_.Status -eq 'Error' -and $_.Detail -like '*force-push*' }
        $errorResult | Should -HaveCount 1
    }

    It 'fails when no required PR reviews configured' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            return [PSCustomObject]@{
                allow_force_pushes            = [PSCustomObject]@{ enabled = $false }
                allow_deletions               = [PSCustomObject]@{ enabled = $false }
                required_pull_request_reviews = $null
                required_status_checks        = [PSCustomObject]@{ strict = $true }
            }
        }

        $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object Status -EQ 'Fail'
        ($fail | Where-Object { $_.Detail -like '*pull request reviews*' }) | Should -HaveCount 1
    }
}

Describe 'Test-SecretScanning' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when secret scanning is enabled and no open alerts' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { return @() }

        $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
        $results[0].AttackMapping | Should -Contain 'committed-credentials-exposure'
    }

    It 'fails when secret scanning is not enabled (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

        $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].AttackMapping | Should -Contain 'committed-credentials-exposure'
    }

    It 'warns when open alerts are present with no High/Critical severity' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{ secret_type = 'github_personal_access_token'; state = 'open'; severity = 'medium'; created_at = '2024-01-01T00:00:00Z' }
                [PSCustomObject]@{ secret_type = 'aws_access_key_id'; state = 'open'; severity = 'low'; created_at = '2024-02-01T00:00:00Z' }
            )
        }

        $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].Detail | Should -BeLike '*2 open*'
        $results[0].Detail | Should -BeLike '*Highest severity: medium*'
    }

    It 'fails when open alerts include High or Critical severity' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{ secret_type = 'github_personal_access_token'; state = 'open'; severity = 'critical'; created_at = '2024-01-01T00:00:00Z' }
                [PSCustomObject]@{ secret_type = 'aws_access_key_id'; state = 'open'; severity = 'medium'; created_at = '2024-02-01T00:00:00Z' }
            )
        }

        $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
    }

    It 'returns Info when alerts scope is missing but scanning appears enabled' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'secret-scanning/alerts') {
                throw '403 Forbidden'
            }

            if ($Endpoint -eq 'repos/org/repo') {
                return [PSCustomObject]@{
                    security_and_analysis = [PSCustomObject]@{
                        secret_scanning = [PSCustomObject]@{ status = 'enabled' }
                    }
                }
            }

            throw '404 Not Found'
        }

        $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Info'
        $results[0].Severity | Should -Be 'Info'
    }
}

Describe 'Test-DependabotAlert' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when no open critical or high alerts' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{ security_advisory = [PSCustomObject]@{ severity = 'medium' } }
            )
        }

        $results = Test-DependabotAlert -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when Dependabot alerts are not enabled (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

        $results = Test-DependabotAlert -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].AttackMapping | Should -Contain 'event-stream-hijack'
    }

    It 'fails when critical alerts are open' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{ security_advisory = [PSCustomObject]@{ severity = 'critical' } }
                [PSCustomObject]@{ security_advisory = [PSCustomObject]@{ severity = 'high' } }
            )
        }

        $results = Test-DependabotAlert -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
        $results[0].Detail | Should -BeLike '*1 critical*1 high*'
    }

    It 'returns Error when access is forbidden (403)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

        $results = Test-DependabotAlert -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
    }
}

Describe 'Test-CodeScanning' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when code scanning has a recent analysis' {
        $recentDate = ([datetime]::UtcNow.AddDays(-5)).ToString('o')
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @([PSCustomObject]@{ created_at = $recentDate; tool = [PSCustomObject]@{ name = 'CodeQL' } })
        }

        $results = Test-CodeScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when code scanning is not configured (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

        $results = Test-CodeScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].AttackMapping | Should -Contain 'solarwinds-orion'
    }

    It 'fails when last analysis is stale (older than 30 days)' {
        $staleDate = ([datetime]::UtcNow.AddDays(-45)).ToString('o')
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @([PSCustomObject]@{ created_at = $staleDate })
        }

        $results = Test-CodeScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Detail | Should -BeLike '*day*ago*'
    }

    It 'returns Error when access is forbidden (403)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

        $results = Test-CodeScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
    }
}

Describe 'Test-RunnerHygiene' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when only GitHub-hosted runners are used' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when self-hosted runner is used with pull_request_target' {
        $wf = @([PSCustomObject]@{
            Name    = 'deploy.yml'
            Path    = '.github/workflows/deploy.yml'
            Content = @'
name: Deploy
on:
  pull_request_target:
    types: [opened]
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
        $results[0].AttackMapping | Should -Contain 'github-actions-cryptomining'
    }

    It 'warns when self-hosted runner is used with pull_request trigger' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Severity | Should -Be 'Medium'
    }

    It 'warns at Low severity when self-hosted runner is used without untrusted triggers' {
        $wf = @([PSCustomObject]@{
            Name    = 'deploy.yml'
            Path    = '.github/workflows/deploy.yml'
            Content = @'
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: [self-hosted, linux]
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Severity | Should -Be 'Low'
    }

    It 'detects self-hosted runner in multi-line list runs-on syntax' {
        $wf = @([PSCustomObject]@{
            Name    = 'deploy.yml'
            Path    = '.github/workflows/deploy.yml'
            Content = @'
name: Deploy
on:
  pull_request_target:
    types: [opened]
jobs:
  deploy:
    runs-on:
      - self-hosted
      - linux
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'High'
    }

    It 'warns on dynamic matrix expression for runs-on' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Detail | Should -BeLike '*dynamic runner*'
    }
}
