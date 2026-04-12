Describe 'Fylgyr foundation' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $manifestPath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psd1'
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        $attacksPath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Data/attacks.json'
    }

    It 'has a valid module manifest' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest | Should -Not -BeNullOrEmpty
    }

    It 'imports the module without error' {
        { Import-Module -Name $modulePath -Force } | Should -Not -Throw
    }

    It 'has attacks.json with required schema fields' {
        $attacks = Get-Content -Path $attacksPath -Raw | ConvertFrom-Json

        $attacks | Should -Not -BeNullOrEmpty
        $attacks.Count | Should -BeGreaterThan 0

        $requiredFields = @(
            'id',
            'name',
            'date',
            'description',
            'affectedPackages',
            'cves',
            'references',
            'detectionSignals'
        )

        foreach ($attack in $attacks) {
            foreach ($field in $requiredFields) {
                $attack.PSObject.Properties.Name | Should -Contain $field
            }
        }
    }
}

Describe 'Test-ActionPinning' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when all actions are SHA-pinned' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - uses: actions/setup-node@1a4442cacd436585916f9831fb68f413562d456b
'@
        })

        $results = Test-ActionPinning -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when an action uses a tag' {
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
      - uses: actions/checkout@v4
      - uses: actions/setup-node@1a4442cacd436585916f9831fb68f413562d456b
'@
        })

        $results = Test-ActionPinning -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
        $fail[0].Detail | Should -BeLike '*actions/checkout@v4*'
        $fail[0].Severity | Should -Be 'High'
        $fail[0].AttackMapping | Should -Contain 'trivy-tag-poisoning'
    }

    It 'skips local actions' {
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
      - uses: ./local-action
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-ActionPinning -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when SHA-pinned action has a trailing comment' {
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
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
'@
        })

        $results = Test-ActionPinning -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'reports each unpinned reference separately' {
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
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
'@
        })

        $results = Test-ActionPinning -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 2
    }
}

Describe 'Test-DangerousTrigger' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when no dangerous triggers are present' {
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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when pull_request_target checks out untrusted code' {
        $wf = @([PSCustomObject]@{
            Name    = 'pr-target.yml'
            Path    = '.github/workflows/pr-target.yml'
            Content = @'
name: PR Target
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'Critical'
        $fail[0].AttackMapping | Should -Contain 'nx-pwn-request'
        $fail[0].AttackMapping | Should -Contain 'prt-scan-ai-automated'
        $fail[0].AttackMapping | Should -Contain 'trivy-supply-chain-2026'
    }

    It 'detects inline scalar trigger syntax' {
        $wf = @([PSCustomObject]@{
            Name    = 'inline.yml'
            Path    = '.github/workflows/inline.yml'
            Content = @'
name: Inline
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
    }

    It 'detects inline array trigger syntax' {
        $wf = @([PSCustomObject]@{
            Name    = 'array.yml'
            Path    = '.github/workflows/array.yml'
            Content = @'
name: Array
on: [push, pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'Critical'
    }

    It 'warns when pull_request_target is used without untrusted checkout' {
        $wf = @([PSCustomObject]@{
            Name    = 'label.yml'
            Path    = '.github/workflows/label.yml'
            Content = @'
name: Label PR
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Severity | Should -Be 'Medium'
    }
}

Describe 'Test-WorkflowPermission' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when workflow has top-level permissions block' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-WorkflowPermission -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when workflow lacks top-level permissions block' {
        $wf = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-WorkflowPermission -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].AttackMapping | Should -Contain 'tj-actions-shai-hulud'
    }

    It 'does not confuse job-level permissions for top-level' {
        $wf = @([PSCustomObject]@{
            Name    = 'deploy.yml'
            Path    = '.github/workflows/deploy.yml'
            Content = @'
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-WorkflowPermission -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
    }
}

Describe 'Invoke-Fylgyr' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    BeforeEach {
        # Stub repo-level checks so tests that only care about workflow results
        # are not affected by live API calls using fake tokens.
        $stubResult = [PSCustomObject]@{
            CheckName     = 'Stub'
            Status        = 'Pass'
            Severity      = 'Info'
            Resource      = 'test/repo'
            Detail        = 'Stubbed.'
            Remediation   = 'None.'
            AttackMapping = @()
            Target        = 'test/repo'
        }
        Mock -ModuleName Fylgyr Test-BranchProtection     { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-SecretScanning       { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-DependabotAlert      { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-CodeScanning         { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-CodeOwner            { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-SignedCommit         { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-EnvironmentProtection { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-RepoVisibility       { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-ForkSecretExposure   { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-GitHubAppSecurity    { return @($stubResult) }
    }

    It 'returns an Error result when workflow fetch fails' {
        Mock -ModuleName Fylgyr Get-WorkflowFile { throw 'API error' }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $workflowError = $results | Where-Object { $_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Error' }
        $workflowError | Should -HaveCount 1
    }

    It 'returns a Warning when no workflow files found' {
        Mock -ModuleName Fylgyr Get-WorkflowFile { return @() }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $workflowWarning = $results | Where-Object { $_.CheckName -eq 'WorkflowFileFetch' -and $_.Status -eq 'Warning' }
        $workflowWarning | Should -HaveCount 1
    }

    It 'orchestrates all checks and returns combined results' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $results.Count | Should -BeGreaterOrEqual 3

        $checkNames = $results | ForEach-Object { $_.CheckName } | Sort-Object -Unique
        $checkNames | Should -Contain 'ActionPinning'
        $checkNames | Should -Contain 'DangerousTrigger'
        $checkNames | Should -Contain 'WorkflowPermission'
    }

    It 'processes multiple repos via pipeline input' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }

        $results = @(
            [PSCustomObject]@{ Owner = 'org1'; Repo = 'repoA' }
            [PSCustomObject]@{ Owner = 'org1'; Repo = 'repoB' }
        ) | Invoke-Fylgyr -Token 'fake-token'

        $results.Count | Should -BeGreaterOrEqual 6
    }

    It 'handles mixed success and failure across pipeline items' {
        $script:mockCallCount = 0
        Mock -ModuleName Fylgyr Get-WorkflowFile {
            $script:mockCallCount++
            if ($script:mockCallCount -eq 1) {
                throw 'API error'
            }
            return @([PSCustomObject]@{
                Name    = 'ci.yml'
                Path    = '.github/workflows/ci.yml'
                Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
            })
        }

        $results = @(
            [PSCustomObject]@{ Owner = 'org1'; Repo = 'repoA' }
            [PSCustomObject]@{ Owner = 'org1'; Repo = 'repoB' }
        ) | Invoke-Fylgyr -Token 'fake-token'

        $errorResults = $results | Where-Object { $_.Status -eq 'Error' -and $_.CheckName -eq 'WorkflowFileFetch' }
        $errorResults | Should -HaveCount 1

        $checkResults = $results | Where-Object { $_.CheckName -ne 'WorkflowFileFetch' }
        $checkResults.Count | Should -BeGreaterOrEqual 3
    }

    It 'captures a check error without stopping other checks' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = @'
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning { throw 'unexpected error' }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'

        $errorResult = $results | Where-Object { $_.CheckName -eq 'Test-ActionPinning' -and $_.Status -eq 'Error' }
        $errorResult | Should -HaveCount 1

        # Other checks should still have run
        $otherChecks = $results | Where-Object { $_.CheckName -ne 'Test-ActionPinning' }
        $otherChecks.Count | Should -BeGreaterOrEqual 2
    }
}

Describe 'Test-EgressControl' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'warns when no egress controls are present' {
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
      - run: npm test
'@
        })

        $results = Test-EgressControl -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Severity | Should -Be 'Medium'
        $results[0].AttackMapping | Should -Contain 'tj-actions-shai-hulud'
    }

    It 'passes when harden-runner is present with block policy' {
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
      - uses: step-security/harden-runner@abc123abc123abc123abc123abc123abc123abc1
        with:
          egress-policy: block
          allowed-endpoints: >
            github.com:443
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-EgressControl -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'reports info when egress is audit-only' {
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
      - uses: step-security/harden-runner@abc123abc123abc123abc123abc123abc123abc1
        with:
          egress-policy: audit
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-EgressControl -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Info'
    }

    It 'detects network calls without egress controls' {
        $wf = @([PSCustomObject]@{
            Name    = 'deploy.yml'
            Path    = '.github/workflows/deploy.yml'
            Content = @'
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: curl -s https://example.com/script.sh | bash
'@
        })

        $results = Test-EgressControl -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
        $results[0].Detail | Should -BeLike '*network calls*'
    }

    It 'notes BullFrog DNS bypass' {
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
      - uses: bullfrogsec/bullfrog@abc123abc123abc123abc123abc123abc123abc1
        with:
          egress-policy: block
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-EgressControl -WorkflowFiles $wf
        $results | Should -HaveCount 1
        $results[0].Detail | Should -BeLike '*BullFrog*DNS*bypass*'
    }
}

Describe 'Test-ForkSecretExposure' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when no pull_request_target workflows reference secrets' {
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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') {
                return [PSCustomObject]@{ environments = @() }
            }
            if ($Endpoint -match 'actions/secrets') {
                return [PSCustomObject]@{ secrets = @() }
            }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $pass = $results | Where-Object Status -EQ 'Pass'
        $pass | Should -Not -BeNullOrEmpty
    }

    It 'fails when pull_request_target workflow references secrets' {
        $wf = @([PSCustomObject]@{
            Name    = 'pr-target.yml'
            Path    = '.github/workflows/pr-target.yml'
            Content = @'
name: PR Target
on:
  pull_request_target:
    types: [opened]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: echo ${{ secrets.DEPLOY_KEY }}
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') {
                return [PSCustomObject]@{ environments = @() }
            }
            if ($Endpoint -match 'actions/secrets') {
                return [PSCustomObject]@{ secrets = @() }
            }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'Critical'
        $fail[0].AttackMapping | Should -Contain 'prt-scan-ai-automated'
    }

    It 'ignores GITHUB_TOKEN in secret references' {
        $wf = @([PSCustomObject]@{
            Name    = 'label.yml'
            Path    = '.github/workflows/label.yml'
            Content = @'
name: Label
on:
  pull_request_target:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@b4ffde65f46336ab88eb53be808477a3936bae11
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') {
                return [PSCustomObject]@{ environments = @() }
            }
            if ($Endpoint -match 'actions/secrets') {
                return [PSCustomObject]@{ secrets = @() }
            }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        # Should not flag GITHUB_TOKEN as a secret exposure
        $fail = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Detail -like '*GITHUB_TOKEN*' }
        $fail | Should -BeNullOrEmpty
    }

    It 'flags unprotected environments' {
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

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') {
                return [PSCustomObject]@{
                    environments = @(
                        [PSCustomObject]@{
                            name = 'production'
                            protection_rules = @()
                        }
                    )
                }
            }
            if ($Endpoint -match 'actions/secrets') {
                return [PSCustomObject]@{ secrets = @() }
            }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Detail -like '*production*' }
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'High'
    }
}

Describe 'Test-DangerousTrigger secrets detection' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'detects pull_request_target with secrets reference' {
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
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@b4ffde65f46336ab88eb53be808477a3936bae11
        env:
          API_KEY: ${{ secrets.API_KEY }}
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'High'
        $fail[0].Detail | Should -BeLike '*secrets*'
    }

    It 'detects actor-restriction patterns' {
        $wf = @([PSCustomObject]@{
            Name    = 'restricted.yml'
            Path    = '.github/workflows/restricted.yml'
            Content = @'
name: Restricted
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    if: github.actor != 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
'@
        })

        $results = Test-DangerousTrigger -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        # Should mention actor restriction was detected
        $fail[0].Detail | Should -Not -BeLike '*No actor-restriction*'
    }
}

Describe 'Test-RunnerHygiene expanded' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'maps self-hosted runners to praetorian-runner-pivot attack' {
        $wf = @([PSCustomObject]@{
            Name    = 'build.yml'
            Path    = '.github/workflows/build.yml'
            Content = @'
name: Build
on: push
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $warning = $results | Where-Object Status -EQ 'Warning'
        $warning | Should -Not -BeNullOrEmpty
        $warning[0].AttackMapping | Should -Contain 'praetorian-runner-pivot'
    }

    It 'includes praetorian mapping for dangerous trigger + self-hosted' {
        $wf = @([PSCustomObject]@{
            Name    = 'pr.yml'
            Path    = '.github/workflows/pr.yml'
            Content = @'
name: PR
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-RunnerHygiene -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].AttackMapping | Should -Contain 'praetorian-runner-pivot'
        $fail[0].AttackMapping | Should -Contain 'github-actions-cryptomining'
    }
}

Describe 'Test-CodeOwner' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'fails when no CODEOWNERS file exists' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            $err = [System.Net.WebException]::new('404 Not Found')
            throw $err
        }

        $results = Test-CodeOwner -Owner 'org' -Repo 'repo' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].AttackMapping | Should -Contain 'xz-utils-backdoor'
    }

    It 'fails when catch-all is assigned to a single owner' {
        $codeowners = "* @single-user`n"
        $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($codeowners))

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match '/contents/CODEOWNERS$') {
                return [PSCustomObject]@{ content = $b64; encoding = 'base64' }
            }
            throw '404 Not Found'
        }

        $results = Test-CodeOwner -Owner 'org' -Repo 'repo' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        ($fail.Detail -join ' ') | Should -Match 'single owner|distinct owner'
    }

    It 'passes when CODEOWNERS has multiple distinct owners and no single-owner catch-all' {
        $codeowners = "# ownership`n* @org/security @org/maintainers`n/src/ @alice @bob`n"
        $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($codeowners))

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match '/contents/CODEOWNERS$') {
                return [PSCustomObject]@{ content = $b64; encoding = 'base64' }
            }
            throw '404 Not Found'
        }

        $results = Test-CodeOwner -Owner 'org' -Repo 'repo' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }

    It 'downgrades single-owner findings to Warning for personal (User) accounts' {
        $codeowners = "* @pthoor`n"
        $b64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($codeowners))

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/pthoor') {
                return [PSCustomObject]@{ type = 'User' }
            }
            if ($Endpoint -match '/contents/CODEOWNERS$') {
                return [PSCustomObject]@{ content = $b64; encoding = 'base64' }
            }
            throw '404 Not Found'
        }

        $results = Test-CodeOwner -Owner 'pthoor' -Repo 'repo' -Token 'fake'
        $results | Where-Object Status -EQ 'Fail' | Should -BeNullOrEmpty
        $warn = $results | Where-Object Status -EQ 'Warning'
        $warn | Should -Not -BeNullOrEmpty
        ($warn.Detail -join ' ') | Should -Match 'personal GitHub account'
    }
}

Describe 'Test-SignedCommit' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'warns when required signatures is disabled (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/org/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            throw '404 Not Found'
        }

        $results = Test-SignedCommit -Owner 'org' -Repo 'repo' -Token 'fake'
        $warn = $results | Where-Object Status -EQ 'Warning'
        $warn | Should -Not -BeNullOrEmpty
        $warn[0].Severity | Should -Be 'Medium'
        $warn[0].AttackMapping | Should -Contain 'xz-utils-backdoor'
    }

    It 'passes when required signatures is enabled' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/org/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }
            if ($Endpoint -match 'required_signatures$') {
                return [PSCustomObject]@{ enabled = $true }
            }
            throw '404 Not Found'
        }

        $results = Test-SignedCommit -Owner 'org' -Repo 'repo' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }
}

Describe 'Test-ForkPullPolicy' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'fails on pull_request_target with checkout of head.sha' {
        $wf = @([PSCustomObject]@{
            Name    = 'prt.yml'
            Path    = '.github/workflows/prt.yml'
            Content = @'
name: PRT
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.event.pull_request.head.sha }}
'@
        })

        $results = Test-ForkPullPolicy -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
        $fail[0].Severity | Should -Be 'High'
        $fail[0].AttackMapping | Should -Contain 'nx-pwn-request'
        $fail[0].AttackMapping | Should -Contain 'tj-actions-shai-hulud'
    }

    It 'fails on pull_request_target with github.head_ref checkout' {
        $wf = @([PSCustomObject]@{
            Name    = 'prt.yml'
            Path    = '.github/workflows/prt.yml'
            Content = @'
name: PRT
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with:
          ref: ${{ github.head_ref }}
'@
        })

        $results = Test-ForkPullPolicy -WorkflowFiles $wf
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
    }

    It 'passes on pull_request_target without checkout of fork ref' {
        $wf = @([PSCustomObject]@{
            Name    = 'prt.yml'
            Path    = '.github/workflows/prt.yml'
            Content = @'
name: PRT
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
'@
        })

        $results = Test-ForkPullPolicy -WorkflowFiles $wf
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when workflow does not use pull_request_target' {
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
      - run: echo ok
'@
        })

        $results = Test-ForkPullPolicy -WorkflowFiles $wf
        $results[0].Status | Should -Be 'Pass'
    }
}

Describe 'Test-EnvironmentProtection' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'fails when an environment has no required reviewers' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                environments = @(
                    [PSCustomObject]@{
                        name             = 'production'
                        protection_rules = @()
                    }
                )
            }
        }

        $results = Test-EnvironmentProtection -Owner 'org' -Repo 'repo' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'High'
        $fail[0].AttackMapping | Should -Contain 'unauthorized-env-deployment'
    }

    It 'passes when all environments have required reviewers and branch policies' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                environments = @(
                    [PSCustomObject]@{
                        name             = 'production'
                        protection_rules = @(
                            [PSCustomObject]@{
                                type      = 'required_reviewers'
                                reviewers = @([PSCustomObject]@{ type = 'User' })
                            }
                        )
                        deployment_branch_policy = [PSCustomObject]@{ protected_branches = $true }
                    }
                )
            }
        }

        $results = Test-EnvironmentProtection -Owner 'org' -Repo 'repo' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when no environments exist (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

        $results = Test-EnvironmentProtection -Owner 'org' -Repo 'repo' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }
}

Describe 'Test-RepoVisibility' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'fails when public repo name matches internal naming pattern' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                visibility = 'public'
                private    = $false
            }
        }

        $results = Test-RepoVisibility -Owner 'org' -Repo 'platform-internal' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].AttackMapping | Should -Contain 'toyota-source-exposure'
    }

    It 'passes when public repo has no internal naming marker' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                visibility = 'public'
                private    = $false
            }
        }

        $results = Test-RepoVisibility -Owner 'org' -Repo 'open-source-tool' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when private repo matches internal marker' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                visibility = 'private'
                private    = $true
            }
        }

        $results = Test-RepoVisibility -Owner 'org' -Repo 'core-internal' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }
}

Describe 'Test-GitHubAppSecurity user accounts' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'audits personal account when token owner matches' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/alice')      { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
            if ($Endpoint -eq 'user')             { return [PSCustomObject]@{ login = 'alice' } }
            if ($Endpoint -eq 'user/installations') {
                return [PSCustomObject]@{
                    installations = @(
                        [PSCustomObject]@{
                            id                   = 1
                            app_slug             = 'dangerous-app'
                            repository_selection = 'all'
                            permissions          = [PSCustomObject]@{
                                contents = 'write'
                                actions  = 'write'
                            }
                        }
                    )
                }
            }
            throw '404 Not Found'
        }

        $results = Test-GitHubAppSecurity -Owner 'alice' -Token 'fake'
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'Critical'
        $fail[0].Detail | Should -Match 'across all of your repositories'
    }

    It 'returns Info when token does not belong to the user owner' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/alice') { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
            if ($Endpoint -eq 'user')        { return [PSCustomObject]@{ login = 'bob' } }
            throw 'should not be called'
        }

        $results = Test-GitHubAppSecurity -Owner 'alice' -Token 'fake'
        $info = $results | Where-Object Status -EQ 'Info'
        $info | Should -Not -BeNullOrEmpty
        $info[0].Detail | Should -Match 'personal GitHub account'
    }

    It 'passes on a user account with no installations' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/alice')         { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
            if ($Endpoint -eq 'user')                { return [PSCustomObject]@{ login = 'alice' } }
            if ($Endpoint -eq 'user/installations')  { return [PSCustomObject]@{ installations = @() } }
            throw '404 Not Found'
        }

        $results = Test-GitHubAppSecurity -Owner 'alice' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
        $results[0].Detail | Should -Match 'user account'
    }

    It 'still audits organizations via the org endpoint' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/acme')         { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
            if ($Endpoint -eq 'orgs/acme/installations') {
                return [PSCustomObject]@{
                    installations = @(
                        [PSCustomObject]@{
                            id                   = 1
                            app_slug             = 'safe-app'
                            repository_selection = 'selected'
                            permissions          = [PSCustomObject]@{ contents = 'read' }
                        }
                    )
                }
            }
            throw 'unexpected endpoint'
        }

        $results = Test-GitHubAppSecurity -Owner 'acme' -Token 'fake'
        $results[0].Status | Should -Be 'Pass'
    }
}
