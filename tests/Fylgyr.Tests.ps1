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
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Critical'
        $results[0].AttackMapping | Should -Contain 'nx-pwn-request'
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
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Critical'
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

    It 'returns an Error result when workflow fetch fails' {
        Mock -ModuleName Fylgyr Get-WorkflowFile { throw 'API error' }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
        $results[0].CheckName | Should -Be 'WorkflowFileFetch'
    }

    It 'returns a Warning when no workflow files found' {
        Mock -ModuleName Fylgyr Get-WorkflowFile { return @() }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Warning'
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
        $checkNames | Should -Contain 'WorkflowPermissions'
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
