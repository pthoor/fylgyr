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

    It 'has attacks.json with owaspCiCd and mitre fields populated for every entry' {
        $attacks = Get-Content -Path $attacksPath -Raw | ConvertFrom-Json

        foreach ($attack in $attacks) {
            $attack.PSObject.Properties.Name | Should -Contain 'owaspCiCd' -Because "entry '$($attack.id)' is missing owaspCiCd"
            $attack.PSObject.Properties.Name | Should -Contain 'mitre' -Because "entry '$($attack.id)' is missing mitre"
            $attack.owaspCiCd | Should -Not -BeNullOrEmpty -Because "entry '$($attack.id)' has empty owaspCiCd"
            $attack.mitre | Should -Not -BeNullOrEmpty -Because "entry '$($attack.id)' has empty mitre"
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
        $fail[0].AttackMapping | Should -Contain 'actions-cool-issues-helper-compromise'
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

    It 'flags an unpinned uses inside a composite action.yml' {
        $action = @([PSCustomObject]@{
            Name    = 'action.yml'
            Path    = '.github/actions/build/action.yml'
            Content = @'
name: build
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
'@
        })

        $results = Test-ActionPinning -WorkflowFiles @() -ActionFiles $action
        $fail = $results | Where-Object Status -EQ 'Fail'
        $fail | Should -HaveCount 1
        $fail[0].Detail | Should -BeLike '*composite action file*actions/checkout@v4*'
        $fail[0].Resource | Should -BeLike '.github/actions/build/action.yml:*'
    }

    It 'passes a SHA-pinned composite action.yml' {
        $action = @([PSCustomObject]@{
            Name    = 'action.yml'
            Path    = 'action.yml'
            Content = @'
name: build
runs:
  using: composite
  steps:
    - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
'@
        })

        $results = Test-ActionPinning -WorkflowFiles @() -ActionFiles $action
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }
}

Describe 'Get-ActionDefinitionFile' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'selects action.yml/action.yaml blobs and decodes their content' {
        InModuleScope Fylgyr {
            Mock Get-RepoTree {
                return [PSCustomObject]@{
                    tree = @(
                        [PSCustomObject]@{ path = 'action.yml'; type = 'blob'; sha = 'aaa' }
                        [PSCustomObject]@{ path = '.github/actions/foo/action.yaml'; type = 'blob'; sha = 'bbb' }
                        [PSCustomObject]@{ path = 'docs/action.yml.bak'; type = 'blob'; sha = 'ccc' }
                        [PSCustomObject]@{ path = 'src'; type = 'tree'; sha = 'ddd' }
                    )
                }
            }
            Mock Invoke-GitHubApi {
                param($Endpoint)
                $body = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('name: x'))
                return [PSCustomObject]@{ content = $body }
            }

            $files = Get-ActionDefinitionFile -Owner 'o' -Repo 'r' -Token 't'
            @($files).Count | Should -Be 2
            ($files.Path | Sort-Object) | Should -Be @('.github/actions/foo/action.yaml', 'action.yml')
            $files[0].Content | Should -Be 'name: x'
        }
    }

    It 'returns empty when the repo has no action definition files' {
        InModuleScope Fylgyr {
            Mock Get-RepoTree { return [PSCustomObject]@{ tree = @([PSCustomObject]@{ path = 'README.md'; type = 'blob'; sha = 'aaa' }) } }
            $files = Get-ActionDefinitionFile -Owner 'o' -Repo 'r' -Token 't'
            @($files).Count | Should -Be 0
        }
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

    It 'emits one could-not-verify advisory when the approval policy read is forbidden (403)' {
        $wf = @([PSCustomObject]@{
            Name    = 'a.yml'
            Path    = '.github/workflows/a.yml'
            Content = "name: A`non: pull_request_target`njobs:`n  x:`n    runs-on: ubuntu-latest`n    steps:`n      - run: echo hi"
        }, [PSCustomObject]@{
            Name    = 'b.yml'
            Path    = '.github/workflows/b.yml'
            Content = "name: B`non: pull_request_target`njobs:`n  y:`n    runs-on: ubuntu-latest`n    steps:`n      - run: echo hi"
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

        $results = Test-DangerousTrigger -WorkflowFiles $wf -Owner 'o' -Repo 'r' -Token 't'
        $notVerified = $results | Where-Object { $_.Detail -like '*Could not verify*' }
        $notVerified | Should -HaveCount 1
        $notVerified[0].Severity | Should -Be 'Low'
        $notVerified[0].Resource | Should -Be 'o/r'
    }

    It 'emits the missing-gate advisory (not could-not-verify) on a 404' {
        $wf = @([PSCustomObject]@{
            Name    = 'a.yml'
            Path    = '.github/workflows/a.yml'
            Content = "name: A`non: pull_request_target`njobs:`n  x:`n    runs-on: ubuntu-latest`n    steps:`n      - run: echo hi"
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '404 Not Found' }

        $results = Test-DangerousTrigger -WorkflowFiles $wf -Owner 'o' -Repo 'r' -Token 't'
        ($results | Where-Object { $_.Detail -like '*Could not verify*' }) | Should -BeNullOrEmpty
        ($results | Where-Object { $_.Detail -like '*first-time contributor approval*' }) | Should -Not -BeNullOrEmpty
    }

    It 'does not emit could-not-verify when no pull_request_target workflow is present' {
        $wf = @([PSCustomObject]@{
            Name    = 'a.yml'
            Path    = '.github/workflows/a.yml'
            Content = "name: A`non: push`njobs:`n  x:`n    runs-on: ubuntu-latest`n    steps:`n      - run: echo hi"
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw '403 Forbidden' }

        $results = Test-DangerousTrigger -WorkflowFiles $wf -Owner 'o' -Repo 'r' -Token 't'
        ($results | Where-Object { $_.Detail -like '*Could not verify*' }) | Should -BeNullOrEmpty
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
        Mock -ModuleName Fylgyr Test-Rulesets             { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-WebhookSecurity      { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-BinaryArtifact       { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-PrivateVulnReporting { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-DefaultTokenPermission { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-DeployKey            { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-TagProtection        { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-AccountSecurity      { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-AccountKey           { return @($stubResult) }
        # Isolate composite action.yml fetching from the network for orchestration tests.
        Mock -ModuleName Fylgyr Get-ActionDefinitionFile  { return @() }
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

    It 'marks matching findings as Suppressed when BaselinePath is provided' {
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
      - uses: actions/checkout@v4
'@
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'Unpinned action reference: actions/checkout@v4'
                    Remediation   = 'Pin to a full SHA.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }

        $baseline = [PSCustomObject]@{
            results = @(
                [PSCustomObject]@{
                    CheckName = 'ActionPinning'
                    Status = 'Fail'
                    Severity = 'High'
                    Resource = '.github/workflows/ci.yml'
                    Detail = 'Unpinned action reference: actions/checkout@v4'
                    Remediation = 'Pin to a full SHA.'
                }
            )
        }

        $baselineFile = New-TemporaryFile
        $baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineFile.FullName

        try {
            $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -BaselinePath $baselineFile.FullName
        }
        finally {
            Remove-Item -Path $baselineFile.FullName -ErrorAction SilentlyContinue
        }

        $suppressed = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $suppressed | Should -Not -BeNullOrEmpty
        $suppressed[0].Status | Should -Be 'Suppressed'
    }

    It 'does not suppress Error findings when BaselinePath is provided' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Error'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'ActionPinning check failed.'
                    Remediation   = 'Fix check execution.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }

        $baseline = [PSCustomObject]@{
            results = @(
                [PSCustomObject]@{
                    CheckName = 'ActionPinning'
                    Status = 'Error'
                    Severity = 'High'
                    Resource = '.github/workflows/ci.yml'
                    Detail = 'ActionPinning check failed.'
                    Remediation = 'Fix check execution.'
                }
            )
        }

        $baselineFile = New-TemporaryFile
        $baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineFile.FullName

        try {
            $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -BaselinePath $baselineFile.FullName
        }
        finally {
            Remove-Item -Path $baselineFile.FullName -ErrorAction SilentlyContinue
        }

        $finding = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $finding | Should -Not -BeNullOrEmpty
        $finding[0].Status | Should -Be 'Error'
    }

    It 'returns BaselineDiff error result when BaselinePath is invalid' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -BaselinePath '/tmp/does-not-exist-baseline.json'
        $baselineError = $results | Where-Object { $_.CheckName -eq 'BaselineDiff' }
        $baselineError | Should -Not -BeNullOrEmpty
        $baselineError[0].Status | Should -Be 'Error'
    }

    It 'suppresses matching findings from config suppression rules' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'Unpinned action reference.'
                    Remediation   = 'Pin action.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{
                Rules = @(
                    [PSCustomObject]@{
                        Check = 'ActionPinning'
                        Resource = '.github/workflows/ci.yml'
                        Reason = 'Accepted temporary risk'
                        ExpiresUtc = $null
                    }
                )
                Diagnostics = @()
            }
        }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $suppressed = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $suppressed | Should -Not -BeNullOrEmpty
        $suppressed[0].Status | Should -Be 'Suppressed'
        $suppressed[0].Detail | Should -BeLike '*Suppressed by .fylgyr.yml*'
    }

    It 'keeps findings active and adds expiry note when suppression is expired' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'Unpinned action reference.'
                    Remediation   = 'Pin action.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{
                Rules = @(
                    [PSCustomObject]@{
                        Check = 'ActionPinning'
                        Resource = '.github/workflows/ci.yml'
                        Reason = 'Legacy exception'
                        ExpiresUtc = [datetime]::UtcNow.AddDays(-2)
                    }
                )
                Diagnostics = @()
            }
        }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $finding = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $finding | Should -Not -BeNullOrEmpty
        $finding[0].Status | Should -Be 'Fail'
        $finding[0].Detail | Should -BeLike '*Suppression expired on*'
    }

    It 'does not suppress when config suppression target does not match finding target' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'Unpinned action reference.'
                    Remediation   = 'Pin action.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{
                Rules = @(
                    [PSCustomObject]@{
                        Check = 'ActionPinning'
                        Resource = '.github/workflows/ci.yml'
                        Reason = 'Accepted temporary risk'
                        ExpiresUtc = $null
                        Target = 'other/repo'
                    }
                )
                Diagnostics = @()
            }
        }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $finding = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $finding | Should -Not -BeNullOrEmpty
        $finding[0].Status | Should -Be 'Fail'
    }

    It 'surfaces config diagnostics as ConfigSuppression results' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{
                Rules = @()
                Diagnostics = @(
                    [PSCustomObject]@{
                        Status = 'Warning'
                        Severity = 'Low'
                        Detail = 'Invalid suppression entry.'
                        Remediation = 'Fix config.'
                    }
                )
            }
        }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $configResult = $results | Where-Object { $_.CheckName -eq 'ConfigSuppression' }
        $configResult | Should -Not -BeNullOrEmpty
        $configResult[0].Status | Should -Be 'Warning'
    }

    It 'skips config suppressions when IgnoreConfig is set' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-ActionPinning {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'ActionPinning'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = '.github/workflows/ci.yml'
                    Detail        = 'Unpinned action reference.'
                    Remediation   = 'Pin action.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{
                Rules = @(
                    [PSCustomObject]@{
                        Check = 'ActionPinning'
                        Resource = '.github/workflows/ci.yml'
                        Reason = 'Accepted temporary risk'
                        ExpiresUtc = $null
                    }
                )
                Diagnostics = @()
            }
        } -ParameterFilter { -not $IgnoreConfig }
        Mock -ModuleName Fylgyr Get-FylgyrConfigSuppression {
            return [PSCustomObject]@{ Rules = @(); Diagnostics = @() }
        } -ParameterFilter { $IgnoreConfig }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -IgnoreConfig
        $finding = $results | Where-Object { $_.CheckName -eq 'ActionPinning' }
        $finding | Should -Not -BeNullOrEmpty
        $finding[0].Status | Should -Be 'Fail'
    }

    It 'calls Add-FylgyrEvidence when IncludeEvidence is set' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Add-FylgyrEvidence {
            param($Results)
            return $Results
        }

        $null = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -IncludeEvidence
        Assert-MockCalled -ModuleName Fylgyr Add-FylgyrEvidence -Times 1
    }

    It 'sets LASTEXITCODE to 1 when FailOn threshold is met' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-BranchProtection {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'BranchProtection'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = 'test/repo (branch: main)'
                    Detail        = 'Branch protection missing.'
                    Remediation   = 'Enable branch protection.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }

        $global:LASTEXITCODE = 0
        $null = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -FailOn High
        $global:LASTEXITCODE | Should -Be 1
    }

    It 'sets LASTEXITCODE to 0 when findings are below FailOn threshold' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: push"
        })

        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }
        Mock -ModuleName Fylgyr Test-BranchProtection {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'BranchProtection'
                    Status        = 'Fail'
                    Severity      = 'High'
                    Resource      = 'test/repo (branch: main)'
                    Detail        = 'Branch protection missing.'
                    Remediation   = 'Enable branch protection.'
                    AttackMapping = @()
                    Target        = ''
                }
            )
        }

        $global:LASTEXITCODE = 1
        $null = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -FailOn Critical
        $global:LASTEXITCODE | Should -Be 0
    }

    It 'returns ChangedOnly error when Repo is not provided' {
        $results = Invoke-Fylgyr -Owner 'acme' -Token 'fake-token' -ChangedOnly
        $changedOnlyError = $results | Where-Object { $_.CheckName -eq 'ChangedOnly' }
        $changedOnlyError | Should -Not -BeNullOrEmpty
        $changedOnlyError[0].Status | Should -Be 'Error'
    }

    It 'skips repo-level checks in ChangedOnly mode' {
        $fakeWorkflows = @(
            [PSCustomObject]@{
                Name    = 'ci.yml'
                Path    = '.github/workflows/ci.yml'
                Content = "name: CI`non: pull_request"
            },
            [PSCustomObject]@{
                Name    = 'release.yml'
                Path    = '.github/workflows/release.yml'
                Content = "name: Release`non: push"
            }
        )

        Mock -ModuleName Fylgyr Get-FylgyrChangedWorkflowPath { return @('.github/workflows/ci.yml') }
        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -ChangedOnly -SinceRef origin/main

        Assert-MockCalled -ModuleName Fylgyr Test-BranchProtection -Times 0
        ($results | Where-Object { $_.CheckName -eq 'ChangedOnly' -and $_.Status -eq 'Error' }) | Should -BeNullOrEmpty
    }

    It 'returns ChangedOnly info when no changed workflow files are detected' {
        $fakeWorkflows = @([PSCustomObject]@{
            Name    = 'ci.yml'
            Path    = '.github/workflows/ci.yml'
            Content = "name: CI`non: pull_request"
        })

        Mock -ModuleName Fylgyr Get-FylgyrChangedWorkflowPath { return @() }
        Mock -ModuleName Fylgyr Get-WorkflowFile { return $fakeWorkflows }

        $results = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -ChangedOnly -SinceRef origin/main
        $changedOnlyInfo = $results | Where-Object { $_.CheckName -eq 'ChangedOnly' }
        $changedOnlyInfo | Should -Not -BeNullOrEmpty
        $changedOnlyInfo[0].Status | Should -Be 'Info'
        $changedOnlyInfo[0].Target | Should -Be 'test/repo'
    }

    It 'rejects ChangedOnly SinceRef values that start with a dash' {
        {
            Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -ChangedOnly -SinceRef '--help'
        } | Should -Throw
    }

    It 'runs org checks once when IncludeOrgChecks is used without Repo' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'orgs/acme/repos?per_page=100') {
                return @([PSCustomObject]@{ name = 'repo1' })
            }
            throw 'unexpected endpoint'
        }
        Mock -ModuleName Fylgyr Get-WorkflowFile {
            return @([PSCustomObject]@{ Name = 'ci.yml'; Path = '.github/workflows/ci.yml'; Content = "name: CI`non: push" })
        }
        Mock -ModuleName Fylgyr Invoke-FylgyrOrgScan {
            return @(
                [PSCustomObject]@{
                    CheckName     = 'OrgMfaPolicy'
                    Status        = 'Pass'
                    Severity      = 'Info'
                    Resource      = 'org/acme'
                    Detail        = 'ok'
                    Remediation   = 'none'
                    AttackMapping = @()
                    Target        = 'org/acme'
                }
            )
        }

        $results = Invoke-Fylgyr -Owner 'acme' -Token 'fake-token' -IncludeOrgChecks -ThrottleLimit 1
        ($results | Where-Object CheckName -EQ 'OrgMfaPolicy') | Should -Not -BeNullOrEmpty
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrOrgScan -Times 1
    }

    It 'does not run org checks when Repo is specified even with IncludeOrgChecks' {
        Mock -ModuleName Fylgyr Get-WorkflowFile {
            return @([PSCustomObject]@{ Name = 'ci.yml'; Path = '.github/workflows/ci.yml'; Content = "name: CI`non: push" })
        }
        Mock -ModuleName Fylgyr Invoke-FylgyrOrgScan { throw 'should not be called' }

        $null = Invoke-Fylgyr -Owner 'acme' -Repo 'repo1' -Token 'fake-token' -IncludeOrgChecks
        Assert-MockCalled -ModuleName Fylgyr Invoke-FylgyrOrgScan -Times 0
    }

    It 'normalizes org-check names when Invoke-FylgyrOrgScan records check errors' {
        Mock -ModuleName Fylgyr Test-OrgMfaPolicy { throw 'boom' }
        Mock -ModuleName Fylgyr Test-OrgDefaultPermissions { return @() }
        Mock -ModuleName Fylgyr Test-IpAllowlist { return @() }
        Mock -ModuleName Fylgyr Test-AuditLogStreaming { return @() }
        Mock -ModuleName Fylgyr Test-OAuthAppPolicy { return @() }
        Mock -ModuleName Fylgyr Test-OrgActionRestrictions { return @() }
        Mock -ModuleName Fylgyr Test-OutsideCollaborators { return @() }
        Mock -ModuleName Fylgyr Test-PatPolicy { return @() }
        Mock -ModuleName Fylgyr Test-GitHubAppSecurity { return @() }
        Mock -ModuleName Fylgyr Test-Rulesets { return @() }
        Mock -ModuleName Fylgyr Test-DefaultTokenPermission { return @() }
        Mock -ModuleName Fylgyr Test-OrgSecretVisibility { return @() }

        $results = InModuleScope Fylgyr {
            Invoke-FylgyrOrgScan -Owner 'acme' -Token 'fake-token'
        }

        $errorResult = $results | Where-Object { $_.Status -eq 'Error' } | Select-Object -First 1
        $errorResult | Should -Not -BeNullOrEmpty
        $errorResult.CheckName | Should -Be 'OrgMfaPolicy'
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

Describe 'Get-FylgyrOrgScanThrottle' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'uses minimum of requested throttle and repo count when rate metadata is unavailable' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi { throw 'rate_limit unavailable' }

        $throttle = InModuleScope Fylgyr {
            Get-FylgyrOrgScanThrottle -RequestedThrottle 5 -RepoTotal 2 -Token 'fake-token'
        }

        $throttle | Should -Be 2
    }

    It 'forces throttle to 1 when rate limit remaining is zero' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                resources = [PSCustomObject]@{
                    core = [PSCustomObject]@{ remaining = 0 }
                }
            }
        }

        $throttle = InModuleScope Fylgyr {
            Get-FylgyrOrgScanThrottle -RequestedThrottle 6 -RepoTotal 6 -Token 'fake-token'
        }

        $throttle | Should -Be 1
    }

    It 'applies conservative clamp based on remaining core budget' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                resources = [PSCustomObject]@{
                    core = [PSCustomObject]@{ remaining = 450 }
                }
            }
        }

        $throttle = InModuleScope Fylgyr {
            Get-FylgyrOrgScanThrottle -RequestedThrottle 8 -RepoTotal 10 -Token 'fake-token'
        }

        $throttle | Should -Be 2
    }

    It 'never exceeds requested throttle when remaining budget is high' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return [PSCustomObject]@{
                resources = [PSCustomObject]@{
                    core = [PSCustomObject]@{ remaining = 5000 }
                }
            }
        }

        $throttle = InModuleScope Fylgyr {
            Get-FylgyrOrgScanThrottle -RequestedThrottle 3 -RepoTotal 20 -Token 'fake-token'
        }

        $throttle | Should -Be 3
    }
}

Describe 'Add-FylgyrEvidence' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'adds commit, permalink and YAML snippet evidence for workflow findings' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'repos/test/repo') {
                return [PSCustomObject]@{ default_branch = 'main' }
            }

            if ($Endpoint -eq 'repos/test/repo/commits/main') {
                return [PSCustomObject]@{ sha = 'abc123abc123abc123abc123abc123abc123abcd' }
            }

            throw 'unexpected endpoint'
        }

        $inputResults = @(
            [PSCustomObject]@{
                CheckName   = 'ActionPinning'
                Status      = 'Fail'
                Severity    = 'High'
                Resource    = '.github/workflows/ci.yml:3'
                Detail      = 'Unpinned action reference.'
                Remediation = 'Pin action.'
                Target      = 'test/repo'
            }
        )

        $workflowFiles = @(
            [PSCustomObject]@{
                Name    = 'ci.yml'
                Path    = '.github/workflows/ci.yml'
                Content = "name: CI`non: push`njobs:`n  build: {}"
            }
        )

        $results = InModuleScope Fylgyr -Parameters @{
            InputResults = $inputResults
            InputWorkflowFiles = $workflowFiles
        } {
            Add-FylgyrEvidence -Results $InputResults -WorkflowFiles $InputWorkflowFiles -Owner 'test' -Repo 'repo' -Token 'fake-token'
        }

        $results[0].Evidence | Should -Not -BeNullOrEmpty
        $results[0].Evidence.CommitSha | Should -Be 'abc123abc123abc123abc123abc123abc123abcd'
        $results[0].Evidence.Permalink | Should -BeLike '*github.com/test/repo/blob/*/.github/workflows/ci.yml#L3'
        $results[0].Evidence.YamlSnippet | Should -Match '0003:'
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
        $results[0].AttackMapping | Should -Contain 'actions-cool-issues-helper-compromise'
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

    It 'flags workflow_run referencing secrets as High' {
        $wf = @([PSCustomObject]@{
            Name    = 'wr.yml'
            Path    = '.github/workflows/wr.yml'
            Content = @'
name: WR
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo ${{ secrets.NPM_TOKEN }}
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') { return [PSCustomObject]@{ environments = @() } }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Detail -like '*workflow_run*' }
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'High'
        $fail[0].AttackMapping | Should -Contain 'artifact-poisoning-workflow-run'
    }

    It 'detects bracket-notation secret references' {
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
      - run: echo ${{ secrets['DEPLOY_KEY'] }}
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') { return [PSCustomObject]@{ environments = @() } }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        $fail = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Detail -like '*DEPLOY_KEY*' }
        $fail | Should -Not -BeNullOrEmpty
        $fail[0].Severity | Should -Be 'Critical'
    }

    It 'does not flag a bracket-notation GITHUB_TOKEN reference' {
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
      - run: echo ${{ secrets['GITHUB_TOKEN'] }}
'@
        })

        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -match 'environments') { return [PSCustomObject]@{ environments = @() } }
            return $null
        }

        $results = Test-ForkSecretExposure -WorkflowFiles $wf -Owner 'test' -Repo 'repo' -Token 'fake-token'
        ($results | Where-Object { $_.Detail -like '*GITHUB_TOKEN*' }) | Should -BeNullOrEmpty
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

Describe 'Test-GitHubAppSecurity org-level behavior' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    BeforeEach {
        InModuleScope Fylgyr {
            $script:FylgyrOwnerContextCache = @{}
        }
    }

    It 'returns Info when owner is a user account' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/alice') { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
            if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'alice' } }
            throw "unexpected endpoint: $Endpoint"
        }

        $results = Test-GitHubAppSecurity -Owner 'alice' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Info'
        $results[0].Detail | Should -Match 'personal account'
    }

    It 'passes when organization has no app installations' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/acme') { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
            if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'auditor' } }
            if ($Endpoint -eq 'orgs/acme') { return [PSCustomObject]@{ plan = [PSCustomObject]@{ name = 'team' } } }
            if ($Endpoint -eq 'orgs/acme/installations') { return [PSCustomObject]@{ installations = @() } }
            throw 'unexpected endpoint'
        }

        $results = Test-GitHubAppSecurity -Owner 'acme' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails Critical when organization_administration:write is granted' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/acme') { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
            if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'auditor' } }
            if ($Endpoint -eq 'orgs/acme') { return [PSCustomObject]@{ plan = [PSCustomObject]@{ name = 'enterprise' } } }
            if ($Endpoint -eq 'orgs/acme/installations') {
                return [PSCustomObject]@{
                    installations = @(
                        [PSCustomObject]@{
                            id                   = 1
                            app_slug             = 'org-admin-app'
                            repository_selection = 'selected'
                            permissions          = [PSCustomObject]@{ organization_administration = 'write' }
                        }
                    )
                }
            }
            throw 'unexpected endpoint'
        }

        $results = Test-GitHubAppSecurity -Owner 'acme' -Token 'fake'
        $critical = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }
        $critical | Should -Not -BeNullOrEmpty
    }

    It 'fails High when app is all-repos with any write permission' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/acme') { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
            if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'auditor' } }
            if ($Endpoint -eq 'orgs/acme') { return [PSCustomObject]@{ plan = [PSCustomObject]@{ name = 'enterprise' } } }
            if ($Endpoint -eq 'orgs/acme/installations') {
                return [PSCustomObject]@{
                    installations = @(
                        [PSCustomObject]@{
                            id                   = 2
                            app_slug             = 'wide-writer'
                            repository_selection = 'all'
                            permissions          = [PSCustomObject]@{ contents = 'write' }
                        }
                    )
                }
            }
            throw 'unexpected endpoint'
        }

        $results = Test-GitHubAppSecurity -Owner 'acme' -Token 'fake'
        $high = $results | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' }
        $high | Should -Not -BeNullOrEmpty
        ($high | Where-Object { $_.Detail -match 'all repositories' }) | Should -Not -BeNullOrEmpty
    }

    It 'returns Error on 403 from installations endpoint' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            param($Endpoint)
            if ($Endpoint -eq 'users/acme') { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
            if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'auditor' } }
            if ($Endpoint -eq 'orgs/acme') { return [PSCustomObject]@{ plan = [PSCustomObject]@{ name = 'team' } } }
            if ($Endpoint -eq 'orgs/acme/installations') { throw '403 Forbidden' }
            throw 'unexpected endpoint'
        }

        $results = Test-GitHubAppSecurity -Owner 'acme' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'

        Assert-MockCalled -ModuleName Fylgyr Invoke-GitHubApi -Times 0 -ParameterFilter {
            $Endpoint -eq 'user/installations'
        }
    }
}

Describe 'Test-WebhookSecurity' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when all hooks have a secret configured' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{
                    config = [PSCustomObject]@{
                        url    = 'https://ci.example.com/hook'
                        secret = 's3cret'
                    }
                }
            )
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when a hook has no secret configured' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @(
                [PSCustomObject]@{
                    config = [PSCustomObject]@{
                        url = 'https://ci.example.com/hook'
                    }
                }
            )
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Low'
        $results[0].AttackMapping | Should -Contain 'codecov-bash-uploader'
    }

    It 'passes when no hooks exist (empty list)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            return @()
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'passes when no hooks exist (404)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            throw '404 Not Found'
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'degrades to Info on 403 (insufficient scope)' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            throw '403 Forbidden'
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Info'
        $results[0].Detail | Should -BeLike '*admin:repo_hook*'
    }

    It 'returns Error on unexpected API failure' {
        Mock -ModuleName Fylgyr Invoke-GitHubApi {
            throw 'connection timeout'
        }

        $results = Test-WebhookSecurity -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
    }
}

Describe 'Test-BinaryArtifact' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'passes when no binary files are present' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            return [PSCustomObject]@{
                truncated = $false
                tree      = @(
                    [PSCustomObject]@{ path = 'src/main.go';      type = 'blob' }
                    [PSCustomObject]@{ path = 'README.md';        type = 'blob' }
                    [PSCustomObject]@{ path = 'src';              type = 'tree' }
                )
            }
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'fails when binary files are present' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            return [PSCustomObject]@{
                truncated = $false
                tree      = @(
                    [PSCustomObject]@{ path = 'src/main.go';       type = 'blob' }
                    [PSCustomObject]@{ path = 'bin/tool.exe';       type = 'blob' }
                    [PSCustomObject]@{ path = 'lib/native.dll';     type = 'blob' }
                )
            }
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Fail'
        $results[0].Severity | Should -Be 'Low'
        $results[0].AttackMapping | Should -Contain 'solarwinds-orion'
        $results[0].Detail | Should -BeLike '*2 binary file*'
    }

    It 'returns Info when tree is truncated' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            return [PSCustomObject]@{
                truncated = $true
                tree      = @(
                    [PSCustomObject]@{ path = 'src/main.go'; type = 'blob' }
                )
            }
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Info'
        $results[0].Detail | Should -BeLike '*truncated*'
    }

    It 'passes when repository is empty' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            return [PSCustomObject]@{ tree = @(); truncated = $false; empty = $true }
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Pass'
    }

    It 'degrades to Error on 403' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            throw '403 Forbidden'
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
        $results[0].Detail | Should -BeLike '*Insufficient permissions*'
    }

    It 'returns Error on unexpected API failure' {
        Mock -ModuleName Fylgyr Get-RepoTree {
            throw 'connection timeout'
        }

        $results = Test-BinaryArtifact -Owner 'org' -Repo 'repo' -Token 'fake'
        $results | Should -HaveCount 1
        $results[0].Status | Should -Be 'Error'
    }
}

Describe 'Get-FylgyrOwnerContext' {
        BeforeAll {
                $repoRoot = Split-Path -Path $PSScriptRoot -Parent
                $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
                Import-Module -Name $modulePath -Force
        }

        BeforeEach {
                InModuleScope Fylgyr {
                        $script:FylgyrOwnerContextCache = @{}
                }
        }

        It 'returns User context when owner is a personal account' {
                Mock -ModuleName Fylgyr Invoke-GitHubApi {
                        param($Endpoint)
                        if ($Endpoint -eq 'users/alice') { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
                        if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'alice'; plan = [PSCustomObject]@{ name = 'Pro' } } }
                        throw 'unexpected endpoint'
                }

                $ctx = InModuleScope Fylgyr {
                        Get-FylgyrOwnerContext -Owner 'alice' -Token 'fake-token'
                }

                $ctx.Type | Should -Be 'User'
                $ctx.Login | Should -Be 'alice'
                $ctx.TokenOwner | Should -Be 'alice'
                $ctx.TokenMatchesOwner | Should -BeTrue
                $ctx.PlanName | Should -Be 'pro'
        }

        It 'returns Organization context when owner is an organization' {
                Mock -ModuleName Fylgyr Invoke-GitHubApi {
                        param($Endpoint)
                        if ($Endpoint -eq 'users/acme') { return [PSCustomObject]@{ type = 'Organization'; login = 'acme' } }
                        if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'auditor' } }
                        if ($Endpoint -eq 'orgs/acme') { return [PSCustomObject]@{ plan = [PSCustomObject]@{ name = 'Enterprise' } } }
                        throw 'unexpected endpoint'
                }

                $ctx = InModuleScope Fylgyr {
                        Get-FylgyrOwnerContext -Owner 'acme' -Token 'fake-token'
                }

                $ctx.Type | Should -Be 'Organization'
                $ctx.Login | Should -Be 'acme'
                $ctx.TokenOwner | Should -Be 'auditor'
                $ctx.TokenMatchesOwner | Should -BeFalse
                $ctx.PlanName | Should -Be 'enterprise'
        }

        It 'returns Unknown context on 404 owner lookup failure' {
                Mock -ModuleName Fylgyr Invoke-GitHubApi {
                        param($Endpoint)
                        if ($Endpoint -eq 'users/missing-owner') { throw '404 Not Found' }
                        throw 'unexpected endpoint'
                }

                $ctx = InModuleScope Fylgyr {
                        Get-FylgyrOwnerContext -Owner 'missing-owner' -Token 'fake-token'
                }

                $ctx.Type | Should -Be 'Unknown'
                $ctx.Login | Should -Be 'missing-owner'
                $ctx.PlanName | Should -Be 'unknown'
                $ctx.TokenOwner | Should -Be 'unknown'
        }

        It 'returns Unknown context on 403 owner lookup failure' {
                Mock -ModuleName Fylgyr Invoke-GitHubApi {
                        param($Endpoint)
                        if ($Endpoint -eq 'users/locked-owner') { throw '403 Forbidden' }
                        throw 'unexpected endpoint'
                }

                $ctx = InModuleScope Fylgyr {
                        Get-FylgyrOwnerContext -Owner 'locked-owner' -Token 'fake-token'
                }

                $ctx.Type | Should -Be 'Unknown'
                $ctx.Login | Should -Be 'locked-owner'
                $ctx.PlanName | Should -Be 'unknown'
        }

        It 'uses cache for repeated owner lookups in the same invocation' {
                Mock -ModuleName Fylgyr Invoke-GitHubApi {
                        param($Endpoint)
                        if ($Endpoint -eq 'users/alice') { return [PSCustomObject]@{ type = 'User'; login = 'alice' } }
                        if ($Endpoint -eq 'user') { return [PSCustomObject]@{ login = 'alice' } }
                        throw 'unexpected endpoint'
                }

                InModuleScope Fylgyr {
                        $null = Get-FylgyrOwnerContext -Owner 'alice' -Token 'fake-token'
                        $null = Get-FylgyrOwnerContext -Owner 'alice' -Token 'fake-token'
                }

                Assert-MockCalled -ModuleName Fylgyr Invoke-GitHubApi -Times 1 -ParameterFilter { $Endpoint -eq 'users/alice' }
                Assert-MockCalled -ModuleName Fylgyr Invoke-GitHubApi -Times 1 -ParameterFilter { $Endpoint -eq 'user' }
        }
}

Describe 'Test-PublishIntegrity' {
        BeforeAll {
                $repoRoot = Split-Path -Path $PSScriptRoot -Parent
                $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
                Import-Module -Name $modulePath -Force
        }

        It 'passes for npm publish with provenance and id-token write' {
                $wf = @([PSCustomObject]@{
                        Name = 'release.yml'
                        Path = '.github/workflows/release.yml'
                        Content = @'
name: Release
on: push
permissions:
    contents: read
    id-token: write
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - run: npm publish --provenance
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results | Should -HaveCount 1
                $results[0].Status | Should -Be 'Pass'
                $results[0].Detail | Should -Match 'OIDC trust hardening'
                $results[0].Detail | Should -Not -Match 'Test-OidcTrust'
        }

        It 'fails for npm publish without provenance when token auth is present' {
                $wf = @([PSCustomObject]@{
                        Name = 'release.yml'
                        Path = '.github/workflows/release.yml'
                        Content = @'
name: Release
on: push
env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - run: npm publish
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results | Should -HaveCount 1
                $results[0].Status | Should -Be 'Fail'
                $results[0].Severity | Should -Be 'High'
                $results[0].AttackMapping | Should -Contain 'shai-hulud-npm-worm'
        }

        It 'passes for PyPI trusted publishing without password' {
                $wf = @([PSCustomObject]@{
                        Name = 'publish-pypi.yml'
                        Path = '.github/workflows/publish-pypi.yml'
                        Content = @'
name: Publish
on: release
permissions:
    id-token: write
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - uses: pypa/gh-action-pypi-publish@release/v1
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results[0].Status | Should -Be 'Pass'
        }

        It 'fails for PyPI publish when password input is used' {
                $wf = @([PSCustomObject]@{
                        Name = 'publish-pypi.yml'
                        Path = '.github/workflows/publish-pypi.yml'
                        Content = @'
name: Publish
on: release
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - uses: pypa/gh-action-pypi-publish@release/v1
                with:
                    password: ${{ secrets.PYPI_API_TOKEN }}
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results[0].Status | Should -Be 'Fail'
        }

        It 'fails when docker push is configured without attestation' {
                $wf = @([PSCustomObject]@{
                        Name = 'container.yml'
                        Path = '.github/workflows/container.yml'
                        Content = @'
name: Container
on: push
jobs:
    build:
        runs-on: ubuntu-latest
        steps:
            - uses: docker/build-push-action@v6
                with:
                    push: true
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results[0].Status | Should -Be 'Fail'
                $results[0].Detail | Should -Match 'docker/build-push-action'
        }

        It 'fails mixed workflows when one publish path lacks integrity controls' {
                $wf = @([PSCustomObject]@{
                        Name = 'mixed.yml'
                        Path = '.github/workflows/mixed.yml'
                        Content = @'
name: Mixed
on: push
permissions:
    id-token: write
jobs:
    publish:
        runs-on: ubuntu-latest
        steps:
            - run: npm publish --provenance
            - uses: docker/build-push-action@v6
                with:
                    push: true
'@
                })

                $results = Test-PublishIntegrity -WorkflowFiles $wf
                $results[0].Status | Should -Be 'Fail'
        }
}
