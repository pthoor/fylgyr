Describe 'ConvertTo-FylgyrJson' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'produces valid JSON with summary counts' {
        $json = InModuleScope Fylgyr {
            $results = @(
                (Format-FylgyrResult -CheckName 'TestCheck' -Status 'Pass' -Severity 'Info' -Resource 'test' -Detail 'OK' -Remediation 'None.')
                (Format-FylgyrResult -CheckName 'TestCheck' -Status 'Fail' -Severity 'High' -Resource 'test' -Detail 'Bad' -Remediation 'Fix it.')
            )
            ConvertTo-FylgyrJson -Results $results -Target 'org/repo'
        }

        $parsed = $json | ConvertFrom-Json

        $parsed.tool | Should -Be 'Fylgyr'
        $parsed.target | Should -Be 'org/repo'
        $parsed.summary.total | Should -Be 2
        $parsed.summary.pass | Should -Be 1
        $parsed.summary.fail | Should -Be 1
        $parsed.results.Count | Should -Be 2
    }
}

Describe 'ConvertTo-FylgyrSarif' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'produces valid SARIF 2.1.0 structure' {
        $json = InModuleScope Fylgyr {
            $results = @(
                (Format-FylgyrResult -CheckName 'ActionPinning' -Status 'Fail' -Severity 'High' -Resource '.github/workflows/ci.yml:5' -Detail 'Unpinned action' -Remediation 'Pin it.' -AttackMapping @('trivy-tag-poisoning'))
            )
            ConvertTo-FylgyrSarif -Results $results
        }

        $sarif = $json | ConvertFrom-Json

        $sarif.version | Should -Be '2.1.0'
        $sarif.runs.Count | Should -Be 1
        $sarif.runs[0].tool.driver.name | Should -Be 'Fylgyr'
        $sarif.runs[0].results.Count | Should -Be 1
        $sarif.runs[0].results[0].ruleId | Should -Be 'fylgyr/ActionPinning'
        $sarif.runs[0].results[0].level | Should -Be 'error'
    }

    It 'parses resource line numbers into SARIF locations' {
        $json = InModuleScope Fylgyr {
            $results = @(
                (Format-FylgyrResult -CheckName 'Check1' -Status 'Fail' -Severity 'Medium' -Resource '.github/workflows/ci.yml:42' -Detail 'Issue' -Remediation 'Fix.')
            )
            ConvertTo-FylgyrSarif -Results $results
        }

        $sarif = $json | ConvertFrom-Json
        $loc = $sarif.runs[0].results[0].locations[0].physicalLocation
        $loc.artifactLocation.uri | Should -Be '.github/workflows/ci.yml'
        $loc.region.startLine | Should -Be 42
    }

    It 'includes attack tags in properties' {
        $json = InModuleScope Fylgyr {
            $results = @(
                (Format-FylgyrResult -CheckName 'Check1' -Status 'Fail' -Severity 'High' -Resource 'test' -Detail 'Bad' -Remediation 'Fix.' -AttackMapping @('trivy-tag-poisoning', 'tj-actions-shai-hulud'))
            )
            ConvertTo-FylgyrSarif -Results $results
        }

        $sarif = $json | ConvertFrom-Json
        $sarif.runs[0].results[0].properties.tags | Should -Contain 'attack:trivy-tag-poisoning'
        $sarif.runs[0].results[0].properties.tags | Should -Contain 'attack:tj-actions-shai-hulud'
    }
}

Describe 'Write-FylgyrConsole' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    It 'writes output without throwing' {
        {
            InModuleScope Fylgyr {
                $results = @(
                    (Format-FylgyrResult -CheckName 'TestCheck' -Status 'Pass' -Severity 'Info' -Resource 'test' -Detail 'OK' -Remediation 'None.' -Target 'org/repo')
                    (Format-FylgyrResult -CheckName 'TestCheck' -Status 'Fail' -Severity 'High' -Resource 'test:10' -Detail 'Bad' -Remediation 'Fix it.' -AttackMapping @('trivy-tag-poisoning') -Target 'org/repo')
                )
                Write-FylgyrConsole -Results $results -Target 'org/repo'
            }
        } | Should -Not -Throw
    }
}

Describe 'Invoke-Fylgyr OutputFormat' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    BeforeEach {
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
        Mock -ModuleName Fylgyr Test-BranchProtection { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-SecretScanning   { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-DependabotAlert  { return @($stubResult) }
        Mock -ModuleName Fylgyr Test-CodeScanning     { return @($stubResult) }
    }

    It 'returns JSON string when OutputFormat is JSON' {
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

        $json = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -OutputFormat JSON
        $parsed = $json | ConvertFrom-Json
        $parsed.tool | Should -Be 'Fylgyr'
        $parsed.results.Count | Should -BeGreaterOrEqual 3
    }

    It 'returns SARIF string when OutputFormat is SARIF' {
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

        $sarif = Invoke-Fylgyr -Owner 'test' -Repo 'repo' -Token 'fake-token' -OutputFormat SARIF
        $parsed = $sarif | ConvertFrom-Json
        $parsed.version | Should -Be '2.1.0'
    }

    It 'pipes string repo names for a single owner' {
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

        $results = 'repoA', 'repoB' | Invoke-Fylgyr -Owner 'org' -Token 'fake-token'
        $results.Count | Should -BeGreaterOrEqual 6
    }
}
