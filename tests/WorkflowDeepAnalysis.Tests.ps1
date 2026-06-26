Describe 'Phase 8 workflow deep analysis checks' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
        Import-Module -Name $modulePath -Force
    }

    Describe 'Test-ScriptInjection' {
        It 'fails when untrusted event context is interpolated in a run block scalar' {
            $wf = @([PSCustomObject]@{
                Name = 'inject.yml'
                Path = '.github/workflows/inject.yml'
                Content = @'
name: Inject
on: issue_comment
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.comment.body }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results | Should -HaveCount 1
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].AttackMapping | Should -Contain 'github-actions-script-injection'
            $results[0].Remediation | Should -Match 'shell variable'
        }

        It 'passes when run expressions only use allowlisted context values' {
            $wf = @([PSCustomObject]@{
                Name = 'safe.yml'
                Path = '.github/workflows/safe.yml'
                Content = @'
name: Safe
on: push
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }

        It 'flags bracket-notation access to an untrusted event field' {
            $wf = @([PSCustomObject]@{
                Name = 'bracket.yml'
                Path = '.github/workflows/bracket.yml'
                Content = @'
name: Bracket
on: issues
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event['issue']['title'] }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'flags workflow_run.pull_requests interpolation' {
            $wf = @([PSCustomObject]@{
                Name = 'wr.yml'
                Path = '.github/workflows/wr.yml'
                Content = @'
name: WR
on: workflow_run
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.workflow_run.pull_requests[0].head.ref }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'flags pull_request_review_comment.body interpolation' {
            $wf = @([PSCustomObject]@{
                Name = 'prrc.yml'
                Path = '.github/workflows/prrc.yml'
                Content = @'
name: PRRC
on: pull_request_review_comment
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request_review_comment.body }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'flags an env var assigned untrusted data and later interpolated in run (indirection)' {
            $wf = @([PSCustomObject]@{
                Name = 'envtaint.yml'
                Path = '.github/workflows/envtaint.yml'
                Content = @'
name: EnvTaint
on: issues
env:
  TITLE: ${{ github.event.issue.title }}
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ env.TITLE }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'flags step-level env taint as well as workflow-level' {
            $wf = @([PSCustomObject]@{
                Name = 'stepenv.yml'
                Path = '.github/workflows/stepenv.yml'
                Content = @'
name: StepEnv
on: issues
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{ github.event.issue.body }}
        run: echo "${{ env.BODY }}"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }

        It 'passes when untrusted data is bound to env and used as a shell variable' {
            $wf = @([PSCustomObject]@{
                Name = 'safeenv.yml'
                Path = '.github/workflows/safeenv.yml'
                Content = @'
name: SafeEnv
on: issues
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }

        It 'flags untrusted interpolation inside a github-script script: input' {
            $wf = @([PSCustomObject]@{
                Name = 'ghscript.yml'
                Path = '.github/workflows/ghscript.yml'
                Content = @'
name: GhScript
on: issues
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            console.log("${{ github.event.issue.title }}")
'@
            })

            $results = Test-ScriptInjection -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
        }
    }

    Describe 'Test-ArtifactPoisoning' {
        It 'elevates severity when workflow_run downloads and executes artifacts' {
            $wf = @([PSCustomObject]@{
                Name = 'artifact.yml'
                Path = '.github/workflows/artifact.yml'
                Content = @'
name: Artifact
on: workflow_run
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: bash artifact/build.sh
'@
            })

            $results = Test-ArtifactPoisoning -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'Critical'
            $results[0].AttackMapping | Should -Contain 'artifact-poisoning-workflow-run'
        }
    }

    Describe 'Test-OidcTrust' {
        It 'returns High Fail for OIDC publish-adjacent jobs without environment scoping' {
            $wf = @([PSCustomObject]@{
                Name = 'oidc-publish.yml'
                Path = '.github/workflows/oidc-publish.yml'
                Content = @'
name: Publish
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: npm publish --provenance
'@
            })

            $results = Test-OidcTrust -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'bitwarden-cli-2026-04'
            $results[0].AttackMapping | Should -Contain 'oidc-trust-abuse'
        }

        It 'returns Medium Warning for OIDC without publish indicators and no environment' {
            $wf = @([PSCustomObject]@{
                Name = 'oidc-generic.yml'
                Path = '.github/workflows/oidc-generic.yml'
                Content = @'
name: Deploy
on: push
jobs:
  cloud-auth:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - run: echo "auth"
'@
            })

            $results = Test-OidcTrust -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AttackMapping | Should -Contain 'oidc-trust-abuse'
            $results[0].AttackMapping | Should -Not -Contain 'bitwarden-cli-2026-04'
        }
    }

    Describe 'Test-CacheIntegrity' {
        It 'fails when cache key uses github.head_ref in pull_request workflow' {
            $wf = @([PSCustomObject]@{
                Name = 'cache.yml'
                Path = '.github/workflows/cache.yml'
                Content = @'
name: Cache
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          key: cache-${{ github.head_ref }}
'@
            })

            $results = Test-CacheIntegrity -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'cache-poisoning-pr-branch'
        }
    }

    Describe 'Test-TriggerFilter' {
        It 'warns when issue_comment trigger has no types filter' {
            $wf = @([PSCustomObject]@{
                Name = 'trigger.yml'
                Path = '.github/workflows/trigger.yml'
                Content = @'
name: Trigger
on:
  issue_comment:
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
'@
            })

            $results = Test-TriggerFilter -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
        }
    }

    Describe 'Test-DependencyReview' {
        It 'warns when PR workflows do not run dependency-review-action' {
            $wf = @([PSCustomObject]@{
                Name = 'pr.yml'
                Path = '.github/workflows/pr.yml'
                Content = @'
name: PR
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
'@
            })

            $results = Test-DependencyReview -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
            $results[0].AttackMapping | Should -Contain 'event-stream-hijack'
        }

        It 'passes when a PR workflow uses dependency-review-action' {
            $wf = @([PSCustomObject]@{
                Name = 'pr.yml'
                Path = '.github/workflows/pr.yml'
                Content = @'
name: PR
on: pull_request
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
'@
            })

            $results = Test-DependencyReview -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Describe 'Test-ArtifactAttestation' {
        It 'warns when release jobs miss attestation permissions/step' {
            $wf = @([PSCustomObject]@{
                Name = 'release.yml'
                Path = '.github/workflows/release.yml'
                Content = @'
name: Release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release create v1.2.3 artifact.zip
'@
            })

            $results = Test-ArtifactAttestation -WorkflowFiles $wf
            $results[0].Status | Should -Be 'Warning'
            $results[0].Severity | Should -Be 'Medium'
            $results[0].AttackMapping | Should -Contain 'solarwinds-orion'
        }
    }

    Describe 'Test-ReusableWorkflowTrust' {
        It 'fails for unpinned or untrusted reusable workflow references' {
            $wf = @([PSCustomObject]@{
                Name = 'reuse.yml'
                Path = '.github/workflows/reuse.yml'
                Content = @'
name: Reuse
on: push
jobs:
  call:
    uses: evil-org/workflows/.github/workflows/reuse.yml@main
'@
            })

            $results = Test-ReusableWorkflowTrust -WorkflowFiles $wf -Owner 'acme'
            $results[0].Status | Should -Be 'Fail'
            $results[0].Severity | Should -Be 'High'
            $results[0].AttackMapping | Should -Contain 'tj-actions-shai-hulud'
        }

        It 'passes for same-owner SHA pinned reusable workflow references' {
            $wf = @([PSCustomObject]@{
                Name = 'reuse-safe.yml'
                Path = '.github/workflows/reuse-safe.yml'
                Content = @'
name: Reuse Safe
on: push
jobs:
  call:
    uses: acme/platform-ci/.github/workflows/reuse.yml@11bd71901bbe5b1630ceea73d27597364c9af683
'@
            })

            $results = Test-ReusableWorkflowTrust -WorkflowFiles $wf -Owner 'acme'
            $results[0].Status | Should -Be 'Pass'
        }
    }

    Describe 'Test-PrivateVulnReporting' {
        It 'passes when private vulnerability reporting is enabled' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                return [PSCustomObject]@{ enabled = $true }
            }

            $results = Test-PrivateVulnReporting -Owner 'org' -Repo 'repo' -Token 'fake-token'
            $results[0].Status | Should -Be 'Pass'
        }

        It 'returns Info when endpoint is unsupported (404)' {
            Mock -ModuleName Fylgyr Invoke-GitHubApi {
                throw '404 Not Found'
            }

            $results = Test-PrivateVulnReporting -Owner 'org' -Repo 'repo' -Token 'fake-token'
            $results[0].Status | Should -Be 'Info'
            $results[0].Severity | Should -Be 'Info'
        }
    }
}
