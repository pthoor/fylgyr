Describe 'Security anti-pattern guardrails' {
    BeforeAll {
        $repoRoot = Split-Path -Path $PSScriptRoot -Parent
        $srcRoot = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr'

        # Collect all .ps1 source files (Public + Private)
        $sourceFiles = Get-ChildItem -Path $srcRoot -Filter '*.ps1' -Recurse
    }

    Context 'Error handling' {

        It 'never uses raw $_ in string interpolation inside catch blocks' {
            # Raw $_ in error messages leaks stack traces, tokens, and internal paths.
            # Must use $_.Exception.Message instead.
            $violations = foreach ($file in $sourceFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                # Find catch blocks, then look for "$_" that is NOT followed by .Exception or .ErrorDetails or .ToString
                # We match "$_" inside strings but not "$_.Exception", "$_.ErrorDetails", "$_.ToString()"
                $lines = Get-Content -Path $file.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    # Match string interpolation containing bare $_ (not $_. something)
                    if ($line -match '\$_[^.\w]' -or $line -match '\$_"' -or $line -match '\$_$') {
                        # Exclude lines that are clearly using $_ in a pipeline (Where-Object, ForEach-Object)
                        if ($line -notmatch 'Where-Object|ForEach-Object|Select-Object|Sort-Object|%\s*\{|\|\s*\{') {
                            # Exclude $_.Exception, $_.ErrorDetails, $_.ToString patterns on the same line
                            if ($line -notmatch '\$_\.(Exception|ErrorDetails|ToString|FullyQualifiedErrorId|PSObject)') {
                                [PSCustomObject]@{
                                    File = $file.Name
                                    Line = $i + 1
                                    Content = $line.Trim()
                                }
                            }
                        }
                    }
                }
            }

            if ($violations) {
                $details = ($violations | ForEach-Object { "$($_.File):$($_.Line) -> $($_.Content)" }) -join "`n"
                $violations | Should -BeNullOrEmpty -Because "raw `$_ leaks internals. Use `$_.Exception.Message instead.`n$details"
            }
        }

        It 'never uses Invoke-Expression or iex' {
            foreach ($file in $sourceFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                $content | Should -Not -Match '\bInvoke-Expression\b' -Because "$($file.Name) must not use Invoke-Expression (code injection risk)"
                $content | Should -Not -Match '(?<!\w)\biex\b' -Because "$($file.Name) must not use iex alias (code injection risk)"
            }
        }

        It 'never uses Start-Process for command execution' {
            foreach ($file in $sourceFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                $content | Should -Not -Match '\bStart-Process\b' -Because "$($file.Name) must not use Start-Process (code execution risk)"
            }
        }

        It 'never uses ConvertFrom-SecureString' {
            foreach ($file in $sourceFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                $content | Should -Not -Match '\bConvertFrom-SecureString\b' -Because "$($file.Name) must not store credentials"
            }
        }
    }

    Context 'HTTP status code matching' {

        It 'never uses regex character classes that accidentally match wrong status codes' {
            # Catches patterns like 40[04] which matches 400 AND 404,
            # or 50[02] which matches 500 AND 502 when only one is intended.
            $violations = foreach ($file in $sourceFiles) {
                $lines = Get-Content -Path $file.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match "\d0\[\d+\]") {
                        [PSCustomObject]@{
                            File = $file.Name
                            Line = $i + 1
                            Content = $lines[$i].Trim()
                        }
                    }
                }
            }

            if ($violations) {
                $details = ($violations | ForEach-Object { "$($_.File):$($_.Line) -> $($_.Content)" }) -join "`n"
                $violations | Should -BeNullOrEmpty -Because "use explicit status codes (e.g. '404') not character classes (e.g. '40[04]') to avoid matching unintended codes.`n$details"
            }
        }
    }

    Context 'API security' {

        It 'enforces HTTPS-only in Invoke-GitHubApi' {
            $apiFile = $sourceFiles | Where-Object Name -EQ 'Invoke-GitHubApi.ps1'
            $apiFile | Should -Not -BeNullOrEmpty
            $content = Get-Content -Path $apiFile.FullName -Raw
            $content | Should -Match "http://" -Because "there must be an explicit HTTP rejection check"
            $content | Should -Match "HTTPS" -Because "HTTPS enforcement must be documented/implemented"
        }

        It 'scrubs tokens from error messages in Invoke-GitHubApi' {
            $apiFile = $sourceFiles | Where-Object Name -EQ 'Invoke-GitHubApi.ps1'
            $content = Get-Content -Path $apiFile.FullName -Raw
            $content | Should -Match 'Escape\(\$Token\)' -Because "token values must be scrubbed from error messages"
        }

        It 'validates token for control characters in Invoke-GitHubApi' {
            $apiFile = $sourceFiles | Where-Object Name -EQ 'Invoke-GitHubApi.ps1'
            $content = Get-Content -Path $apiFile.FullName -Raw
            $content | Should -Match '\\x00' -Because "tokens must be validated for control characters to prevent header injection"
        }

        It 'uses SkipHeaderValidation in Invoke-GitHubApi' {
            $apiFile = $sourceFiles | Where-Object Name -EQ 'Invoke-GitHubApi.ps1'
            $content = Get-Content -Path $apiFile.FullName -Raw
            $content | Should -Match 'SkipHeaderValidation' -Because "fine-grained PATs require SkipHeaderValidation"
        }

        It 'has pagination bounds in Invoke-GitHubApi' {
            $apiFile = $sourceFiles | Where-Object Name -EQ 'Invoke-GitHubApi.ps1'
            $content = Get-Content -Path $apiFile.FullName -Raw
            $content | Should -Match 'maxPages' -Because "pagination must be bounded to prevent infinite loops"
        }
    }

    Context 'Function signatures' {

        It 'all functions declare [OutputType()]' {
            foreach ($file in $sourceFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                if ($content -match '^\s*function\s+\w' ) {
                    $content | Should -Match '\[OutputType\(' -Because "$($file.Name) must declare [OutputType()]"
                }
            }
        }

        It 'Owner/Repo parameters use ValidatePattern in public API functions' {
            $publicFiles = $sourceFiles | Where-Object { $_.FullName -match 'Public' }
            foreach ($file in $publicFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                # Only check files that accept Owner/Repo parameters
                if ($content -match '\[string\]\$Owner' -and $content -match '\[string\]\$Repo') {
                    $content | Should -Match "ValidatePattern\(" -Because "$($file.Name) must validate Owner/Repo to prevent injection"
                }
            }
        }
    }

    Context 'Endpoint path encoding' {
        BeforeAll {
            $repoRoot = Split-Path -Path $PSScriptRoot -Parent
            $modulePath = Join-Path -Path $repoRoot -ChildPath 'src/Fylgyr/Fylgyr.psm1'
            Import-Module -Name $modulePath -Force
        }

        It 'encodes a slash inside a path segment so it is not read as a separator' {
            $encoded = InModuleScope Fylgyr { ConvertTo-FylgyrEscapedPathSegment -Value 'release/v1' }
            $encoded | Should -Be 'release%2Fv1'
        }

        It 'encodes characters that are significant in a URL' {
            $encoded = InModuleScope Fylgyr { ConvertTo-FylgyrEscapedPathSegment -Value 'a b?c#d' }
            $encoded | Should -Be 'a%20b%3Fc%23d'
        }

        It 'leaves an ordinary segment unchanged' {
            $encoded = InModuleScope Fylgyr { ConvertTo-FylgyrEscapedPathSegment -Value 'main' }
            $encoded | Should -Be 'main'
        }

        It 'accepts an empty string' {
            $encoded = InModuleScope Fylgyr { ConvertTo-FylgyrEscapedPathSegment -Value '' }
            $encoded | Should -Be ''
        }

        It 'does not interpolate a raw API-derived branch variable straight into an -Endpoint' {
            # Regression guard: API-sourced branch names must be passed through
            # ConvertTo-FylgyrEscapedPathSegment, never interpolated raw, or a
            # slash-containing branch breaks the request and becomes an injection point.
            $violations = foreach ($file in $sourceFiles) {
                $lines = Get-Content -Path $file.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match '-Endpoint\s+"[^"]*branches/\$defaultBranch') {
                        [PSCustomObject]@{ File = $file.Name; Line = $i + 1; Content = $lines[$i].Trim() }
                    }
                }
            }

            if ($violations) {
                $details = ($violations | ForEach-Object { "$($_.File):$($_.Line) -> $($_.Content)" }) -join "`n"
                $violations | Should -BeNullOrEmpty -Because "use `$escapedBranch via ConvertTo-FylgyrEscapedPathSegment.`n$details"
            }
        }
    }

    Context 'Error message quality' {

        It 'permission error messages mention both fine-grained and classic token types' {
            $checkFiles = $sourceFiles | Where-Object { $_.Name -match '^Test-' -and $_.FullName -match 'Public' }
            foreach ($file in $checkFiles) {
                $content = Get-Content -Path $file.FullName -Raw
                # Find lines with permission/insufficient messages
                if ($content -match 'Insufficient permissions') {
                    $content | Should -Match 'fine-grained' -Because "$($file.Name) permission errors must guide users of both token types"
                    $content | Should -Match 'classic token' -Because "$($file.Name) permission errors must guide users of both token types"
                }
            }
        }
    }
}
