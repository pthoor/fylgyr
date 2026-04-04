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
