@{
    RootModule = 'Fylgyr.psm1'
    ModuleVersion = '0.4.0'
    GUID = 'f3e1c20d-3f0d-4a40-a4e3-9dca27b6bd4a'
    Author = 'Pierre Thoor'
    CompanyName = 'Community'
    Copyright = '(c) Pierre Thoor. All rights reserved.'
    Description = 'Audits GitHub repositories and organizations for supply chain risks mapped to real-world attack campaigns.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Invoke-Fylgyr'
        'Test-ActionPinning'
        'Test-BranchProtection'
        'Test-CodeOwner'
        'Test-CodeScanning'
        'Test-DangerousTrigger'
        'Test-DependabotAlert'
        'Test-EgressControl'
        'Test-EnvironmentProtection'
        'Test-ForkPullPolicy'
        'Test-ForkSecretExposure'
        'Test-GitHubAppSecurity'
        'Test-RepoVisibility'
        'Test-RunnerHygiene'
        'Test-SecretScanning'
        'Test-SignedCommit'
        'Test-WorkflowPermission'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('PowerShell', 'GitHub', 'Security', 'SupplyChain', 'DevSecOps')
            ProjectUri = 'https://github.com/pthoor/Fylgyr'
            LicenseUri = 'https://github.com/pthoor/Fylgyr/blob/main/LICENSE'
        }
    }
}
