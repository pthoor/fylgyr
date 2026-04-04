@{
    RootModule = 'Fylgyr.psm1'
    ModuleVersion = '0.1.0'
    GUID = 'f3e1c20d-3f0d-4a40-a4e3-9dca27b6bd4a'
    Author = 'Pierre Thoor'
    CompanyName = 'Community'
    Copyright = '(c) Pierre Thoor. All rights reserved.'
    Description = 'Audits GitHub repositories and organizations for supply chain risks mapped to real-world attack campaigns.'
    PowerShellVersion = '7.0'
    FunctionsToExport = '*'
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
