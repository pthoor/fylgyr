@{
    RootModule = 'Fylgyr.psm1'
    ModuleVersion = '0.8.1'
    GUID = 'f3e1c20d-3f0d-4a40-a4e3-9dca27b6bd4a'
    Author = 'Pierre Thoor'
    CompanyName = 'Community'
    Copyright = '(c) Pierre Thoor. All rights reserved.'
    Description = 'Audits GitHub repositories and organizations for supply chain risks mapped to real-world attack campaigns.'
    PowerShellVersion = '7.0'
    RequiredModules = @(
        @{
            ModuleName = 'powershell-yaml'
            ModuleVersion = '0.4.12'
        }
    )
    FunctionsToExport = @(
        'Invoke-Fylgyr'
        'Test-AccountKey'
        'Test-AccountSecurity'
        'Test-ActionPinning'
        'Test-ArtifactAttestation'
        'Test-ArtifactPoisoning'
        'Test-CacheIntegrity'
        'Test-BranchProtection'
        'Test-CodeOwner'
        'Test-ContainerPinning'
        'Test-LifecycleScript'
        'Test-UntrustedDownload'
        'Test-CodeScanning'
        'Test-ContinueOnError'
        'Test-DangerousTrigger'
        'Test-DefaultWorkflowPermission'
        'Test-DependabotAlert'
        'Test-DependencyReview'
        'Test-DefaultTokenPermission'
        'Test-DeployKey'
        'Test-EgressControl'
        'Test-EnvironmentProtection'
        'Test-ForkPullPolicy'
        'Test-ForkSecretExposure'
        'Test-GitHubAppSecurity'
        'Test-IpAllowlist'
        'Test-OidcTrust'
        'Test-OrgActionRestrictions'
        'Test-OrgDefaultPermissions'
        'Test-OrgMfaPolicy'
        'Test-OrgSecretVisibility'
        'Test-TagProtection'
        'Test-OAuthAppPolicy'
        'Test-OutsideCollaborators'
        'Test-PatPolicy'
        'Test-PrivateVulnReporting'
        'Test-RepoVisibility'
        'Test-ReusableWorkflowTrust'
        'Test-Rulesets'
        'Test-RunnerHygiene'
        'Test-RunnerPinning'
        'Test-AuditLogStreaming'
        'Test-PublishIntegrity'
        'Test-ScriptInjection'
        'Test-SecretScanning'
        'Test-SignedCommit'
        'Test-TriggerFilter'
        'Test-WebhookSecurity'
        'Test-WorkflowConcurrency'
        'Test-WorkflowPermission'
        'Test-BinaryArtifact'
        'Test-RecentCollaboratorChange'
        'Test-RecentAppAuthorization'
        'Test-RecentProtectionChange'
        'Test-RecentForcePush'
        'Test-RecentRunnerRegistration'
        'Test-RecentSecretChange'
        'Test-RecentTokenExposure'
        'Test-RecentWorkflowAdd'
        'Send-FylgyrToLogAnalytics'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    FileList = @(
        'Fylgyr.psd1'
        'Fylgyr.psm1'
        'Data/attacks.json'
        'Data/report-template.html'
    )
    PrivateData = @{
        PSData = @{
            Tags = @('PowerShell', 'GitHub', 'Security', 'SupplyChain', 'DevSecOps')
            ProjectUri = 'https://github.com/pthoor/Fylgyr'
            LicenseUri = 'https://github.com/pthoor/Fylgyr/blob/main/LICENSE'
        }
    }
}
