targetScope = 'resourceGroup'

@description('Set to existing when the Log Analytics workspace already exists in this resource group.')
@allowed([
  'existing'
  'new'
])
param workspaceMode string = 'existing'

@description('Name of the Log Analytics workspace. For workspaceMode=existing, this workspace must already exist in the target resource group.')
param workspaceName string

@description('Azure region for new resources.')
param location string = resourceGroup().location

@description('Workspace SKU when creating a new workspace.')
@allowed([
  'PerGB2018'
  'CapacityReservation'
])
param workspaceSkuName string = 'PerGB2018'

@description('Retention (days) for a newly created workspace.')
@minValue(30)
@maxValue(730)
param workspaceRetentionInDays int = 30

@description('Public network access for ingestion on a newly created workspace. Keep Enabled for public ingestion patterns.')
@allowed([
  'Enabled'
  'Disabled'
])
param workspacePublicNetworkAccessForIngestion string = 'Enabled'

@description('Public network access for query on a newly created workspace.')
@allowed([
  'Enabled'
  'Disabled'
])
param workspacePublicNetworkAccessForQuery string = 'Enabled'

@description('Set to new to onboard Microsoft Sentinel on the workspace.')
@allowed([
  'existing'
  'new'
])
param sentinelMode string = 'new'

@description('Set to existing to re-use an existing Data Collection Endpoint in this resource group.')
@allowed([
  'existing'
  'new'
])
param dceMode string = 'new'

@description('Name of the Data Collection Endpoint when dceMode is new.')
param dceName string = 'fylgyr-dce'

@description('Name of the existing Data Collection Endpoint when dceMode is existing.')
param existingDceName string = ''

@description('Public network setting for a new Data Collection Endpoint.')
@allowed([
  'Enabled'
  'Disabled'
  'SecuredByPerimeter'
])
param dcePublicNetworkAccess string = 'Enabled'

@description('Name of the Data Collection Rule.')
param dcrName string = 'fylgyr-dcr'

@description('Custom stream name used by Fylgyr ingestion.')
param streamName string = 'Custom-FylgyrRaw'

@description('Optional principal object ID to grant Monitoring Metrics Publisher on the DCR. Leave empty to skip role assignment.')
param ingestionPrincipalObjectId string = ''

@description('Principal type for role assignment when ingestionPrincipalObjectId is set.')
@allowed([
  'ServicePrincipal'
  'User'
  'Group'
  'ForeignGroup'
  'Device'
])
param ingestionPrincipalType string = 'ServicePrincipal'

@description('Optional resource tags.')
param tags object = {}

@description('Runtime model for scheduled ingestion. githubActions keeps infrastructure-only deployment; azureFunction also deploys Function App infrastructure.')
@allowed([
  'githubActions'
  'azureFunction'
])
param runtimeMode string = 'githubActions'

@description('Name of the Function App when runtimeMode is azureFunction.')
param functionAppName string = 'fylgyr-func'

@description('Name of the App Service plan for the Function App when runtimeMode is azureFunction.')
param functionPlanName string = 'fylgyr-func-plan'

@description('Optional storage account name for the Function App. Leave empty to auto-generate a globally unique name.')
param functionStorageAccountName string = ''

@description('Public network access for the Function App when runtimeMode is azureFunction.')
@allowed([
  'Enabled'
  'Disabled'
])
param functionPublicNetworkAccess string = 'Disabled'

@description('Fylgyr owner value stored as FYLGYR_OWNER app setting on the Function App.')
param functionFylgyrOwner string = ''

@description('Fylgyr repo value stored as FYLGYR_REPO app setting on the Function App.')
param functionFylgyrRepo string = ''

@description('Optional HTTPS zip package URI for WEBSITE_RUN_FROM_PACKAGE. Leave empty to create infrastructure and settings only.')
param functionPackageUri string = ''

@description('How the Function loads Fylgyr module: Auto (try PSGallery then bundled), Gallery (PSGallery only), Bundled (package only).')
@allowed([
  'Auto'
  'Gallery'
  'Bundled'
])
param functionModuleSource string = 'Bundled'

@description('Set to new to deploy a Key Vault for Function App secrets, or existing to use one already present in this resource group.')
@allowed([
  'existing'
  'new'
])
param keyVaultMode string = 'existing'

@description('Name of the Key Vault used for Function App secret references.')
param keyVaultName string

@description('Public network access for a new Key Vault.')
@allowed([
  'Enabled'
  'Disabled'
])
param keyVaultPublicNetworkAccess string = 'Enabled'

@description('Name of the secret in Key Vault containing the GitHub token used by Fylgyr.')
param keyVaultGithubTokenSecretName string = 'fylgyr-github-token'

@description('Optional fixed secret version for the GitHub token reference. Leave empty to use the latest secret version.')
param keyVaultGithubTokenSecretVersion string = ''

var monitoringMetricsPublisherRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
var keyVaultSecretsUserRoleDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
var shouldCreateWorkspace = workspaceMode == 'new'
var shouldCreateSentinel = sentinelMode == 'new'
var shouldCreateDce = dceMode == 'new'
var shouldAssignRole = !empty(ingestionPrincipalObjectId)
var shouldCreateFunction = runtimeMode == 'azureFunction'
var shouldCreateKeyVault = keyVaultMode == 'new'
var keyVaultDnsSuffix = environment().suffixes.keyvaultDns
var keyVaultHost = startsWith(keyVaultDnsSuffix, '.') ? '${keyVaultName}${keyVaultDnsSuffix}' : '${keyVaultName}.${keyVaultDnsSuffix}'
var workspaceResourceId = shouldCreateWorkspace ? workspaceNew.id : workspaceExisting.id
var sentinelSolutionName = 'SecurityInsights(${workspaceName})'
var outputTableName = 'Fylgyr_CL'
var functionStorageAccountNameResolved = empty(functionStorageAccountName)
  ? toLower('fylgyr${uniqueString(resourceGroup().id, functionAppName)}')
  : toLower(functionStorageAccountName)
var functionCodePackageSetting = empty(functionPackageUri) ? '1' : functionPackageUri
var dceLogsIngestionEndpoint = shouldCreateDce ? (dceNew.?properties.?logsIngestion.?endpoint ?? '') : (dceExisting.?properties.?logsIngestion.?endpoint ?? '')
var keyVaultUri = 'https://${keyVaultHost}/'
var githubTokenSecretUri = empty(keyVaultGithubTokenSecretVersion)
  ? '${keyVaultUri}secrets/${keyVaultGithubTokenSecretName}'
  : '${keyVaultUri}secrets/${keyVaultGithubTokenSecretName}/${keyVaultGithubTokenSecretVersion}'
var functionGithubTokenSettingResolved = '@Microsoft.KeyVault(SecretUri=${githubTokenSecretUri})'

resource workspaceNew 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (shouldCreateWorkspace) {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: workspaceSkuName
    }
    retentionInDays: workspaceRetentionInDays
    publicNetworkAccessForIngestion: workspacePublicNetworkAccessForIngestion
    publicNetworkAccessForQuery: workspacePublicNetworkAccessForQuery
  }
}

resource workspaceExisting 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!shouldCreateWorkspace) {
  name: workspaceName
}

resource sentinelSolution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = if (shouldCreateSentinel) {
  name: sentinelSolutionName
  location: location
  tags: tags
  properties: {
    workspaceResourceId: workspaceResourceId
  }
  plan: {
    name: sentinelSolutionName
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
    promotionCode: ''
  }
}

resource sentinelOnWorkspaceNew 'Microsoft.SecurityInsights/onboardingStates@2024-09-01' = if (shouldCreateSentinel && shouldCreateWorkspace) {
  scope: workspaceNew
  name: 'default'
  properties: {}
  dependsOn: [
    sentinelSolution
  ]
}

resource sentinelOnWorkspaceExisting 'Microsoft.SecurityInsights/onboardingStates@2024-09-01' = if (shouldCreateSentinel && !shouldCreateWorkspace) {
  scope: workspaceExisting
  name: 'default'
  properties: {}
  dependsOn: [
    sentinelSolution
  ]
}

resource dceNew 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = if (shouldCreateDce) {
  name: dceName
  location: location
  tags: tags
  properties: {
    description: 'Fylgyr Logs Ingestion endpoint'
    networkAcls: {
      publicNetworkAccess: dcePublicNetworkAccess
    }
  }
}

resource dceExisting 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' existing = if (!shouldCreateDce) {
  name: existingDceName
}

resource outputTableNewWorkspace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = if (shouldCreateWorkspace) {
  parent: workspaceNew
  name: outputTableName
  properties: {
    plan: 'Analytics'
    retentionInDays: workspaceRetentionInDays
    totalRetentionInDays: workspaceRetentionInDays
    schema: {
      name: outputTableName
      columns: [
        {
          name: 'TimeGenerated'
          type: 'dateTime'
        }
        {
          name: 'EventVendor'
          type: 'string'
        }
        {
          name: 'EventProduct'
          type: 'string'
        }
        {
          name: 'EventSchema'
          type: 'string'
        }
        {
          name: 'EventType'
          type: 'string'
        }
        {
          name: 'ScanId_g'
          type: 'string'
        }
        {
          name: 'ScanStartTime_dt'
          type: 'dateTime'
        }
        {
          name: 'FylgyrVersion_s'
          type: 'string'
        }
        {
          name: 'CheckName_s'
          type: 'string'
        }
        {
          name: 'Severity_s'
          type: 'string'
        }
        {
          name: 'Status_s'
          type: 'string'
        }
        {
          name: 'Mode_s'
          type: 'string'
        }
        {
          name: 'Resource_s'
          type: 'string'
        }
        {
          name: 'Target_s'
          type: 'string'
        }
        {
          name: 'Owner_s'
          type: 'string'
        }
        {
          name: 'Repo_s'
          type: 'string'
        }
        {
          name: 'Detail_s'
          type: 'string'
        }
        {
          name: 'Remediation_s'
          type: 'string'
        }
        {
          name: 'AttackMapping_s'
          type: 'string'
        }
        {
          name: 'DriftFrom_s'
          type: 'string'
        }
        {
          name: 'DriftTo_s'
          type: 'string'
        }
        {
          name: 'EvidenceYaml_s'
          type: 'string'
        }
        {
          name: 'EvidenceCommitSha_s'
          type: 'string'
        }
        {
          name: 'EvidencePermalink_s'
          type: 'string'
        }
      ]
    }
  }
}

resource outputTableExistingWorkspace 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = if (!shouldCreateWorkspace) {
  parent: workspaceExisting
  name: outputTableName
  properties: {
    plan: 'Analytics'
    schema: {
      name: outputTableName
      columns: [
        {
          name: 'TimeGenerated'
          type: 'dateTime'
        }
        {
          name: 'EventVendor'
          type: 'string'
        }
        {
          name: 'EventProduct'
          type: 'string'
        }
        {
          name: 'EventSchema'
          type: 'string'
        }
        {
          name: 'EventType'
          type: 'string'
        }
        {
          name: 'ScanId_g'
          type: 'string'
        }
        {
          name: 'ScanStartTime_dt'
          type: 'dateTime'
        }
        {
          name: 'FylgyrVersion_s'
          type: 'string'
        }
        {
          name: 'CheckName_s'
          type: 'string'
        }
        {
          name: 'Severity_s'
          type: 'string'
        }
        {
          name: 'Status_s'
          type: 'string'
        }
        {
          name: 'Mode_s'
          type: 'string'
        }
        {
          name: 'Resource_s'
          type: 'string'
        }
        {
          name: 'Target_s'
          type: 'string'
        }
        {
          name: 'Owner_s'
          type: 'string'
        }
        {
          name: 'Repo_s'
          type: 'string'
        }
        {
          name: 'Detail_s'
          type: 'string'
        }
        {
          name: 'Remediation_s'
          type: 'string'
        }
        {
          name: 'AttackMapping_s'
          type: 'string'
        }
        {
          name: 'DriftFrom_s'
          type: 'string'
        }
        {
          name: 'DriftTo_s'
          type: 'string'
        }
        {
          name: 'EvidenceYaml_s'
          type: 'string'
        }
        {
          name: 'EvidenceCommitSha_s'
          type: 'string'
        }
        {
          name: 'EvidencePermalink_s'
          type: 'string'
        }
      ]
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  tags: tags
  dependsOn: [
    outputTableNewWorkspace
    outputTableExistingWorkspace
  ]
  properties: {
    description: 'Fylgyr Sentinel ingestion DCR'
    dataCollectionEndpointId: shouldCreateDce ? dceNew.id : dceExisting.id
    streamDeclarations: {
      '${streamName}': {
        columns: [
          {
            name: 'TimeGenerated'
            type: 'datetime'
          }
          {
            name: 'Type'
            type: 'string'
          }
          {
            name: 'EventVendor'
            type: 'string'
          }
          {
            name: 'EventProduct'
            type: 'string'
          }
          {
            name: 'EventSchema'
            type: 'string'
          }
          {
            name: 'EventType'
            type: 'string'
          }
          {
            name: 'ScanId_g'
            type: 'string'
          }
          {
            name: 'ScanStartTime_dt'
            type: 'datetime'
          }
          {
            name: 'FylgyrVersion_s'
            type: 'string'
          }
          {
            name: 'CheckName_s'
            type: 'string'
          }
          {
            name: 'Severity_s'
            type: 'string'
          }
          {
            name: 'Status_s'
            type: 'string'
          }
          {
            name: 'Mode_s'
            type: 'string'
          }
          {
            name: 'Resource_s'
            type: 'string'
          }
          {
            name: 'Target_s'
            type: 'string'
          }
          {
            name: 'Owner_s'
            type: 'string'
          }
          {
            name: 'Repo_s'
            type: 'string'
          }
          {
            name: 'Detail_s'
            type: 'string'
          }
          {
            name: 'Remediation_s'
            type: 'string'
          }
          {
            name: 'AttackMapping_s'
            type: 'string'
          }
          {
            name: 'DriftFrom_s'
            type: 'string'
          }
          {
            name: 'DriftTo_s'
            type: 'string'
          }
          {
            name: 'EvidenceYaml_s'
            type: 'string'
          }
          {
            name: 'EvidenceCommitSha_s'
            type: 'string'
          }
          {
            name: 'EvidencePermalink_s'
            type: 'string'
          }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          name: 'fylgyrDestination'
          workspaceResourceId: shouldCreateWorkspace ? workspaceNew.id : workspaceExisting.id
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          streamName
        ]
        destinations: [
          'fylgyrDestination'
        ]
        outputStream: 'Custom-Fylgyr_CL'
        transformKql: '''
source
| project
    TimeGenerated,
    EventVendor,
    EventProduct,
    EventSchema,
    EventType,
    ScanId_g,
    ScanStartTime_dt,
    FylgyrVersion_s,
    CheckName_s,
    Severity_s,
    Status_s,
    Mode_s,
    Resource_s,
    Target_s,
    Owner_s,
    Repo_s,
    Detail_s,
    Remediation_s,
    AttackMapping_s,
    DriftFrom_s,
    DriftTo_s,
    EvidenceYaml_s,
    EvidenceCommitSha_s,
    EvidencePermalink_s
'''
      }
    ]
  }
}

resource keyVaultNew 'Microsoft.KeyVault/vaults@2023-07-01' = if (shouldCreateKeyVault) {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: keyVaultPublicNetworkAccess
    accessPolicies: []
  }
}

resource keyVaultExisting 'Microsoft.KeyVault/vaults@2023-07-01' existing = if (!shouldCreateKeyVault) {
  name: keyVaultName
}

resource functionStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = if (shouldCreateFunction) {
  name: functionStorageAccountNameResolved
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource functionPlan 'Microsoft.Web/serverfarms@2023-12-01' = if (shouldCreateFunction) {
  name: functionPlanName
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: false
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = if (shouldCreateFunction) {
  name: functionAppName
  location: location
  tags: tags
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: functionPlan.id
    httpsOnly: true
    publicNetworkAccess: functionPublicNetworkAccess
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      powerShellVersion: '7.6'
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${functionStorage.name};AccountKey=${functionStorage!.listKeys().keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME_VERSION'
          value: '7.6'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: functionCodePackageSetting
        }
        {
          name: 'FYLGYR_OWNER'
          value: functionFylgyrOwner
        }
        {
          name: 'FYLGYR_REPO'
          value: functionFylgyrRepo
        }
        {
          name: 'FYLGYR_DCR_IMMUTABLE_ID'
          value: dcr.properties.immutableId
        }
        {
          name: 'FYLGYR_DCE_URI'
          value: dceLogsIngestionEndpoint
        }
        {
          name: 'FYLGYR_STREAM_NAME'
          value: streamName
        }
        {
          name: 'GITHUB_TOKEN'
          value: functionGithubTokenSettingResolved
        }
        {
          name: 'FYLGYR_MODULE_SOURCE'
          value: functionModuleSource
        }
      ]
    }
  }
}

resource dcrPublisherRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldAssignRole) {
  name: guid(dcr.id, ingestionPrincipalObjectId, monitoringMetricsPublisherRoleDefinitionId)
  scope: dcr
  properties: {
    principalId: ingestionPrincipalObjectId
    principalType: ingestionPrincipalType
    roleDefinitionId: monitoringMetricsPublisherRoleDefinitionId
  }
}

resource functionDcrPublisherRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldCreateFunction) {
  name: guid(dcr.id, functionApp.id, monitoringMetricsPublisherRoleDefinitionId)
  scope: dcr
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: monitoringMetricsPublisherRoleDefinitionId
  }
}

resource functionKeyVaultSecretsUserRoleAssignmentNewVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldCreateFunction && shouldCreateKeyVault) {
  name: guid(keyVaultNew.id, functionApp.id, keyVaultSecretsUserRoleDefinitionId)
  scope: keyVaultNew
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleDefinitionId
  }
}

resource functionKeyVaultSecretsUserRoleAssignmentExistingVault 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (shouldCreateFunction && !shouldCreateKeyVault) {
  name: guid(keyVaultExisting.id, functionApp.id, keyVaultSecretsUserRoleDefinitionId)
  scope: keyVaultExisting
  properties: {
    principalId: functionApp!.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: keyVaultSecretsUserRoleDefinitionId
  }
}

output workspaceResourceId string = shouldCreateWorkspace ? workspaceNew.id : workspaceExisting.id
output dceResourceId string = shouldCreateDce ? dceNew.id : dceExisting.id
output dceLogsIngestionUri string = dceLogsIngestionEndpoint
output dcrResourceId string = dcr.id
output dcrImmutableId string = dcr.properties.immutableId
output streamNameOut string = streamName
output runtimeModeOut string = runtimeMode
output functionAppResourceId string = shouldCreateFunction ? functionApp.id : ''
output functionPrincipalObjectId string = shouldCreateFunction ? (functionApp.?identity.?principalId ?? '') : ''
output functionStorageAccountNameOut string = shouldCreateFunction ? functionStorage.name : ''
output keyVaultResourceId string = shouldCreateKeyVault ? keyVaultNew.id : keyVaultExisting.id
output keyVaultUriOut string = keyVaultUri
output functionGithubTokenSettingOut string = shouldCreateFunction ? functionGithubTokenSettingResolved : ''
