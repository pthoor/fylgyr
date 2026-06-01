using './fylgyr-sentinel.bicep'

param workspaceMode = 'existing'
param workspaceName = 'existing-law-name'
param workspacePublicNetworkAccessForIngestion = 'Enabled'
param workspacePublicNetworkAccessForQuery = 'Enabled'

// Default is 'new' to ensure Sentinel onboarding resources are deployed.
// Set to 'existing' only when you intentionally want to skip onboarding resources.
param sentinelMode = 'new'

param dceMode = 'new'
param dceName = 'fylgyr-dce'
param existingDceName = ''
param dcePublicNetworkAccess = 'Enabled'

param dcrName = 'fylgyr-dcr'
param streamName = 'Custom-FylgyrRaw'

// Runtime options:
// - githubActions: deploy ingestion infrastructure only.
// - azureFunction: also deploy Function App infrastructure with managed identity.
param runtimeMode = 'githubActions'

param functionAppName = 'fylgyr-func'
param functionPlanName = 'fylgyr-func-plan'
param functionStorageAccountName = ''
param functionPublicNetworkAccess = 'Disabled'
param functionFylgyrOwner = ''
param functionFylgyrRepo = ''
param functionPackageUri = ''
param functionModuleSource = 'Bundled'

param keyVaultMode = 'existing'
param keyVaultName = 'existing-kv-name'
param keyVaultPublicNetworkAccess = 'Enabled'
param keyVaultGithubTokenSecretName = 'fylgyr-github-token'
param keyVaultGithubTokenSecretVersion = ''

// Optional: set this to the managed identity or app object id used for ingestion.
param ingestionPrincipalObjectId = ''
param ingestionPrincipalType = 'ServicePrincipal'

param tags = {
  solution: 'fylgyr'
  environment: 'security'
}
