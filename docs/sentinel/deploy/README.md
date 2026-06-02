# Fylgyr Microsoft Sentinel deployment (Bicep)

This deployment pack installs the ingestion-side Azure resources for Fylgyr Microsoft Sentinel integration.

## What it deploys

- Log Analytics workspace (optional: create new or use existing)
- Microsoft Sentinel enablement (SecurityInsights solution + onboarding state, optional)
- Data Collection Endpoint (DCE) (optional: create new or use existing)
- Log Analytics custom table `Fylgyr_CL` (created/updated before DCR)
- Data Collection Rule (DCR) for stream `Custom-FylgyrRaw`
- Key Vault (new or existing) for `GITHUB_TOKEN` secret reference
- Optional RBAC assignment (`Monitoring Metrics Publisher`) on the DCR for your ingestion principal
- Optional Azure Function runtime infrastructure (`runtimeMode = 'azureFunction'`):
  - Storage account
  - Consumption App Service plan
  - Function App with managed identity
  - Function app settings wired to DCR immutable id, DCE URI, and stream name
  - Automatic DCR role assignment (`Monitoring Metrics Publisher`) for the Function managed identity
  - Automatic Key Vault role assignment (`Key Vault Secrets User`) for the Function managed identity

## Runtime model selection

Use `runtimeMode` to choose your operating model:

- `githubActions` (default): deploy ingestion infrastructure only (DCE/DCR/workspace/Sentinel as configured)
- `azureFunction`: deploy ingestion infrastructure plus Azure Function runtime resources

Important:

- The template deploys Function App infrastructure and settings. Function code package deployment is still a separate step unless you provide `functionPackageUri`.
- If you provide `functionPackageUri`, it must be an HTTPS URL to a zip package consumable by `WEBSITE_RUN_FROM_PACKAGE`.
- `GITHUB_TOKEN` app setting is auto-generated as a Key Vault reference from `keyVaultName`, `keyVaultGithubTokenSecretName`, and optional `keyVaultGithubTokenSecretVersion`.
- Function App runtime is configured for PowerShell 7.6 (`FUNCTIONS_EXTENSION_VERSION ~4`).
- `functionModuleSource` controls how the Function loads Fylgyr:
  - `Bundled` (default): package-only module (no PSGallery download).
  - `Auto`: try PSGallery first, then bundled module fallback.
  - `Gallery`: PSGallery only (always install latest).
  - For production, keep `Bundled` to avoid runtime module supply-chain drift.

Production baseline defaults in this template:

- `functionPublicNetworkAccess = 'Disabled'`
- `functionModuleSource = 'Bundled'`

Compatibility mode (opt-in):

- Set `functionPublicNetworkAccess = 'Enabled'` only when inbound public access is required.
- Set `functionModuleSource = 'Auto'` or `Gallery` only when runtime PSGallery updates are explicitly desired.

Azure Function parameters (used when `runtimeMode = 'azureFunction'`):

- `functionAppName`
- `functionPlanName`
- `functionStorageAccountName` (optional; auto-generated if empty)
- `functionPublicNetworkAccess`
- `functionFylgyrOwner`
- `functionFylgyrRepo` (optional; set empty for owner-wide repo enumeration)
- `functionPackageUri` (optional)
- `functionModuleSource` (`Auto`, `Gallery`, `Bundled`)
- `keyVaultMode` (`existing`, `new`)
- `keyVaultName`
- `keyVaultPublicNetworkAccess` (`Enabled`, `Disabled`, used when creating a new vault)
- `keyVaultGithubTokenSecretName`
- `keyVaultGithubTokenSecretVersion` (optional; defaults to latest version)

## Existing vs new workspace and Sentinel

Use these parameters:

- `workspaceMode`: `existing` or `new`
- `sentinelMode`: `existing` or `new`

Default behavior:

- `sentinelMode = 'new'` ensures Sentinel onboarding resources are deployed (matches common Sentinel-as-Code patterns).

Skip Sentinel onboarding resources intentionally:

- `sentinelMode = 'existing'`

If your workspace already has Sentinel enabled, leaving `sentinelMode = 'new'` is safe and idempotent.

## Security posture (public ingestion supported)

This deployment keeps public ingestion support available by design for broad compatibility.

- Use managed identity or service principal auth for ingestion.
- Grant only `Monitoring Metrics Publisher` on the target DCR scope.
- Keep `dcePublicNetworkAccess` explicit (`Enabled`, `Disabled`, or `SecuredByPerimeter`).
- For new workspaces, set `workspacePublicNetworkAccessForIngestion` and `workspacePublicNetworkAccessForQuery` explicitly.
- Ensure deployment identity can manage `Microsoft.OperationalInsights/workspaces/tables` on the target workspace.
- Ensure deployment identity can manage `Microsoft.KeyVault/vaults` and `Microsoft.Authorization/roleAssignments` when `keyVaultMode = 'new'`.

Future hardening:

- Network Security Perimeter (NSP) can be introduced later without changing the ingestion schema.
- AMPLS/private-endpoint topology is intentionally out of scope for this baseline deployment pack.

## Deploy

Locate or create your resource group in target Azure subscription, then customize the parameters in `fylgyr-sentinel.bicepparam` as needed.

Use the Azure CLI to deploy the Bicep template with your parameter file:

```powershell
az deployment group create `
  --resource-group <rg-name> `
  --template-file docs/sentinel/deploy/fylgyr-sentinel.bicep `
  --parameters docs/sentinel/deploy/fylgyr-sentinel.bicepparam
```

For local/private parameter values, create a local parameter file (for example `fylgyr-sentinel.local.bicepparam`) and keep it excluded from source control.

## End-to-end install flow

1. Deploy infrastructure with `az deployment group create` and your chosen `.bicepparam` file.
2. Create or update the GitHub token secret in Key Vault.
3. Publish Function code package with `scripts/publish-fylgyr-function-package.ps1` (or pass `functionPackageUri` directly in Bicep parameters).
4. Validate the timer Function starts successfully and writes records to `Fylgyr_CL`.
5. Enable and tune analytics rules from `docs/sentinel/rules/`.

If you use an existing DCE in the same resource group:

- set `dceMode = 'existing'`
- set `existingDceName` to that DCE name

If you use an existing Key Vault in the same resource group:

- set `keyVaultMode = 'existing'`
- set `keyVaultName` to that vault name
- set `keyVaultGithubTokenSecretName` (and optional `keyVaultGithubTokenSecretVersion`) to your stored GitHub token secret

If you create a new Key Vault:

- set `keyVaultMode = 'new'`
- set `keyVaultName` to a globally unique vault name
- add the GitHub token secret to the vault after deployment (the Function app reference is already configured)

## GitHub token (PAT) setup

Use a fine-grained PAT for Sentinel/Azure Function scans and store it in Key Vault.

Recommended fine-grained repository permissions:

- `Contents: Read`
- `Administration: Read` (for branch protection checks)
- `Secret scanning alerts: Read`
- `Dependabot alerts: Read`

If these permissions are missing, related checks return permission errors.

Create/update the Key Vault secret:

```powershell
$KvName = '<key-vault-name>'
$SecretName = '<secret-name-from-keyVaultGithubTokenSecretName>'
$GitHubPat = Read-Host -Prompt 'GitHub PAT' -MaskInput

az keyvault secret set `
  --vault-name $KvName `
  --name $SecretName `
  --value $GitHubPat

Remove-Variable GitHubPat -ErrorAction SilentlyContinue
```

If `keyVaultGithubTokenSecretVersion` is empty (default), the Function always reads the latest secret version. If you set a fixed version, update that parameter when rotating the token.

## Outputs you need for ingestion

After deployment, capture:

- `dcrImmutableId`
- `dceLogsIngestionUri`
- `streamNameOut`

If `runtimeMode = 'azureFunction'`, additional outputs are available:

- `functionAppResourceId`
- `functionPrincipalObjectId`
- `functionStorageAccountNameOut`
- `keyVaultResourceId`
- `keyVaultUriOut`
- `functionGithubTokenSettingOut`

Use those values with `Send-FylgyrToLogAnalytics`.

## Role assignment

Set `ingestionPrincipalObjectId` to the object id of your managed identity or app registration to assign `Monitoring Metrics Publisher` automatically on the DCR.

If empty, no role assignment is created.

## Function package publish script

To package `run.ps1` + `function.json` + bundled module and deploy it as `functionPackageUri`, use:

```powershell
./scripts/publish-fylgyr-function-package.ps1 -ResourceGroupName <rg-name>
```

The script uploads the zip to the Function storage account, creates an HTTPS SAS URI, and runs a deployment update with `functionPackageUri`.

- Uses a static deployment name `fylgyr-function-package` by default for the package update deployment.
- Auto-discovers Function App and storage account from the target resource group.
- Falls back to deployment outputs only when storage account cannot be derived from app settings.
- Automatically reads outputs from the latest successful infrastructure deployment if fallback is needed, unless you set `-InfrastructureDeploymentName`.
- You can override the package update deployment name with `-PublishDeploymentName`.
- You can force explicit resource targeting with `-FunctionAppName` and `-FunctionStorageAccountName`.

Typical run:

```powershell
./scripts/publish-fylgyr-function-package.ps1 -ResourceGroupName <rg-name>
```

From the `scripts/` folder:

```powershell
./publish-fylgyr-function-package.ps1 -ResourceGroupName <rg-name>
```

Verify the Function has the expected Key Vault reference:

```powershell
az functionapp config appsettings list `
  --resource-group <rg-name> `
  --name <function-app-name> `
  --query "[?name=='GITHUB_TOKEN'].value" `
  -o tsv
```

## Post-deployment security checklist

Use this checklist as an operational gate after each deploy and after any identity/networking change.

Deployment context:

- Date:
- Environment:
- Resource group:
- Workspace:
- DCR:
- Reviewer:

Checklist:

- [ ] Identity confirmed
  - Record ingestion principal display name and object id.
- [ ] DCR role scope confirmed
  - `Monitoring Metrics Publisher` is assigned only at DCR scope.
- [ ] Secret handling confirmed
  - `GITHUB_TOKEN` Key Vault secret exists and the Function managed identity has `Key Vault Secrets User` on the vault.
- [ ] Endpoint and transport confirmed
  - `dceLogsIngestionUri` uses `https://` and points to the expected Azure Monitor ingestion endpoint.
- [ ] Network posture reviewed
  - `dcePublicNetworkAccess`, `workspacePublicNetworkAccessForIngestion`, and `workspacePublicNetworkAccessForQuery` match intended environment posture.
- [ ] Ingestion smoke test passed
  - Recent Fylgyr events are visible in Log Analytics/Sentinel.
- [ ] Alerting configured
  - Ingestion/auth failure alerting is enabled and routed to the on-call channel.
- [ ] Rotation owner and cadence documented
  - Owner and credential/token rotation interval are defined.

Optional validation query:

```kql
Fylgyr_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, CheckName_s, Severity_s, Status_s, Owner_s, Repo_s, Target_s, Resource_s
| order by TimeGenerated desc
```
