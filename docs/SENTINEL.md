# Fylgyr Microsoft Sentinel Integration

This guide explains how to stream Fylgyr findings to Microsoft Sentinel through Azure Monitor Logs Ingestion API.

## Why use Fylgyr with Microsoft Sentinel

Fylgyr and Microsoft Sentinel solve different parts of the same problem:

- Fylgyr gives attack-mapped findings with clear remediation context.
- Microsoft Sentinel gives central detection, alert routing, workbooks, and SOC workflows.
- Together, they provide actionable supply-chain posture telemetry that can be queried, correlated, and alerted on.

## Current scope and assumptions

This integration currently targets public Azure Monitor ingestion over TLS 1.2+.

Deployment model: Bicep-first. Use the single resource-group scoped template at `docs/sentinel/deploy/fylgyr-sentinel.bicep` for Azure resource deployment and configuration.

- GitHub-hosted runners are supported.
- No VNet integration is required for the initial setup.
- AMPLS and private-endpoint topology are intentionally out of scope for this guide.

If private networking is needed later, treat it as a future hardening track after baseline telemetry is stable.

## Enterprise-scale placement recommendation

For enterprise landing zones, the default recommendation is to deploy this solution under the Security management group and a dedicated Security subscription.

Why this is the default:

- Keeps SOC telemetry and detection engineering ownership centralized.
- Enables consistent RBAC, policy, retention, and incident routing controls.
- Reduces operational drift across business units.

Alternative model:

- Decentralized workspaces per business unit can be used when regulatory or data residency requirements require local ownership.
- If you use this model, keep central detection standards and content governance to avoid rule drift.

## What is included

- Mode support in `Invoke-Fylgyr` (`-Mode Audit`, `-Mode Drift`, `-Mode Both`; Sentinel schedules usually use `-Mode Both`)
- Log Analytics formatter (`-OutputFormat LogAnalytics`)
- Ingestion helper: `Send-FylgyrToLogAnalytics`
- Bicep deployment assets:
  - `docs/sentinel/deploy/fylgyr-sentinel.bicep` (single resource-group template for workspace, Sentinel onboarding, DCE, DCR, and optional DCR RBAC assignment)
  - `docs/sentinel/deploy/fylgyr-sentinel.bicepparam`
  - `docs/sentinel/table-schema.json`
- Operations assets:
  - `docs/sentinel/rules/*.yaml`
  - `docs/sentinel/workbook.json`
  - `docs/sentinel/github-actions-cron.yml`
  - `docs/sentinel/azure-function/*`
  - `docs/sentinel/architecture.md`

## Recommended operating model

In this guide, "drift" means change-over-time telemetry: events that indicate your trust boundary or protections changed recently, not just whether a setting is currently compliant.

Mode selection:

- `-Mode Audit`: posture snapshot only.
- `-Mode Drift`: change events only (from org audit log and/or baseline diff).
- `-Mode Both`: posture + change telemetry together (recommended for most Microsoft Sentinel schedules).

Use a dedicated scheduled ingestion job as your default pattern.

- Run every 6 hours as a practical baseline.
- Keep manual dispatch enabled for incident response and validation.
- Add event-driven runs only for high-signal paths (for example workflow-file changes).
- Do not emit full Microsoft Sentinel telemetry on every application CI run unless there is a specific use case.

Why this model works:

- Drift checks are lookback-based and fit periodic polling.
- Scheduled runs reduce duplicate findings and alert noise.
- Security telemetry stays independent from application build outcomes.

## Architecture diagrams

- End-to-end solution architecture: `docs/ARCHITECTURE.md`
- Microsoft Sentinel ingestion flow: `docs/sentinel/architecture.md`

## Setup and configuration

### 1) Deploy Azure ingestion resources (Bicep)

Deploy with the single resource-group scoped Bicep template (`docs/sentinel/deploy/fylgyr-sentinel.bicep`).

This template can create or re-use the Log Analytics workspace, either onboard Sentinel (`sentinelMode = 'new'`) or use existing Sentinel onboarding (`sentinelMode = 'existing'`), create or re-use the DCE, configure the DCR stream/transform, create or re-use Key Vault for `GITHUB_TOKEN` secret reference, and optionally assign `Monitoring Metrics Publisher` on the DCR.

`runtimeMode` controls runtime assets:

- `githubActions` (default): ingestion infrastructure only.
- `azureFunction`: ingestion infrastructure plus Azure Function runtime infrastructure (storage account, plan, function app, managed identity DCR role assignment, and managed identity Key Vault secret-read role assignment).

For detailed deployment parameters and post-deploy steps, use the install guide at `docs/sentinel/deploy/README.md`.

Most organizations should use existing workspace/Microsoft Sentinel mode:

- `workspaceMode = 'existing'`
- `sentinelMode = 'existing'`

Prerequisites for deployment commands:

- Azure CLI installed and available in your shell.
- Signed in to Azure and targeting the correct subscription.
- Bicep support available in Azure CLI (`az bicep`).
- If `az --version` returns "command not found", install Azure CLI first: https://learn.microsoft.com/cli/azure/install-azure-cli

```powershell
# Verify Azure CLI is installed
Get-Command az -ErrorAction SilentlyContinue
az --version

# Update Azure CLI (after it is installed)
az upgrade --yes

# Sign in and select subscription
az login
az account set --subscription '<subscription-id-or-name>'

# Ensure Bicep support is available in Azure CLI
az bicep install
az bicep version
```

Example Bicep deployment:

```powershell
az deployment group create `
  --resource-group <rg-name> `
  --template-file docs/sentinel/deploy/fylgyr-sentinel.bicep `
  --parameters docs/sentinel/deploy/fylgyr-sentinel.bicepparam
```

Capture outputs:

- `dcrImmutableId`
- `dceLogsIngestionUri`
- `streamNameOut`

### 2) Configure identity and Azure role

Supported auth modes, in preferred order:

1. Managed Identity (`-UseManagedIdentity`) for Azure-hosted runtimes.
2. Workload identity federation (OIDC) with federated token input.
3. Client secret fallback (`-ClientSecret`) only when required.

There is no IMDS fallback in `Send-FylgyrToLogAnalytics` today. Bare Azure VMs would be the only deployment where an IMDS-based token flow would be relevant.

`Send-FylgyrToLogAnalytics` also validates ingestion endpoints and requires HTTPS with non-local, non-private, and non-link-local targets. Private-link or localhost-style endpoints are not supported by this helper's current public-ingestion model.

| Deployment | Auth method | IMDS needed? |
| --- | --- | --- |
| GitHub Actions | OIDC / federated token | No |
| Azure Functions | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` | No |
| Azure Container Apps | `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` | No |
| Azure App Service | `MSI_ENDPOINT` + `MSI_SECRET` | No |
| Bare Azure VM | IMDS | Yes — this is the only case |

Grant `Monitoring Metrics Publisher` on the target DCR to the ingestion identity.

For `runtimeMode = 'azureFunction'`, also ensure the Function managed identity has `Key Vault Secrets User` on the vault that contains the GitHub token secret.

### 3) Choose ingestion runtime pattern

#### Option A: GitHub Actions (OIDC)

Use `docs/sentinel/github-actions-cron.yml`.

Requirements:

- Workflow permissions include `id-token: write` and `contents: read`.
- Azure federated credential configured for the workflow identity.
- Repo/org secrets set for `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_DCR_IMMUTABLE_ID`, and `AZURE_DCE_URI`.

#### Option B: Azure Function timer (Managed Identity)

Use files under `docs/sentinel/azure-function/`.

Requirements:

- Function App managed identity enabled.
- Required app settings configured (`FYLGYR_OWNER`, `FYLGYR_DCR_IMMUTABLE_ID`, `FYLGYR_DCE_URI`, `GITHUB_TOKEN`; optional `FYLGYR_REPO`, `FYLGYR_STREAM_NAME`, `FYLGYR_MODULE_SOURCE`).
- `FYLGYR_REPO` behavior:
  - set to scan a single repository under `FYLGYR_OWNER`.
  - leave empty to enumerate and scan all repositories for `FYLGYR_OWNER`.
- `GITHUB_TOKEN` should be provided through Key Vault secret reference (generated by the Bicep template from Key Vault parameters).
- Use a fine-grained PAT in that Key Vault secret. Recommended repository permissions: `Contents: Read`, `Administration: Read`, `Secret scanning alerts: Read`, `Dependabot alerts: Read`.
- Module source behavior (`FYLGYR_MODULE_SOURCE`):
  - `Bundled` (default): bundled module only (no PSGallery dependency).
  - `Auto`: PSGallery latest install with bundled fallback.
  - `Gallery`: PSGallery latest install only.
- If using `Gallery` or `Auto`, the worker needs outbound HTTPS access to PowerShell Gallery.
- DCR role assignment (`Monitoring Metrics Publisher`) granted to the function identity.
- Key Vault role assignment (`Key Vault Secrets User`) granted to the function identity.
- Publish Function zip package (run.ps1 + function.json + bundled module) with `scripts/publish-fylgyr-function-package.ps1`.

### 4) Run scan and ingest

Generate Log Analytics-formatted NDJSON:

```powershell
Invoke-Fylgyr -Owner 'my-org' -Repo 'my-repo' -Mode Both -OutputFormat LogAnalytics -OutputPath './fylgyr-la.ndjson'
```

Send to Azure Monitor Logs:

```powershell
Get-Content ./fylgyr-la.ndjson |
  Send-FylgyrToLogAnalytics `
    -DcrImmutableId 'dcr-00000000000000000000000000000000' `
    -DceUri 'https://example.westeurope-1.ingest.monitor.azure.com' `
    -StreamName 'Custom-FylgyrRaw' `
    -UseManagedIdentity
```

### 5) Validate in Sentinel

```kql
Fylgyr_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, Mode_s, CheckName_s, Severity_s, Owner_s, Repo_s, Target_s, Resource_s, Detail_s
```

Attribution columns in `Fylgyr_CL`:

- `Target_s`: canonical target context emitted by the check (for example `owner/repo`, org resource identifiers).
- `Owner_s`: extracted owner when `Target_s` or `Resource_s` contains an `owner/repo` prefix.
- `Repo_s`: extracted repository when `Target_s` or `Resource_s` contains an `owner/repo` prefix.

Then enable the sample analytics rules in `docs/sentinel/rules/` and tune lookback/suppression for your cadence.

## Baseline integrity (drift mode)

The drift baseline (`-BaselinePath`) drives finding *suppression*: drift mode reports differences from the baseline, so anyone who can rewrite the baseline file can silently hide a malicious change from the next scan. Treat the baseline as a security artifact:

- **Store baselines in immutable or write-restricted storage.** For Azure-hosted pipelines, use an Azure Blob Storage container with a [time-based immutability policy (WORM)](https://learn.microsoft.com/azure/storage/blobs/immutable-storage-overview), versioning enabled, and write access restricted to the scan identity (managed identity or federated workflow). Each scan writes a new versioned snapshot rather than overwriting.
- **Never commit baselines to the repository being scanned.** A contributor with push access to the scanned repo must not be able to influence what the next scan suppresses.
- **Restrict reads to the scan identity and security team.** Baselines describe your protection posture — useful reconnaissance for an attacker.
- **Prefer audit-log-backed drift where available.** Audit-log findings carry actor attribution and do not depend on baseline integrity; baseline diff is the fallback path.

## Security controls implemented in Fylgyr

- HTTPS-only GitHub API communication.
- Drift findings include `Evidence.Source` (`audit-log` or `baseline-diff`).
- Baseline fallback details explicitly note missing actor attribution.
- Baseline JSON parsing is depth-bounded and failures degrade to a controlled `BaselineDiff` error result.
- Log ingestion retry uses bounded exponential backoff.
- No token values included in findings or evidence payloads; the client-secret fallback clears the plaintext secret immediately after token acquisition.
