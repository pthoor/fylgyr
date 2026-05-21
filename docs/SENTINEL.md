# Fylgyr Sentinel Integration (Phase 9.5)

This guide explains how to stream Fylgyr findings to Microsoft Sentinel through Azure Monitor Logs Ingestion API.

## What ships in Phase 9.5

- Drift mode in `Invoke-Fylgyr` (`-Mode Drift` and `-Mode Both`)
- Log Analytics formatter (`-OutputFormat LogAnalytics`)
- Ingestion helper: `Send-FylgyrToLogAnalytics`
- Sentinel artifacts:
  - `docs/sentinel/dcr.json`
  - `docs/sentinel/table-schema.json`
  - `docs/sentinel/rules/*.yaml`
  - `docs/sentinel/workbook.json`
  - `docs/sentinel/github-actions-cron.yml`
  - `docs/sentinel/azure-function/*`
  - `docs/sentinel/architecture.mmd`

## Authentication model (secure-by-default)

`Send-FylgyrToLogAnalytics` supports these auth modes in order of preference:

1. Managed Identity (`-UseManagedIdentity`) for Azure Functions or other Azure-hosted runtimes.
2. Workload identity federation (OIDC) by passing a federated token (`-FederatedToken` or `-FederatedTokenFile`).
3. Service principal client secret (`-ClientSecret`) as fallback only.

Never print secrets or tokens to logs.

## Required Azure permissions

Assign `Monitoring Metrics Publisher` on the Data Collection Rule (DCR) to the identity that sends data.

For deployment automation, additional Contributor scopes may be needed on DCR/DCE resource groups.

## Endpoint model

`Send-FylgyrToLogAnalytics` accepts either:

- `-DcrEndpointUri` for direct DCR ingestion endpoint.
- `-DceUri` for Data Collection Endpoint path.

If your environment uses private networking, use a DCE path with AMPLS/private endpoint.

## Private endpoint support

Phase 9.5 supports private endpoint topology when you configure Azure Monitor Private Link Scope (AMPLS):

1. Create AMPLS.
2. Add Log Analytics workspace and DCE to AMPLS.
3. Create private endpoint connected to AMPLS.
4. Configure DNS zones for Azure Monitor private endpoints.
5. Set ingestion access mode to `PrivateOnly` where required.
6. Validate ingestion path resolves to private IPs from the scanning runtime.

If private link is not configured, ingestion works via public endpoint over TLS 1.2+.

## Quick start

### 1) Generate Log Analytics-shaped NDJSON

```powershell
Invoke-Fylgyr -Owner 'my-org' -Repo 'my-repo' -Mode Both -OutputFormat LogAnalytics -OutputPath './fylgyr-la.ndjson'
```

### 2) Send to Azure Monitor Logs

```powershell
Get-Content ./fylgyr-la.ndjson |
  Send-FylgyrToLogAnalytics `
    -DcrImmutableId 'dcr-00000000000000000000000000000000' `
    -DceUri 'https://example.westeurope-1.ingest.monitor.azure.com' `
    -StreamName 'Custom-FylgyrRaw' `
    -UseManagedIdentity
```

### 3) Query data in Sentinel

```kql
Fylgyr_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, Mode_s, CheckName_s, Severity_s, Resource_s, Detail_s
```

## GitHub Actions pattern (OIDC)

Use the sample workflow in `docs/sentinel/github-actions-cron.yml`.

- Request `id-token: write` in workflow permissions.
- Use Azure Login with federated credentials.
- Avoid storing client secrets in GitHub.

## Azure Function pattern (Managed Identity)

Use files under `docs/sentinel/azure-function/`.

- Enable system- or user-assigned managed identity.
- Grant identity `Monitoring Metrics Publisher` on DCR.
- Keep DCE and workspace in private-link scope when required.

## Security controls implemented in Fylgyr

- HTTPS-only GitHub API communication.
- Drift findings include `Evidence.Source` (`audit-log` or `baseline-diff`).
- Baseline fallback details explicitly note missing actor attribution.
- Log ingestion retry uses bounded exponential backoff.
- No token values included in findings or evidence payloads.
