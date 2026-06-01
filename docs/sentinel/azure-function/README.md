# Azure Function timer sample

This sample runs Fylgyr every 6 hours and ingests findings into Azure Monitor.

At cold start, the function loads the `Fylgyr` module based on `FYLGYR_MODULE_SOURCE`:

- `Bundled` (default): uses only the module bundled in the function package.
- `Auto`: installs latest from PSGallery, then falls back to bundled module if gallery is unavailable.
- `Gallery`: installs latest from PSGallery only.

## Required app settings

- `FYLGYR_OWNER`
- `FYLGYR_REPO` (optional; leave empty for owner-wide repo enumeration)
- `FYLGYR_MODE` (optional, default `Audit`; allowed: `Audit`, `Drift`, `Both`)
- `FYLGYR_DCR_IMMUTABLE_ID`
- `FYLGYR_DCE_URI`
- `FYLGYR_STREAM_NAME` (optional, defaults to `Custom-FylgyrRaw`)
- `FYLGYR_MODULE_SOURCE` (optional, default `Bundled`; allowed: `Auto`, `Gallery`, `Bundled`)
- `GITHUB_TOKEN` (recommend Key Vault reference)

## Identity

Enable managed identity for the Function App and assign:

- `Monitoring Metrics Publisher` on the target DCR.
- `Key Vault Secrets User` on the Key Vault that stores the GitHub token secret.

## Notes

- This sample assumes public Azure Monitor ingestion over TLS 1.2+.
- No VNet integration is required for the initial rollout.
- Keep app settings in Key Vault references where possible.
- The deployment template configures PowerShell 7.6 runtime for the Function App.
- Outbound HTTPS access to `www.powershellgallery.com` is required only when `FYLGYR_MODULE_SOURCE` is `Auto` or `Gallery`.
- For egress-restricted environments, set `FYLGYR_MODULE_SOURCE=Bundled` and include the `Fylgyr` module in your Function package under `Modules/`.
- For production, keep `FYLGYR_MODULE_SOURCE=Bundled` to avoid runtime module supply-chain drift.
- The sample validates owner/repo names (repo is optional) and enforces HTTPS for `FYLGYR_DCE_URI`.
- NSP is a future hardening option; AMPLS/private endpoint topology is out of scope for this sample.
