# Azure Function timer sample

This sample runs Fylgyr every 6 hours and ingests findings into Azure Monitor.

## Required app settings

- `FYLGYR_OWNER`
- `FYLGYR_REPO` (optional if you adapt to org-wide iteration)
- `FYLGYR_DCR_IMMUTABLE_ID`
- `FYLGYR_DCE_URI`
- `GITHUB_TOKEN` (recommend Key Vault reference)

## Identity

Enable managed identity for the Function App and assign `Monitoring Metrics Publisher` on the target DCR.

## Notes

- For private networking, place Function in a VNet with AMPLS private endpoint DNS resolution.
- Keep app settings in Key Vault references where possible.
