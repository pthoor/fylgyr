# Fylgyr Solution Architecture

This page documents the end-to-end architecture for Fylgyr and the Sentinel integration.

## End-to-end solution flow

```mermaid
flowchart LR
    subgraph Source[GitHub]
      A[Repository workflows and settings]
      B[Organization policies and audit events]
    end

    subgraph Engine[Fylgyr engine]
      C[Invoke-Fylgyr orchestrator]
      D[Repository and org checks]
      E[Attack mapping from attacks.json]
      F[Normalized result schema]
    end

    subgraph Outputs[Output formats]
      G[Console and Object]
      H[JSON and NDJSON]
      I[SARIF]
      J[LogAnalytics NDJSON]
      K[HTML report]
    end

    subgraph Consumers[Downstream consumers]
      L[Maintainer triage]
      M[GitHub Code Scanning]
      N[SIEM and stream pipelines]
      O[Microsoft Sentinel]
      P[Stakeholder reporting]
    end

    A --> C
    B --> C
    C --> D
    D --> E
    E --> F

    F --> G
    F --> H
    F --> I
    F --> J
    F --> K

    G --> L
    I --> M
    H --> N
    J --> O
    K --> P
```

## Sentinel integration flow (current scope)

This diagram reflects the currently supported rollout:

- Scheduled ingestion job as default
- Public Azure Monitor ingestion endpoint over TLS
- No VNet integration required

```mermaid
flowchart LR
    A[Scheduled scan job every 6h] --> C[Invoke-Fylgyr Mode Both]
    B[Manual dispatch for incident response] --> C

    C --> D[Audit findings]
    C --> E[Drift findings]
    E --> F{Drift evidence source}
    F -->|Primary| G[Org audit log]
    F -->|Fallback| H[Baseline diff]

    D --> I[LogAnalytics NDJSON]
    E --> I

    I --> J[Send-FylgyrToLogAnalytics]
    J --> K[DCE ingestion endpoint public]
    K --> L[DCR transform]
    L --> M[Fylgyr_CL]

    M --> N[Sentinel analytics rules]
    M --> O[Sentinel workbook]
```

## Runtime choices for ingestion

You can run the ingestion job with either runtime:

1. GitHub Actions schedule with OIDC federation.
2. Azure Function timer with managed identity.

Both patterns use the same DCR stream and Sentinel artifacts under docs/sentinel.
