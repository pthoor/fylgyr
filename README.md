# Fylgyr

> Guardian spirit for your repos

[![CI](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml/badge.svg)](https://github.com/pthoor/Fylgyr/actions/workflows/ci.yml)
[![PSGallery Version](https://img.shields.io/powershellgallery/v/Fylgyr)](https://www.powershellgallery.com/packages/Fylgyr)

Fylgyr audits GitHub repositories and organizations for supply chain risks by mapping every finding to a real-world attack campaign.

Unlike score-based tools such as [OpenSSF Scorecard](https://securityscorecards.dev/), Fylgyr is attack-mapped, not score-based. Every finding explains which known campaign it aligns with and why that behavior matters.

## Attack Catalog (Initial)

| ID | Campaign | Date | Summary |
|---|---|---|---|
| `trivy-tag-poisoning` | Trivy tag poisoning | 2024 | Attacker force-pushed a malicious commit to a Trivy release tag. |
| `tj-actions-shai-hulud` | tj-actions/changed-files (Shai-Hulud) token exfil | 2025-03 | Compromised action exfiltrated CI secrets through workflow logs. |
| `nx-pwn-request` | nx/Pwn Request | 2025 | PR-trigger abuse enabled arbitrary code execution in CI context. |
| `axios-npm-token-leak` | Axios npm token leak | 2024 | npm publish token leaked in CI logs and was reused for malicious publishes. |
| `trivy-force-push-main` | Trivy force-push to main | 2024 | Direct force-push to main succeeded due to insufficient branch protection. |

## Installation

```powershell
Install-Module Fylgyr
```

## Quick Usage

```powershell
Invoke-Fylgyr -Owner <org> -Repo <repo>
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
