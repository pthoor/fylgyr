# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes (latest: 0.3.2) |
| < 0.3   | No                  |

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting flow for this repository.

- Go to the **Security** tab in this repository.
- Create a private vulnerability report using **GitHub Security Advisories**.
- Include clear reproduction steps, impact, and any known mitigations.

Do not report vulnerabilities by email or in public issues.

## Response Expectations

We will acknowledge valid reports as quickly as possible and coordinate fixes,
validation, and disclosure through the advisory workflow.

## Scope

The following are in scope for security reports:

- Credential or token leakage via error messages, logs, or output formats.
- Command injection or code execution via crafted repository names, workflow content, or API responses.
- SARIF or JSON output that could be exploited when imported into downstream tools.
- Bypass of checks that would cause a dangerous configuration to be reported as safe.

Out of scope:

- Findings about repositories Fylgyr scans (those are the repository owner's responsibility).
- Rate-limit exhaustion (this is a known constraint of the GitHub API).

## Security Considerations for Users

- **Token handling**: Fylgyr reads your GitHub token from `$env:GITHUB_TOKEN` or the `-Token` parameter. Tokens are never written to disk, logged, or included in output. Use fine-grained personal access tokens with the minimum required scopes.
- **Output content**: Scan results may contain repository names, file paths, and alert details from the GitHub API. Treat output as potentially sensitive if scanning private repositories.
- **Network**: All API calls are made over HTTPS to `api.github.com`. HTTP is explicitly rejected.
- **No outbound data**: Fylgyr does not phone home, collect telemetry, or send data to any service other than the GitHub API.

## Security Design Principles

This module follows these principles in its own code:

1. **Input validation** on all user-facing parameters (Owner, Repo).
2. **Error sanitization** to prevent token or path leakage in exception messages.
3. **HTTPS-only** enforcement for all API communication.
4. **Bounded pagination** to prevent infinite loops from malformed API responses.
5. **No dynamic code execution** (`Invoke-Expression`, `Start-Process`, etc. are never used).
6. **Least-privilege workflows** with SHA-pinned actions and scoped permissions.
