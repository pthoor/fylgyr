# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes (latest: 0.3.2) |
| < 0.3   | No                  |

## Reporting a Vulnerability

Please use GitHub's private vulnerability reporting flow for this repository.

1. Go to this repository's **Security** tab.
2. Open **Advisories**.
3. Click **Report a vulnerability** (or **New draft security advisory** if shown).
4. Submit a private report that includes:
	- clear reproduction steps
	- affected branch, tag, or release version
	- impact statement (what an attacker can do)
	- expected vs actual behavior
	- supporting evidence (logs/screenshots/commits) with secrets redacted

Do not report vulnerabilities by email or in public issues.

## Report Template (Copy/Paste)

Use this template in your private advisory submission:

```markdown
## Summary
Short description of the vulnerability.

## Affected Component
- Repository:
- Branch/Tag/Version:
- File/Workflow (if known):

## Impact
What can an attacker do if this is exploited?

## Reproduction Steps
1.
2.
3.

## Expected vs Actual Behavior
- Expected:
- Actual:

## Evidence
- Logs/Screenshots/Commits (redact all secrets):

## Suggested Mitigation (Optional)
Any workaround or fix ideas.
```

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
