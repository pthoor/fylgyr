# Contributing to Fylgyr

Thank you for helping improve supply chain security.

## Add a New Check

1. Create a new `Test-<Name>.ps1` file in `src/Fylgyr/Public/`.
2. Implement detection logic and return standardized output through `Format-FylgyrResult`.
3. Add or update Pester tests in `tests/`.
4. Map findings to campaign IDs from `src/Fylgyr/Data/attacks.json`.
5. Run `Invoke-ScriptAnalyzer -Path ./src -Recurse` and `Invoke-Pester ./tests`.

## Add a New Attack Mapping

Open a PR that updates `src/Fylgyr/Data/attacks.json` with a new object including all required fields:

- `id` (slug)
- `name`
- `date` (ISO 8601)
- `description`
- `affectedPackages` (array)
- `cves` (array, can be empty)
- `references` (array of URLs)
- `detectionSignals` (array)

## Coding Standards

- Use approved PowerShell verbs (`Get-Verb`).
- All check output must be generated via `Format-FylgyrResult`.
- Never hardcode tokens or secrets.
- Target PowerShell 7+ only.
- Keep PSScriptAnalyzer findings at zero.

## Pull Requests

Use the PR template and include tests for all behavior changes.

## Code of Conduct

This project follows [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
