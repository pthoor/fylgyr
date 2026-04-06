# Copilot Instructions for Fylgyr

## What This Project Is

Fylgyr is a PowerShell 7+ security tool that audits GitHub repositories for supply chain risks. Every finding maps to a real-world attack campaign. This is a **security tool** — it must not contain security vulnerabilities itself.

## Security Requirements — MANDATORY

These rules apply to every code change. No exceptions.

### Error handling and information leakage
- **Never use raw `$_` in error messages.** Always use `$_.Exception.Message` to prevent leaking stack traces, tokens, or internal paths.
- **Sanitize API error responses** before including them in output. Parse JSON error bodies and extract only the `.message` field.
- **Never log, display, or include tokens** in error messages, warnings, verbose output, or result objects.

### Input validation
- **All Owner/Repo parameters must use `[ValidatePattern('^[a-zA-Z0-9._-]+$')]`** to reject injection attempts.
- **Enforce HTTPS-only** for all API communication. HTTP endpoints must be explicitly rejected.

### Safe coding patterns
- **Never use `Invoke-Expression`, `Start-Process`, or dynamic code execution.**
- **Never use `ConvertFrom-SecureString`** or store credentials in any form.
- **Bound all loops** — pagination must have a maximum page limit to prevent infinite loops.
- **Wrap external data decoding** (Base64, JSON) in try/catch blocks.

### Output safety
- **Treat all data from the GitHub API as untrusted.** Repository names, file paths, and alert details could contain special characters.
- **Use `ConvertTo-Json` for structured output** — never manual string concatenation for JSON or SARIF.

## Code Conventions

- All checks go in `src/Fylgyr/Public/Test-<Name>.ps1`
- All checks must call `Format-FylgyrResult` and map to attack IDs from `Data/attacks.json`
- Use approved PowerShell verbs only (`Get-Verb`)
- All functions must declare `[OutputType(...)]`
- Use `[System.Collections.Generic.List[PSCustomObject]]` for arrays — never `+=` in a loop
- Strip YAML comment lines (`^\s*#`) before pattern matching
- Use `return` inside a `process` block only when it is intentional for pipeline-aware control flow and consistent with existing function patterns; avoid unnecessary `return` statements that make processing behavior unclear
- PSScriptAnalyzer must report zero errors and zero warnings

## Before Completing Any Change

1. Run `Invoke-ScriptAnalyzer -Path ./src -Recurse -Severity Error,Warning` — zero findings
2. Run `Invoke-Pester -Path ./tests -Output Detailed` — zero failures
3. Verify the README is up to date with any new checks, attack mappings, or features
