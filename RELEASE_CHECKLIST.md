# Release Checklist

## Phase 1 Merge Readiness

- [ ] Phase 1 PR merged to main from phase1/foundation.
- [ ] CI workflow is green on main.
- [ ] Repository settings enforce branch protection on main.
- [ ] PSGALLERY_API_KEY exists in repository secrets.

## Pre-Tag Validation

Run from repository root:

```powershell
Test-ModuleManifest -Path ./src/Fylgyr/Fylgyr.psd1
Import-Module ./src/Fylgyr/Fylgyr.psm1 -Force
Invoke-Pester -Path ./tests -Output Detailed
Invoke-ScriptAnalyzer -Path ./src -Recurse -Severity Error,Warning
```

- [ ] Manifest validation passes.
- [ ] Module imports without error.
- [ ] Pester tests pass.
- [ ] PSScriptAnalyzer passes.

## Changelog and Metadata

- [ ] Update CHANGELOG.md for the release version.
- [ ] Confirm ModuleVersion in src/Fylgyr/Fylgyr.psd1 matches release tag.
- [ ] Confirm README badges and links are correct.

## Tag and Release

```bash
git switch main
git pull --ff-only
git tag -a v0.1.0 -m "Fylgyr v0.1.0"
git push origin v0.1.0
```

- [ ] Release workflow succeeds.
- [ ] Module appears on PSGallery.
- [ ] Create GitHub Release notes from CHANGELOG.md.

## Post-Release

- [ ] Verify Install-Module Fylgyr from a clean environment.
- [ ] Open Phase 2 tracking issue and milestone.
