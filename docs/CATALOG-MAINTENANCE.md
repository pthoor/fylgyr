# Attack Catalog Maintenance

The attack catalog (`src/Fylgyr/Data/attacks.json`) is Fylgyr's primary differentiator over score-based tools. If it goes stale, the differentiator dies. This document defines the maintenance discipline.

## Review cadence

**Monthly triage — first Monday of each month (Pierre).**

Spend 30–60 minutes scanning the sources below and running each new or updated incident through the triage rubric. The goal is not exhaustive coverage of every CVE — it is high-signal incidents that reveal new attack primitives or validate existing checks.

## Sources to watch

| Source | What to look for |
|---|---|
| [GitHub Security Lab](https://securitylab.github.com/research/) | New pwn-request patterns, action poisoning, injection research |
| [OpenSSF advisories](https://openssf.org/blog/) | Ecosystem-wide supply chain findings |
| [StepSecurity blog](https://www.stepsecurity.io/blog) | Real-world CI/CD attack detections |
| [Sysdig blog](https://sysdig.com/blog/) | Runner abuse, cryptomining, container attack chains |
| [Aikido blog](https://www.aikido.dev/blog) | Dependency confusion, malicious package campaigns |
| [Socket research](https://socket.dev/research) | npm/PyPI malicious packages, maintainer account compromises |
| [Praetorian blog](https://www.praetorian.com/blog/) | Red-team runner pivot, lateral movement case studies |
| [BleepingComputer](https://www.bleepingcomputer.com/news/security/) | Incident reporting with follow-up corrections and vendor quotes |
| [Snyk vulnerability DB](https://security.snyk.io/) | New CVEs in CI/CD tooling |
| [NVD](https://nvd.nist.gov/) | CI/CD-tagged CVEs (filter: GitHub Actions, npm, build systems) |
| [MITRE ATT&CK updates](https://attack.mitre.org/resources/updates/) | New or revised supply-chain techniques |
| [Mandiant / Google Cloud threat intel](https://cloud.google.com/blog/topics/threat-intelligence) | Nation-state supply chain campaigns |
| [Ransomware.live](https://ransomware.live/) | Leak-site claim monitoring; treat as unverified until corroborated |

## Triage rubric

For each new incident, answer three questions:

1. **Does it map to an existing `attacks.json` entry?**
   → Enrich the existing entry: add `detectionSignals`, update `references`, add CVEs. No schema change needed.

2. **Is it a new TTP not covered by any existing entry?**
   → Add a new entry (see schema requirements below). Flag it in the monthly triage notes.

3. **Does it expose a gap in our checks?**
   → Add to the backlog in `docs/COVERAGE.md` (Roadmap Signal section) as a candidate check with the relevant OWASP/MITRE mapping.

## Claim verification rule

For extortion and leak-site incidents, separate **claims** from **confirmed facts** before editing `attacks.json`:

1. **First-party confirmation preferred**
   - Vendor disclosure (blog/advisory/status post), regulator filing, or direct incident statement.

2. **Independent corroboration required for attribution**
   - At least one reputable secondary source (for example, BleepingComputer, Mandiant, major vendor threat intel) in addition to leak-site/tracker claims.

3. **Catalog wording discipline**
   - If attribution is uncertain, phrase entries as "claimed" or "assessed" and avoid definitive actor linkage.
   - Keep `detectionSignals` focused on defender-observable behavior, not actor branding.

## Schema requirements

Every `attacks.json` entry must contain all eight base fields plus the two governance fields. Pester enforces this at test time — a CI failure here means a required field is missing.

**Required fields:**

| Field | Type | Notes |
|---|---|---|
| `id` | string | kebab-case, unique, never reused |
| `name` | string | Human-readable campaign name |
| `date` | string | ISO 8601 (`YYYY-MM-DD`); use `YYYY-01-01` if only year is known |
| `description` | string | 2–5 sentence summary of the attack and why it matters |
| `affectedPackages` | array | Empty `[]` for generic patterns |
| `cves` | array | Empty `[]` if none |
| `references` | array | At least one authoritative source |
| `detectionSignals` | array | 3–6 observable indicators; phrased as what a defender would see |
| `owaspCiCd` | array | One or more of `CICD-SEC-1` through `CICD-SEC-10` |
| `mitre` | array | One or more MITRE ATT&CK technique IDs (e.g. `T1195.002`) |

**Do not use empty `[]` for `owaspCiCd` or `mitre`** — if a technique truly has no mapping, document the justification in a PR comment rather than leaving it empty and breaking tests.

## Catalog-only releases

The catalog can ship as a standalone patch release (e.g. v0.4.x) without any code changes when a high-impact incident lands between scheduled feature releases. This keeps the differentiator fresh without waiting for the next phase.

Criteria for a catalog-only release:
- Incident has significant public coverage (major security blogs, CVE assigned, or named campaign).
- New entry adds at least two distinct `detectionSignals` not already in the catalog.
- All Pester tests pass with the new entry.
- `docs/COVERAGE.md` is updated if the new entry maps to a CICD-SEC or MITRE technique not yet in the matrix.
- Version bumped as a patch (third digit).

## Update `docs/COVERAGE.md`

After any catalog change, verify that `docs/COVERAGE.md` is still accurate:
- New entries → add rows to the OWASP and MITRE tables.
- Enriched entries → update the coverage cell if a new OWASP/MITRE ID was added.
- New checks → add the check name to the covering checks column.
- Open gap closed → move the row from Roadmap Signal to the main tables.
