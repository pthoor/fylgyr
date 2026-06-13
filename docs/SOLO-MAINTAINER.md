# Solo-Maintainer Security Baseline

This is the hardening baseline for a repository maintained by **one person**.

Most "best practice" checklists quietly assume a team. Several of them — "require
1 approving review", "assign 2+ code owners" — are not merely hard for a solo
maintainer, they are *structurally impossible*: you cannot review your own pull
request as a second person. Chasing them produces guilt, not security.

So this baseline is built around a different question:

> **What raises an attacker's cost without requiring a second human?**

For a one-person project the realistic threats are not a malicious pull request
sneaking past review (there is no review). They are:

1. **Your credentials get stolen** — a leaked PAT, a phished session, a
   compromised laptop.
2. **A dependency or action you trust gets compromised** — the supply-chain
   path (event-stream, ua-parser-js, tj-actions, Shai-Hulud).
3. **You make a mistake** — a force-push, an accidental secret commit.

Everything below maps to one of those, and almost none of it needs a second
person.

---

## Tier 1 — highest impact, ~zero friction (do these first)

### 1. Hardware-backed 2FA / passkey on your account

This is the single biggest control for a solo maintainer, because account
takeover is threat #1. A passkey or hardware security key (WebAuthn) defeats
phishing in a way that TOTP codes do not.

- GitHub → Settings → Password and authentication → add a passkey or security key.
- Fylgyr's `AccountSecurity` check reports your 2FA posture (when scanned with a
  token owned by the account).

### 2. Short-lived, narrowly-scoped tokens

A leaked token with `repo` + `admin:org` is a catastrophe; a leaked token scoped
to one repo, read-only, expiring in 7 days is a shrug.

- Prefer **fine-grained PATs** scoped to a single repository, read-only, with a
  short expiry.
- Keep the workflow `GITHUB_TOKEN` read-only (see Tier 1.3).
- See [PERMISSIONS.md](PERMISSIONS.md) for the minimum scopes each check needs.

### 3. Lock down the default `GITHUB_TOKEN`

- Settings → Actions → General → Workflow permissions → **Read repository
  contents and packages permissions** (read-only default).
- Disallow "Allow GitHub Actions to create and approve pull requests".
- Fylgyr's `DefaultTokenPermission` check verifies both.

### 4. Pin everything in CI

- SHA-pin every `uses:` reference (actions **and** reusable workflows).
- Pin container images to a digest (`image@sha256:...`), not a tag.
- Run an egress firewall first in every job:
  `step-security/harden-runner` with `egress-policy: block`.
- Fylgyr checks: `ActionPinning`, `ContainerPinning`, `ReusableWorkflowTrust`,
  `EgressControl`.

---

## Tier 2 — strong, low friction, machine-enforced (no human needed)

### 5. SSH commit signing + Vigilant Mode

You do not need GPG. SSH signing reuses the key you already push with.

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then:

- Add the public key as a **signing key** (GitHub → Settings → SSH and GPG keys
  → New SSH key → key type: *Signing Key*).
- Turn on **Vigilant Mode** (Settings → SSH and GPG keys → Flag unsigned commits
  as unverified). This makes any commit *not* signed by you show as "Unverified"
  on your history — that is the detection win against an attacker pushing as you.
- Enforce it in your ruleset (next step). Fylgyr's `SignedCommit` check now
  recognizes enforcement via either classic branch protection **or** a ruleset.

> **What signing does and does not do.** The green "Verified" badge is *not* a
> security boundary — commits made through the GitHub web UI are signed by
> GitHub's web-flow key, and an attacker who has compromised your account can
> register their own signing key. Signing's real value for a solo maintainer is
> *detection of impersonation* via Vigilant Mode, not prevention. For published
> releases, signing **tags** is the higher-value move.

### 6. A ruleset that machines can enforce

Create a branch ruleset on your default branch (Settings → Rules → Rulesets) with:

- **Require a pull request before merging** — but set **required approvals to 0**.
  (You cannot approve your own PR; requiring 1 would lock you out of your own
  repo. 0 approvals with a required CI gate is the documented solo tradeoff.)
- **Require status checks to pass** — *this is your reviewer.* CI is the second
  opinion a solo project can actually have. Add your build/test/lint checks.
- **Block force-pushes** (non-fast-forward).
- **Block deletion.**
- **Require signed commits** (`required_signatures`).
- Do **not** add always-on bypass actors — a bypass actor's compromise defeats
  the whole ruleset.

Fylgyr checks: `BranchProtection`, `Rulesets`, `SignedCommit`.

### 7. Catch the rest automatically

- **Secret scanning + push protection** on (blocks credential pushes *before*
  they reach history). Fylgyr: `SecretScanning`.
- **Dependabot alerts** on. Fylgyr: `DependabotAlert`.
- **`--ignore-scripts` for CI installs** (`npm ci --ignore-scripts`), so a
  compromised transitive dependency cannot run install-time code on your runner.
  Fylgyr: `LifecycleScript`.
- **Protect release tags** with a tag ruleset (block deletion + non-fast-forward)
  so a published release cannot be silently re-pointed. Fylgyr: `TagProtection`.
- **Sign release tags** (Tier 2.5 sets `tag.gpgsign true`); for a PowerShell
  module published to the Gallery, Authenticode-sign the module as the
  ecosystem-native provenance signal. Fylgyr: `PublishIntegrity`,
  `ArtifactAttestation`.

---

## Tier 3 — accept with rationale (structurally impossible solo)

These are real controls, but you cannot satisfy them alone:

| Control | Why you can't do it solo | Compensating control |
|---|---|---|
| Require ≥ 1 approving review | You can't approve your own PR | Required status checks (CI gate) + signed commits + hardware 2FA |
| 2+ distinct CODEOWNERS | There is only one of you | Same as above; revisit if you add a collaborator or move to an org |

Document this decision (a `SECURITY.md` note is enough) so it is a *conscious
accepted risk*, not an oversight. If you later add a collaborator or migrate the
repo into an organization, promote these from "accepted" to "enforced".

### Make Fylgyr stop nagging about the impossible ones

Run Fylgyr with the solo-maintainer profile. It re-ranks exactly the Tier-3
findings (the 0-approvers branch finding and single-owner CODEOWNERS findings) to
an informational, non-blocking status and appends the compensating-control note,
while leaving every Tier-1/2 guardrail at full severity:

```powershell
Invoke-Fylgyr -Owner 'your-user' -Repo 'your-repo' -SoloMaintainer -OutputFormat Console
```

Combined with a CI gate, the impossible-solo findings no longer fail your build:

```powershell
Invoke-Fylgyr -Owner 'your-user' -Repo 'your-repo' -SoloMaintainer -FailOn High
```

The result is a clean, achievable punch-list instead of unfixable noise.

---

## The 10-minute version

If you do nothing else:

1. Add a **passkey** to your GitHub account.
2. Turn on **SSH commit signing** + **Vigilant Mode** (the four `git config`
   lines above).
3. Create a **ruleset**: require PR (0 approvals) + required status checks +
   block force-push + block deletion + require signed commits.
4. Turn on **secret scanning push protection** and **Dependabot**.
5. Scan with `Invoke-Fylgyr -SoloMaintainer` and clear whatever is left.

See also: [MAINTAINER-GUIDE.md](MAINTAINER-GUIDE.md) for install and token setup,
and the "Recommended Protection Baseline" section of the
[README](../README.md#recommended-protection-baseline).
