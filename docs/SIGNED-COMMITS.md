# Signed Commits — Why It Matters and How to Enable It

## What is commit signing?

When you push a commit to GitHub, the author name and email in that commit can be anything — Git does not verify them. An attacker who has stolen a developer's credentials, or who has been granted write access through social engineering, can push commits that appear to come from any identity.

Commit signing binds a cryptographic key to each commit. GitHub verifies the signature and shows a **Verified** badge on signed commits. Unsigned commits get no badge — or an explicit **Unverified** label when required signatures are enforced. Requiring signed commits on protected branches means any commit that was not signed by a known key is rejected at push time.

## The real-world attack this defends against

The **xz-utils backdoor** (CVE-2024-3094, March 2024) is the clearest example of why this matters. An attacker operating as "Jia Tan" spent roughly two years building trust as a contributor before obtaining commit access to xz-utils, a compression library present in nearly every Linux distribution. Once trusted, they inserted an obfuscated backdoor into the build system that compromised `sshd` on affected systems.

Key factors that made this possible — and that signed commits would have complicated:

- **Unsigned commits.** The malicious commits carried no cryptographic proof of identity. A signing policy tied to known maintainer keys would have flagged commits from a new, unverified key or forced the attacker to compromise an existing key.
- **No secondary review.** The attacker leveraged social pressure to get changes merged without careful review.
- **Single maintainer with broad write access.** There was no CODEOWNERS enforcement requiring a second trusted approver.

Signed commits are not a silver bullet — an attacker who has compromised a maintainer's signing key bypasses this control. But they raise the cost of impersonation and create an auditable trail tied to physical key possession.

Fylgyr maps this check to `xz-utils-backdoor` and flags any default branch that does not require signed commits as a `Warning`.

## Signing methods supported by GitHub

| Method | Key type | Verification | Best for |
|---|---|---|---|
| GPG | RSA / EdDSA | Strong | Teams with existing GPG infrastructure |
| SSH signing | Ed25519 / RSA | Strong | Developers already using SSH keys |
| S/MIME | X.509 certificate | Strong | Enterprises with PKI |
| GitHub's web UI | GitHub-managed | GitHub-verified | Web edits only |

SSH signing (available since Git 2.34) is the lowest-friction option for most developers — you reuse the same key you already use to authenticate to GitHub.

## Step-by-step: SSH commit signing

### 1. Generate a signing key (skip if you have one)

```bash
ssh-keygen -t ed25519 -C "your@email.com" -f ~/.ssh/id_ed25519_signing
```

You can reuse your existing authentication key if you prefer — Git distinguishes signing keys from authentication keys by their allowed-signers configuration, not key type.

### 2. Add the key to GitHub as a signing key

Go to **GitHub → Settings → SSH and GPG keys → New SSH key**, select **Signing Key** as the key type, and paste your public key.

### 3. Configure Git to use SSH signing

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_signing.pub
git config --global commit.gpgsign true
```

`commit.gpgsign true` signs every commit automatically — no `-S` flag needed per commit.

### 4. Configure the allowed-signers file (needed for local verification)

```bash
mkdir -p ~/.config/git
echo "your@email.com namespaces=\"git\" $(cat ~/.ssh/id_ed25519_signing.pub)" \
  >> ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

### 5. Verify a signed commit

```bash
git log --show-signature -1
```

You should see `Good "git" signature for your@email.com` in the output.

## Step-by-step: GPG commit signing

### 1. Generate a GPG key

```bash
gpg --full-generate-key
# Choose: RSA and RSA, 4096 bits, no expiry (or set an expiry), enter email matching GitHub
```

### 2. Export the public key and add it to GitHub

```bash
gpg --armor --export your@email.com
```

Paste the output into **GitHub → Settings → SSH and GPG keys → New GPG key**.

### 3. Configure Git

```bash
# Get the key ID from: gpg --list-secret-keys --keyid-format=long
git config --global user.signingkey <KEYID>
git config --global commit.gpgsign true
```

On macOS, also run:

```bash
brew install pinentry-mac
echo "pinentry-program $(which pinentry-mac)" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

## Enabling required signed commits on GitHub

Once your team has signing configured, enforce it at the branch level:

### Classic branch protection rules

1. Go to **Settings → Branches → Branch protection rules**.
2. Edit or create a rule for your default branch (e.g., `main`).
3. Enable **Require signed commits**.
4. Save.

From this point, any push to `main` that contains an unsigned commit is rejected with:

```
remote: error: GH006: Protected branch update failed for refs/heads/main.
remote: error: Commits must have verified signatures.
```

### Rulesets (recommended for organizations)

Branch protection rules are per-repository. GitHub Rulesets let you enforce the same policy across all repositories in an organization from a single place.

1. Go to **Organization → Settings → Rules → Rulesets → New ruleset**.
2. Set the target to your default branch pattern (e.g., `~DEFAULT_BRANCH`).
3. Under **Require a commit's signature**, enable it.
4. Set enforcement to **Active**.

Rulesets support bypass lists — you can exempt service accounts or automated bots that legitimately cannot sign commits (e.g., Dependabot).

## Handling bots and automated commits

Dependabot commits (and other commits created via GitHub's web UI or API, including many GitHub App commits) are signed by GitHub's own key and carry the **Verified** badge automatically. Commits created by a workflow using `git commit` are not automatically signed unless you configure signing in the job.

For other automation (scripts, CI jobs, release bots):

- **Recommended:** Use a GitHub App instead of a PAT. App-generated commits are signed by GitHub.
- **Alternative:** Generate a dedicated GPG or SSH key for the bot, add it to GitHub as a signing key under a machine account, and configure the automation to use it.
- **Bypass via ruleset:** If the automation cannot sign, add it to the ruleset bypass list scoped to `Repository role: Write`. Scope bypasses as narrowly as possible.

## Rollout checklist for organizations

```
[ ] Survey which developers have signing configured (check GitHub profiles for GPG/SSH signing keys)
[ ] Document the signing method your org standardises on (SSH signing recommended for lowest friction)
[ ] Add signing key setup to your onboarding runbook
[ ] Create a signed-commits ruleset in org settings targeting ~DEFAULT_BRANCH
[ ] Set enforcement to Active (not Evaluate) once all maintainers are signed up
[ ] Review bot/automation accounts — exempt only those that cannot sign
[ ] Re-run Fylgyr: Invoke-Fylgyr -Owner <org> -Repo <repo> -Check SignedCommit
```

## Rollout checklist for solo maintainers

```
[ ] Generate or identify an Ed25519 SSH key or GPG key
[ ] Add the key to GitHub Settings as a Signing Key (SSH) or GPG Key
[ ] Configure git config --global commit.gpgsign true and user.signingkey
[ ] Enable "Require signed commits" on your default branch protection rule
[ ] Optionally: add the git config lines to your dotfiles repo so new machines are covered
```

## Interpreting Fylgyr output

| Status | What it means |
|---|---|
| `Pass` | The default branch requires signed commits. No action needed. |
| `Warning` | Required signatures are disabled. This is a recommendation, not a hard failure — adoption is still low across the ecosystem — but it is a meaningful defence. |
| `Error` | The check could not run, usually due to insufficient token permissions. Use a fine-grained token with `Administration: read` or a classic `repo`-scoped token. |

To remediate a `Warning`:

```powershell
# Re-run after enabling the setting to confirm
Invoke-Fylgyr -Owner <owner> -Repo <repo>
```

## Further reading

- [GitHub Docs: Managing commit signature verification](https://docs.github.com/authentication/managing-commit-signature-verification)
- [GitHub Docs: Signing commits with SSH](https://docs.github.com/authentication/managing-commit-signature-verification/signing-commits)
- [GitHub Docs: About rulesets](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [Sigstore / Gitsign](https://github.com/sigstore/gitsign) — keyless signing backed by OIDC for CI pipelines
- [CVE-2024-3094 analysis](https://research.swtch.com/xz-script) — detailed xz-utils backdoor breakdown
