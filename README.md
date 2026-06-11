# Ground Cyber

**False-closure verification for GitHub Secret Scanning alerts.**

> Closed is a status. Revoked is evidence.

Ground Cyber does not ask whether a secret alert was marked resolved. It asks
whether the underlying credential is actually proven dead. It answers one
question across your repos or organization:

> **Which of my closed GitHub secret alerts are not verifiably closed?**

Ground Cyber does not modify alerts. It verifies whether closure evidence
exists.

## What Ground Cyber does

- Fetches GitHub Secret Scanning alerts (read-only, GET requests only).
- Scores every alert with a deterministic rule table — no AI is involved in
  any closure decision.
- Separates alerts that are **verifiably closed** (provider-side validity
  check says the credential is inactive) from alerts that are merely
  **marked** closed.
- Produces a local closure-risk report in Markdown, JSON, and HTML.
- Runs locally or as a GitHub Action. Nothing is uploaded anywhere.

## Why "closed" does not mean "safe"

GitHub lets anyone with write access resolve a secret alert with a label:
`revoked`, `used_in_tests`, `false_positive`, `wont_fix`, `pattern_deleted`.
None of those labels prove anything about the credential. A key resolved as
"revoked" can still be live. A key resolved as "used in tests" can still
authenticate against production.

GitHub also runs **validity checks** for many secret types and records
whether the credential is `active`, `inactive`, or `unknown`. That field is
evidence. The label is not.

Ground Cyber's closure rule, which configuration cannot weaken:

- **GCS-0 (verified closed) requires provider-side validity = `inactive`.**
- A resolution label never produces GCS-0 by itself.
- **Unknown validity is not safe.**
- A human dismissal or override is risk acceptance, not verified closure.
- If evidence is unavailable (API failure, missing data), the alert fails
  **closed** to a non-safe state — never to "fine".

## GCS scoring model

| State | Name | Meaning | How it is produced |
|---|---|---|---|
| GCS-0 | Verified closed | Credential proven dead | Resolved alert **and** provider validity `inactive`. The only path. |
| GCS-1 | Low residual risk | Mostly closed, minor gap | Open alert whose credential is already `inactive`, or inactive evidence awaiting a delayed re-check |
| GCS-2 | Provisional / unknown | Evidence incomplete or unavailable | Open alert with unknown validity; any alert whose evidence could not be fetched |
| GCS-3 | False-closure risk | Closed on paper, not in fact | Alert resolved with an administrative label but no provider-side `inactive` evidence |
| GCS-4 | Active risk | Exploitable now | Provider validity `active` (even if the alert is resolved); publicly leaked credential with unknown validity; the same credential active in another alert |

`closure_confirmed: true` appears only on GCS-0 findings.

## Quick start: CLI

Requires Python 3.10+.

```bash
pip install git+https://github.com/sergiumargan-sudo/ground-cyber-plugin.git

export GITHUB_TOKEN=ghp_...        # or GH_TOKEN; never passed as a flag

groundcyber init                   # writes .groundcyber.yml
groundcyber doctor --repo owner/repo   # checks token + API access, fetches no secrets
groundcyber audit github --repo owner/repo --output markdown,json
```

Reports land in `./groundcyber-report/`. Audit an organization:

```bash
groundcyber audit github --org example-org \
  --exclude-repo "example-org/sandbox-*" \
  --output markdown,json,html
```

Useful flags: `--include-repo` / `--exclude-repo` (glob patterns,
repeatable), `--config`, `--out-dir`, `--redact-repo-names`,
`--fail-on-gcs3`, `--fail-on-gcs4`, `--dry-run` (prints the plan, makes zero
API calls), `--verbose`.

Exit codes: `0` success · `1` fail-on threshold hit · `2` config/usage
error · `3` auth/API error.

## Quick start: GitHub Action

```yaml
name: Ground Cyber Closure Audit

on:
  workflow_dispatch:
  schedule:
    - cron: "0 9 * * 1"

permissions:
  contents: read
  security-events: read

jobs:
  closure-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Ground Cyber
        uses: sergiumargan-sudo/ground-cyber-plugin@main
        with:
          output: "markdown,json"
          fail-on-gcs3: "false"
          fail-on-gcs4: "true"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The action runs the audit read-only, appends the Markdown report to the job
summary, uploads the report directory as an artifact, and (optionally) fails
the workflow when GCS-3 or GCS-4 findings exist. It never prints raw secret
values and never modifies alerts. See
[`examples/workflows/closure-audit.yml`](examples/workflows/closure-audit.yml).

## Permissions required

| Scenario | Token | Permissions |
|---|---|---|
| Single repository in Actions | default `GITHUB_TOKEN` | workflow `permissions: security-events: read` (repo must have secret scanning enabled) |
| Single repository, local CLI | fine-grained PAT | repository permission **Secret scanning alerts: read** |
| Organization-wide audit | fine-grained PAT or GitHub App token | organization-wide **Secret scanning alerts: read** |
| Classic PAT alternative | classic PAT | `repo` + `security_events` scopes |

**Limitation of the default `GITHUB_TOKEN`:** it is scoped to the repository
the workflow runs in. Org-level audits (`--org` / the `org:` input) will
return `403/404` with it. Create a fine-grained PAT or GitHub App token with
organization-level secret-scanning read access, store it as an Actions
secret, and pass it as `GITHUB_TOKEN` to the action.

`groundcyber doctor` checks all of this before you run a real audit.

## Privacy and security model

- **Local-first.** The audit runs on your machine or your runner. There is
  no Ground Cyber server, no telemetry, no upload. The
  `upload_to_ground_dashboard` config key exists as a placeholder and must
  remain `false`.
- **Read-only.** The tool issues GitHub GET requests only; the HTTP client
  refuses any other method. It never modifies alerts, repositories, files,
  issues, or settings.
- **No raw secret storage.** If the API exposes a secret value, it is hashed
  with SHA-256 the moment the response is parsed and the raw value is
  discarded. Hashes are used only to detect the same credential appearing in
  multiple alerts.
- **No raw secret printing.** Every string written to the terminal or a
  report passes through a redaction filter that replaces secret-shaped
  content with `[REDACTED-SECRET:sha256:…]` markers.
- **No AI in closure decisions.** Scoring is a deterministic rule table;
  the same inputs always produce the same verdict.
- **Fail closed.** Unavailable, ambiguous, or stale evidence produces a
  provisional or risk state, never a safe one.
- Optional `--redact-repo-names` replaces repository names with stable
  pseudonyms for reports you need to share.

These guarantees are enforced by the test suite, and the corresponding
configuration keys (`read_only`, `store_raw_secrets`, `print_raw_secrets`,
`require_provider_inactive_for_gcs0`, …) are validated: trying to weaken
them is a configuration error.

## Example output

```text
Ground Cyber Closure Report

Total secret alerts scanned: 8
Verified closed: 1
Low residual risk: 1
Provisional / unknown: 1
False-closure risk: 3
Active risk: 2

Highest-risk finding:
Alert #233 (GCS-4 Active risk): Provider validity is 'active': the
credential is usable right now and the alert is open.
```

Each finding records the alert number, repo (redacted if configured),
secret type, alert state, resolution label, validity state, GCS score,
`closure_confirmed`, the basis for the verdict, closure blockers, a
recommended next action, and timestamps. Full sample reports:
[Markdown](docs/sample-report/groundcyber-report.md) ·
[JSON](docs/sample-report/groundcyber-report.json) ·
[HTML](docs/sample-report/groundcyber-report.html)

## Configuration

`groundcyber init` writes a commented `.groundcyber.yml` covering scope
(org/repos/include/exclude), closure policy (`treat_unknown_validity_as`,
`stale_resolved_days`, `require_delayed_recheck`, extra non-closing labels),
privacy, and report outputs. CLI flags override the file.

## Limitations

- GitHub runs validity checks only for supported secret types from
  participating providers. Secret types without validity checks can never
  reach GCS-0 through this tool — they surface as provisional or
  false-closure risk. That is deliberate: unknown validity is not safe.
- Validity reflects GitHub's most recent check and may lag a very recent
  revocation or reactivation.
- GCS-0 means the credential is dead **now**; it says nothing about whether
  the credential was abused during its exposure window.
- Resolving an alert does not rewrite git history; the secret string remains
  in history until rotated and scrubbed.
- Secrets GitHub never detected (unsupported types, missing custom
  patterns) are invisible to this audit.
- Org-level audits need org-level token permissions (see above).

## FAQ

**Does it ever change anything in my GitHub account?**
No. Only GET requests are made. There is no code path that writes.

**Does it send my data anywhere?**
No. Reports are written to a local directory. There is no upload endpoint.

**Why is my alert "false-closure risk" when we really did revoke the key?**
Because no provider-side evidence confirms it. If GitHub's validity check
shows `inactive`, the alert becomes GCS-0 on the next audit. If the secret
type has no validity check, Ground Cyber will not take the label's word for
it — verify revocation at the issuing provider and keep the audit finding as
a record of the evidence gap.

**Can I make unknown validity count as safe?**
No. `treat_unknown_validity_as` accepts `provisional` or `active_risk` only.

**Does it use AI?**
No. Scoring is a deterministic rule table; the same inputs always produce
the same verdict.

**What does exit code 1 mean in CI?**
You enabled `fail-on-gcs3` or `fail-on-gcs4` and the audit found findings at
that level. The report artifact tells you which.

## Design partners

Ground Cyber is self-serve: everything above works without contacting
anyone. If you want a hands-on closure audit of a larger estate, or want to
shape where the tool goes next, open an issue on this repository.
