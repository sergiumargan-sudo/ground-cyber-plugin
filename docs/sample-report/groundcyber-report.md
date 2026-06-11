# Ground Cyber Closure Report
> Closed is a status. Revoked is evidence. Unknown validity is not safe.
## Executive summary
```text
Ground Cyber Closure Report

Total secret alerts scanned: 8
Verified closed: 1
Low residual risk: 1
Provisional / unknown: 1
False-closure risk: 3
Active risk: 2

Highest-risk finding:
Alert #233 (GCS-4 Active risk): Provider validity is 'active': the credential is usable right now and the alert is open.
```
## Scope
GitHub Secret Scanning alerts — organization 'example-org'
Generated at: 2026-06-11T09:00:00Z · groundcyber v0.3.0
## Methodology
Ground Cyber asks one question per alert: is the underlying credential
proven dead, or merely marked resolved?

1. Secret-scanning alerts are fetched with read-only GET requests.
2. Any raw secret value in an API response is hashed (SHA-256) immediately
   and the raw value is discarded. Hashes are used only to detect the same
   credential appearing in multiple alerts.
3. Each alert is scored with a deterministic rule table (no AI):
   - GCS-0 (verified closed) requires provider-side validity == "inactive".
     Nothing else produces GCS-0.
   - Resolution labels (revoked, used_in_tests, false_positive, wont_fix,
     pattern_deleted, pattern_edited, ...) are administrative statements
     and never count as closure evidence by themselves.
   - Unknown or missing validity is never safe.
   - If evidence cannot be retrieved, the alert fails closed to a
     provisional (non-safe) state.
   - A credential active in any alert escalates every other alert that
     shares the same secret hash (duplicate active exposure).

## Security and privacy model
- Local-first: the audit runs where you invoke it; nothing is uploaded.
- Read-only: only GitHub GET requests are issued. Alerts, repositories,
  issues, and settings are never modified.
- No raw secret storage: secret values are hashed with SHA-256 on receipt
  and discarded.
- No raw secret printing: all report text passes through a redaction
  filter that replaces secret-shaped strings with hashed markers.
- Human overrides and dismissals are treated as risk acceptance, not as
  verified closure.

## Closure summary
| State | Meaning | Count |
|---|---|---|
| GCS-4 | Active risk | 2 |
| GCS-3 | False-closure risk | 3 |
| GCS-2 | Provisional / unknown | 1 |
| GCS-1 | Low residual risk | 1 |
| GCS-0 | Verified closed | 1 |

## Findings
| Alert | Repo | Secret type | State | Resolution | Validity | GCS | Closure confirmed |
|---|---|---|---|---|---|---|---|
| #233 | example-org/infra-terraform | Stripe API Key | open | — | active | GCS-4 | no |
| #89 | example-org/mobile-app | Stripe API Key | resolved | revoked | inactive | GCS-4 | no |
| #460 | example-org/data-pipeline | npm Access Token | resolved | wont_fix | unknown | GCS-3 | no |
| #210 | example-org/infra-terraform | Slack API Token | resolved | false_positive | unknown | GCS-3 | no |
| #1842 | example-org/payments-api | AWS Access Key ID | resolved | used_in_tests | unknown | GCS-3 | no |
| #88 | example-org/mobile-app | Google API Key | open | — | unknown | GCS-2 | no |
| #412 | example-org/data-pipeline | Azure Storage Account Key | open | — | inactive | GCS-1 | no |
| #1901 | example-org/payments-api | GitHub Personal Access Token | resolved | revoked | inactive | GCS-0 | yes |

## Per-alert reasoning
### Alert #233 — example-org/infra-terraform (GCS-4: Active risk)
- **Secret type:** Stripe API Key
- **State / resolution / validity:** open / — / active
- **Created:** 2026-06-01T11:22:00Z
- **Closure confirmed:** false
- **Basis:** Provider validity is 'active': the credential is usable right now and the alert is open.
- **Closure blockers:**
  - Provider-side validity check reports the credential is ACTIVE.
- **Recommended next action:** Revoke or rotate the credential at the issuing provider immediately, then confirm validity flips to 'inactive'.

### Alert #89 — example-org/mobile-app (GCS-4: Active risk)
- **Secret type:** Stripe API Key
- **State / resolution / validity:** resolved / revoked / inactive
- **Created:** 2026-05-30T10:00:00Z
- **Resolved:** 2026-05-30T12:00:00Z
- **Closure confirmed:** false
- **Basis:** Provider-side validity check confirms the credential is inactive. This is closure evidence, independent of the resolution label ('revoked'). Escalated to active risk: the same credential is active in another alert.
- **Closure blockers:**
  - Duplicate active exposure: the same credential (matched by hash) is active in another alert in scope.
- **Recommended next action:** Revoke or rotate the credential at the issuing provider; it is active in at least one other location.

### Alert #460 — example-org/data-pipeline (GCS-3: False-closure risk)
- **Secret type:** npm Access Token
- **State / resolution / validity:** resolved / wont_fix / unknown
- **Created:** 2026-01-09T18:20:00Z
- **Resolved:** 2026-01-10T08:00:00Z
- **Closure confirmed:** false
- **Basis:** Alert was closed as 'wont_fix', but no provider-side inactive-validity evidence exists. A label is a status, not proof the credential is dead.
- **Closure blockers:**
  - Resolution label 'wont_fix' is an administrative statement, not closure evidence.
  - No provider-side inactive-validity evidence was found (validity: 'unknown').
  - Resolution is older than 30 days and the evidence gap was never closed.
- **Recommended next action:** Verify at the issuing provider that the credential is revoked; if it cannot be proven dead, rotate it and re-check validity.

### Alert #210 — example-org/infra-terraform (GCS-3: False-closure risk)
- **Secret type:** Slack API Token
- **State / resolution / validity:** resolved / false_positive / unknown
- **Created:** 2025-11-20T08:00:00Z
- **Resolved:** 2025-11-21T09:30:00Z
- **Closure confirmed:** false
- **Basis:** Alert was closed as 'false_positive', but no provider-side inactive-validity evidence exists. A label is a status, not proof the credential is dead.
- **Closure blockers:**
  - Resolution label 'false_positive' is an administrative statement, not closure evidence.
  - No provider-side inactive-validity evidence was found (validity: 'unknown').
  - Resolution is older than 30 days and the evidence gap was never closed.
- **Recommended next action:** Verify at the issuing provider that the credential is revoked; if it cannot be proven dead, rotate it and re-check validity.

### Alert #1842 — example-org/payments-api (GCS-3: False-closure risk)
- **Secret type:** AWS Access Key ID
- **State / resolution / validity:** resolved / used_in_tests / unknown
- **Created:** 2026-03-02T09:14:00Z
- **Resolved:** 2026-03-02T10:01:00Z
- **Closure confirmed:** false
- **Basis:** Alert was closed as 'used_in_tests', but no provider-side inactive-validity evidence exists. A label is a status, not proof the credential is dead.
- **Closure blockers:**
  - Resolution label 'used_in_tests' is an administrative statement, not closure evidence.
  - No provider-side inactive-validity evidence was found (validity: 'unknown').
  - Resolution is older than 30 days and the evidence gap was never closed.
- **Recommended next action:** Verify at the issuing provider that the credential is revoked; if it cannot be proven dead, rotate it and re-check validity.

### Alert #88 — example-org/mobile-app (GCS-2: Provisional / unknown)
- **Secret type:** Google API Key
- **State / resolution / validity:** open / — / unknown
- **Created:** 2026-05-28T13:00:00Z
- **Closure confirmed:** false
- **Basis:** Open alert with no provider-side validity evidence. Unknown validity is not safe; the alert is provisional until proven inactive.
- **Closure blockers:**
  - No provider-side validity evidence (validity: 'unknown').
- **Recommended next action:** Determine whether the credential is live (provider validity check or manual verification); revoke/rotate if it is, then resolve with evidence.

### Alert #412 — example-org/data-pipeline (GCS-1: Low residual risk)
- **Secret type:** Azure Storage Account Key
- **State / resolution / validity:** open / — / inactive
- **Created:** 2026-05-12T07:45:00Z
- **Closure confirmed:** false
- **Basis:** Provider validity is 'inactive' but the alert is still open. The credential appears dead; the alert workflow is unfinished.
- **Closure blockers:**
  - Alert remains open despite inactive validity.
- **Recommended next action:** Confirm the credential was rotated/revoked intentionally, then resolve the alert with that evidence on record.

### Alert #1901 — example-org/payments-api (GCS-0: Verified closed)
- **Secret type:** GitHub Personal Access Token
- **State / resolution / validity:** resolved / revoked / inactive
- **Created:** 2026-04-11T16:40:00Z
- **Resolved:** 2026-04-11T17:05:00Z
- **Closure confirmed:** true
- **Basis:** Provider-side validity check confirms the credential is inactive. This is closure evidence, independent of the resolution label ('revoked').
- **Recommended next action:** None. Closure is verified by provider evidence.

## Recommended remediation order
1. GCS-4 first: revoke/rotate active credentials at the issuing provider.
2. GCS-3 next: produce provider-side proof of revocation for administratively closed alerts, or rotate.
3. GCS-2: obtain validity evidence; treat as live until proven otherwise.
4. GCS-1: finish the closure workflow (resolve open alerts whose credentials are already inactive, or re-check after the delay window).

## Limitations
- Provider validity checks exist only for secret types GitHub actively
  verifies; other types can never reach GCS-0 through this tool and will
  surface as provisional or false-closure risk. That is by design:
  unknown validity is not safe.
- Validity reflects GitHub's most recent check, which may lag a recent
  revocation or reactivation.
- A credential proven inactive may still have been used during its
  exposure window; this tool verifies closure, not absence of past abuse.
- Git history is not rewritten by resolving an alert: an exposed secret
  remains in history until rotated and scrubbed.
- Organization-level scans require a token with organization-wide secret
  scanning read access; the default Actions GITHUB_TOKEN is repo-scoped.
- Alerts GitHub never raised (undetected secret types, private patterns
  not configured) are invisible to this audit.

## Evidence appendix
Evidence per alert is limited to: GitHub alert metadata (state, resolution, timestamps), the provider validity field, and SHA-256 fingerprints of secret values where the API exposed them. Raw secret values are never stored or reproduced.
