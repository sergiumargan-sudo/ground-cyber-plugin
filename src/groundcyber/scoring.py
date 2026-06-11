"""Deterministic GCS scoring for secret-scanning alerts.

No AI is involved in closure decisions. Every verdict is produced by the
rule table below and is reproducible from the same inputs.

The closure rule (cannot be weakened by configuration):

    GCS-0 (verified closed) requires provider-side validity == "inactive".

Resolution labels ("revoked", "used_in_tests", "false_positive", "wont_fix",
"pattern_deleted", "pattern_edited", ...) are administrative statements.
They never produce GCS-0 by themselves. Unknown validity is not safe.
Missing or failed evidence fails closed to a non-safe state.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import Config
from .models import (
    GCS,
    VALIDITY_ACTIVE,
    VALIDITY_INACTIVE,
    Alert,
    Finding,
)

RECHECK_WINDOW_HOURS = 24


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def score_alert(alert: Alert, config: Config, now: Optional[datetime] = None) -> Finding:
    """Score a single alert. Pure function of (alert, config, now)."""
    now = now or _now()
    validity = (alert.validity or "unknown").lower()
    resolved = alert.state == "resolved"
    resolution = alert.resolution or None

    # Rule 1 — fail closed: missing evidence can never look safe.
    if alert.fetch_error:
        return Finding(
            alert=alert,
            gcs=GCS.PROVISIONAL,
            closure_confirmed=False,
            basis=(
                "Closure evidence could not be retrieved; the result is "
                "provisional, not safe (fail-closed)."
            ),
            blockers=[f"Evidence unavailable: {alert.fetch_error}"],
            recommended_action=(
                "Re-run the audit with working API access, then verify "
                "provider-side validity for this alert."
            ),
        )

    # Rule 2 — an active credential is active risk regardless of alert state.
    if validity == VALIDITY_ACTIVE:
        blockers = ["Provider-side validity check reports the credential is ACTIVE."]
        if resolved:
            blockers.append(
                f"Alert was resolved as {resolution!r} while the credential "
                "is still active: the resolution is contradicted by evidence."
            )
        return Finding(
            alert=alert,
            gcs=GCS.ACTIVE_RISK,
            closure_confirmed=False,
            basis=(
                "Provider validity is 'active': the credential is usable right "
                "now"
                + (
                    " even though the alert is marked resolved."
                    if resolved
                    else " and the alert is open."
                )
            ),
            blockers=blockers,
            recommended_action=(
                "Revoke or rotate the credential at the issuing provider "
                "immediately, then confirm validity flips to 'inactive'."
            ),
        )

    if resolved:
        if validity == VALIDITY_INACTIVE:
            # The only path to verified closure.
            if config.require_delayed_recheck:
                resolved_at = _parse_ts(alert.resolved_at)
                if resolved_at and now - resolved_at < timedelta(
                    hours=RECHECK_WINDOW_HOURS
                ):
                    return Finding(
                        alert=alert,
                        gcs=GCS.LOW_RESIDUAL_RISK,
                        closure_confirmed=False,
                        basis=(
                            "Provider validity is 'inactive', but the alert was "
                            f"resolved less than {RECHECK_WINDOW_HOURS}h ago and "
                            "the configuration requires a delayed re-check before "
                            "verified closure."
                        ),
                        blockers=[
                            "Delayed re-check pending: re-run the audit after "
                            f"{RECHECK_WINDOW_HOURS}h to confirm the credential "
                            "stayed inactive."
                        ],
                        recommended_action=(
                            "Re-run the audit after the re-check window to "
                            "confirm GCS-0."
                        ),
                    )
            return Finding(
                alert=alert,
                gcs=GCS.VERIFIED_CLOSED,
                closure_confirmed=True,
                basis=(
                    "Provider-side validity check confirms the credential is "
                    "inactive. This is closure evidence, independent of the "
                    f"resolution label ({resolution!r})."
                ),
                blockers=[],
                recommended_action="None. Closure is verified by provider evidence.",
            )

        # Resolved without inactive evidence: the false-closure case.
        label_note = (
            f"Resolution label {resolution!r} is an administrative statement, "
            "not closure evidence."
            if resolution
            else "Alert is resolved with no resolution label and no closure evidence."
        )
        blockers = [
            label_note,
            "No provider-side inactive-validity evidence was found "
            f"(validity: {validity!r}).",
        ]
        resolved_at = _parse_ts(alert.resolved_at)
        if (
            resolved_at
            and config.stale_resolved_days
            and now - resolved_at > timedelta(days=config.stale_resolved_days)
        ):
            blockers.append(
                f"Resolution is older than {config.stale_resolved_days} days "
                "and the evidence gap was never closed."
            )
        return Finding(
            alert=alert,
            gcs=GCS.FALSE_CLOSURE_RISK,
            closure_confirmed=False,
            basis=(
                f"Alert was closed as {resolution!r}, but no provider-side "
                "inactive-validity evidence exists. A label is a status, not "
                "proof the credential is dead."
            ),
            blockers=blockers,
            recommended_action=(
                "Verify at the issuing provider that the credential is revoked; "
                "if it cannot be proven dead, rotate it and re-check validity."
            ),
        )

    # Open alerts.
    if validity == VALIDITY_INACTIVE:
        return Finding(
            alert=alert,
            gcs=GCS.LOW_RESIDUAL_RISK,
            closure_confirmed=False,
            basis=(
                "Provider validity is 'inactive' but the alert is still open. "
                "The credential appears dead; the alert workflow is unfinished."
            ),
            blockers=["Alert remains open despite inactive validity."],
            recommended_action=(
                "Confirm the credential was rotated/revoked intentionally, "
                "then resolve the alert with that evidence on record."
            ),
        )

    # Open with unknown/absent validity.
    if alert.publicly_leaked:
        return Finding(
            alert=alert,
            gcs=GCS.ACTIVE_RISK,
            closure_confirmed=False,
            basis=(
                "Open alert with unknown validity for a credential GitHub "
                "reports as publicly leaked. Exposure must be treated as "
                "exploitable until proven inactive."
            ),
            blockers=[
                "Credential is publicly leaked.",
                "No provider-side validity evidence (validity: "
                f"{validity!r}).",
            ],
            recommended_action=(
                "Rotate or revoke the credential immediately and confirm "
                "validity flips to 'inactive'."
            ),
        )

    if config.treat_unknown_validity_as == "active_risk":
        gcs = GCS.ACTIVE_RISK
        basis = (
            "Open alert with unknown validity; configuration treats unknown "
            "validity as active risk."
        )
    else:
        gcs = GCS.PROVISIONAL
        basis = (
            "Open alert with no provider-side validity evidence. Unknown "
            "validity is not safe; the alert is provisional until proven "
            "inactive."
        )
    return Finding(
        alert=alert,
        gcs=gcs,
        closure_confirmed=False,
        basis=basis,
        blockers=[
            f"No provider-side validity evidence (validity: {validity!r})."
        ],
        recommended_action=(
            "Determine whether the credential is live (provider validity check "
            "or manual verification); revoke/rotate if it is, then resolve "
            "with evidence."
        ),
    )


def apply_duplicate_exposure(findings: list[Finding]) -> list[Finding]:
    """Escalate alerts whose secret (by hash) is active elsewhere.

    If the same credential appears in another alert scored GCS-4, a calmer
    verdict on this alert is an illusion: the credential is exploitable.
    """
    active_hashes = {
        f.alert.secret_hash
        for f in findings
        if f.gcs is GCS.ACTIVE_RISK and f.alert.secret_hash
    }
    for f in findings:
        h = f.alert.secret_hash
        if h and h in active_hashes and f.gcs is not GCS.ACTIVE_RISK:
            f.gcs = GCS.ACTIVE_RISK
            f.closure_confirmed = False
            f.blockers.append(
                "Duplicate active exposure: the same credential (matched by "
                "hash) is active in another alert in scope."
            )
            f.basis += (
                " Escalated to active risk: the same credential is active in "
                "another alert."
            )
            f.recommended_action = (
                "Revoke or rotate the credential at the issuing provider; it "
                "is active in at least one other location."
            )
    return findings


def score_alerts(
    alerts: list[Alert], config: Config, now: Optional[datetime] = None
) -> list[Finding]:
    findings = [score_alert(a, config, now=now) for a in alerts]
    return apply_duplicate_exposure(findings)
