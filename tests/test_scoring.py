"""Closure-rule tests: GCS-0 must be impossible without provider-inactive evidence."""

from datetime import datetime, timedelta, timezone

from groundcyber.config import DEFAULT_NON_CLOSING_LABELS, Config
from groundcyber.models import GCS, Alert
from groundcyber.scoring import score_alert, score_alerts

NOW = datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def make_alert(**kwargs) -> Alert:
    defaults = dict(
        number=1,
        repo="acme/api",
        state="open",
        secret_type="github_pat",
        secret_type_display="GitHub Personal Access Token",
    )
    defaults.update(kwargs)
    return Alert(**defaults)


def test_resolution_labels_never_produce_gcs0():
    """Every administrative label without inactive validity is false-closure risk."""
    for label in DEFAULT_NON_CLOSING_LABELS:
        for validity in (None, "unknown"):
            finding = score_alert(
                make_alert(state="resolved", resolution=label, validity=validity),
                Config(),
                now=NOW,
            )
            assert finding.gcs is GCS.FALSE_CLOSURE_RISK, label
            assert finding.closure_confirmed is False


def test_unknown_or_none_validity_can_never_be_gcs0():
    """Exhaustive: no state/resolution combination reaches GCS-0 without inactive."""
    for state in ("open", "resolved"):
        for resolution in [None] + DEFAULT_NON_CLOSING_LABELS:
            for validity in (None, "unknown", "active"):
                finding = score_alert(
                    make_alert(state=state, resolution=resolution, validity=validity),
                    Config(),
                    now=NOW,
                )
                assert finding.gcs is not GCS.VERIFIED_CLOSED
                assert finding.closure_confirmed is False


def test_provider_inactive_on_resolved_alert_is_gcs0():
    finding = score_alert(
        make_alert(state="resolved", resolution="revoked", validity="inactive"),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.VERIFIED_CLOSED
    assert finding.closure_confirmed is True


def test_active_validity_is_gcs4_even_when_resolved():
    finding = score_alert(
        make_alert(state="resolved", resolution="revoked", validity="active"),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.ACTIVE_RISK
    assert finding.closure_confirmed is False


def test_open_inactive_is_low_residual_risk():
    finding = score_alert(
        make_alert(state="open", validity="inactive"), Config(), now=NOW
    )
    assert finding.gcs is GCS.LOW_RESIDUAL_RISK
    assert finding.closure_confirmed is False


def test_open_unknown_validity_is_provisional_by_default():
    finding = score_alert(make_alert(state="open", validity=None), Config(), now=NOW)
    assert finding.gcs is GCS.PROVISIONAL


def test_open_unknown_validity_can_be_treated_as_active_risk():
    config = Config(treat_unknown_validity_as="active_risk")
    finding = score_alert(make_alert(state="open", validity=None), config, now=NOW)
    assert finding.gcs is GCS.ACTIVE_RISK


def test_publicly_leaked_open_unknown_is_active_risk():
    finding = score_alert(
        make_alert(state="open", validity="unknown", publicly_leaked=True),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.ACTIVE_RISK


def test_api_failure_fails_closed_never_safe():
    finding = score_alert(
        make_alert(
            state="resolved",
            resolution="revoked",
            validity="inactive",  # even with inactive on record,
            fetch_error="HTTP 500 while fetching evidence",  # a fetch error wins
        ),
        Config(),
        now=NOW,
    )
    assert finding.gcs is GCS.PROVISIONAL
    assert finding.closure_confirmed is False
    assert any("Evidence unavailable" in b for b in finding.blockers)


def test_delayed_recheck_caps_fresh_resolutions_at_gcs1():
    config = Config(require_delayed_recheck=True)
    fresh = make_alert(
        state="resolved",
        resolution="revoked",
        validity="inactive",
        resolved_at=(NOW - timedelta(hours=2)).isoformat(),
    )
    finding = score_alert(fresh, config, now=NOW)
    assert finding.gcs is GCS.LOW_RESIDUAL_RISK
    assert finding.closure_confirmed is False

    old = make_alert(
        state="resolved",
        resolution="revoked",
        validity="inactive",
        resolved_at=(NOW - timedelta(days=3)).isoformat(),
    )
    finding = score_alert(old, config, now=NOW)
    assert finding.gcs is GCS.VERIFIED_CLOSED


def test_stale_resolution_gets_staleness_blocker():
    alert = make_alert(
        state="resolved",
        resolution="wont_fix",
        validity="unknown",
        resolved_at=(NOW - timedelta(days=90)).isoformat(),
    )
    finding = score_alert(alert, Config(stale_resolved_days=30), now=NOW)
    assert finding.gcs is GCS.FALSE_CLOSURE_RISK
    assert any("older than 30 days" in b for b in finding.blockers)


def test_duplicate_active_exposure_escalates_resolved_twin():
    shared_hash = "a" * 64
    active = make_alert(number=1, state="open", validity="active", secret_hash=shared_hash)
    resolved_twin = make_alert(
        number=2,
        state="resolved",
        resolution="revoked",
        validity="inactive",
        secret_hash=shared_hash,
    )
    unrelated = make_alert(
        number=3,
        state="resolved",
        resolution="revoked",
        validity="inactive",
        secret_hash="b" * 64,
    )
    findings = {f.alert.number: f for f in score_alerts(
        [active, resolved_twin, unrelated], Config(), now=NOW
    )}
    assert findings[1].gcs is GCS.ACTIVE_RISK
    assert findings[2].gcs is GCS.ACTIVE_RISK
    assert findings[2].closure_confirmed is False
    assert any("Duplicate active exposure" in b for b in findings[2].blockers)
    assert findings[3].gcs is GCS.VERIFIED_CLOSED


def test_scoring_is_deterministic():
    alert = make_alert(state="resolved", resolution="false_positive", validity="unknown")
    first = score_alert(alert, Config(), now=NOW)
    second = score_alert(alert, Config(), now=NOW)
    assert (first.gcs, first.closure_confirmed, first.basis, first.blockers) == (
        second.gcs,
        second.closure_confirmed,
        second.basis,
        second.blockers,
    )
