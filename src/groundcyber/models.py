"""Data model for the Ground Cyber closure audit.

GCS — Ground Closure State for secret-scanning alerts:

  GCS-0  verified closed     provider-confirmed inactive validity only
  GCS-1  low residual risk   mostly closed, minor evidence gap
  GCS-2  provisional         incomplete or unavailable closure evidence
  GCS-3  false-closure risk  closed administratively, no inactive evidence
  GCS-4  active risk         active credential or duplicate active exposure

GCS-0 is the only state in which ``closure_confirmed`` may be true, and it
can only be produced by provider-side validity == "inactive". Resolution
labels, dismissals, and human overrides never produce GCS-0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class GCS(IntEnum):
    VERIFIED_CLOSED = 0
    LOW_RESIDUAL_RISK = 1
    PROVISIONAL = 2
    FALSE_CLOSURE_RISK = 3
    ACTIVE_RISK = 4

    @property
    def label(self) -> str:
        return f"GCS-{int(self)}"

    @property
    def title(self) -> str:
        return _GCS_TITLES[self]


_GCS_TITLES = {
    GCS.VERIFIED_CLOSED: "Verified closed",
    GCS.LOW_RESIDUAL_RISK: "Low residual risk",
    GCS.PROVISIONAL: "Provisional / unknown",
    GCS.FALSE_CLOSURE_RISK: "False-closure risk",
    GCS.ACTIVE_RISK: "Active risk",
}

# Validity states GitHub's secret-scanning API can report.
VALIDITY_ACTIVE = "active"
VALIDITY_INACTIVE = "inactive"
VALIDITY_UNKNOWN = "unknown"


@dataclass
class Alert:
    """A sanitized secret-scanning alert. Never carries a raw secret value.

    ``secret_hash`` is the SHA-256 of the secret if the API exposed it
    (hashed immediately on receipt, raw value discarded); otherwise None.
    """

    number: int
    repo: str  # "owner/name"
    state: str  # "open" | "resolved"
    secret_type: str
    secret_type_display: str
    resolution: Optional[str] = None
    validity: Optional[str] = None  # "active" | "inactive" | "unknown" | None
    secret_hash: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None
    publicly_leaked: Optional[bool] = None
    multi_repo: Optional[bool] = None
    push_protection_bypassed: Optional[bool] = None
    html_url: Optional[str] = None
    fetch_error: Optional[str] = None  # set when evidence could not be retrieved


@dataclass
class Finding:
    """The deterministic closure verdict for one alert."""

    alert: Alert
    gcs: GCS
    closure_confirmed: bool
    basis: str
    blockers: list[str] = field(default_factory=list)
    recommended_action: str = ""

    @property
    def display_repo(self) -> str:
        return self.alert.repo


@dataclass
class AuditResult:
    findings: list[Finding]
    scope_description: str
    generated_at: str
    errors: list[str] = field(default_factory=list)

    def count(self, gcs: GCS) -> int:
        return sum(1 for f in self.findings if f.gcs is gcs)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def highest_risk(self) -> Optional[Finding]:
        if not self.findings:
            return None
        worst = max(f.gcs for f in self.findings)
        if worst <= GCS.LOW_RESIDUAL_RISK:
            return None
        candidates = [f for f in self.findings if f.gcs is worst]
        return candidates[0]
