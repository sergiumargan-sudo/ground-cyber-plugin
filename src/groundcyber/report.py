"""Report generation: markdown, JSON, and simple HTML.

Every free-text field passes through ``redact_text`` before it is written.
The JSON report is built from an explicit whitelist of fields; raw alert
payloads are never serialized, so a raw secret value cannot appear even if
one slipped past sanitization upstream.
"""

from __future__ import annotations

import html as html_module
import json
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .models import GCS, AuditResult, Finding
from .redact import pseudonymize_repo, redact_text

GCS_ORDER = [
    GCS.ACTIVE_RISK,
    GCS.FALSE_CLOSURE_RISK,
    GCS.PROVISIONAL,
    GCS.LOW_RESIDUAL_RISK,
    GCS.VERIFIED_CLOSED,
]

METHODOLOGY = """\
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
"""

SECURITY_MODEL = """\
- Local-first: the audit runs where you invoke it; nothing is uploaded.
- Read-only: only GitHub GET requests are issued. Alerts, repositories,
  issues, and settings are never modified.
- No raw secret storage: secret values are hashed with SHA-256 on receipt
  and discarded.
- No raw secret printing: all report text passes through a redaction
  filter that replaces secret-shaped strings with hashed markers.
- Human overrides and dismissals are treated as risk acceptance, not as
  verified closure.
"""

LIMITATIONS = """\
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
"""


def _display_repo(finding: Finding, config: Config) -> str:
    if config.redact_repo_names:
        return pseudonymize_repo(finding.alert.repo)
    return finding.alert.repo


def _scope_text(result: AuditResult, config: Config) -> str:
    if config.redact_repo_names:
        return (
            "GitHub Secret Scanning alerts — scope identifiers redacted "
            "(redact_repo_names enabled)"
        )
    return _clean(result.scope_description)


def _clean(text: Any) -> str:
    return redact_text(str(text)) if text is not None else ""


def summary_block(result: AuditResult) -> str:
    lines = [
        "Ground Cyber Closure Report",
        "",
        f"Total secret alerts scanned: {result.total}",
        f"Verified closed: {result.count(GCS.VERIFIED_CLOSED)}",
        f"Low residual risk: {result.count(GCS.LOW_RESIDUAL_RISK)}",
        f"Provisional / unknown: {result.count(GCS.PROVISIONAL)}",
        f"False-closure risk: {result.count(GCS.FALSE_CLOSURE_RISK)}",
        f"Active risk: {result.count(GCS.ACTIVE_RISK)}",
    ]
    top = result.highest_risk
    if top:
        lines += [
            "",
            "Highest-risk finding:",
            _clean(
                f"Alert #{top.alert.number} ({top.gcs.label} {top.gcs.title}): "
                f"{top.basis}"
            ),
        ]
    return "\n".join(lines)


def _sorted_findings(result: AuditResult) -> list[Finding]:
    rank = {g: i for i, g in enumerate(GCS_ORDER)}
    return sorted(
        result.findings,
        key=lambda f: (rank[f.gcs], f.alert.repo, f.alert.number),
    )


# ── JSON ────────────────────────────────────────────────────────────────────
def build_json(result: AuditResult, config: Config) -> dict[str, Any]:
    findings = []
    for f in _sorted_findings(result):
        a = f.alert
        findings.append(
            {
                "alert_number": a.number,
                "repo": _clean(_display_repo(f, config)),
                "secret_type": _clean(a.secret_type),
                "secret_type_display": _clean(a.secret_type_display),
                "secret_hash": a.secret_hash,
                "alert_state": _clean(a.state),
                "resolution": _clean(a.resolution) or None,
                "validity": _clean(a.validity) or "unknown",
                "gcs": f.gcs.label,
                "gcs_title": f.gcs.title,
                "closure_confirmed": f.closure_confirmed,
                "basis": _clean(f.basis),
                "closure_blockers": [_clean(b) for b in f.blockers],
                "recommended_action": _clean(f.recommended_action),
                "publicly_leaked": a.publicly_leaked,
                "push_protection_bypassed": a.push_protection_bypassed,
                "created_at": a.created_at,
                "resolved_at": a.resolved_at,
                "updated_at": a.updated_at,
                "url": None if config.redact_repo_names else a.html_url,
                "evidence_error": _clean(a.fetch_error) or None,
            }
        )
    return {
        "tool": "groundcyber",
        "version": __version__,
        "generated_at": result.generated_at,
        "scope": _scope_text(result, config),
        "summary": {
            "total": result.total,
            "verified_closed": result.count(GCS.VERIFIED_CLOSED),
            "low_residual_risk": result.count(GCS.LOW_RESIDUAL_RISK),
            "provisional_unknown": result.count(GCS.PROVISIONAL),
            "false_closure_risk": result.count(GCS.FALSE_CLOSURE_RISK),
            "active_risk": result.count(GCS.ACTIVE_RISK),
        },
        "closure_rule": (
            "GCS-0 requires provider-side validity == 'inactive'. Resolution "
            "labels are not closure evidence. Unknown validity is not safe."
        ),
        "errors": [_clean(e) for e in result.errors],
        "findings": findings,
    }


def render_json(result: AuditResult, config: Config) -> str:
    return json.dumps(build_json(result, config), indent=2) + "\n"


# ── Markdown ────────────────────────────────────────────────────────────────
def render_markdown(result: AuditResult, config: Config) -> str:
    parts: list[str] = []
    parts.append("# Ground Cyber Closure Report\n")
    parts.append("> Closed is a status. Revoked is evidence. "
                 "Unknown validity is not safe.\n")

    parts.append("## Executive summary\n")
    parts.append("```text\n" + summary_block(result) + "\n```\n")

    parts.append("## Scope\n")
    parts.append(_scope_text(result, config) + "\n")
    parts.append(f"Generated at: {result.generated_at} · groundcyber v{__version__}\n")

    if config.include_methodology:
        parts.append("## Methodology\n")
        parts.append(METHODOLOGY + "\n")

    parts.append("## Security and privacy model\n")
    parts.append(SECURITY_MODEL + "\n")

    parts.append("## Closure summary\n")
    parts.append("| State | Meaning | Count |\n|---|---|---|\n")
    for gcs in GCS_ORDER:
        parts.append(f"| {gcs.label} | {gcs.title} | {result.count(gcs)} |\n")
    parts.append("\n")

    parts.append("## Findings\n")
    if not result.findings:
        parts.append("No secret-scanning alerts were found in scope.\n")
    else:
        parts.append(
            "| Alert | Repo | Secret type | State | Resolution | Validity "
            "| GCS | Closure confirmed |\n"
            "|---|---|---|---|---|---|---|---|\n"
        )
        for f in _sorted_findings(result):
            a = f.alert
            parts.append(
                f"| #{a.number} | {_clean(_display_repo(f, config))} "
                f"| {_clean(a.secret_type_display)} | {_clean(a.state)} "
                f"| {_clean(a.resolution) or '—'} | {_clean(a.validity) or 'unknown'} "
                f"| {f.gcs.label} | {'yes' if f.closure_confirmed else 'no'} |\n"
            )
        parts.append("\n## Per-alert reasoning\n")
        for f in _sorted_findings(result):
            a = f.alert
            parts.append(
                f"### Alert #{a.number} — {_clean(_display_repo(f, config))} "
                f"({f.gcs.label}: {f.gcs.title})\n"
            )
            parts.append(f"- **Secret type:** {_clean(a.secret_type_display)}\n")
            parts.append(
                f"- **State / resolution / validity:** {_clean(a.state)} / "
                f"{_clean(a.resolution) or '—'} / {_clean(a.validity) or 'unknown'}\n"
            )
            if a.created_at:
                parts.append(f"- **Created:** {a.created_at}\n")
            if a.resolved_at:
                parts.append(f"- **Resolved:** {a.resolved_at}\n")
            parts.append(
                f"- **Closure confirmed:** "
                f"{'true' if f.closure_confirmed else 'false'}\n"
            )
            parts.append(f"- **Basis:** {_clean(f.basis)}\n")
            if f.blockers:
                parts.append("- **Closure blockers:**\n")
                for b in f.blockers:
                    parts.append(f"  - {_clean(b)}\n")
            parts.append(
                f"- **Recommended next action:** {_clean(f.recommended_action)}\n"
            )
            if a.html_url and not config.redact_repo_names:
                parts.append(f"- **Alert:** {a.html_url}\n")
            parts.append("\n")

    parts.append("## Recommended remediation order\n")
    parts.append(
        "1. GCS-4 first: revoke/rotate active credentials at the issuing "
        "provider.\n"
        "2. GCS-3 next: produce provider-side proof of revocation for "
        "administratively closed alerts, or rotate.\n"
        "3. GCS-2: obtain validity evidence; treat as live until proven "
        "otherwise.\n"
        "4. GCS-1: finish the closure workflow (resolve open alerts whose "
        "credentials are already inactive, or re-check after the delay "
        "window).\n"
    )

    if config.include_limitations:
        parts.append("\n## Limitations\n")
        parts.append(LIMITATIONS + "\n")

    parts.append("## Evidence appendix\n")
    parts.append(
        "Evidence per alert is limited to: GitHub alert metadata (state, "
        "resolution, timestamps), the provider validity field, and SHA-256 "
        "fingerprints of secret values where the API exposed them. Raw "
        "secret values are never stored or reproduced.\n"
    )
    if result.errors:
        parts.append("\n### Data-collection errors (fail-closed)\n")
        for e in result.errors:
            parts.append(f"- {_clean(e)}\n")

    return "".join(parts)


# ── HTML ────────────────────────────────────────────────────────────────────
_GCS_COLORS = {
    GCS.VERIFIED_CLOSED: "#1a7f37",
    GCS.LOW_RESIDUAL_RISK: "#4d7c0f",
    GCS.PROVISIONAL: "#9a6700",
    GCS.FALSE_CLOSURE_RISK: "#bc4c00",
    GCS.ACTIVE_RISK: "#cf222e",
}


def render_html(result: AuditResult, config: Config) -> str:
    def esc(value: Any) -> str:
        return html_module.escape(_clean(value))

    rows = []
    for f in _sorted_findings(result):
        a = f.alert
        color = _GCS_COLORS[f.gcs]
        blockers = "".join(f"<li>{esc(b)}</li>" for b in f.blockers)
        rows.append(
            f"<tr>"
            f"<td>#{a.number}</td>"
            f"<td>{esc(_display_repo(f, config))}</td>"
            f"<td>{esc(a.secret_type_display)}</td>"
            f"<td>{esc(a.state)} / {esc(a.resolution) or '—'}</td>"
            f"<td>{esc(a.validity) or 'unknown'}</td>"
            f"<td><strong style='color:{color}'>{f.gcs.label}</strong> "
            f"{esc(f.gcs.title)}</td>"
            f"<td>{'yes' if f.closure_confirmed else 'no'}</td>"
            f"<td>{esc(f.basis)}<ul>{blockers}</ul>"
            f"<em>Next: {esc(f.recommended_action)}</em></td>"
            f"</tr>"
        )
    summary = html_module.escape(summary_block(result))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ground Cyber Closure Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,sans-serif;margin:2rem;color:#1f2328}}
pre{{background:#f6f8fa;padding:1rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #d0d7de;padding:.5rem;vertical-align:top;text-align:left}}
th{{background:#f6f8fa}}
</style>
</head>
<body>
<h1>Ground Cyber Closure Report</h1>
<p><em>Closed is a status. Revoked is evidence. Unknown validity is not safe.</em></p>
<pre>{summary}</pre>
<p>Scope: {html_module.escape(_scope_text(result, config))}<br>
Generated at: {esc(result.generated_at)} · groundcyber v{__version__}</p>
<h2>Findings</h2>
<table>
<tr><th>Alert</th><th>Repo</th><th>Secret type</th><th>State / resolution</th>
<th>Validity</th><th>GCS</th><th>Closure confirmed</th><th>Reasoning</th></tr>
{''.join(rows) if rows else '<tr><td colspan="8">No alerts in scope.</td></tr>'}
</table>
<h2>Methodology</h2><pre>{html_module.escape(METHODOLOGY)}</pre>
<h2>Security and privacy model</h2><pre>{html_module.escape(SECURITY_MODEL)}</pre>
<h2>Limitations</h2><pre>{html_module.escape(LIMITATIONS)}</pre>
</body>
</html>
"""


RENDERERS = {
    "markdown": ("groundcyber-report.md", render_markdown),
    "json": ("groundcyber-report.json", render_json),
    "html": ("groundcyber-report.html", render_html),
}


def write_reports(result: AuditResult, config: Config, out_dir: str) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in config.outputs:
        filename, renderer = RENDERERS[fmt]
        path = out / filename
        path.write_text(renderer(result, config))
        written.append(path)
    return written
