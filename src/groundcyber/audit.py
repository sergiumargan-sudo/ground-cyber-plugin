"""Audit orchestration: resolve scope, fetch alerts read-only, score, report."""

from __future__ import annotations

from datetime import datetime, timezone

from .config import Config
from .github_client import GitHubClient, GitHubError
from .models import Alert, AuditResult
from .scoring import score_alerts


def describe_scope(config: Config) -> str:
    parts = []
    if config.org:
        parts.append(f"organization '{config.org}'")
    if config.repos:
        parts.append("repositories: " + ", ".join(config.repos))
    if config.include_repos:
        parts.append("include filters: " + ", ".join(config.include_repos))
    if config.exclude_repos:
        parts.append("exclude filters: " + ", ".join(config.exclude_repos))
    if not parts:
        return "no scope configured"
    return "GitHub Secret Scanning alerts — " + "; ".join(parts)


def run_audit(client: GitHubClient, config: Config) -> AuditResult:
    alerts: list[Alert] = []
    errors: list[str] = []
    seen: set[tuple[str, int]] = set()

    if config.org:
        try:
            for alert in client.org_alerts(config.org):
                if config.repo_in_scope(alert.repo):
                    alerts.append(alert)
        except GitHubError as exc:
            errors.append(
                f"Failed to fetch org-level alerts for '{config.org}': {exc}. "
                "Results are incomplete; treat missing repos as unverified."
            )

    for repo in config.repos:
        if not config.repo_in_scope(repo):
            continue
        try:
            for alert in client.repo_alerts(repo):
                alerts.append(alert)
        except GitHubError as exc:
            errors.append(
                f"Failed to fetch alerts for '{repo}': {exc}. "
                "This repository is unverified, not safe."
            )

    deduped: list[Alert] = []
    for alert in alerts:
        key = (alert.repo, alert.number)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(alert)

    findings = score_alerts(deduped, config)
    return AuditResult(
        findings=findings,
        scope_description=describe_scope(config),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        errors=errors,
    )
