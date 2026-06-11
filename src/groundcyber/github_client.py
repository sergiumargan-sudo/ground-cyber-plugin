"""Read-only GitHub API client.

Guarantees enforced here:
- Only HTTP GET requests are ever issued. Any other method raises before a
  connection is opened.
- Raw secret values returned by the secret-scanning API are hashed with
  SHA-256 the moment the response is parsed; the raw value is discarded and
  never stored on any object this module returns.
- Alert state is never modified; there is no code path that writes.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator, Optional

from . import __version__
from .models import Alert
from .redact import hash_secret, redact_text

API_ROOT = "https://api.github.com"
USER_AGENT = f"groundcyber/{__version__} (read-only closure audit)"


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(redact_text(message))
        self.status = status


class ReadOnlyViolation(RuntimeError):
    """Raised if anything attempts a non-GET request. This must never fire."""


def sanitize_alert_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Hash and remove the raw secret value from an API alert payload.

    Returns a new dict; the input dict also has its 'secret' key removed so
    no caller can accidentally retain the raw value.
    """
    secret_value = raw.pop("secret", None)
    sanitized = dict(raw)
    sanitized.pop("secret", None)
    if isinstance(secret_value, str) and secret_value:
        sanitized["secret_hash"] = hash_secret(secret_value)
        del secret_value
    else:
        sanitized["secret_hash"] = None
    return sanitized


def alert_from_payload(raw: dict[str, Any], repo_full_name: str) -> Alert:
    sanitized = sanitize_alert_payload(raw)
    return Alert(
        number=sanitized.get("number", 0),
        repo=repo_full_name,
        state=sanitized.get("state") or "open",
        secret_type=sanitized.get("secret_type") or "unknown",
        secret_type_display=(
            sanitized.get("secret_type_display_name")
            or sanitized.get("secret_type")
            or "unknown"
        ),
        resolution=sanitized.get("resolution"),
        validity=sanitized.get("validity"),
        secret_hash=sanitized.get("secret_hash"),
        created_at=sanitized.get("created_at"),
        updated_at=sanitized.get("updated_at"),
        resolved_at=sanitized.get("resolved_at"),
        resolved_by=(sanitized.get("resolved_by") or {}).get("login")
        if isinstance(sanitized.get("resolved_by"), dict)
        else None,
        publicly_leaked=sanitized.get("publicly_leaked"),
        multi_repo=sanitized.get("multi_repo"),
        push_protection_bypassed=sanitized.get("push_protection_bypassed"),
        html_url=sanitized.get("html_url"),
    )


class GitHubClient:
    def __init__(
        self,
        token: str,
        api_root: str = API_ROOT,
        max_retries: int = 3,
        sleep=time.sleep,
    ):
        self.token = token
        self.api_root = api_root.rstrip("/")
        self.max_retries = max_retries
        self._sleep = sleep

    # ── transport ────────────────────────────────────────────────────────
    def _get(self, path: str, params: Optional[dict[str, str]] = None) -> tuple[Any, dict[str, str]]:
        """Issue a GET request. Returns (parsed_json, response_headers)."""
        url = path if path.startswith("http") else f"{self.api_root}{path}"
        if params:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(params)

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
        )
        if request.get_method() != "GET":
            raise ReadOnlyViolation(
                f"non-GET request blocked: {request.get_method()} {url}"
            )

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    body = response.read().decode("utf-8")
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    return (json.loads(body) if body else None), headers
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = json.loads(exc.read().decode("utf-8")).get("message", "")
                except Exception:
                    pass
                if exc.code in (429, 502, 503) or (
                    exc.code == 403 and "rate limit" in detail.lower()
                ):
                    last_error = GitHubError(
                        f"GET {path} failed with {exc.code}: {detail}", exc.code
                    )
                    if attempt < self.max_retries:
                        self._sleep(2**attempt)
                        continue
                raise GitHubError(
                    f"GET {path} failed with {exc.code}: {detail}", exc.code
                ) from exc
            except urllib.error.URLError as exc:
                last_error = GitHubError(f"GET {path} failed: {exc.reason}")
                if attempt < self.max_retries:
                    self._sleep(2**attempt)
                    continue
                raise last_error from exc
        raise last_error or GitHubError(f"GET {path} failed")

    def _paginate(
        self, path: str, params: Optional[dict[str, str]] = None
    ) -> Iterator[Any]:
        params = dict(params or {})
        params.setdefault("per_page", "100")
        url: Optional[str] = path
        first = True
        while url:
            data, headers = self._get(url, params if first else None)
            first = False
            if isinstance(data, list):
                yield from data
            else:
                yield data
            url = _next_link(headers.get("link", ""))

    # ── read-only endpoints ──────────────────────────────────────────────
    def rate_limit(self) -> dict[str, Any]:
        data, _ = self._get("/rate_limit")
        return data

    def current_user(self) -> tuple[dict[str, Any], dict[str, str]]:
        return self._get("/user")

    def repo_alerts(self, repo_full_name: str) -> list[Alert]:
        owner_repo = repo_full_name.strip("/")
        path = f"/repos/{owner_repo}/secret-scanning/alerts"
        return [
            alert_from_payload(item, owner_repo)
            for item in self._paginate(path)
            if isinstance(item, dict)
        ]

    def org_alerts(self, org: str) -> list[Alert]:
        path = f"/orgs/{org}/secret-scanning/alerts"
        alerts = []
        for item in self._paginate(path):
            if not isinstance(item, dict):
                continue
            repo = (item.get("repository") or {}).get("full_name") or "unknown/unknown"
            alerts.append(alert_from_payload(item, repo))
        return alerts

    def probe_secret_scanning(self, org: str = "", repo: str = "") -> tuple[bool, str]:
        """Check secret-scanning API access without retrieving secret values."""
        if org:
            path = f"/orgs/{org}/secret-scanning/alerts"
        elif repo:
            path = f"/repos/{repo}/secret-scanning/alerts"
        else:
            return False, "no org or repo provided to probe"
        try:
            self._get(path, {"per_page": "1"})
            return True, "secret-scanning alert API reachable"
        except GitHubError as exc:
            return False, str(exc)


def _next_link(link_header: str) -> Optional[str]:
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        if 'rel="next"' in section[1]:
            return section[0].strip().strip("<>")
    return None
