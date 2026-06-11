"""Secret hashing and redaction utilities.

Hard rules enforced here:
- Raw secret values are never stored: hash immediately, discard the raw value.
- Raw secret values are never printed: every string that reaches a log line,
  report, or terminal goes through ``redact_text``.
"""

from __future__ import annotations

import hashlib
import re

REDACTION_TEMPLATE = "[REDACTED-SECRET:sha256:{fingerprint}]"
FINGERPRINT_LENGTH = 12

# Patterns for secret-shaped strings. Deliberately aggressive: a false
# redaction costs readability, a missed redaction leaks a credential.
_SECRET_PATTERNS = [
    # GitHub tokens (classic, fine-grained, app, oauth, refresh)
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,255}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,255}"),
    # AWS access key id + secret access key heuristic
    re.compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}"),
    re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+=]{40}['\"]"),
    # OpenAI / Anthropic / Stripe / Slack / Google / GitLab / npm / PyPI
    re.compile(r"sk-[A-Za-z0-9_\-]{20,255}"),
    re.compile(r"(?:r|s)k_live_[A-Za-z0-9]{16,255}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,255}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"glpat-[A-Za-z0-9\-_]{20,255}"),
    re.compile(r"npm_[A-Za-z0-9]{36}"),
    re.compile(r"pypi-[A-Za-z0-9_\-]{20,255}"),
    # JWTs
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    # Private key blocks
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        re.DOTALL,
    ),
    # Generic long high-entropy-looking tokens assigned to secret-ish names
    re.compile(
        r"(?i)(?:secret|token|password|passwd|api[_\-]?key|auth)"
        r"['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=_\-]{16,}"
    ),
]


def hash_secret(raw_value: str) -> str:
    """Return the SHA-256 hex digest of a raw secret value.

    The caller must discard the raw value immediately after calling this.
    """
    return hashlib.sha256(raw_value.encode("utf-8", errors="replace")).hexdigest()


def fingerprint(raw_value: str) -> str:
    """Short non-reversible identifier used in reports and duplicate detection."""
    return hash_secret(raw_value)[:FINGERPRINT_LENGTH]


def redaction_for(raw_value: str) -> str:
    return REDACTION_TEMPLATE.format(fingerprint=fingerprint(raw_value))


def redact_text(text: str) -> str:
    """Replace every secret-shaped substring with a hashed redaction marker."""
    if not text:
        return text

    def _replace(match: re.Match) -> str:
        return redaction_for(match.group(0))

    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(_replace, text)
    return text


def pseudonymize_repo(full_name: str) -> str:
    """Stable non-reversible label for a repository name (privacy mode)."""
    return "repo-" + hash_secret(full_name)[:10]
