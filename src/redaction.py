import json
import hashlib
import os
import re
from typing import Any


SECRET_ENV_NAMES = [
    "MH_API_KEY",
    "SOLANA_PRIVATE_KEY",
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
]

SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|private[_-]?key|secret|seed|mnemonic|bearer|authorization|token|password)"
)

QUERY_SECRET_RE = re.compile(r"(?i)([?&](?:key|api_key|apikey)=)([^&\s\"']+)")
BEARER_RE = re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{12,})")
PREFIXED_SECRET_RE = re.compile(r"\b((?:sk|pk|ghp|gho|github_pat|xoxb|xoxp|mh_test|mh_live)_[A-Za-z0-9_\-]{8,})\b")
SOLANA_KEYPAIR_RE = re.compile(r"\[(?:\s*\d{1,3}\s*,){63}\s*\d{1,3}\s*\]")


def known_secrets() -> list[str]:
    values: list[str] = []
    for name in SECRET_ENV_NAMES:
        value = os.environ.get(name)
        if value and len(value) >= 6 and "<" not in value:
            values.append(value)
    return values


def _fingerprint(secret: str, label: str = "secret") -> str:
    digest = hashlib.sha256(secret.encode("utf-8", "ignore")).hexdigest()[:16]
    return f"<redacted-{label}:sha256={digest}:len={len(secret)}>"


def redact_text(text: str) -> str:
    safe = text
    for secret in known_secrets():
        safe = safe.replace(secret, _fingerprint(secret, "env-secret"))
    safe = QUERY_SECRET_RE.sub(lambda m: m.group(1) + _fingerprint(m.group(2), "query-secret"), safe)
    safe = BEARER_RE.sub(lambda m: m.group(1) + _fingerprint(m.group(2), "bearer"), safe)
    safe = PREFIXED_SECRET_RE.sub(lambda m: _fingerprint(m.group(1), "prefixed-secret"), safe)
    safe = SOLANA_KEYPAIR_RE.sub(lambda m: _fingerprint(m.group(0), "solana-keypair"), safe)
    return safe


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        safe = {}
        for key, item in value.items():
            if SECRET_KEY_RE.search(str(key)):
                if isinstance(item, str):
                    safe[key] = _fingerprint(item, "field-secret")
                else:
                    safe[key] = "<redacted-secret-value>"
            else:
                safe[key] = sanitize(item)
        return safe
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def safe_json(value: Any, *, indent: int | None = None, max_chars: int | None = None) -> str:
    text = json.dumps(sanitize(value), indent=indent, default=str)
    text = redact_text(text)
    if max_chars is not None:
        return text[:max_chars]
    return text
