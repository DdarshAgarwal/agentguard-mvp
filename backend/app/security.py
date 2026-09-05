import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCAL_SECRET = ROOT / ".agentguard_secret"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_id(prefix: str = "id") -> str:
    return f"{prefix}_{secrets.token_hex(6)}"


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load_secret(env_name: str) -> str:
    value = os.getenv(env_name)
    if value and len(value) >= 32:
        return value
    if os.getenv("AGENTGUARD_ENV", "development").lower() in {"production", "prod"}:
        raise RuntimeError(f"{env_name} must be configured with a 32+ character secret in production")
    if not LOCAL_SECRET.exists():
        LOCAL_SECRET.write_text(secrets.token_hex(32), encoding="utf-8")
        try:
            os.chmod(LOCAL_SECRET, 0o600)
        except OSError:
            pass
    secret = LOCAL_SECRET.read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        secret = secrets.token_hex(32)
        LOCAL_SECRET.write_text(secret, encoding="utf-8")
    return secret


def capability_secret() -> str:
    return _load_secret("CAPABILITY_SIGNING_SECRET")


def audit_secret() -> str:
    return _load_secret("AUDIT_SIGNING_SECRET")


def hmac_sha256(payload: Any, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left or "", right or "")


def hash_event(event: dict[str, Any], previous_hash: str) -> str:
    return hmac_sha256({"event": event, "previous_hash": previous_hash}, audit_secret())
