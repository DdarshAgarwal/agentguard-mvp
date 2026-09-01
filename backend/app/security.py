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
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _load_secret(env_name: str) -> str:
    value = os.getenv(env_name)
    if value:
        return value
    if not LOCAL_SECRET.exists():
        LOCAL_SECRET.write_text(secrets.token_hex(32), encoding="utf-8")
    return LOCAL_SECRET.read_text(encoding="utf-8").strip()


def capability_secret() -> str:
    return _load_secret("CAPABILITY_SIGNING_SECRET")


def audit_secret() -> str:
    return _load_secret("AUDIT_SIGNING_SECRET")


def hmac_sha256(payload: Any, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        canonical_json(payload).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left or "", right or "")


def hash_event(event: dict[str, Any], previous_hash: str) -> str:
    payload = {
        "event": event,
        "previous_hash": previous_hash,
    }
    return hmac_sha256(payload, audit_secret())
