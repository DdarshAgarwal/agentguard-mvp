import hashlib, json, secrets
from datetime import datetime, timezone

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def make_id(prefix="id"):
    return f"{prefix}_{secrets.token_hex(6)}"

def hash_event(event: dict, previous_hash: str) -> str:
    payload=json.dumps(event,sort_keys=True,separators=(",",":"))
    return hashlib.sha256((previous_hash+payload).encode()).hexdigest()
