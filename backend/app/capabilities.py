from datetime import datetime, timedelta, timezone
from typing import Any

from .models import CapabilityPayload, SignedCapability
from .security import capability_secret, constant_time_equal, hmac_sha256, make_id, now_iso
from .store import get_agent


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def issue_capability(agent_id: str = "shopping-agent-01", ttl_minutes: int = 10) -> SignedCapability:
    agent = get_agent(agent_id)
    if not agent:
        raise ValueError("UNKNOWN_AGENT")
    issued_at = datetime.now(timezone.utc)
    payload = CapabilityPayload(
        capability_id=make_id("cap"),
        agent_id=agent_id,
        subject=agent_id,
        action="purchase",
        max_transaction_amount=agent["transaction_limit"],
        daily_limit=agent["daily_limit"],
        allowed_merchants=agent["allowed_merchants"],
        allowed_categories=agent["allowed_categories"],
        issued_at=issued_at.isoformat(),
        expires_at=(issued_at + timedelta(minutes=ttl_minutes)).isoformat(),
        nonce=make_id("nonce"),
    )
    return sign_capability(payload)


def sign_capability(payload: CapabilityPayload) -> SignedCapability:
    return SignedCapability(
        payload=payload,
        signature=hmac_sha256(payload.model_dump(), capability_secret()),
    )


def verify_capability(capability: SignedCapability) -> dict[str, Any]:
    payload = capability.payload
    expected = hmac_sha256(payload.model_dump(), capability_secret())
    if not constant_time_equal(capability.signature, expected):
        return {
            "valid": False,
            "code": "CRYPTOGRAPHIC_SIGNATURE_INVALID",
            "message": "Capability signature does not match the signed payload.",
        }
    if payload.version != "cap-v1":
        return {
            "valid": False,
            "code": "CAPABILITY_VERSION_INVALID",
            "message": "Unsupported capability version.",
        }
    if _parse_time(payload.expires_at) <= datetime.now(timezone.utc):
        return {
            "valid": False,
            "code": "CAPABILITY_EXPIRED",
            "message": "Capability has expired.",
        }
    return {"valid": True, "code": "CAPABILITY_VALID", "message": "Capability verified."}


def validate_capability_scope(capability: SignedCapability, intent) -> list[dict[str, Any]]:
    payload = capability.payload
    failures: list[dict[str, Any]] = []
    if payload.agent_id != intent.agent_id or payload.subject != intent.agent_id:
        failures.append(
            {
                "code": "CAPABILITY_AGENT_MISMATCH",
                "message": "Capability is not bound to the requesting agent.",
                "expected": payload.agent_id,
                "actual": intent.agent_id,
            }
        )
    if payload.action != intent.action:
        failures.append(
            {
                "code": "CAPABILITY_ACTION_DENIED",
                "message": "Capability does not allow the requested action.",
                "expected": payload.action,
                "actual": intent.action,
            }
        )
    if intent.amount > payload.max_transaction_amount:
        failures.append(
            {
                "code": "CAPABILITY_AMOUNT_EXCEEDED",
                "message": "Transaction exceeds capability amount.",
                "expected": payload.max_transaction_amount,
                "actual": intent.amount,
            }
        )
    if intent.merchant not in payload.allowed_merchants:
        failures.append(
            {
                "code": "CAPABILITY_MERCHANT_DENIED",
                "message": "Merchant is outside capability allowlist.",
                "expected": payload.allowed_merchants,
                "actual": intent.merchant,
            }
        )
    if intent.category not in payload.allowed_categories:
        failures.append(
            {
                "code": "CAPABILITY_CATEGORY_DENIED",
                "message": "Category is outside capability allowlist.",
                "expected": payload.allowed_categories,
                "actual": intent.category,
            }
        )
    return failures
