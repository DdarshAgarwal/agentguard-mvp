import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from app.main import app, process_transaction
from app.models import SignedCapability, TransactionRequest
from app.engine import compile_intent, idem_key
from app.capabilities import issue_capability
from app.store import get_spent, reset_demo, upsert_agent, verify_audit_chain


@pytest.fixture()
def client():
    reset_demo()
    with TestClient(app) as test_client:
        yield test_client
    reset_demo()


def compiled(client, instruction="Buy groceries under ₹3000", agent_id="shopping-agent-01"):
    response = client.post("/api/intent/compile", json={"instruction": instruction, "agent_id": agent_id})
    assert response.status_code == 200
    return response.json()


def submit(client, intent, capability, key=None):
    response = client.post(
        "/api/evaluate",
        json={
            "intent": intent,
            "capability": capability,
            "idempotency_key": key or idem_key(compile_intent(intent["constraints"]["source_instruction"], intent["agent_id"])),
        },
    )
    assert response.status_code == 200
    return response.json()


def test_legitimate_transaction_allows_and_executes(client):
    data = compiled(client)
    result = submit(client, data["intent"], data["capability"], "legit-key-0001")
    assert result["decision"]["decision"] == "ALLOW"
    assert result["transaction"]["amount"] == 3000


@pytest.mark.parametrize(
    "attack",
    [
        "amount-escalation",
        "merchant-substitution",
        "prompt-injection",
        "velocity",
        "expired-capability",
        "capability-tampering",
        "unauthorized-action",
        "budget-exhaustion",
    ],
)
def test_attack_lab_blocks_core_attacks(client, attack):
    response = client.post(f"/api/attacks/{attack}")
    assert response.status_code == 200
    assert response.json()["blocked"] is True


def test_replay_blocks_second_execution(client):
    data = compiled(client)
    key = "same-idempotency-key"
    first = submit(client, data["intent"], data["capability"], key)
    second = submit(client, data["intent"], data["capability"], key)
    assert first["decision"]["decision"] == "ALLOW"
    assert second["replayed"] is True
    assert second["decision"]["reason_codes"] == ["REPLAY_DETECTED"]
    assert get_spent("shopping-agent-01") == 3000


def test_expired_capability_blocks(client):
    intent = compiled(client)["intent"]
    cap = issue_capability("shopping-agent-01", ttl_minutes=-1).model_dump()
    result = submit(client, intent, cap, "expired-cap-key")
    assert result["decision"]["decision"] == "BLOCK"
    assert "CAPABILITY_EXPIRED" in result["decision"]["reason_codes"]


def test_invalid_capability_signature_blocks(client):
    data = compiled(client)
    cap = data["capability"]
    cap["signature"] = "invalid"
    result = submit(client, data["intent"], cap, "bad-sig-key")
    assert result["decision"]["decision"] == "BLOCK"
    assert "CRYPTOGRAPHIC_SIGNATURE_INVALID" in result["decision"]["reason_codes"]


def test_frontend_claims_cannot_override_decision(client):
    data = compiled(client)
    data["intent"]["amount"] = 80000
    response = client.post(
        "/api/evaluate",
        json={
            "intent": data["intent"],
            "capability": data["capability"],
            "idempotency_key": "override-key",
            "client_claims": {"decision": "ALLOW", "risk_score": 0, "payment_status": "SUCCESS"},
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"]["decision"] == "BLOCK"


def test_concurrent_race_condition_does_not_overspend():
    reset_demo()
    upsert_agent("race-agent-01", "Race Demo Agent", 10000, 8000, ["purchase"], ["FreshMart"], ["groceries"], 10, 60)
    intent = compile_intent("Buy groceries under ₹8000", "race-agent-01")
    capability = issue_capability("race-agent-01")

    def send(label):
        return process_transaction(
            TransactionRequest(
                intent=intent,
                capability=capability,
                idempotency_key=f"race-test-{label}",
            )
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(send, ["a", "b"]))

    allowed = [r for r in results if r["decision"]["decision"] == "ALLOW"]
    blocked = [r for r in results if r["decision"]["decision"] == "BLOCK"]
    assert len(allowed) == 1
    assert len(blocked) == 1
    assert get_spent("race-agent-01") == 8000


def test_audit_hash_verification(client):
    data = compiled(client)
    submit(client, data["intent"], data["capability"], "audit-key")
    assert verify_audit_chain()["status"] == "AUDIT_CHAIN_VALID"


def test_malformed_request_is_rejected(client):
    response = client.post(
        "/api/evaluate",
        json={
            "intent": {"agent_id": "shopping-agent-01", "merchant": "FreshMart", "amount": -1},
            "idempotency_key": "bad-request",
        },
    )
    assert response.status_code == 422


def test_user_policy_changes_are_enforced_server_side(client):
    response = client.put(
        "/api/settings/shopping-agent-01",
        json={"daily_limit": 6000, "transaction_limit": 2000, "velocity_limit_count": 3, "velocity_window_seconds": 60},
    )
    assert response.status_code == 200
    data = compiled(client, "Buy groceries under ₹3000")
    assert data["capability"]["payload"]["max_transaction_amount"] == 2000
    result = submit(client, data["intent"], data["capability"], "policy-enforce-01")
    assert result["decision"]["decision"] == "BLOCK"
    assert "CAPABILITY_AMOUNT_EXCEEDED" in result["decision"]["reason_codes"]


def test_atomic_transaction_limit_is_final_server_boundary(client):
    data = compiled(client, "Buy groceries under ₹3000")
    data["intent"]["amount"] = 5001
    result = submit(client, data["intent"], data["capability"], "atomic-limit-01")
    assert result["decision"]["decision"] == "BLOCK"
    assert get_spent("shopping-agent-01") == 0
