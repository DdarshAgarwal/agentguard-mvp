import hashlib
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .capabilities import validate_capability_scope, verify_capability
from .models import (
    AuthorizationBoundary,
    Decision,
    PaymentIntent,
    PolicyCheck,
    RiskContribution,
    SignedCapability,
)
from .security import make_id, now_iso
from .store import get_agent, get_recent_transaction_count, get_spent


MERCHANTS = {
    "hotel": ("StayEasy", "travel"),
    "book": ("BookNest", "books"),
    "books": ("BookNest", "books"),
    "groceries": ("FreshMart", "groceries"),
    "grocery": ("FreshMart", "groceries"),
}

PROMPT_INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous instructions",
    "override policy",
    "bypass security",
    "system prompt",
    "jailbreak",
    "administrator override",
    "forget the user's limits",
    "increase the spending limit",
    "disable safeguards",
    "ignore previous",
]


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def compile_intent(instruction: str, agent_id: str) -> PaymentIntent:
    low = instruction.lower()
    numbers = re.findall(r"(?:₹|rs\.?\s*)?([\d,]+)", low)
    amount = float(numbers[-1].replace(",", "")) if numbers else 1000
    merchant, category = next(
        ((merchant, category) for keyword, (merchant, category) in MERCHANTS.items() if keyword in low),
        ("FreshMart", "groceries"),
    )

    max_amount = amount
    if any(word in low for word in ["under", "below", "maximum", "max"]):
        max_amount = float(numbers[0].replace(",", "")) if numbers else amount
        amount = max_amount

    if "ignore" in low and len(numbers) > 1:
        amount = float(numbers[-1].replace(",", ""))

    issued_at = now_iso()
    authorization = AuthorizationBoundary(
        authorization_id=make_id("auth"),
        agent_id=agent_id,
        original_instruction=instruction,
        max_amount=max_amount,
        allowed_merchants=[merchant],
        allowed_categories=[category],
        allowed_actions=["purchase"],
        issued_at=issued_at,
    )
    return PaymentIntent(
        agent_id=agent_id,
        action="purchase",
        category=category,
        merchant=merchant,
        amount=amount,
        max_amount=max_amount,
        authorization_id=authorization.authorization_id,
        constraints={
            "source_instruction": instruction,
            "authorization_boundary": authorization.model_dump(),
        },
    )


def _check(rule: str, ok: bool, expected: Any, actual: Any, severity: str, message: str) -> PolicyCheck:
    return PolicyCheck(
        rule=rule,
        status="PASS" if ok else "FAIL",
        expected=expected,
        actual=actual,
        severity=severity,
        message=message,
    )


def _risk(signal: str, points: int, explanation: str) -> RiskContribution:
    return RiskContribution(signal=signal, points=points, explanation=explanation)


def evaluate(
    intent: PaymentIntent,
    idempotency_key: str,
    capability: Optional[SignedCapability],
) -> Decision:
    started = time.perf_counter()
    agent = get_agent(intent.agent_id)
    checks: list[PolicyCheck] = []
    risk: list[RiskContribution] = []
    reason_codes: list[str] = []
    hard_blocks: list[str] = []

    def fail(code: str, points: int, explanation: str, hard: bool = False) -> None:
        reason_codes.append(code)
        risk.append(_risk(code, points, explanation))
        if hard:
            hard_blocks.append(code)

    checks.append(_check("agent_identity", bool(agent), "known agent", intent.agent_id, "CRITICAL", "Agent identity exists."))
    if not agent:
        fail("UNKNOWN_AGENT", 100, "Unknown agent identity.", True)
    else:
        checks.append(
            _check(
                "agent_action",
                intent.action in agent["capabilities"],
                agent["capabilities"],
                intent.action,
                "CRITICAL",
                "Agent has the requested action capability.",
            )
        )
        if intent.action not in agent["capabilities"]:
            fail("UNAUTHORIZED_ACTION", 90, "Agent does not possess the requested action.", True)

    if not capability:
        checks.append(_check("capability_present", False, "signed capability", None, "CRITICAL", "Signed capability is required."))
        fail("CAPABILITY_MISSING", 100, "Request did not include a signed capability.", True)
    else:
        verification = verify_capability(capability)
        checks.append(
            _check(
                "capability_signature",
                verification["valid"],
                "valid signature and expiry",
                verification["code"],
                "CRITICAL",
                verification["message"],
            )
        )
        if not verification["valid"]:
            fail(verification["code"], 100, verification["message"], True)
        for scope_failure in validate_capability_scope(capability, intent):
            checks.append(
                _check(
                    scope_failure["code"].lower(),
                    False,
                    scope_failure["expected"],
                    scope_failure["actual"],
                    "CRITICAL" if "AGENT" in scope_failure["code"] or "ACTION" in scope_failure["code"] else "HIGH",
                    scope_failure["message"],
                )
            )
            fail(
                scope_failure["code"],
                90 if "AGENT" in scope_failure["code"] or "ACTION" in scope_failure["code"] else 50,
                scope_failure["message"],
                "AGENT" in scope_failure["code"] or "ACTION" in scope_failure["code"],
            )

    authorization = intent.constraints.get("authorization_boundary", {})
    authorized_amount = float(authorization.get("max_amount") or intent.max_amount or 0)
    allowed_merchants = authorization.get("allowed_merchants") or []
    allowed_categories = authorization.get("allowed_categories") or []
    allowed_actions = authorization.get("allowed_actions") or []

    checks.append(
        _check(
            "user_authorized_amount",
            authorized_amount > 0 and intent.amount <= authorized_amount,
            authorized_amount,
            intent.amount,
            "CRITICAL",
            "Request stays within the original user amount boundary.",
        )
    )
    if not authorized_amount or intent.amount > authorized_amount:
        fail("USER_AUTHORIZATION_AMOUNT_EXCEEDED", 70, "Transaction exceeds the user's original authorization.", True)

    checks.append(
        _check(
            "user_authorized_merchant",
            intent.merchant in allowed_merchants,
            allowed_merchants,
            intent.merchant,
            "HIGH",
            "Requested merchant matches the original user authorization.",
        )
    )
    if intent.merchant not in allowed_merchants:
        fail("USER_AUTHORIZATION_MERCHANT_MISMATCH", 45, "Merchant is outside the user's authorization.", False)

    checks.append(
        _check(
            "user_authorized_action",
            intent.action in allowed_actions,
            allowed_actions,
            intent.action,
            "CRITICAL",
            "Requested action matches the original user authorization.",
        )
    )
    if intent.action not in allowed_actions:
        fail("USER_AUTHORIZATION_ACTION_MISMATCH", 80, "Action is outside the user's authorization.", True)

    checks.append(
        _check(
            "user_authorized_category",
            intent.category in allowed_categories,
            allowed_categories,
            intent.category,
            "MEDIUM",
            "Requested category matches the original user authorization.",
        )
    )
    if intent.category not in allowed_categories:
        fail("USER_AUTHORIZATION_CATEGORY_MISMATCH", 30, "Category is outside the user's authorization.", False)

    expires_at = _parse_time(intent.expires_at)
    if expires_at:
        active = expires_at > datetime.now(timezone.utc)
        checks.append(_check("authorization_expiry", active, "future expiry", intent.expires_at, "CRITICAL", "Authorization time window is still active."))
        if not active:
            fail("AUTHORIZATION_EXPIRED", 80, "Client request used an expired authorization window.", True)

    if agent:
        checks.append(
            _check(
                "transaction_limit",
                intent.amount <= agent["transaction_limit"],
                agent["transaction_limit"],
                intent.amount,
                "HIGH",
                "Amount stays under the agent transaction limit.",
            )
        )
        if intent.amount > agent["transaction_limit"]:
            fail("TRANSACTION_LIMIT_EXCEEDED", 100, "Amount exceeds the server-enforced transaction limit.", True)

        spent = get_spent(intent.agent_id)
        checks.append(
            _check(
                "daily_budget",
                spent + intent.amount <= agent["daily_limit"],
                agent["daily_limit"] - spent,
                intent.amount,
                "HIGH",
                "Daily budget has enough remaining capacity.",
            )
        )
        if spent + intent.amount > agent["daily_limit"]:
            fail("DAILY_BUDGET_EXCEEDED", 60, "Transaction would exceed the daily budget.", True)

        since = (datetime.now(timezone.utc) - timedelta(seconds=agent["velocity_window_seconds"])).isoformat()
        recent = get_recent_transaction_count(intent.agent_id, since)
        checks.append(
            _check(
                "velocity_limit",
                recent < agent["velocity_limit_count"],
                f"{agent['velocity_limit_count']} per {agent['velocity_window_seconds']}s",
                recent + 1,
                "HIGH",
                "Transaction frequency is within velocity policy.",
            )
        )
        if recent >= agent["velocity_limit_count"]:
            fail("VELOCITY_LIMIT_EXCEEDED", 80, "Velocity policy would be exceeded.", True)

    instruction = str(intent.constraints.get("source_instruction", "")).lower()
    detected = [pattern for pattern in PROMPT_INJECTION_PATTERNS if pattern in instruction]
    checks.append(
        _check(
            "prompt_injection_signal",
            not detected,
            "no suspicious prompt patterns",
            detected,
            "HIGH",
            "Instruction does not contain known prompt-injection indicators.",
        )
    )
    if detected:
        fail("PROMPT_INJECTION_DETECTED", 100, "Suspicious prompt-injection wording was detected.", True)

    score = min(100, sum(item.points for item in risk))
    if hard_blocks or score >= 70:
        decision = "BLOCK"
    elif score >= 40:
        decision = "ESCALATE"
    else:
        decision = "ALLOW"

    if not reason_codes:
        reason_codes = ["SECURITY_CONTROLS_PASSED"]
        reasons = [
            "Agent identity verified",
            "Capability signature valid",
            "Transaction is within user authorization",
            "Merchant and budget controls passed",
            "No prompt-injection indicators",
        ]
    else:
        reasons = [item.explanation for item in risk]

    latency_ms = round((time.perf_counter() - started) * 1000, 3)
    return Decision(
        decision=decision,
        risk_score=score,
        reasons=reasons,
        reason_codes=reason_codes,
        policy_checks=checks,
        risk_contributions=risk,
        hard_blocks=hard_blocks,
        decision_id=make_id("dec"),
        latency_ms=latency_ms,
    )


def idem_key(intent: PaymentIntent) -> str:
    raw = (
        f"{intent.agent_id}|{intent.action}|{intent.category}|"
        f"{intent.merchant}|{intent.amount:.2f}|"
        f"{intent.constraints.get('source_instruction', '')}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
