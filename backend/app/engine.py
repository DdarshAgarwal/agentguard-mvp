import re
import hashlib
from .models import PaymentIntent, Decision
from .security import make_id
from .store import get_agent, get_spent


MERCHANTS = {
    "hotel": "StayEasy",
    "book": "BookNest",
    "books": "BookNest",
    "groceries": "FreshMart",
    "grocery": "FreshMart",
}


# ---------------------------------------------------------
# INTENT COMPILER
# ---------------------------------------------------------

def compile_intent(instruction, agent_id):

    low = instruction.lower()

    numbers = re.findall(
        r"(?:₹|rs\.?\s*)?([\d,]+)",
        low
    )

    amount = (
        float(numbers[-1].replace(",", ""))
        if numbers
        else 1000
    )

    merchant = next(
        (
            merchant
            for keyword, merchant in MERCHANTS.items()
            if keyword in low
        ),
        "FreshMart"
    )

    max_amount = amount

    if any(
        word in low
        for word in ["under", "below", "maximum", "max"]
    ):
        max_amount = (
            float(numbers[0].replace(",", ""))
            if numbers
            else amount
        )

        amount = max_amount

    # Simulated prompt injection.
    # IMPORTANT:
    # The AI output is treated as untrusted.
    if "ignore" in low and len(numbers) > 1:

        amount = float(
            numbers[-1].replace(",", "")
        )

    return PaymentIntent(
        agent_id=agent_id,
        merchant=merchant,
        amount=amount,
        max_amount=max_amount,
        constraints={
            "source_instruction": instruction
        }
    )


# ---------------------------------------------------------
# CAPABILITY CHECK
# ---------------------------------------------------------

def check_capability(intent, agent):

    reasons = []
    risk = 0

    # 1. Agent must exist
    if not agent:
        return [
            "Unknown agent identity"
        ], 100

    # 2. Capability check
    if "purchase" not in agent["capabilities"]:

        reasons.append(
            "Agent does not possess PURCHASE capability"
        )

        risk += 70

    # 3. Transaction limit
    if intent.amount > agent["transaction_limit"]:

        reasons.append(
            f"Amount ₹{intent.amount:,.0f} exceeds "
            f"capability limit ₹{agent['transaction_limit']:,.0f}"
        )

        risk += 50

    # 4. Merchant capability
    if intent.merchant not in agent["allowed_merchants"]:

        reasons.append(
            f"Merchant '{intent.merchant}' "
            f"is outside capability allowlist"
        )

        risk += 50

    return reasons, risk


# ---------------------------------------------------------
# POLICY CHECK
# ---------------------------------------------------------

def check_policy(intent, agent):

    reasons = []
    risk = 0

    spent = get_spent(intent.agent_id)

    # User-authorized maximum
    if (
        intent.max_amount is not None
        and intent.amount > intent.max_amount
    ):

        reasons.append(
            "Transaction exceeds user-authorized maximum"
        )

        risk += 70

    # Daily budget
    if (
        spent + intent.amount
        > agent["daily_limit"]
    ):

        reasons.append(
            "Transaction would exceed daily agent budget"
        )

        risk += 60

    return reasons, risk


# ---------------------------------------------------------
# AI / PROMPT SECURITY
# ---------------------------------------------------------

def check_ai_security(intent):

    reasons = []
    risk = 0

    instruction = (
        intent.constraints
        .get("source_instruction", "")
        .lower()
    )

    injection_patterns = [
        "ignore previous",
        "ignore all previous",
        "disregard previous",
        "override instructions",
        "system prompt",
        "jailbreak",
    ]

    detected = [
        pattern
        for pattern in injection_patterns
        if pattern in instruction
    ]

    if detected:

        reasons.append(
            "Prompt-injection pattern detected"
        )

        risk += 50

    return reasons, risk


# ---------------------------------------------------------
# FINAL DECISION ENGINE
# ---------------------------------------------------------

def evaluate(intent, idempotency_key):

    agent = get_agent(intent.agent_id)

    reasons = []
    risk = 0

    # -----------------------------------------
    # CAPABILITY
    # -----------------------------------------

    capability_reasons, capability_risk = (
        check_capability(
            intent,
            agent
        )
    )

    reasons.extend(capability_reasons)
    risk += capability_risk

    # -----------------------------------------
    # POLICY
    # -----------------------------------------

    if agent:

        policy_reasons, policy_risk = (
            check_policy(
                intent,
                agent
            )
        )

        reasons.extend(policy_reasons)
        risk += policy_risk

    # -----------------------------------------
    # AI SECURITY
    # -----------------------------------------

    ai_reasons, ai_risk = (
        check_ai_security(intent)
    )

    reasons.extend(ai_reasons)
    risk += ai_risk

    # -----------------------------------------
    # RISK NORMALIZATION
    # -----------------------------------------

    risk = min(
        100,
        risk
    )

    # -----------------------------------------
    # DECISION
    # -----------------------------------------

    if risk >= 70:

        decision = "BLOCK"

    elif risk >= 40:

        decision = "ESCALATE"

    else:

        decision = "ALLOW"

    # -----------------------------------------
    # SUCCESS EXPLANATION
    # -----------------------------------------

    if not reasons:

        reasons = [
            "Agent capability verified",
            "Transaction amount within capability",
            "Merchant is authorized",
            "Daily budget available",
            "No prompt-injection indicators"
        ]

    return Decision(
        decision=decision,
        risk_score=risk,
        reasons=reasons,
        policy_version="capability-policy-v2",
        decision_id=make_id("dec")
    )


# ---------------------------------------------------------
# IDEMPOTENCY
# ---------------------------------------------------------

def idem_key(intent):

    raw = (
        f"{intent.agent_id}|"
        f"{intent.merchant}|"
        f"{intent.amount:.2f}|"
        f"{intent.constraints.get('source_instruction', '')}"
    )

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()