from pydantic import BaseModel, Field
from typing import Optional, Literal, Any

class IntentRequest(BaseModel):
    instruction: str
    agent_id: str = "shopping-agent-01"

class PaymentIntent(BaseModel):
    agent_id: str
    category: str = "purchase"
    merchant: str
    amount: float = Field(gt=0)
    currency: str = "INR"
    max_amount: Optional[float] = None
    user_authorized: bool = True
    expires_at: Optional[str] = None
    constraints: dict[str, Any] = {}

class TransactionRequest(BaseModel):
    intent: PaymentIntent
    idempotency_key: str
    attack_mode: Optional[str] = None

class Decision(BaseModel):
    decision: Literal["ALLOW", "BLOCK", "ESCALATE"]
    risk_score: float
    reasons: list[str]
    policy_version: str = "policy-v1"
    decision_id: str
