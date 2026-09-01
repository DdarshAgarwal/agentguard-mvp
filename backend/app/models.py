from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


DecisionLiteral = Literal["ALLOW", "ESCALATE", "BLOCK"]
StatusLiteral = Literal["PASS", "FAIL", "WARN"]
SeverityLiteral = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class IntentRequest(BaseModel):
    instruction: str = Field(min_length=1, max_length=500)
    agent_id: str = Field(default="shopping-agent-01", min_length=1, max_length=80)


class AuthorizationBoundary(BaseModel):
    authorization_id: str
    agent_id: str
    original_instruction: str
    max_amount: float = Field(gt=0)
    allowed_merchants: list[str]
    allowed_categories: list[str]
    allowed_actions: list[str]
    issued_at: str


class PaymentIntent(BaseModel):
    agent_id: str = Field(min_length=1, max_length=80)
    action: str = Field(default="purchase", min_length=1, max_length=40)
    category: str = Field(default="groceries", min_length=1, max_length=80)
    merchant: str = Field(min_length=1, max_length=120)
    amount: float = Field(gt=0, le=1_000_000)
    currency: Literal["INR"] = "INR"
    authorization_id: Optional[str] = None
    max_amount: Optional[float] = Field(default=None, gt=0)
    user_authorized: bool = True
    expires_at: Optional[str] = None
    constraints: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CapabilityPayload(BaseModel):
    capability_id: str
    agent_id: str
    subject: str
    action: Literal["purchase"]
    max_transaction_amount: float = Field(gt=0)
    daily_limit: float = Field(gt=0)
    allowed_merchants: list[str]
    allowed_categories: list[str]
    issued_at: str
    expires_at: str
    nonce: str
    version: Literal["cap-v1"] = "cap-v1"


class SignedCapability(BaseModel):
    payload: CapabilityPayload
    signature: str
    algorithm: Literal["HMAC-SHA256"] = "HMAC-SHA256"


class PolicyCheck(BaseModel):
    rule: str
    status: StatusLiteral
    expected: Any = None
    actual: Any = None
    severity: SeverityLiteral
    message: str


class RiskContribution(BaseModel):
    signal: str
    points: int
    explanation: str


class Decision(BaseModel):
    decision: DecisionLiteral
    risk_score: int
    reasons: list[str]
    reason_codes: list[str]
    policy_checks: list[PolicyCheck]
    risk_contributions: list[RiskContribution]
    hard_blocks: list[str] = Field(default_factory=list)
    policy_version: str = "capability-policy-v3"
    decision_id: str
    latency_ms: float = 0


class TransactionRequest(BaseModel):
    intent: PaymentIntent
    idempotency_key: str = Field(min_length=8, max_length=160)
    capability: Optional[SignedCapability] = None
    attack_mode: Optional[str] = None
    client_claims: dict[str, Any] = Field(default_factory=dict)


class CapabilityIssueRequest(BaseModel):
    agent_id: str = "shopping-agent-01"


class CapabilityVerifyRequest(BaseModel):
    capability: SignedCapability


class AttackRun(BaseModel):
    attack: str
    name: str
    description: str
    payload: dict[str, Any]
    expected_boundary: str
    blocked: bool
    result: dict[str, Any]
    execution_time_ms: float
    attempted_amount: float = 0
    unauthorized_executed: float = 0
