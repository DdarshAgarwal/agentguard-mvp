import json
import os
import sqlite3
from contextlib import contextmanager
from typing import Any, Optional
from datetime import datetime, timedelta, timezone

from .security import hash_event, make_id, now_iso


DB = os.getenv(
    "DATABASE_URL",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "agentguard.db"),
)


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB, timeout=30, isolation_level=None, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


@contextmanager
def db():
    c = conn()
    try:
        yield c
    finally:
        c.close()


def _add_column(c: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = [row["name"] for row in c.execute(f"PRAGMA table_info({table})")]
    if column not in columns:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init() -> None:
    with db() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  daily_limit REAL NOT NULL,
  transaction_limit REAL NOT NULL,
  spent_today REAL NOT NULL DEFAULT 0,
  spend_day TEXT NOT NULL DEFAULT '',
  policy_version INTEGER NOT NULL DEFAULT 1,
  capabilities TEXT NOT NULL,
  allowed_merchants TEXT NOT NULL,
  allowed_categories TEXT NOT NULL DEFAULT '["groceries","books","travel"]',
  velocity_limit_count INTEGER NOT NULL DEFAULT 3,
  velocity_window_seconds INTEGER NOT NULL DEFAULT 60
);
            CREATE TABLE IF NOT EXISTS transactions (
              id TEXT PRIMARY KEY,
              idempotency_key TEXT UNIQUE NOT NULL,
              agent_id TEXT NOT NULL,
              merchant TEXT NOT NULL,
              amount REAL NOT NULL,
              status TEXT NOT NULL,
              decision_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              decision TEXT,
              risk_score REAL,
              capability_id TEXT,
              original_instruction TEXT,
              attack_run_id TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_id TEXT UNIQUE NOT NULL,
              transaction_id TEXT,
              agent_id TEXT,
              event_type TEXT NOT NULL,
              decision TEXT,
              risk_score REAL,
              policy_version TEXT,
              capability_id TEXT,
              reason_codes TEXT NOT NULL,
              amount REAL,
              merchant TEXT,
              payload TEXT NOT NULL,
              previous_hash TEXT NOT NULL,
              event_hash TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attack_runs (
              id TEXT PRIMARY KEY,
              attack TEXT NOT NULL,
              blocked INTEGER NOT NULL,
              attempted_amount REAL NOT NULL,
              unauthorized_executed REAL NOT NULL,
              latency_ms REAL NOT NULL,
              payload TEXT NOT NULL,
              result TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_transactions_agent_created ON transactions(agent_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
            """
        )
        for column, definition in [
            ("allowed_categories", "TEXT NOT NULL DEFAULT '[\"groceries\",\"books\",\"travel\"]'"),
            ("velocity_limit_count", "INTEGER NOT NULL DEFAULT 3"),
            ("velocity_window_seconds", "INTEGER NOT NULL DEFAULT 60"),
            ("policy_version", "INTEGER NOT NULL DEFAULT 1"),
            ("spend_day", "TEXT NOT NULL DEFAULT ''"),
        ]:
            _add_column(c, "agents", column, definition)
        for column, definition in [
            ("decision", "TEXT"),
            ("risk_score", "REAL"),
            ("capability_id", "TEXT"),
            ("original_instruction", "TEXT"),
            ("attack_run_id", "TEXT"),
        ]:
            _add_column(c, "transactions", column, definition)
        c.execute(
            """
            INSERT OR IGNORE INTO agents
            (id, name, daily_limit, transaction_limit, spent_today, capabilities,
             allowed_merchants, allowed_categories, velocity_limit_count, velocity_window_seconds)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "shopping-agent-01",
                "Shopping Agent",
                10000,
                5000,
                0,
                json.dumps(["purchase"]),
                json.dumps(["FreshMart", "BookNest", "StayEasy"]),
                json.dumps(["groceries", "books", "travel"]),
                3,
                60,
            ),
        )


def reset_demo(clear_attack_runs: bool = True) -> None:
    init()
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        c.execute("UPDATE agents SET spent_today=0, spend_day=? WHERE id='shopping-agent-01'", (_today(),))
        c.execute("DELETE FROM transactions")
        c.execute("DELETE FROM audit_events")
        if clear_attack_runs:
            c.execute("DELETE FROM attack_runs")
        c.execute("COMMIT")


def get_agent(agent_id: str) -> Optional[dict[str, Any]]:
    with db() as c:
        row = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (agent_id,),
        ).fetchone()

        if not row:
            return None

        data = dict(row)

        today = _today()

        if data.get("spend_day") != today:
            c.execute(
                """
                UPDATE agents
                SET spent_today=0, spend_day=?
                WHERE id=?
                """,
                (today, agent_id),
            )

            data["spent_today"] = 0
            data["spend_day"] = today

        data["capabilities"] = json.loads(data["capabilities"])
        data["allowed_merchants"] = json.loads(data["allowed_merchants"])
        data["allowed_categories"] = json.loads(data["allowed_categories"])

        return data

def list_agents() -> list[dict[str, Any]]:
    with db() as c:
        rows = c.execute("SELECT * FROM agents ORDER BY id").fetchall()
    return [get_agent(row["id"]) for row in rows]


def upsert_agent(
    agent_id: str,
    name: str,
    daily_limit: float,
    transaction_limit: float,
    capabilities: list[str],
    allowed_merchants: list[str],
    allowed_categories: list[str],
    velocity_limit_count: int = 3,
    velocity_window_seconds: int = 60,
) -> None:
    with db() as c:
        c.execute(
            """
            INSERT INTO agents
            (id, name, daily_limit, transaction_limit, spent_today, capabilities,
             allowed_merchants, allowed_categories, velocity_limit_count, velocity_window_seconds)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
              name=excluded.name,
              daily_limit=excluded.daily_limit,
              transaction_limit=excluded.transaction_limit,
              spent_today=0,
              capabilities=excluded.capabilities,
              allowed_merchants=excluded.allowed_merchants,
              allowed_categories=excluded.allowed_categories,
              velocity_limit_count=excluded.velocity_limit_count,
              velocity_window_seconds=excluded.velocity_window_seconds
            """,
            (
                agent_id,
                name,
                daily_limit,
                transaction_limit,
                0,
                json.dumps(capabilities),
                json.dumps(allowed_merchants),
                json.dumps(allowed_categories),
                velocity_limit_count,
                velocity_window_seconds,
            ),
        )


def get_spent(agent_id: str) -> float:

    agent = get_agent(agent_id)

    if not agent:
        return 0.0

    return float(agent["spent_today"])


def get_recent_transaction_count(agent_id: str, since_iso: str) -> int:
    with db() as c:
        row = c.execute(
            "SELECT COUNT(*) AS count FROM transactions WHERE agent_id=? AND status='SUCCESS' AND created_at>=?",
            (agent_id, since_iso),
        ).fetchone()
    return int(row["count"]) if row else 0


def get_tx_by_key(key: str) -> Optional[dict[str, Any]]:
    with db() as c:
        row = c.execute("SELECT * FROM transactions WHERE idempotency_key=?", (key,)).fetchone()
    return dict(row) if row else None


def list_transactions(limit: int = 50) -> list[dict[str, Any]]:
    with db() as c:
        rows = c.execute(
            "SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def execute_payment_atomic(
    tx: dict[str, Any],
    daily_limit: float | None = None,
    attack_run_id: Optional[str] = None,
) -> dict[str, Any]:
    """Atomically enforce replay, policy, velocity and daily budget before payment."""
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        try:
            existing = c.execute(
                "SELECT * FROM transactions WHERE idempotency_key=?",
                (tx["idempotency_key"],),
            ).fetchone()
            if existing:
                c.execute("COMMIT")
                return {"status": "REPLAY", "transaction": dict(existing)}

            agent = c.execute(
                """
                SELECT spent_today, daily_limit, transaction_limit,
                       spend_day, velocity_limit_count, velocity_window_seconds
                FROM agents WHERE id=?
                """,
                (tx["agent_id"],),
            ).fetchone()
            if not agent:
                c.execute("ROLLBACK")
                return {"status": "BLOCKED", "reason": "UNKNOWN_AGENT"}

            today = _today()
            spent = float(agent["spent_today"])
            if agent["spend_day"] != today:
                spent = 0.0
                c.execute("UPDATE agents SET spent_today=0, spend_day=? WHERE id=?", (today, tx["agent_id"]))

            amount = float(tx["amount"])
            current_daily = float(agent["daily_limit"])
            current_transaction = float(agent["transaction_limit"])
            velocity_limit = int(agent["velocity_limit_count"])
            velocity_window = int(agent["velocity_window_seconds"])

            if amount > current_transaction:
                c.execute("ROLLBACK")
                return {
                    "status": "BLOCKED",
                    "reason": "ATOMIC_TRANSACTION_LIMIT_EXCEEDED",
                    "transaction_limit": current_transaction,
                    "attempted_amount": amount,
                }

            since = (datetime.now(timezone.utc) - timedelta(seconds=velocity_window)).isoformat()
            recent_row = c.execute(
                "SELECT COUNT(*) AS count FROM transactions WHERE agent_id=? AND status='SUCCESS' AND created_at>=?",
                (tx["agent_id"], since),
            ).fetchone()
            recent = int(recent_row["count"] if recent_row else 0)
            if recent >= velocity_limit:
                c.execute("ROLLBACK")
                return {
                    "status": "BLOCKED",
                    "reason": "ATOMIC_VELOCITY_LIMIT_EXCEEDED",
                    "velocity_limit_count": velocity_limit,
                    "velocity_window_seconds": velocity_window,
                    "recent_transactions": recent,
                }

            if spent + amount > current_daily:
                c.execute("ROLLBACK")
                return {
                    "status": "BLOCKED",
                    "reason": "ATOMIC_BUDGET_EXCEEDED",
                    "spent_before": spent,
                    "daily_limit": current_daily,
                    "remaining": max(0.0, current_daily - spent),
                }

            c.execute(
                "UPDATE agents SET spent_today=spent_today+?, spend_day=? WHERE id=?",
                (amount, today, tx["agent_id"]),
            )
            c.execute(
                """
                INSERT INTO transactions
                (id,idempotency_key,agent_id,merchant,amount,status,decision_id,created_at,
                 decision,risk_score,capability_id,original_instruction,attack_run_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    tx["id"], tx["idempotency_key"], tx["agent_id"], tx["merchant"], amount,
                    tx["status"], tx["decision_id"], tx["created_at"], tx.get("decision"),
                    tx.get("risk_score"), tx.get("capability_id"), tx.get("original_instruction"), attack_run_id,
                ),
            )
            saved = c.execute("SELECT * FROM transactions WHERE id=?", (tx["id"],)).fetchone()
            c.execute("COMMIT")
            return {"status": "SUCCESS", "transaction": dict(saved)}
        except Exception:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

def audit(
    event_type: str,
    actor: Optional[str],
    payload: dict[str, Any],
    transaction_id: Optional[str] = None,
    decision: Optional[str] = None,
    risk_score: Optional[float] = None,
    policy_version: Optional[str] = None,
    capability_id: Optional[str] = None,
    reason_codes: Optional[list[str]] = None,
    amount: Optional[float] = None,
    merchant: Optional[str] = None,
) -> str:
    with db() as c:
        row = c.execute(
            "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = row["event_hash"] if row else "GENESIS"
        created_at = now_iso()
        event_id = make_id("evt")
        normalized_risk = float(risk_score) if risk_score is not None else None
        normalized_amount = float(amount) if amount is not None else None
        event = {
            "event_id": event_id,
            "timestamp": created_at,
            "transaction_id": transaction_id,
            "agent_id": actor,
            "event_type": event_type,
            "decision": decision,
            "risk_score": normalized_risk,
            "policy_version": policy_version,
            "capability_id": capability_id,
            "reason_codes": reason_codes or [],
            "amount": normalized_amount,
            "merchant": merchant,
            "payload": payload,
        }
        event_hash = hash_event(event, previous_hash)
        c.execute(
            """
            INSERT INTO audit_events
            (event_id, transaction_id, agent_id, event_type, decision, risk_score,
             policy_version, capability_id, reason_codes, amount, merchant, payload,
             previous_hash, event_hash, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id,
                transaction_id,
                actor,
                event_type,
                decision,
                normalized_risk,
                policy_version,
                capability_id,
                json.dumps(reason_codes or [], sort_keys=True),
                normalized_amount,
                merchant,
                json.dumps(payload, sort_keys=True),
                previous_hash,
                event_hash,
                created_at,
            ),
        )
        return event_hash


def audits(limit: int = 50) -> list[dict[str, Any]]:
    with db() as c:
        rows = c.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def verify_audit_chain() -> dict[str, Any]:
    with db() as c:
        rows = c.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    previous_hash = "GENESIS"
    for index, row in enumerate(rows):
        payload = json.loads(row["payload"])
        event = {
            "event_id": row["event_id"],
            "timestamp": row["created_at"],
            "transaction_id": row["transaction_id"],
            "agent_id": row["agent_id"],
            "event_type": row["event_type"],
            "decision": row["decision"],
            "risk_score": row["risk_score"],
            "policy_version": row["policy_version"],
            "capability_id": row["capability_id"],
            "reason_codes": json.loads(row["reason_codes"]),
            "amount": row["amount"],
            "merchant": row["merchant"],
            "payload": payload,
        }
        expected_hash = hash_event(event, previous_hash)
        if row["previous_hash"] != previous_hash or row["event_hash"] != expected_hash:
            return {
                "valid": False,
                "status": "TAMPERING_DETECTED",
                "failed_event_id": row["event_id"],
                "failed_index": index,
            }
        previous_hash = row["event_hash"]
    return {"valid": True, "status": "AUDIT_CHAIN_VALID", "events_checked": len(rows)}


def save_attack_run(run: dict[str, Any]) -> None:
    with db() as c:
        c.execute(
            """
            INSERT INTO attack_runs
            (id, attack, blocked, attempted_amount, unauthorized_executed,
             latency_ms, payload, result, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (
                run["id"],
                run["attack"],
                int(run["blocked"]),
                run["attempted_amount"],
                run["unauthorized_executed"],
                run["latency_ms"],
                json.dumps(run["payload"], sort_keys=True),
                json.dumps(run["result"], sort_keys=True),
                now_iso(),
            ),
        )


def list_attack_runs() -> list[dict[str, Any]]:
    with db() as c:
        rows = c.execute("SELECT * FROM attack_runs ORDER BY created_at DESC").fetchall()
    return [dict(row) for row in rows]

def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()

def update_spending_policy(
    agent_id: str,
    daily_limit: float,
    transaction_limit: float,
    velocity_limit_count: int = 3,
    velocity_window_seconds: int = 60,
) -> dict[str, Any]:

    if transaction_limit > daily_limit:
        raise ValueError(
            "TRANSACTION_LIMIT_CANNOT_EXCEED_DAILY_LIMIT"
        )

    with db() as c:
        c.execute("BEGIN IMMEDIATE")

        row = c.execute(
            "SELECT * FROM agents WHERE id=?",
            (agent_id,),
        ).fetchone()

        if not row:
            c.execute("ROLLBACK")
            raise ValueError("UNKNOWN_AGENT")

        current_version = int(row["policy_version"] or 1)

        new_version = current_version + 1

        c.execute(
            """
            UPDATE agents
            SET
                daily_limit=?,
                transaction_limit=?,
                velocity_limit_count=?,
                velocity_window_seconds=?,
                policy_version=?
            WHERE id=?
            """,
            (
                daily_limit,
                transaction_limit,
                velocity_limit_count,
                velocity_window_seconds,
                new_version,
                agent_id,
            ),
        )

        c.execute("COMMIT")

    audit(
        "SPENDING_POLICY_UPDATED",
        agent_id,
        {
            "daily_limit": daily_limit,
            "transaction_limit": transaction_limit,
            "velocity_limit_count": velocity_limit_count,
            "velocity_window_seconds": velocity_window_seconds,
            "policy_version": new_version,
        },
    )

    return get_agent(agent_id)