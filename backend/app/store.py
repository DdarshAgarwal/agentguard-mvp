import sqlite3, json, os
from .security import hash_event, now_iso

DB=os.path.join(os.path.dirname(os.path.dirname(__file__)),"agentguard.db")

def conn():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c

def init():
    c=conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS agents (
      id TEXT PRIMARY KEY, name TEXT, daily_limit REAL, transaction_limit REAL,
      spent_today REAL, capabilities TEXT, allowed_merchants TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, agent_id TEXT,
      merchant TEXT, amount REAL, status TEXT, decision_id TEXT, created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT, actor TEXT,
      payload TEXT, event_hash TEXT, previous_hash TEXT, created_at TEXT
    );
    """)
    c.execute("INSERT OR IGNORE INTO agents VALUES (?,?,?,?,?,?,?)",
      ("shopping-agent-01","Shopping Agent",10000,5000,0,
       json.dumps(["purchase"]),json.dumps(["FreshMart","BookNest","StayEasy"])))
    c.commit(); c.close()

def get_agent(agent_id):
    c=conn(); row=c.execute("SELECT * FROM agents WHERE id=?",(agent_id,)).fetchone(); c.close()
    if not row:return None
    d=dict(row)
    d["capabilities"]=json.loads(d["capabilities"])
    d["allowed_merchants"]=json.loads(d["allowed_merchants"])
    return d

def get_spent(agent_id):
    c=conn(); row=c.execute("SELECT spent_today FROM agents WHERE id=?",(agent_id,)).fetchone(); c.close()
    return row["spent_today"] if row else 0

def add_spend(agent_id,amount):
    c=conn(); c.execute("UPDATE agents SET spent_today=spent_today+? WHERE id=?",(amount,agent_id)); c.commit(); c.close()

def get_tx_by_key(key):
    c=conn(); row=c.execute("SELECT * FROM transactions WHERE idempotency_key=?",(key,)).fetchone(); c.close()
    return dict(row) if row else None

def save_tx(tx):
    c=conn()
    c.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
      (tx["id"],tx["idempotency_key"],tx["agent_id"],tx["merchant"],tx["amount"],tx["status"],tx["decision_id"],tx["created_at"]))
    c.commit(); c.close()

def audit(event_type,actor,payload):
    c=conn(); row=c.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev=row["event_hash"] if row else "GENESIS"; created=now_iso()
    event={"event_type":event_type,"actor":actor,"payload":payload,"created_at":created}
    h=hash_event(event,prev)
    c.execute("INSERT INTO audit(event_type,actor,payload,event_hash,previous_hash,created_at) VALUES (?,?,?,?,?,?)",
      (event_type,actor,json.dumps(payload,sort_keys=True),h,prev,created))
    c.commit(); c.close(); return h

def audits():
    c=conn(); rows=c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 50").fetchall(); c.close()
    return [dict(r) for r in rows]
