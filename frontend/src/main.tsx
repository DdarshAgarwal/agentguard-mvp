import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

const API = "http://localhost:8000/api";

const ATTACKS = [
  ["amount-escalation", "Amount Escalation"],
  ["merchant-substitution", "Merchant Substitution"],
  ["prompt-injection", "Prompt Injection"],
  ["replay", "Replay"],
  ["velocity", "Velocity Abuse"],
  ["expired-capability", "Expired Capability"],
  ["capability-tampering", "Capability Tampering"],
  ["race-condition", "Race Condition"],
  ["unauthorized-action", "Unauthorized Action"],
  ["budget-exhaustion", "Budget Exhaustion"],
];

type ApiState = {
  intent?: any;
  capability?: any;
  authorization?: any;
};

function money(value: number | string | undefined) {
  const amount = Number(value || 0);
  return `₹${amount.toLocaleString("en-IN", { maximumFractionDigits: 0 })}`;
}

async function api(path: string, options: RequestInit = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed with ${response.status}`);
  }
  return response.json();
}

function BoundaryList({ checks = [] }: { checks: any[] }) {
  return (
    <div className="boundaryList">
      {checks.map((check, index) => (
        <div className={`boundary ${check.status.toLowerCase()}`} key={`${check.rule}-${index}`}>
          <span>{check.status === "PASS" ? "✓" : "✕"}</span>
          <div>
            <b>{check.rule.replaceAll("_", " ")}</b>
            <small>{check.message}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

function DecisionCard({ result }: { result: any }) {
  if (!result?.decision) return null;
  const decision = result.decision;
  return (
    <section className={`panel decisionPanel ${decision.decision.toLowerCase()}`}>
      <div className="decisionHero">
        <div>
          <small>SECURITY DECISION</small>
          <h2>{decision.decision}</h2>
          <p>{result.transaction ? "Simulated payment executed." : "No payment was executed."}</p>
        </div>
        <div className="riskDial">
          <span>{decision.risk_score}</span>
          <small>/100 risk</small>
        </div>
        <div>
          <small>LATENCY</small>
          <strong>{decision.latency_ms || 0} ms</strong>
        </div>
      </div>
      <BoundaryList checks={decision.policy_checks || []} />
      <div className="reasonBox">
        <small>WHY</small>
        {(decision.reasons || []).map((reason: string, index: number) => (
          <p key={index}>{reason}</p>
        ))}
      </div>
    </section>
  );
}

function CapabilityCard({ capability, metrics }: { capability?: any; metrics: any }) {
  const payload = capability?.payload;
  return (
    <section className="panel">
      <div className="sectionHead">
        <div>
          <small>AGENT CAPABILITY</small>
          <h2>Signed Spending Authority</h2>
        </div>
        <span className="pill good">Verified server-side</span>
      </div>
      {payload ? (
        <div className="capGrid">
          <div><small>Agent ID</small><b>{payload.agent_id}</b></div>
          <div><small>Action</small><b>{payload.action}</b></div>
          <div><small>Transaction Limit</small><b>{money(payload.max_transaction_amount)}</b></div>
          <div><small>Daily Limit</small><b>{money(payload.daily_limit)}</b></div>
          <div><small>Spent Today</small><b>{money(metrics.spent_today)}</b></div>
          <div><small>Expires</small><b>{new Date(payload.expires_at).toLocaleTimeString()}</b></div>
          <div className="wide"><small>Allowed Merchants</small><b>{payload.allowed_merchants.join(", ")}</b></div>
          <div className="wide"><small>Capability ID</small><b>{payload.capability_id}</b></div>
        </div>
      ) : (
        <p>Compile an instruction to issue a short-lived signed capability.</p>
      )}
    </section>
  );
}

function App() {
  const [instruction, setInstruction] = useState("Buy groceries under ₹3000");
  const [compiled, setCompiled] = useState<ApiState>({});
  const [result, setResult] = useState<any>(null);
  const [attacks, setAttacks] = useState<any[]>([]);
  const [benchmark, setBenchmark] = useState<any>(null);
  const [auditStatus, setAuditStatus] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>({});
  const [auditRows, setAuditRows] = useState<any[]>([]);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function refresh() {
    const [nextMetrics, nextAudit] = await Promise.all([api("/metrics"), api("/audit")]);
    setMetrics(nextMetrics);
    setAuditRows(nextAudit);
  }

  async function run(label: string, fn: () => Promise<void>) {
    setBusy(label);
    setError("");
    try {
      await fn();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Security gateway error");
    } finally {
      setBusy("");
    }
  }

  async function compile() {
    await run("compile", async () => {
      const data = await api("/intent/compile", {
        method: "POST",
        body: JSON.stringify({ instruction, agent_id: "shopping-agent-01" }),
      });
      setCompiled(data);
      setResult(null);
    });
  }

  async function execute() {
    if (!compiled.intent || !compiled.capability) return;
    await run("execute", async () => {
      const data = await api("/evaluate", {
        method: "POST",
        body: JSON.stringify({
          intent: compiled.intent,
          capability: compiled.capability,
          idempotency_key: crypto.randomUUID(),
        }),
      });
      setResult(data);
    });
  }

  async function attack(name: string) {
    await run(name, async () => {
      const data = await api(`/attacks/${name}`, { method: "POST" });
      setAttacks((items) => [data, ...items].slice(0, 10));
    });
  }

  async function runBenchmark() {
    await run("benchmark", async () => setBenchmark(await api("/benchmark/run", { method: "POST" })));
  }

  async function verifyAudit() {
    await run("audit", async () => setAuditStatus(await api("/audit/verify", { method: "POST" })));
  }

  async function reset() {
    await run("reset", async () => {
      await api("/demo/reset", { method: "POST" });
      setCompiled({});
      setResult(null);
      setAttacks([]);
      setBenchmark(null);
      setAuditStatus(null);
    });
  }

  useEffect(() => {
    refresh().catch((err) => setError(err.message));
  }, []);

  const demoSteps = useMemo(
    () => ["Legitimate transaction", "Amount escalation", "Prompt injection", "Capability tampering", "Replay", "Race condition", "Security benchmark"],
    []
  );

  return (
    <div className="app">
      <header className="hero">
        <div>
          <small>ZERO-TRUST FINANCIAL AI</small>
          <h1>AgentGuard</h1>
          <p>AI can request money. Deterministic controls decide.</p>
        </div>
        <div className="heroActions">
          <span className="status">SYSTEM ONLINE</span>
          <button onClick={reset} disabled={!!busy}>Reset Demo</button>
        </div>
      </header>

      {error && <div className="error"><b>SECURITY GATEWAY ERROR</b><span>{error}</span></div>}

      <main>
        <section className="flow">
          {["USER", "AI AGENT", "AGENTGUARD", "SIMULATED PAYMENT"].map((item, index) => (
            <React.Fragment key={item}>
              <span className={item === "AGENTGUARD" ? "active" : ""}>{item}</span>
              {index < 3 && <b>→</b>}
            </React.Fragment>
          ))}
        </section>

        <div className="layout">
          <section className="panel simulator">
            <div className="sectionHead">
              <div>
                <small>TRANSACTION SIMULATOR</small>
                <h2>Untrusted AI Intent</h2>
              </div>
              <span className="pill">Mock payment environment</span>
            </div>
            <label>User Instruction</label>
            <textarea value={instruction} onChange={(event) => setInstruction(event.target.value)} />
            <div className="buttonRow">
              <button onClick={compile} disabled={!!busy}>{busy === "compile" ? "Compiling..." : "Compile Intent"}</button>
              <button className="primary" onClick={execute} disabled={!compiled.intent || !!busy}>Submit to AgentGuard</button>
            </div>
            <label>Untrusted AI Output</label>
            <pre>{compiled.intent ? JSON.stringify(compiled.intent, null, 2) : "Compile an instruction to create a payment intent."}</pre>
          </section>

          <CapabilityCard capability={compiled.capability} metrics={metrics} />
        </div>

        <DecisionCard result={result} />

        <section className="panel">
          <div className="sectionHead">
            <div>
              <small>ADVERSARIAL TESTING</small>
              <h2>Attack Lab</h2>
            </div>
            <span>Isolated simulations against backend controls</span>
          </div>
          <div className="attackGrid">
            {ATTACKS.map(([key, label]) => (
              <button key={key} onClick={() => attack(key)} disabled={!!busy}>
                <span>{label}</span>
                <small>{busy === key ? "Evaluating" : "Run attack"}</small>
              </button>
            ))}
          </div>
          <div className="attackResults">
            {attacks.map((item) => (
              <div className="attackResult" key={`${item.attack}-${item.execution_time_ms}`}>
                <div>
                  <b>{item.name}</b>
                  <small>{item.expected_boundary}</small>
                </div>
                <span className={item.blocked ? "pill good" : "pill bad"}>{item.blocked ? "BLOCKED" : "NOT BLOCKED"}</span>
                <span>{money(item.attempted_amount)} attempted</span>
                <span>{item.execution_time_ms} ms</span>
              </div>
            ))}
          </div>
        </section>

        <section className="stats">
          {[
            ["Decisions", metrics.decisions || 0],
            ["Blocked", metrics.blocked_decisions || 0],
            ["Payments Executed", metrics.executed || 0],
            ["Money Prevented", money(metrics.unauthorized_money_prevented)],
          ].map(([label, value]) => (
            <div className="stat" key={label}>
              <small>{label}</small>
              <b>{value}</b>
            </div>
          ))}
        </section>

        <section className="panel benchmark">
          <div className="sectionHead">
            <div>
              <small>SECURITY BENCHMARK</small>
              <h2>Unauthorized Money Prevented</h2>
            </div>
            <button onClick={runBenchmark} disabled={!!busy}>{busy === "benchmark" ? "Running..." : "Run Benchmark"}</button>
          </div>
          {benchmark ? (
            <div className="benchmarkGrid">
              <div><small>Security Score</small><b>{benchmark.security_score}%</b></div>
              <div><small>Scenarios</small><b>{benchmark.blocked_attacks}/{benchmark.total_attack_scenarios}</b></div>
              <div><small>Attempted</small><b>{money(benchmark.attempted_malicious_amount)}</b></div>
              <div><small>Executed</small><b>{money(benchmark.unauthorized_amount_executed)}</b></div>
              <div><small>Prevented</small><b>{money(benchmark.unauthorized_money_prevented)}</b></div>
              <div><small>p95 Latency</small><b>{benchmark.p95_decision_latency_ms} ms</b></div>
            </div>
          ) : (
            <p>Run all adversarial scenarios to calculate security score and prevented amount from actual simulations.</p>
          )}
        </section>

        <section className="panel">
          <div className="sectionHead">
            <div>
              <small>AUDIT TRAIL</small>
              <h2>Tamper-Evident Hash Chain</h2>
            </div>
            <button onClick={verifyAudit} disabled={!!busy}>Verify Audit Integrity</button>
          </div>
          {auditStatus && <div className={`auditStatus ${auditStatus.valid ? "goodText" : "badText"}`}>{auditStatus.status}</div>}
          <div className="auditTable">
            {auditRows.slice(0, 8).map((row) => (
              <div className="auditRow" key={row.event_id}>
                <span>{new Date(row.created_at).toLocaleTimeString()}</span>
                <b>{row.event_type}</b>
                <span>{row.decision || "RECORDED"}</span>
                <span>{row.risk_score ?? "-"}</span>
                <code>{row.event_hash.slice(0, 12)}</code>
              </div>
            ))}
          </div>
        </section>

        <section className="panel demo">
          <small>5-MINUTE DEMO MODE</small>
          <div>{demoSteps.map((step, index) => <span key={step}>{index + 1}. {step}</span>)}</div>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
