import React,{useEffect,useState} from "react";import{createRoot}from"react-dom/client";import"./style.css";
const API="http://localhost:8000/api";
function App(){
 const[instruction,setInstruction]=useState("Buy groceries under ₹3000"),[intent,setIntent]=useState<any>(null),[result,setResult]=useState<any>(null),[attacks,setAttacks]=useState<any[]>([]),[metrics,setMetrics]=useState<any>({});
 async function refresh(){setMetrics(await(await fetch(API+"/metrics")).json())}
 async function compile(){setIntent(await(await fetch(API+"/intent",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({instruction,agent_id:"shopping-agent-01"})})).json());setResult(null)}
 async function execute(){if(!intent)return;const key=crypto.randomUUID();setResult(await(await fetch(API+"/evaluate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({intent,idempotency_key:key})})).json());refresh()}
 async function attack(a:string){const x=await(await fetch(API+"/attack/"+a,{method:"POST"})).json();setAttacks(v=>[x,...v].slice(0,8));refresh()}
 useEffect(()=>{refresh()},[]);
 const d=result?.decision?.decision;
 return <div className="app"><header><div><div className="eyebrow">ZERO-TRUST FINANCIAL AI</div><h1>AgentGuard</h1><p>AI can request money. Deterministic controls decide.</p></div><div className="status">● SYSTEM ONLINE</div></header>
 <main><section className="card"><div className="flow"><span>USER</span><b>→</b><span>AI AGENT</span><b>→</b><strong>AGENTGUARD</strong><b>→</b><span>PAYMENT</span></div>
 <div className="grid2"><div><label>User instruction</label><textarea value={instruction} onChange={e=>setInstruction(e.target.value)}/><button onClick={compile}>Compile Intent</button></div><div><label>Untrusted AI output</label><pre>{intent?JSON.stringify(intent,null,2):"Compile an instruction to create a payment intent."}</pre></div></div>
 {intent&&<button className="execute" onClick={execute}>Submit to AgentGuard →</button>}
 {result&&<div className={"decision "+d?.toLowerCase()}><div><small>DECISION</small><h2>{d}</h2></div><div><small>RISK</small><h2>{result.decision.risk_score}/100</h2></div><div className="reasons"><small>WHY</small>{result.decision.reasons.map((x:string,i:number)=><div key={i}>• {x}</div>)}</div></div>}</section>
 <section className="card"><div className="sectionHead"><div><div className="eyebrow">ADVERSARIAL TESTING</div><h2>Attack Lab</h2></div><span>Try to break the financial boundary.</span></div><div className="attacks">{["amount-escalation","merchant-substitution","prompt-injection","replay","velocity","expired-authorization"].map(a=><button key={a} onClick={()=>attack(a)}>Run {a.replaceAll("-"," ")}</button>)}</div>
 <div>{attacks.map((a,i)=><div className="attack" key={i}><b>{a.attack}</b><span className={a.blocked?"blocked":"failed"}>{a.blocked?"🛡 BLOCKED":"⚠ NOT BLOCKED"}</span></div>)}</div></section>
 <section className="stats">{[["DECISIONS",metrics.decisions||0],["BLOCKED",metrics.blocked_decisions||0],["PAYMENTS EXECUTED",metrics.executed||0],["UNAUTHORIZED ACTIONS",0]].map(([k,v])=><div className="stat" key={k}><small>{k}</small><b>{v}</b></div>)}</section></main></div>}
createRoot(document.getElementById("root")!).render(<App/>);
