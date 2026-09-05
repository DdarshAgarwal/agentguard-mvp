====================================================================
                         AGENTGUARD
          ZERO-TRUST SECURITY FOR AUTONOMOUS AI PAYMENTS
====================================================================

AI CAN REQUEST MONEY.
DETERMINISTIC CONTROLS DECIDE.

Razorpay AI Buildathon 2026
Track: Open Track

--------------------------------------------------------------------
1. PROJECT OVERVIEW
--------------------------------------------------------------------

AgentGuard is a prototype zero-trust security control plane designed
to protect financial actions initiated by autonomous AI agents.

As LLM-powered AI agents become capable of taking actions on behalf
of users, including initiating purchases and financial transactions,
a critical security problem emerges:

An LLM can understand instructions and generate a payment intent, but
its output should never automatically be treated as authorization to
move money.

LLMs are probabilistic systems. They can:

- Misinterpret user instructions
- Hallucinate transaction amounts
- Generate unauthorized actions
- Be manipulated through prompt injection
- Repeat previously executed requests
- Behave unexpectedly

AgentGuard addresses this by separating:

                    AI REASONING
                         from
                FINANCIAL AUTHORIZATION

The AI agent generates a proposed payment intent.

AgentGuard independently determines whether that intent is authorized.

The architecture is:

USER POLICY
     |
     v
LLM / AI AGENT
     |
     v
UNTRUSTED PAYMENT INTENT
     |
     v
AGENTGUARD
     |
     +--> Identity Verification
     +--> Capability Verification
     +--> Policy Validation
     +--> Transaction Limit
     +--> Daily Budget
     +--> Velocity Controls
     +--> Merchant/Category Rules
     +--> Replay Protection
     +--> Risk Evaluation
     +--> Prompt Injection Detection
     |
     v
DETERMINISTIC AUTHORIZATION
     |
     +---- BLOCK
     |
     +---- ESCALATE
     |
     v
SIMULATED PAYMENT
     |
     v
TAMPER-EVIDENT AUDIT LOG


Core principle:

"AI can request money. Deterministic controls decide whether money
can actually move."


--------------------------------------------------------------------
2. PROBLEM STATEMENT
--------------------------------------------------------------------

Autonomous AI agents are moving from simply answering questions to
taking actions on behalf of users.

An agent may eventually be able to:

- Purchase products
- Book services
- Pay bills
- Subscribe to services
- Transfer funds
- Manage recurring payments

This creates a fundamental authorization problem.

Traditional software generally follows deterministic rules.

AI agents do not.

An LLM may produce a perfectly valid-looking payment request while
still violating the user's actual financial policy.

For example:

USER POLICY:

Daily spending limit:        Rs. 10,000
Transaction limit:           Rs. 5,000
Allowed category:            Groceries

AI REQUEST:

"Buy groceries for Rs. 8,000."

The LLM may generate this request successfully.

However:

Rs. 8,000 > Rs. 5,000 transaction limit

Therefore:

LLM REQUEST = VALID INPUT
AUTHORIZATION = BLOCKED

AgentGuard deliberately treats these as separate concepts.


--------------------------------------------------------------------
3. OBJECTIVES
--------------------------------------------------------------------

The primary objectives of AgentGuard are:

1. Treat AI-generated payment intents as untrusted input.

2. Prevent an AI agent from directly becoming the financial
   authorization layer.

3. Allow users to define deterministic spending policies.

4. Provide AI agents with narrowly scoped spending authority.

5. Use cryptographically signed capabilities rather than simple
   permission flags.

6. Prevent stale capabilities from remaining valid after policy
   changes.

7. Prevent replay of completed payment requests.

8. Prevent concurrent requests from exceeding spending budgets.

9. Detect and block adversarial payment requests.

10. Maintain a verifiable audit trail.

11. Provide measurable security testing through an Attack Lab and
    benchmark suite.


--------------------------------------------------------------------
4. KEY FEATURES
--------------------------------------------------------------------

4.1 USER SPENDING POLICIES
--------------------------

Users can configure:

- Daily spending limit
- Maximum transaction amount
- Velocity limit
- Velocity time window
- Allowed merchants
- Allowed categories

Example:

Daily Limit:             Rs. 10,000
Transaction Limit:       Rs. 5,000
Velocity:                3 transactions / 60 seconds
Allowed Merchants:       Example merchants
Allowed Categories:      Groceries


4.2 AI-GENERATED PAYMENT INTENTS
--------------------------------

The AI agent does not directly execute a payment.

Instead, it generates an intent such as:

"Buy groceries for Rs. 3,000."

AgentGuard converts and evaluates the intent as untrusted input.

The intent is then checked against the authorization boundary.


4.3 SIGNED SPENDING CAPABILITIES
--------------------------------

AgentGuard issues short-lived spending capabilities.

A capability contains information such as:

- Capability ID
- Agent ID
- Subject
- Action
- Maximum transaction amount
- Daily limit
- Allowed merchants
- Allowed categories
- Issued timestamp
- Expiration timestamp
- Nonce
- Policy version
- Capability version

The capability is cryptographically signed using:

HMAC-SHA256


4.4 POLICY VERSIONING
---------------------

Every policy has a version.

When a user changes their policy:

    policy_version = policy_version + 1

Capabilities issued under the previous policy version become stale.

Example:

Initial policy:

Transaction limit = Rs. 5,000
Policy version = 1

Capability:

Policy version = 1

User changes policy:

Transaction limit = Rs. 2,000
Policy version = 2

The previous capability still contains:

Policy version = 1

AgentGuard therefore rejects it.

This prevents old authorization from remaining active after a
security policy has changed.


4.5 CAPABILITY EXPIRATION
-------------------------

Capabilities are short-lived.

A capability contains:

issued_at
expires_at

AgentGuard checks the expiration server-side.

Expired capabilities cannot authorize new transactions.


4.6 CAPABILITY TAMPERING PROTECTION
-----------------------------------

The capability payload is signed using HMAC-SHA256.

If an attacker changes:

transaction amount
agent ID
merchant
category
expiration
policy version

the signature no longer matches.

AgentGuard detects the mismatch and rejects the capability.


4.7 REPLAY PROTECTION
---------------------

A previously executed request should not be executed again simply
because the same request is submitted again.

AgentGuard uses transaction identifiers/idempotency controls to
prevent completed transactions from being replayed as new payments.


4.8 VELOCITY CONTROL
--------------------

Users can define limits such as:

3 transactions in 60 seconds

This prevents an agent from rapidly generating many individually
valid transactions to drain a budget.


4.9 ATOMIC BUDGET ENFORCEMENT
-----------------------------

One of the most important technical protections is atomic budget
enforcement.

Consider:

Remaining budget = Rs. 10,000

Two simultaneous requests:

Request A = Rs. 8,000
Request B = Rs. 8,000

A naive implementation might do:

1. Check balance
2. Approve
3. Update balance

Both requests could observe Rs. 10,000 before either updates it.

AgentGuard instead uses atomic database transactions and locking.

The budget validation and spend update occur as one atomic operation.

Expected result:

Request A -> ALLOW
Request B -> BLOCK

Final spend:

Rs. 8,000

This prevents race-condition-based budget bypasses.


4.10 MERCHANT AND CATEGORY CONTROLS
------------------------------------

Users can restrict where or what the AI agent is allowed to purchase.

Examples:

Allowed category:
    groceries

Requested category:
    electronics

Result:
    BLOCK


4.11 RISK EVALUATION
--------------------

AgentGuard generates a risk score based on multiple security
signals.

The score is represented on a 0-100 scale.

Security signals can include:

- Policy violations
- Amount violations
- Capability violations
- Velocity abuse
- Replay attempts
- Prompt injection indicators
- Unauthorized actions

The risk result is combined with deterministic policy checks to
produce a final decision.


4.12 DECISION STATES
--------------------

AgentGuard supports three high-level outcomes:

ALLOW
BLOCK
ESCALATE

ALLOW:
The request satisfies the authorization requirements.

BLOCK:
The request violates a critical security policy.

ESCALATE:
The request requires additional scrutiny based on risk or policy
conditions.


4.13 ATTACK LAB
---------------

AgentGuard includes an adversarial Attack Lab.

It tests scenarios such as:

- Amount escalation
- Policy violation
- Capability tampering
- Expired authority
- Replay attempts
- Velocity abuse
- Unauthorized requests
- Prompt-injection-style manipulation

The purpose is to test the security boundary instead of only
demonstrating successful payments.


4.14 SECURITY BENCHMARK
-----------------------

AgentGuard includes a benchmark that measures implemented security
controls.

The benchmark reports metrics including:

- Security score
- Scenarios attempted
- Scenarios blocked
- Unauthorized executions
- Money prevented
- Decision latency

The benchmark provides a reproducible demonstration of how the
implemented controls behave under adversarial scenarios.

It is not intended to represent production-level security assurance.


4.15 TAMPER-EVIDENT AUDIT TRAIL
-------------------------------

Security decisions are recorded in an audit trail.

Audit events are linked through a hash chain.

Conceptually:

EVENT 1
   |
   v
HASH 1
   |
   v
EVENT 2 + HASH 1
   |
   v
HASH 2
   |
   v
EVENT 3 + HASH 2
   |
   v
HASH 3

If an earlier event is modified, the chain integrity can be detected.

The audit system provides visibility into:

- What was requested
- What was checked
- Why it was allowed
- Why it was blocked
- What transaction occurred


--------------------------------------------------------------------
5. SYSTEM ARCHITECTURE
--------------------------------------------------------------------

AgentGuard is divided into three major layers.

                    +---------------------+
                    |       USER          |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |   LLM / AI AGENT    |
                    |                     |
                    | Intent Generation   |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |    AGENTGUARD       |
                    |                     |
                    | Zero-Trust Control  |
                    | Plane               |
                    +----------+----------+
                               |
               +---------------+----------------+
               |               |                |
               v               v                v
        Policy Engine    Capability Engine   Risk Engine
               |               |                |
               +---------------+----------------+
                               |
                               v
                    +---------------------+
                    | Atomic DB Layer     |
                    |                     |
                    | Budget Enforcement  |
                    | Replay Protection   |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    | Simulated Payment   |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    | Audit Hash Chain    |
                    +---------------------+


--------------------------------------------------------------------
6. TECHNOLOGY STACK
--------------------------------------------------------------------

FRONTEND
--------

React
TypeScript
Vite
CSS


BACKEND
-------

Python
FastAPI


DATABASE
--------

SQLite


SECURITY
--------

HMAC-SHA256
Cryptographically signed capabilities
Policy versioning
Replay/idempotency protection
Atomic database transactions
Server-side authorization
Tamper-evident audit hashing


TESTING
-------

Python automated tests
Attack Lab
Security benchmark
Concurrency/race-condition testing


--------------------------------------------------------------------
7. PROJECT STRUCTURE
--------------------------------------------------------------------

agentguard/
|
+-- backend/
|   |
|   +-- app/
|   |   |
|   |   +-- main.py
|   |   +-- models.py
|   |   +-- store.py
|   |   +-- engine.py
|   |   +-- capabilities.py
|   |   +-- security.py
|   |
|   +-- tests/
|   |   |
|   |   +-- test_security.py
|   |
|   +-- agentguard.db
|   +-- .agentguard_secret
|   +-- requirements.txt
|
+-- frontend/
    |
    +-- src/
    |   |
    |   +-- main.tsx
    |   +-- style.css
    |   +-- vite-env.d.ts
    |
    +-- public/
    |
    +-- index.html
    +-- package.json
    +-- package-lock.json
    +-- tsconfig.json
    +-- vite.config.ts


--------------------------------------------------------------------
8. BACKEND COMPONENTS
--------------------------------------------------------------------

8.1 main.py
-----------

Main FastAPI application.

Responsibilities:

- API routing
- CORS configuration
- Security headers
- Request handling
- Agent endpoints
- Intent endpoints
- Capability endpoints
- Evaluation endpoints
- Payment execution
- Attack Lab
- Benchmark
- Metrics
- Audit endpoints
- Settings


8.2 models.py
-------------

Contains application data models and request/response structures.

Examples include:

- Agent
- Payment intent
- Capability
- Policy
- Transaction
- Audit event
- Security decision


8.3 store.py
------------

Responsible for database operations.

Includes:

- SQLite connection management
- Database initialization
- Agent storage
- Policy storage
- Transaction storage
- Audit storage
- Atomic budget enforcement
- Replay protection
- Velocity tracking
- Policy versioning


8.4 engine.py
-------------

Contains the main security decision engine.

Responsibilities:

- Parse payment intent
- Build authorization boundary
- Evaluate policies
- Validate agent identity
- Validate capabilities
- Calculate risk
- Detect policy violations
- Detect adversarial patterns
- Produce ALLOW/BLOCK/ESCALATE decisions


8.5 capabilities.py
-------------------

Handles:

- Capability generation
- Capability signing
- Capability verification
- Expiration validation
- Scope validation
- Policy version validation


8.6 security.py
---------------

Contains security primitives including:

- Canonical JSON generation
- HMAC-SHA256 signing
- Constant-time signature comparison
- Secret generation
- Secret management
- Audit hashing
- Hash-chain generation


--------------------------------------------------------------------
9. FRONTEND
--------------------------------------------------------------------

The React frontend provides a dashboard for interacting with AgentGuard.

Major sections include:

1. Overview
2. Spending Policy
3. Transaction Simulator
4. Signed Spending Authority
5. Security Decision
6. Attack Lab
7. Security Metrics
8. Benchmark
9. Audit Trail


The dashboard is designed to make the security architecture visible
during a live demonstration.


--------------------------------------------------------------------
10. PREREQUISITES
--------------------------------------------------------------------

Required software:

Python 3.10+
Node.js 18+
npm

Recommended:

Git
VS Code
Modern web browser


--------------------------------------------------------------------
11. LOCAL INSTALLATION
--------------------------------------------------------------------

STEP 1: CLONE THE REPOSITORY
----------------------------

git clone <YOUR_GITHUB_REPOSITORY_URL>

cd agentguard


STEP 2: CREATE PYTHON VIRTUAL ENVIRONMENT
-----------------------------------------

Mac/Linux:

python3 -m venv .venv

source .venv/bin/activate

Windows:

python -m venv .venv

.venv\Scripts\activate


STEP 3: INSTALL BACKEND DEPENDENCIES
------------------------------------

cd backend

pip install -r requirements.txt


STEP 4: START THE BACKEND
-------------------------

From the backend directory:

uvicorn app.main:app --host 127.0.0.1 --port 8000

Backend will run at:

http://127.0.0.1:8000


API health endpoint:

http://127.0.0.1:8000/api/health


STEP 5: INSTALL FRONTEND DEPENDENCIES
-------------------------------------

Open a second terminal.

cd frontend

npm install


STEP 6: START FRONTEND
----------------------

npm run dev


The frontend will normally be available at:

http://localhost:5173


The Vite development server proxies /api requests to:

http://127.0.0.1:8000


--------------------------------------------------------------------
12. RUNNING THE APPLICATION
--------------------------------------------------------------------

Start backend first:

cd backend

uvicorn app.main:app --host 127.0.0.1 --port 8000


Then start frontend:

cd frontend

npm run dev


Open the URL shown by Vite, normally:

http://localhost:5173


The application should load the AgentGuard dashboard.


--------------------------------------------------------------------
13. DATABASE
--------------------------------------------------------------------

AgentGuard uses SQLite for the prototype.

Database file:

backend/agentguard.db

The database stores information related to:

- Agents
- Policies
- Transactions
- Spending activity
- Audit events
- Security decisions


SQLite WAL mode and transactional operations are used to support
concurrent operations and atomic budget enforcement.


--------------------------------------------------------------------
14. SECRET MANAGEMENT
--------------------------------------------------------------------

AgentGuard uses cryptographic secrets for capability signing and
audit integrity.

A local secret is stored in:

backend/.agentguard_secret

This file should NOT be committed to Git.

For production-style deployments, secrets should be provided through
environment variables or a dedicated secret-management system.

The secret should be:

- Random
- High entropy
- At least 32 characters
- Kept outside source control


IMPORTANT:

Never commit:

.agentguard_secret

to GitHub.


--------------------------------------------------------------------
15. API ENDPOINTS
--------------------------------------------------------------------

HEALTH
------

GET /api/health

Checks backend health.


AGENTS
------

GET /api/agents

Returns available agents.


GET /api/agent/{agent_id}

Returns details for a specific agent.


INTENTS
-------

POST /api/intent/compile

Compiles a natural-language instruction into a structured intent.


POST /api/intent

Creates/submits a payment intent.


CAPABILITIES
------------

POST /api/capabilities/issue

Issues a signed spending capability.


POST /api/capabilities/verify

Verifies a signed capability.


SECURITY EVALUATION
-------------------

POST /api/evaluate

Evaluates an intent against AgentGuard's security controls.


PAYMENT
-------

POST /api/payment/execute

Executes an authorized simulated payment.


ATTACK LAB
----------

GET /api/attacks/{attack_name}

Runs or retrieves an attack scenario.


POST /api/attack/{attack_name}

Executes a specific adversarial test.


BENCHMARK
---------

POST /api/benchmark/run

Runs the security benchmark.


TRANSACTIONS
------------

GET /api/transactions

Returns transaction history.


AUDIT
-----

GET /api/audit

Returns audit events.


GET /api/audit/verify

Verifies audit hash-chain integrity.


METRICS
-------

GET /api/metrics

Returns security and transaction metrics.


DEMO
----

POST /api/demo/reset

Resets demonstration activity while preserving the user policy.


SETTINGS
--------

GET /api/settings/{agent_id}

Returns spending policy.


PUT /api/settings/{agent_id}

Updates spending policy.


--------------------------------------------------------------------
16. SECURITY DECISION FLOW
--------------------------------------------------------------------

A typical request follows this sequence:

STEP 1
------

User gives a natural-language instruction.

Example:

"Buy groceries for Rs. 3,000."


STEP 2
------

LLM/agent generates a proposed payment intent.


STEP 3
------

AgentGuard treats the intent as untrusted.


STEP 4
------

Agent identity is verified.


STEP 5
------

The capability signature is verified.


STEP 6
------

Capability expiration is checked.


STEP 7
------

Capability policy version is checked.


STEP 8
------

Transaction amount is compared with the authorized limit.


STEP 9
------

Daily remaining budget is calculated.


STEP 10
-------

Velocity constraints are checked.


STEP 11
-------

Merchant/category restrictions are checked.


STEP 12
-------

Replay protection is evaluated.


STEP 13
-------

Risk signals are evaluated.


STEP 14
-------

If critical violations exist:

BLOCK


Otherwise:

ALLOW / ESCALATE


STEP 15
-------

If allowed, the transaction is executed atomically.


STEP 16
-------

The decision and transaction are recorded in the audit chain.


--------------------------------------------------------------------
17. EXAMPLE LEGITIMATE TRANSACTION
--------------------------------------------------------------------

USER POLICY:

Daily limit:             Rs. 10,000
Transaction limit:       Rs. 5,000

REQUEST:

"Buy groceries for Rs. 3,000."


Evaluation:

Amount <= transaction limit
Amount <= remaining daily budget
Category = allowed
Capability = valid
Capability = unexpired
Policy version = current
No replay detected


RESULT:

ALLOW


Simulated payment executes.


--------------------------------------------------------------------
18. EXAMPLE ATTACK: AMOUNT ESCALATION
--------------------------------------------------------------------

USER POLICY:

Transaction limit = Rs. 5,000


AI REQUEST:

"Buy groceries for Rs. 8,000."


AgentGuard detects:

Rs. 8,000 > Rs. 5,000


RESULT:

BLOCK


The AI cannot override the user's transaction limit.


--------------------------------------------------------------------
19. EXAMPLE ATTACK: CAPABILITY TAMPERING
--------------------------------------------------------------------

Original capability:

Maximum transaction amount = Rs. 5,000


Attacker attempts to modify it:

Maximum transaction amount = Rs. 50,000


The payload changes but the original HMAC signature remains.

AgentGuard recomputes the signature.

Signatures do not match.

RESULT:

BLOCK


--------------------------------------------------------------------
20. EXAMPLE ATTACK: EXPIRED CAPABILITY
--------------------------------------------------------------------

A capability has:

expires_at = previous time


The agent attempts to use it.

AgentGuard verifies the expiration timestamp.

RESULT:

BLOCK


--------------------------------------------------------------------
21. EXAMPLE ATTACK: POLICY VERSION INVALIDATION
--------------------------------------------------------------------

Policy version:

1


Capability version:

1


User changes policy.

Policy version becomes:

2


Old capability:

version = 1


AgentGuard detects the mismatch.

RESULT:

BLOCK


--------------------------------------------------------------------
22. EXAMPLE ATTACK: CONCURRENT SPENDING
--------------------------------------------------------------------

Initial daily budget:

Rs. 10,000


Two simultaneous requests:

Request A = Rs. 8,000
Request B = Rs. 8,000


Because the authorization and balance update are atomic:

Request A = ALLOW
Request B = BLOCK


Final spend:

Rs. 8,000


The system therefore prevents the two requests from consuming the
same remaining budget.


--------------------------------------------------------------------
23. ATTACK LAB SCENARIOS
--------------------------------------------------------------------

The Attack Lab is designed to test:

1. Amount escalation
2. Policy violation
3. Capability tampering
4. Expired capability
5. Replay attempt
6. Velocity abuse
7. Unauthorized action
8. Prompt-injection-style manipulation
9. Merchant/category violation
10. Additional authorization boundary violations


The objective is to demonstrate that security controls are actually
tested rather than simply described.


--------------------------------------------------------------------
24. SECURITY TESTING
--------------------------------------------------------------------

Automated backend security tests are included in:

backend/tests/test_security.py


Run:

cd backend

pytest


The test suite validates implemented security behavior including
capability integrity, authorization boundaries and related controls.


--------------------------------------------------------------------
25. BENCHMARKING
--------------------------------------------------------------------

AgentGuard contains a benchmark endpoint:

POST /api/benchmark/run


The benchmark evaluates adversarial scenarios and reports metrics
including:

- Security score
- Scenarios attempted
- Scenarios blocked
- Unauthorized executions
- Money prevented
- P95 decision latency


During development, the implemented benchmark scenarios were
successfully blocked.

The benchmark is intended as a reproducible evaluation of the
prototype's implemented controls, not as a guarantee of production
security.


--------------------------------------------------------------------
26. AUDIT INTEGRITY
--------------------------------------------------------------------

AgentGuard maintains a tamper-evident audit chain.

Each event is linked to the previous event's hash.

Conceptually:

current_hash =
    HASH(previous_hash + event_data)


This means that changing an earlier event changes its hash and
breaks the chain relationship with subsequent events.

Audit integrity can be checked through:

GET /api/audit/verify


Expected result:

Audit chain valid


--------------------------------------------------------------------
27. DEMO WORKFLOW
--------------------------------------------------------------------

For a 5-minute demonstration:

STEP 1
------

Open AgentGuard dashboard.


STEP 2
------

Show the spending policy.

Example:

Daily limit: Rs. 10,000
Transaction limit: Rs. 5,000


STEP 3
------

Create a legitimate request:

"Buy groceries for Rs. 3,000."


Show:

ALLOW


STEP 4
------

Create an unauthorized request:

"Buy groceries for Rs. 8,000."


Show:

BLOCK


Explain:

The AI generated the request, but it does not control authorization.


STEP 5
------

Show the signed spending capability.

Highlight:

- Agent ID
- Transaction limit
- Daily limit
- Expiration
- Policy version
- Capability ID


STEP 6
------

Change the policy.

Example:

Transaction limit:

Rs. 5,000 -> Rs. 2,000


Explain policy version invalidation.


STEP 7
------

Open Attack Lab.

Run adversarial scenarios.


STEP 8
------

Run the security benchmark.


STEP 9
------

Show the audit trail.


STEP 10
-----

Show the concurrency protection if required.


STEP 11
-----

Finish with:

"AI can request money.
Deterministic controls decide."


--------------------------------------------------------------------
28. BUILD CHALLENGES
--------------------------------------------------------------------

The first major challenge was deciding how to give an AI agent useful
financial capabilities without allowing the AI itself to become the
authorization layer.

The solution was to separate intent generation from authorization.

The LLM generates a request.

AgentGuard independently verifies whether the request is permitted.


The second major challenge was concurrent spending.

A simple check-then-update implementation could allow two requests
to consume the same remaining budget.

This was solved using atomic database transactions and locking.


Another challenge was secure delegated authority.

A simple permission flag was not sufficient because the system needed
to know exactly what an agent was authorized to do.

This led to the implementation of short-lived HMAC-SHA256 signed
capabilities with scoped authorization.


Policy changes created another security challenge.

A capability issued before a policy update should not necessarily
remain valid.

Policy versioning was implemented so that changing a policy
invalidates older capabilities.


Finally, the project needed to be tested against malicious behavior,
not only legitimate transactions.

The Attack Lab was created to test amount escalation, replay,
tampering, expiration, velocity abuse and prompt-injection-style
manipulation.


--------------------------------------------------------------------
29. DESIGN PRINCIPLES
--------------------------------------------------------------------

AgentGuard follows several important principles.

1. ZERO TRUST

The AI agent is not automatically trusted.

Every payment intent is independently evaluated.


2. LEAST PRIVILEGE

Capabilities grant only the authority necessary for the agent's
intended operation.


3. SERVER-SIDE ENFORCEMENT

Security decisions are enforced by the backend rather than relying
on frontend controls.


4. DETERMINISTIC AUTHORIZATION

The final financial authorization decision is based on explicit
security policies rather than LLM confidence.


5. SHORT-LIVED AUTHORITY

Capabilities expire.


6. REVOCABLE AUTHORITY

Policy changes invalidate stale capabilities.


7. ATOMICITY

Budget enforcement must remain correct under concurrent requests.


8. AUDITABILITY

Important decisions must be traceable and verifiable.


--------------------------------------------------------------------
30. DEPLOYMENT
--------------------------------------------------------------------

AgentGuard is primarily designed and demonstrated as a local
prototype.

For a public deployment, the architecture can be separated into:

FRONTEND
    |
    v
PUBLIC HTTPS
    |
    v
FASTAPI BACKEND
    |
    +---- DATABASE
    |
    +---- SECRET MANAGEMENT
    |
    +---- AUDIT SYSTEM


IMPORTANT:

The current implementation uses SQLite and simulated payments.

It should NOT be presented as a production financial payment system.


--------------------------------------------------------------------
31. FRONTEND DEPLOYMENT
--------------------------------------------------------------------

The React/Vite frontend can be built using:

cd frontend

npm install

npm run build


This produces a production build in:

frontend/dist/


The generated frontend can be served through a static hosting
provider or web server.

The production frontend must be configured to communicate with the
deployed backend API.


--------------------------------------------------------------------
32. BACKEND DEPLOYMENT
--------------------------------------------------------------------

The FastAPI backend can be run using:

uvicorn app.main:app --host 0.0.0.0 --port 8000


For production-style deployment, use a proper process manager and
HTTPS reverse proxy.

Example architecture:

Internet
   |
   v
HTTPS Reverse Proxy
   |
   v
FastAPI
   |
   v
Database


Production deployment should also use:

- HTTPS
- Secure environment variables
- Proper secret management
- Restricted CORS
- Database backups
- Monitoring
- Rate limiting
- Production database
- Authentication/authorization infrastructure
- Secure logging
- Key rotation


--------------------------------------------------------------------
33. RECOMMENDED PRODUCTION EVOLUTION
--------------------------------------------------------------------

The current project intentionally uses SQLite for the prototype.

A production implementation should consider PostgreSQL or another
transactional database designed for the expected workload.


Secrets should be moved from local files to a secure secret manager.

Examples include:

- Cloud secret managers
- Vault-style systems
- Managed key-management systems


Payment execution should integrate with an actual payment provider
only after the authorization architecture has undergone appropriate
security review and testing.


--------------------------------------------------------------------
34. ENVIRONMENT VARIABLES
--------------------------------------------------------------------

A production deployment should provide secrets through environment
variables rather than committing them to source control.

Example conceptual configuration:

AGENTGUARD_SECRET=<strong-random-secret>
DATABASE_URL=<production-database-url>
CORS_ORIGINS=<allowed-frontend-origin>


Do not commit actual secret values.


--------------------------------------------------------------------
35. SECURITY CONSIDERATIONS
--------------------------------------------------------------------

AgentGuard is designed as a security prototype.

It demonstrates several important controls but does not claim to
eliminate all possible security vulnerabilities.

Additional production security would be required for:

- Real payment execution
- Identity verification
- User authentication
- Key management
- Hardware-backed key storage
- Distributed rate limiting
- High availability
- Fraud detection
- Payment provider integration
- Compliance requirements
- Secure infrastructure
- Incident response
- Monitoring
- Penetration testing


--------------------------------------------------------------------
36. LIMITATIONS
--------------------------------------------------------------------

AgentGuard is currently a prototype.

Important limitations include:

1. Payments are simulated.

2. SQLite is used as the prototype database.

3. The system does not represent a production payment processor.

4. The benchmark covers implemented attack scenarios and cannot
   represent every possible real-world attack.

5. Prompt-injection detection is not a replacement for comprehensive
   LLM security.

6. The system should undergo extensive security testing before any
   production financial deployment.

7. Production deployment would require stronger identity, key
   management, infrastructure and compliance controls.


--------------------------------------------------------------------
37. FUTURE SCOPE
--------------------------------------------------------------------

Potential future improvements include:

1. Production-grade PostgreSQL deployment.

2. Integration with real payment providers.

3. Hardware-backed cryptographic key management.

4. OAuth/OIDC-based agent identity.

5. Multi-agent authorization.

6. Human-in-the-loop approval for high-risk payments.

7. Adaptive risk scoring.

8. Behavioral anomaly detection.

9. Distributed velocity controls.

10. Multi-region deployment.

11. Stronger prompt-injection defenses.

12. Policy simulation before activation.

13. Policy templates for different spending scenarios.

14. Real-time fraud signals.

15. More advanced audit and compliance tooling.

16. Cryptographic key rotation.

17. More extensive adversarial benchmarking.

18. Agent-to-agent delegated authorization.


--------------------------------------------------------------------
38. WHY AGENTGUARD IS DIFFERENT
--------------------------------------------------------------------

AgentGuard is not designed as another AI chatbot or another payment
interface.

Its primary focus is the security boundary between:

AI-generated intent

and

financial execution.


The project explores an important architectural principle:

The system should not ask:

"Do we trust the AI?"

Instead, it should ask:

"Is this particular action authorized?"

This changes the security model from:

TRUST THE AGENT

to:

VERIFY THE REQUEST.


--------------------------------------------------------------------
39. PROJECT PHILOSOPHY
--------------------------------------------------------------------

The goal is not to make AI blindly trustworthy.

The goal is to make autonomous AI systems usable even when the AI
cannot be assumed to be perfectly reliable.

An AI agent can:

- Reason
- Interpret
- Plan
- Request

But financial authorization should remain independently controlled.

Therefore:

LLM
|
+--> Understands user intent
+--> Generates proposed action
+--> Requests payment

AgentGuard
|
+--> Verifies identity
+--> Verifies authority
+--> Checks policy
+--> Checks risk
+--> Checks budget
+--> Checks replay
+--> Enforces limits
+--> Records decision


--------------------------------------------------------------------
40. GITHUB
--------------------------------------------------------------------

GitHub Repository:

<PASTE YOUR GITHUB REPOSITORY LINK HERE>


--------------------------------------------------------------------
41. DEMO VIDEO
--------------------------------------------------------------------

Demo Video:

<PASTE YOUR YOUTUBE VIDEO LINK HERE>


--------------------------------------------------------------------
42. HACKATHON
--------------------------------------------------------------------

Project:

AgentGuard

Theme:

Zero-Trust Security for Autonomous AI Payments

Event:

Razorpay AI Buildathon 2026

Core Principle:

"AI can request money.
Deterministic controls decide."


--------------------------------------------------------------------
43. FINAL SUMMARY
--------------------------------------------------------------------

AgentGuard explores a security architecture for the emerging world
of autonomous AI payments.

Instead of giving an AI agent unrestricted financial authority,
AgentGuard introduces an independent authorization layer between the
AI and payment execution.

The system combines:

- User-defined spending policies
- Untrusted AI-generated payment intents
- Cryptographically signed capabilities
- Short-lived delegated authority
- Policy versioning
- Transaction limits
- Daily budgets
- Velocity controls
- Merchant/category restrictions
- Replay protection
- Risk evaluation
- Prompt-injection-style defenses
- Atomic database enforcement
- Adversarial testing
- Security benchmarking
- Tamper-evident auditing


The fundamental architectural principle is:

                     AI
                      |
                      | REQUEST
                      v
                AGENTGUARD
                      |
                      | AUTHORIZE
                      v
                   PAYMENT


The AI does not receive unrestricted control over money.

It receives a bounded ability to request an action.

AgentGuard independently determines whether that request is
authorized.

The result is a prototype control plane designed around a simple
idea:

                    AI CAN REQUEST MONEY.

               DETERMINISTIC CONTROLS DECIDE
             WHETHER MONEY CAN ACTUALLY MOVE.


====================================================================
                           END
====================================================================