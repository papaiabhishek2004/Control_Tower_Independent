# AEGIS Control Tower Canonical Integration

The reusable Control Tower code lives in `services1/control_tower_canonical_service.py`.
It has no Streamlit dependency and can be imported by another Python service, API,
agent orchestrator, batch job, or test harness.

## Segregated Architecture

RAG is an onboarded application capability, not the Control Tower measurement
layer. The current Customer 360 RAG demo is exposed through:

```python
from services1.agentic_app_adapters import execute_onboarded_agentic_app

runtime_state = execute_onboarded_agentic_app(
    customer_id="CUST000001",
    user_query="Investigate customer CUST000001",
)
```

That adapter emits the same canonical objects an external agentic/RAG system
should emit. AEGIS then measures, governs, and audits those objects through the
canonical service.

```text
RAG / Agentic Application
    emits runtime events, evidence, decision, cost, trust signals
        -> AEGIS Control Tower
            measures canonical objects, governance, HITL, audit, release
```

## Primary API

```python
from services1.control_tower_canonical_service import measure_control_tower_objects

measurements = measure_control_tower_objects(
    runtime_state={
        "runtime_id": "RUN-001",
        "app_id": "YOUR_AGENTIC_APP",
        "recommendation": "APPROVE",
        "risk_level": "LOW",
        "trust_score": 91,
        "confidence": 86,
        "evidence_pack": [{"evidence_id": "E1"}],
        "compliance": {"status": "COMPLIANT"},
        "token_metrics": {"estimated_cost_usd": 0.0123},
    },
    runtime_events=[
        {
            "runtime_id": "RUN-001",
            "app_id": "YOUR_AGENTIC_APP",
            "agent_name": "Planner",
            "event_type": "COMPLETED",
            "status": "COMPLETED",
            "duration_ms": 42,
        }
    ],
)
```

## Returned Canonical Objects

- `canonical_display`: recommendation, risk, trust, confidence, evidence count, runtime status, and model cost.
- `quality`: trust, confidence, grounding, coverage, and hallucination values.
- `release_assessment`: release route, HITL requirement, governance status, and reasons.
- `llm_judge_assurance`: LLM Judge committee verdicts for OWASP, evidence, grounding, governance, business risk, and final arbitration.
- `ragas_scores`: mandatory LLM-based RAGAS evaluation for faithfulness, answer relevancy, context precision, and context recall.
- `owasp_ai`: OWASP/security verdict derived from judge and security signals.
- `policy_as_code`: release gates for trust, confidence, evidence, OWASP, PII, latency, retry, and risk.
- `final_arbitration`: mandatory LLM final decision packet with `ACCEPT`, `REJECT`, `RETRY`, or `HITL`.
- `canonical_object_audit`: row-level canonical Control Tower objects for dashboards and audit reports.
- `canonical_consistency_audit`: stale projection checks across runtime objects.
- `runtime_event_contract`: normalized AEGIS runtime event contract for emitted agent events.

## LLM Judge and OWASP AI Controls

The independent Control Tower runs AEGIS LLM Judge and OWASP AI controls for
every ingested runtime.

- AEGIS attempts configured LLM judge execution.
- OWASP/security and policy gates are always evaluated.
- If the configured provider cannot run, AEGIS records fallback metadata while preserving the mandatory judge/control result.

The LLM Judge committee includes:

- Security / OWASP Judge
- Evidence Judge
- Grounding Judge
- Governance Judge
- Business Risk Judge
- Final Arbitration Judge

## Mandatory RAGAS Evaluation

AEGIS also runs mandatory LLM-based RAGAS evaluation for every onboarded app
runtime. It uses the emitted evidence and retrieval context to score:

- Faithfulness
- Answer Relevancy
- Context Precision
- Context Recall

RAGAS uses Groq directly through `GROQ_API_KEY` or `.env.local`. It does not use
local model fallback in the independent Control Tower path. If the key/provider
is unavailable, AEGIS records a failed mandatory RAGAS control result.

## User Query OWASP Validation

Onboarded apps should emit `user_query`, `original_query`, or `query` in JSONL
events. AEGIS validates these queries for OWASP AI risks before RAGAS, LLM Judge,
and policy gates run.

AEGIS checks for:

- prompt injection / jailbreak phrases
- attempts to reveal system or developer prompts
- sensitive data / PII in user queries
- data exfiltration or unsafe tool-use requests

Unsafe query findings are stored in `query_security`, copied into
`security_analysis`, shown in the `OWASP AI` tab, and used by policy gates.

## Mandatory Final Arbitration

At the end of every runtime, AEGIS builds a control packet from deterministic
controls, RAGAS, OWASP query validation, policy gates, lifecycle coverage, and
LLM Judge verdicts. The Final Arbitration Judge then chooses one action:

- `ACCEPT`: return/accept the onboarded app response.
- `REJECT`: block the response.
- `RETRY`: send the response back to the onboarded app for retry.
- `HITL`: route to human review.

Deterministic guardrails remain non-bypassable. Critical policy/security
failures cannot be converted to `ACCEPT` by the LLM.

## AEGIS-Derived HITL Logic

External apps should not decide the authoritative `hitl_required` value. They
emit source signals; AEGIS derives HITL from those signals.

AEGIS sets `hitl_required=true` when any of these are true:

- `risk_level` is `HIGH` or `CRITICAL`
- `confidence` is below `70`
- `trust_score` is below `70`
- `control_status`, governance status, or compliance status is failed/blocked/non-compliant/review
- `recommendation` is `ESCALATE`, `REJECT`, `HOLD`, `REVIEW`, or `REVIEW_REQUIRED`

AEGIS stores the derived decision in:

- `hitl_required`
- `human_review_required`
- `hitl_decision`
- `hitl_decision_source = AEGIS_DERIVED`
- `hitl_reasons`
- `canonical_control_tower_measurements.release_assessment`

## Enrich Existing Runtime State

```python
from services1.control_tower_canonical_service import attach_control_tower_measurements

runtime_state = attach_control_tower_measurements(runtime_state)
```

This adds:

- `canonical_control_tower_measurements`
- `canonical_object_audit`
- `canonical_consistency_audit`
- `canonical_values`
- `canonical_runtime_event_contract`

## Minimal Event Fields

External systems should emit these fields where possible:

- `runtime_id`
- `app_id`
- `agent_name` or `agent_id`
- `event_type`
- `status`
- `timestamp`
- `duration_ms` or `execution_time_ms`
- `evidence_ids`
- `tokens`
- `cost_usd`
- `audit_id`

## Tiny File Emitter

An external app can append canonical events to a JSONL text/log file using:

```bash
python tools1/emit_canonical_runtime_log.py --output runtime_events.jsonl
```

Or copy this minimal function into the external app:

```python
from tools1.emit_canonical_runtime_log import emit_event

emit_event(
    "runtime_events.jsonl",
    runtime_id="RUN-001",
    app_id="YOUR_AGENTIC_APP",
    agent_name="Retriever",
    event_type="EVIDENCE_FOUND",
    status="COMPLETED",
    evidence_ids=["E1", "E2"],
    execution_time_ms=420,
)
```

Before the app completes, emit the final canonical objects:

```python
emit_event(
    "runtime_events.jsonl",
    runtime_id="RUN-001",
    app_id="YOUR_AGENTIC_APP",
    agent_name="Decision Agent",
    event_type="FINAL_CANONICAL_OBJECTS",
    status="COMPLETED",
    recommendation="APPROVE",
    risk_level="LOW",
    trust_score=91,
    confidence=86,
    evidence_ids=["E1", "E2"],
    tokens=1280,
    cost_usd=0.0123,
)
```

## Always-On Watcher Mode

For always-on Control Tower monitoring, run:

```bash
streamlit run app_persona_decision_tower.py
```

In the sidebar, select:

- `Ingestion Mode = Watch Folder`
- `Watched Log Folder = runtime_logs`
- `AEGIS Always-On Watcher = enabled`

AEGIS scans the watched folder for the newest `.jsonl` file. When an onboarded
app creates or appends to a JSONL file, AEGIS reloads that runtime and updates
the decision/persona view.

If multiple JSONL files are present in the watched folder, AEGIS matches files
by the `app_id` emitted inside the JSONL events and loads the newest matching
file for the selected registered app.

Recommended app log path pattern:

```text
runtime_logs/YOUR_APP_RUN_001.jsonl
runtime_logs/YOUR_APP_RUN_002.jsonl
```

Apps can emit events:

- before starting: `lifecycle_phase=BEFORE_STARTING`, for `RUNTIME_STARTED`
- during runtime: `lifecycle_phase=DURING_RUNTIME`, for `AGENT_STARTED`, `AGENT_COMPLETED`, `CONTROL_CHECK`, `EVIDENCE_ATTACHED`
- before completion: `lifecycle_phase=BEFORE_COMPLETION`, for `DECISION_PROPOSED`, `RUNTIME_COMPLETING`, `FINAL_CANONICAL_OBJECTS`
- after completion: `lifecycle_phase=AFTER_COMPLETION`, for `RUNTIME_COMPLETED`, `RUNTIME_FAILED`, `AUDIT_WRITTEN`

AEGIS also infers the lifecycle phase from `event_type` when
`lifecycle_phase` is not emitted, but onboarded apps should emit it explicitly.
The Persona Decision Tower has a `Lifecycle` tab that shows which phase events
were observed and which phase events are missing.

Manual mode remains available for loading one specific JSONL file.

## Onboarded App Registry

AEGIS maintains a file-backed registry at:

```text
runtime_registry/onboarded_apps.json
```

Each onboarded app record contains:

- `app_id`
- `app_name`
- `owner`
- `status`
- `log_folder`
- `adapter`
- `expected_lifecycle_phases`
- `required_event_envelope_fields` containing the 7 mandatory event fields
- `expected_canonical_fields` containing the 36 canonical parameters

The Persona Decision Tower has a `Registry` tab and a sidebar
`Register / Update App` action. Register each app once, then have that app emit
JSONL files into its registered `log_folder`.

## Operational Control Loop

For every loaded runtime, AEGIS now writes operational outputs that other
agentic systems can consume.

```text
runtime log -> AEGIS measurement -> LLM/RAGAS/OWASP/policy checks
    -> final arbitration -> response file / HITL queue / alerts / history
```

File-backed outputs:

- `decision_outbox/<app_id>/<runtime_id>_decision.json`: final response packet returned to the onboarded app.
- `runtime_history/runs.jsonl`: append-only run history.
- `hitl_queue/reviews.jsonl`: pending human review items when AEGIS routes to HITL.
- `alerts/alerts.jsonl`: HITL, OWASP, RAGAS, and policy alerts.
- `runtime_registry/agent_registry.json`: observed agents for onboarded apps.
- `runtime_registry/prompt_registry.json`: observed prompt template IDs and hashes.
- `config/aegis_policy.json`: editable control policy thresholds.
- `docs1/aegis_decision_api_contract.json`: lightweight API/webhook contract.

The decision packet contains:

- `runtime_id`
- `app_id`
- `aegis_final_decision`: `ACCEPT`, `REJECT`, `RETRY`, or `HITL`
- `required_action`
- `retry_reason`
- `hitl_required`
- `risk_level`
- `trust_score`
- `confidence`
- `control_status`
- `decision_source`
- `rationale`

The Persona Decision Tower has an `Operations` tab showing response file,
runtime history, HITL queue, alerts, agent registry, prompt registry, policy
config, and the decision API contract location.

## Prompt Template Registry

Onboarded apps should emit:

- `prompt_template_id`
- `prompt_hash`
- `prompt_version`

AEGIS uses these values to track prompt inventory and suggest optimization
patterns such as role/task/context/output-format templates, explicit evidence
requirements, refusal handling, and retry-safe structured JSON outputs.

## Decision API Contract

The current independent package is file-backed. The generated API contract
defines the equivalent service endpoints for teams that want HTTP integration:

- `POST /runtime-events`: submit canonical runtime events.
- `GET /decision/{app_id}/{runtime_id}`: read the final AEGIS decision packet.
- `POST /hitl/{review_id}`: submit reviewer decision/override.

Sample full canonical event:

```text
docs1/sample_canonical_runtime_event.json
```

AEGIS can pick up that file through the JSONL adapter:

```python
from services1.agentic_app_adapters import JSONL_RUNTIME_LOG_APP_ID, execute_onboarded_agentic_app

runtime_state = execute_onboarded_agentic_app(
    customer_id="CUST000001",
    user_query="External app execution",
    app_id=JSONL_RUNTIME_LOG_APP_ID,
    metadata={"path": "runtime_events.jsonl"},
)
```
