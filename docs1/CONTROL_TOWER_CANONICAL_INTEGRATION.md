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
- `canonical_object_audit`: row-level canonical Control Tower objects for dashboards and audit reports.
- `canonical_consistency_audit`: stale projection checks across runtime objects.
- `runtime_event_contract`: normalized AEGIS runtime event contract for emitted agent events.

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

Recommended app log path pattern:

```text
runtime_logs/YOUR_APP_RUN_001.jsonl
runtime_logs/YOUR_APP_RUN_002.jsonl
```

Apps can emit events:

- before starting: `RUNTIME_STARTED`
- during execution: `AGENT_STARTED`, `AGENT_COMPLETED`, `CONTROL_CHECK`, `EVIDENCE_ATTACHED`
- before finishing: `DECISION_PROPOSED`, `RUNTIME_COMPLETING`
- after completion: `FINAL_CANONICAL_OBJECTS`, `RUNTIME_COMPLETED`, `RUNTIME_FAILED`

Manual mode remains available for loading one specific JSONL file.

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
