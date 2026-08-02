"""Tiny external-app emitter for AEGIS canonical runtime parameters.

Run this from any agentic system to append JSONL events that AEGIS can ingest:

    python tools/emit_canonical_runtime_log.py --output runtime_events.jsonl

Each line is one canonical runtime event. Your own app can copy the emit_event
function and call it during runtime and again before completion.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_event(path: str | Path, **event: Any) -> Dict[str, Any]:
    """Append one canonical AEGIS event to a JSONL log file."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    event.setdefault("timestamp", utc_now())
    event.setdefault("audit_id", str(uuid.uuid4()))
    with output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=True, default=str) + "\n")
    return event


def emit_sample_run(path: str | Path, runtime_id: str, app_id: str) -> None:
    emit_event(
        path,
        runtime_id=runtime_id,
        app_id=app_id,
        app_name="External Claims Agent",
        agent_id="planner",
        agent_name="Planner",
        agent_type="PLANNING_AGENT",
        event_type="STARTED",
        status="RUNNING",
        phase="PLANNING",
    )
    time.sleep(0.05)
    emit_event(
        path,
        runtime_id=runtime_id,
        app_id=app_id,
        app_name="External Claims Agent",
        agent_id="retriever",
        agent_name="Retriever",
        agent_type="RETRIEVAL_AGENT",
        event_type="EVIDENCE_FOUND",
        status="COMPLETED",
        phase="RETRIEVAL",
        execution_time_ms=420,
        evidence_ids=["EVID-001", "EVID-002"],
        retrieved_chunks=2,
    )
    time.sleep(0.05)
    emit_event(
        path,
        runtime_id=runtime_id,
        app_id=app_id,
        app_name="External Claims Agent",
        agent_id="decision",
        agent_name="Decision Agent",
        agent_type="DECISION_AGENT",
        event_type="FINAL_CANONICAL_OBJECTS",
        status="COMPLETED",
        phase="DECISION",
        execution_time_ms=180,
        recommendation="APPROVE",
        risk_level="LOW",
        trust_score=91,
        confidence=86,
        evidence_ids=["EVID-001", "EVID-002"],
        tokens=1280,
        cost_usd=0.0123,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Emit AEGIS canonical runtime JSONL events.")
    parser.add_argument("--output", default="runtime_events.jsonl", help="JSONL file path to append events to.")
    parser.add_argument("--runtime-id", default=f"RUN-{uuid.uuid4().hex[:8].upper()}")
    parser.add_argument("--app-id", default="EXTERNAL_AGENTIC_APP")
    args = parser.parse_args()
    emit_sample_run(args.output, args.runtime_id, args.app_id)
    print(f"wrote canonical runtime events to {args.output}")
    print(f"runtime_id={args.runtime_id} app_id={args.app_id}")


if __name__ == "__main__":
    main()
