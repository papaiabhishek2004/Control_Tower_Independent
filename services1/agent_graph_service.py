"""Build a stable, serializable agent-execution graph from AEGIS runtime data."""

from __future__ import annotations

import re
from typing import Any, Dict, List


def _name(value: Any) -> str:
    aliases = {
        "Query Rewriter": "App Query Rewriter",
        "Query Rewriter Agent": "App Query Rewriter",
        "Planner": "App Planner",
        "Planner Agent": "App Planner",
        "Tool Router": "App Tool Router",
        "Tool Router Agent": "App Tool Router",
        "RAG": "App Evidence Retrieval",
        "Retriever Agent": "App Evidence Retrieval",
        "Evidence Retrieval Agent": "App Evidence Retrieval",
        "Evidence": "App Evidence Packager",
        "Evidence Service": "App Evidence Packager",
        "Answer": "App Response Generator",
        "Enterprise Answer Agent": "App Response Generator",
        "Recommendation": "App Proposed Decision",
        "Recommendation Agent": "App Proposed Decision",
        "Runtime Builder": "AEGIS Runtime Packager",
        "Runtime Builder Agent": "AEGIS Runtime Packager",
        "Governance": "AEGIS Governance",
        "Governance Agent": "AEGIS Governance",
        "Compliance": "AEGIS Compliance",
        "Compliance Agent": "AEGIS Compliance",
        "Reflection": "AEGIS Reflection",
        "Reflection Agent": "AEGIS Reflection",
        "RAGAS": "AEGIS RAGAS Evaluation",
        "RAGAS Evaluation Agent": "AEGIS RAGAS Evaluation",
        "Trust": "AEGIS Trust",
        "Trust Agent": "AEGIS Trust",
        "OWASP Security": "AEGIS OWASP Security",
        "OWASP Security Agent": "AEGIS OWASP Security",
        "Hallucination": "AEGIS Hallucination Check",
        "Hallucination Agent": "AEGIS Hallucination Check",
        "Grounding": "AEGIS Grounding Check",
        "Grounding Agent": "AEGIS Grounding Check",
        "Cache Intelligence": "AEGIS Cache Intelligence",
        "Cache Intelligence Agent": "AEGIS Cache Intelligence",
    }
    text = str(value or "Unknown").strip()
    lowered = text.casefold().replace("_", " ")
    if text in aliases:
        return aliases[text]
    if "query rewriter" in lowered:
        return "App Query Rewriter"
    if "tool router" in lowered or "routing" in lowered:
        return "App Tool Router"
    if "planner" in lowered:
        return "App Planner"
    if "ragas" in lowered:
        return "AEGIS RAGAS Evaluation"
    if lowered == "rag" or "retriever" in lowered or "retrieval" in lowered:
        return "App Evidence Retrieval"
    if "evidence" in lowered and "retrieval" not in lowered:
        return "App Evidence Packager"
    if "answer" in lowered or "response generator" in lowered:
        return "App Response Generator"
    if "recommendation" in lowered:
        return "App Proposed Decision"
    if "runtime builder" in lowered or "runtime packager" in lowered:
        return "AEGIS Runtime Packager"
    if "owasp" in lowered or "security" in lowered:
        return "AEGIS OWASP Security"
    if "governance" in lowered or "risk agent" in lowered:
        return "AEGIS Governance"
    if "compliance" in lowered or "aml agent" in lowered:
        return "AEGIS Compliance"
    if "trust" in lowered:
        return "AEGIS Trust"
    if "reflection" in lowered:
        return "AEGIS Reflection"
    if "hallucination" in lowered:
        return "AEGIS Hallucination Check"
    if "grounding" in lowered:
        return "AEGIS Grounding Check"
    if "cache intelligence" in lowered:
        return "AEGIS Cache Intelligence"
    if "customer agent" in lowered:
        return "App Customer Context"
    return text


def _id(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_") or "unknown"


def _skip_reason(label: str, selected: set) -> str:
    if selected and label.casefold() not in selected:
        return (
            f"{label} was planned as an available capability, but the intent router "
            "did not select it for this investigation."
        )
    return f"{label} was planned, but no execution event was recorded for this run."


def build_agent_execution_graph(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Return the graph contract consumed by the Runtime Intelligence UI.

    Observed runtime transitions are authoritative. Planner edges are retained as
    planned transitions, which lets the UI explain both intent and actual execution.
    """
    if not isinstance(runtime_state, dict):
        return {"version": "1.0", "nodes": [], "edges": [], "summary": {}}

    trace = runtime_state.get("agent_trace", [])
    trace = trace if isinstance(trace, list) else []
    rows = [row for row in trace if isinstance(row, dict)]
    rows.sort(key=lambda row: row.get("execution_order", 9999))

    nodes: Dict[str, Dict[str, Any]] = {}
    observed_names: List[str] = []
    for position, row in enumerate(rows, start=1):
        name = _name(row.get("agent") or row.get("agent_name") or row.get("name"))
        node_id = _id(name)
        observed_names.append(name)
        current = nodes.get(node_id)
        duration_ms = row.get("duration_ms", row.get("latency_ms", 0)) or 0
        if current is None:
            nodes[node_id] = {
                "id": node_id,
                "label": name,
                "phase": row.get("phase") or row.get("stage") or "Runtime",
                "status": str(row.get("status") or "UNKNOWN").upper(),
                "execution_order": row.get("execution_order") or position,
                "duration_ms": duration_ms,
                "trust_score": row.get("trust_score", 0) or 0,
                "confidence": row.get("confidence", 0) or 0,
                "tool": row.get("tool_used") or row.get("tool") or "-",
                "observed": True,
                "execution_count": 1,
                "execution_orders": [row.get("execution_order") or position],
            }
        else:
            current["execution_count"] = int(current.get("execution_count", 1)) + 1
            current["execution_orders"] = sorted(set((current.get("execution_orders") or [current.get("execution_order")]) + [row.get("execution_order") or position]))
            current["duration_ms"] = int(current.get("duration_ms", 0) or 0) + int(duration_ms or 0)
            if (row.get("execution_order") or position) < (current.get("execution_order") or position):
                current["execution_order"] = row.get("execution_order") or position

    edge_map: Dict[tuple, Dict[str, Any]] = {}
    for source, target in zip(observed_names, observed_names[1:]):
        key = (_id(source), _id(target))
        edge_map[key] = {
            "source": key[0], "target": key[1], "kind": "observed", "status": "TRAVERSED"
        }

    plan = runtime_state.get("execution_plan", {})
    planner = runtime_state.get("planner_output", {})
    candidates = (
        plan.get("graph") if isinstance(plan, dict) else None
    ) or (planner.get("graph") if isinstance(planner, dict) else None) or runtime_state.get("graph") or []
    if isinstance(candidates, list):
        selected = {
            _name(item).casefold()
            for item in runtime_state.get("selected_agents", [])
            if item
        }
        for edge in candidates:
            if not isinstance(edge, dict):
                continue
            source = _name(edge.get("from", edge.get("source")))
            target = _name(edge.get("to", edge.get("target")))
            if source == "Unknown" or target == "Unknown":
                continue
            for label in (source, target):
                nodes.setdefault(_id(label), {
                    "id": _id(label), "label": label, "phase": "Planned", "status": "PLANNED",
                    "execution_order": None, "duration_ms": 0, "trust_score": 0,
                    "confidence": 0, "tool": "-", "observed": False,
                    "skip_reason": _skip_reason(label, selected),
                })
            key = (_id(source), _id(target))
            edge_map.setdefault(key, {
                "source": key[0], "target": key[1], "kind": "planned", "status": "PENDING"
            })

    node_list = sorted(nodes.values(), key=lambda n: (n["execution_order"] is None, n["execution_order"] or 9999, n["label"]))
    completed = sum(n["status"] in {"COMPLETED", "SUCCESS", "SUCCEEDED"} for n in node_list)
    failed = sum(n["status"] in {"FAILED", "ERROR"} for n in node_list)
    return {
        "version": "1.0",
        "runtime_id": runtime_state.get("runtime_id"),
        "nodes": node_list,
        "edges": list(edge_map.values()),
        "summary": {
            "agents": len(node_list), "observed_agents": len(observed_names),
            "completed": completed, "failed": failed, "transitions": len(edge_map),
        },
    }
