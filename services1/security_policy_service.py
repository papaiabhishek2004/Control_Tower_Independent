"""Dependency-free security policy checks shared by runtime and tests."""

from typing import Any, Dict

APPROVED_INTERNAL_TOOLS = {
    "planner", "retriever", "retrieval", "hybrid retrieval", "evidence",
    "evidence builder", "answer", "enterprise answer", "trust",
    "enterprise trust engine", "governance", "governance engine",
    "compliance", "compliance engine", "audit", "recommendation",
    "recommendation engine", "banking intelligence", "reflection service",
    "ragas", "enterprise evaluation", "tool router",
}


def canonical_tool_name(value: Any) -> str:
    return " ".join(str(value or "").strip().casefold().replace("_", " ").split())


def check_tool_security(runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    selected = runtime_state.get("selected_tools", []) if isinstance(runtime_state, dict) else []
    selected = selected if isinstance(selected, list) else []
    unauthorized = [tool for tool in selected if canonical_tool_name(tool) not in APPROVED_INTERNAL_TOOLS]
    return {"status": "FAIL" if unauthorized else "PASS", "unauthorized_tools": unauthorized, "score": 0 if unauthorized else 100}
