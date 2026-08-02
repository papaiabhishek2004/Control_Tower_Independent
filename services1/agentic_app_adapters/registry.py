"""Registry for onboarded agentic application adapters."""

from __future__ import annotations

from typing import Any, Dict, List

from services1.agentic_app_adapters.base import AgenticAppRequest
from services1.agentic_app_adapters.jsonl_runtime_log_adapter import JsonlRuntimeLogAdapter


JSONL_RUNTIME_LOG_APP_ID = "JSONL_RUNTIME_LOG"

_ADAPTERS = {
    JSONL_RUNTIME_LOG_APP_ID: JsonlRuntimeLogAdapter(),
}


def list_agentic_app_adapters() -> List[Dict[str, Any]]:
    return [
        {
            "app_id": adapter.info.app_id,
            "name": adapter.info.name,
            "kind": adapter.info.kind,
            "description": adapter.info.description,
            "emits": list(adapter.info.emits),
        }
        for adapter in _ADAPTERS.values()
    ]


def get_agentic_app_adapter(app_id: str = JSONL_RUNTIME_LOG_APP_ID):
    adapter = _ADAPTERS.get(app_id)
    if adapter is None:
        supported = ", ".join(sorted(_ADAPTERS))
        raise ValueError(f"Unknown agentic app adapter '{app_id}'. Supported adapters: {supported}")
    return adapter


def execute_onboarded_agentic_app(
    customer_id: str,
    user_query: str,
    original_user_query: str | None = None,
    cache_key_query: str | None = None,
    progress_callback=None,
    use_cached_runtime: bool = True,
    app_id: str = JSONL_RUNTIME_LOG_APP_ID,
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Execute an onboarded agentic app and enrich it for AEGIS Control Tower."""
    request = AgenticAppRequest(
        customer_id=customer_id,
        user_query=user_query,
        original_user_query=original_user_query,
        cache_key_query=cache_key_query,
        progress_callback=progress_callback,
        use_cached_runtime=use_cached_runtime,
        app_id=app_id,
        metadata=metadata or {},
    )
    return get_agentic_app_adapter(app_id).execute(request)
