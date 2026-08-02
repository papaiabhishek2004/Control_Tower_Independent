"""Base contracts for onboarded agentic applications."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol


ProgressCallback = Callable[[Dict[str, Any], Dict[str, Any]], None]


@dataclass(frozen=True)
class AgenticAppRequest:
    """Execution request sent to an onboarded agentic application."""

    customer_id: str
    user_query: str
    original_user_query: Optional[str] = None
    cache_key_query: Optional[str] = None
    progress_callback: Optional[ProgressCallback] = None
    use_cached_runtime: bool = True
    app_id: str = "JSONL_RUNTIME_LOG"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgenticAppAdapterInfo:
    """Describes one onboarded app execution adapter."""

    app_id: str
    name: str
    kind: str
    description: str
    emits: List[str]


class AgenticAppAdapter(Protocol):
    """Protocol implemented by built-in or external app adapters."""

    info: AgenticAppAdapterInfo

    def execute(self, request: AgenticAppRequest) -> Dict[str, Any]:
        """Execute or fetch app output and return an AEGIS-compatible runtime state."""
