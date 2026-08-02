"""File-backed registry for agentic apps onboarded into AEGIS."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


REGISTRY_SCHEMA_VERSION = "AEGIS-ONBOARDED-APP-REGISTRY-2026.08"
DEFAULT_REGISTRY_PATH = Path("runtime_registry/onboarded_apps.json")
DEFAULT_EXPECTED_LIFECYCLE_PHASES = [
    "BEFORE_STARTING",
    "DURING_RUNTIME",
    "BEFORE_COMPLETION",
    "AFTER_COMPLETION",
]
DEFAULT_EXPECTED_CANONICAL_FIELDS = [
    "runtime_id",
    "app_id",
    "agent_id",
    "agent_name",
    "event_type",
    "status",
    "timestamp",
    "lifecycle_phase",
    "recommendation",
    "risk_level",
    "trust_score",
    "confidence",
    "control_status",
    "error_code",
    "evidence_count",
    "estimated_cost_usd",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def registry_path(path: str | Path | None = None) -> Path:
    return Path(path or DEFAULT_REGISTRY_PATH)


def load_registry(path: str | Path | None = None) -> Dict[str, Any]:
    target = registry_path(path)
    if not target.exists():
        return {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "apps": [],
        }
    with target.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        data = {}
    data.setdefault("schema_version", REGISTRY_SCHEMA_VERSION)
    data.setdefault("created_at", utc_now())
    data.setdefault("updated_at", utc_now())
    data.setdefault("apps", [])
    return data


def save_registry(registry: Dict[str, Any], path: str | Path | None = None) -> Dict[str, Any]:
    target = registry_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    registry["schema_version"] = REGISTRY_SCHEMA_VERSION
    registry["updated_at"] = utc_now()
    with target.open("w", encoding="utf-8") as handle:
        json.dump(registry, handle, indent=2, ensure_ascii=True, default=str)
        handle.write("\n")
    return registry


def register_app(
    app_id: str,
    app_name: str,
    log_folder: str = "runtime_logs",
    owner: str = "",
    path: str | Path | None = None,
) -> Dict[str, Any]:
    clean_app_id = (app_id or "").strip() or "EXTERNAL_AGENTIC_APP"
    registry = load_registry(path)
    apps: List[Dict[str, Any]] = [app for app in registry.get("apps", []) if isinstance(app, dict)]
    existing = next((app for app in apps if str(app.get("app_id", "")).casefold() == clean_app_id.casefold()), None)
    record = existing or {}
    record.update({
        "app_id": clean_app_id,
        "app_name": (app_name or "").strip() or clean_app_id,
        "owner": (owner or "").strip() or "-",
        "status": "ACTIVE",
        "log_folder": (log_folder or "").strip() or "runtime_logs",
        "adapter": "JSONL_RUNTIME_LOG",
        "expected_lifecycle_phases": list(DEFAULT_EXPECTED_LIFECYCLE_PHASES),
        "expected_canonical_fields": list(DEFAULT_EXPECTED_CANONICAL_FIELDS),
        "registered_at": record.get("registered_at") or utc_now(),
        "updated_at": utc_now(),
    })
    if existing is None:
        apps.append(record)
    registry["apps"] = apps
    return save_registry(registry, path)


def registry_rows(path: str | Path | None = None) -> List[Dict[str, Any]]:
    rows = []
    for app in load_registry(path).get("apps", []):
        if not isinstance(app, dict):
            continue
        rows.append({
            "App ID": app.get("app_id"),
            "App Name": app.get("app_name"),
            "Owner": app.get("owner"),
            "Status": app.get("status"),
            "Log Folder": app.get("log_folder"),
            "Adapter": app.get("adapter"),
            "Expected Lifecycle Phases": ", ".join(app.get("expected_lifecycle_phases", [])),
            "Expected Canonical Fields": len(app.get("expected_canonical_fields", [])),
            "Updated At": app.get("updated_at"),
        })
    return rows


def app_record(app_id: str, path: str | Path | None = None) -> Dict[str, Any]:
    clean_app_id = (app_id or "").strip()
    for app in load_registry(path).get("apps", []):
        if isinstance(app, dict) and str(app.get("app_id", "")).casefold() == clean_app_id.casefold():
            return app
    return {}
