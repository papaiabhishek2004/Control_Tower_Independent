"""
===============================================================================
AEGIS ENTERPRISE CACHE INTELLIGENCE AGENT
Version : V1
Purpose : Enterprise Cache Monitoring & Optimization
===============================================================================
"""

from __future__ import annotations

from datetime import datetime

from collections import OrderedDict

from copy import deepcopy
from pathlib import Path

import hashlib

import json

import logging

import os

import statistics

import time

import threading

import unicodedata

import zlib

from dataclasses import dataclass

from typing import Any

from typing import Dict

from typing import List

from typing import Optional


logger = logging.getLogger(__name__)


# =============================================================================
# AGENT INFORMATION
# =============================================================================

AGENT_NAME = "Cache Intelligence Agent"

AGENT_VERSION = "V1"

AGENT_PHASE = "Runtime Intelligence"

AGENT_OWNER = "AEGIS"

CACHE_HEALTHY = "HEALTHY"

CACHE_WARNING = "WARNING"

CACHE_CRITICAL = "CRITICAL"

RUNTIME_CACHE_TTL_SECONDS = int(
    os.getenv("AEGIS_RUNTIME_CACHE_TTL_SECONDS", str(6 * 60 * 60))
)

RUNTIME_CACHE_MAX_ENTRIES = 64

RUNTIME_CACHE_VERSION = "v4-canonical-dimensions"
DEFAULT_APP_VERSION = os.getenv("AEGIS_APP_VERSION", "customer360-demo-v1")
DEFAULT_MODEL_VERSION = os.getenv("AEGIS_MODEL_VERSION", "qwen2.5-0.5b-local")
DEFAULT_POLICY_VERSION = os.getenv("AEGIS_POLICY_VERSION", "aegis-policy-v1")

RUNTIME_CACHE_DISK_DIR = Path(__file__).resolve().parent.parent / ".aegis_cache" / "runtime"
LAYER_CACHE_DISK_DIR = Path(__file__).resolve().parent.parent / ".aegis_cache" / "layers"

_runtime_cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()

_runtime_cache_lock = threading.RLock()

_runtime_cache_stats = {
    "lookups": 0,
    "hits": 0,
    "misses": 0,
    "expired": 0,
    "evictions": 0,
    "stores": 0,
}

_LAYER_CONFIG = {
    "embedding": {"ttl": 3600, "max_entries": 2048},
    "prompt": {"ttl": 1800, "max_entries": 512},
    "retrieval": {"ttl": 900, "max_entries": 512},
    "kv": {"ttl": 1800, "max_entries": 1024},
}

_layer_caches = {name: OrderedDict() for name in _LAYER_CONFIG}

_layer_stats = {
    name: {"lookups": 0, "hits": 0, "misses": 0, "stores": 0, "expired": 0, "evictions": 0}
    for name in _LAYER_CONFIG
}


# =============================================================================
# CACHE CONFIGURATION
# =============================================================================

CACHE_TARGET_HIT_RATIO = 85.0

KV_CACHE_TARGET = 90.0

EMBEDDING_CACHE_TARGET = 95.0

PROMPT_CACHE_TARGET = 90.0

RETRIEVAL_CACHE_TARGET = 80.0


# =============================================================================
# CACHE RUNTIME MODEL
# =============================================================================

@dataclass
class CacheMetrics:

    cache_hit_ratio: float = 0.0

    kv_cache_hit_ratio: float = 0.0

    embedding_cache_hit_ratio: float = 0.0

    retrieval_cache_hit_ratio: float = 0.0

    prompt_cache_hit_ratio: float = 0.0

    total_requests: int = 0

    cache_hits: int = 0

    cache_misses: int = 0

    estimated_tokens_saved: int = 0

    estimated_latency_saved_ms: float = 0.0

    estimated_cost_saved: float = 0.0

    reuse_recommended: bool = False

    invalidate_required: bool = False

    overall_status: str = CACHE_WARNING


# =============================================================================
# RUNTIME INITIALIZATION
# =============================================================================

def initialize_cache_runtime(
    runtime_state: Dict[str, Any]
) -> None:

    runtime_state.setdefault(

        "agents",

        {}

    )

    runtime_state.setdefault(

        "agent_trace",

        []

    )

    runtime_state.setdefault(

        "dashboard_metrics",

        {}

    )

    runtime_state.setdefault(

        "runtime_summary",

        {}

    )

    runtime_state.setdefault(

        "cache_metrics",

        {}

    )

    runtime_state.setdefault(

        "cache_statistics",

        {}

    )


# =============================================================================
# AGENT REGISTRATION
# =============================================================================

def register_cache_agent(
    runtime_state: Dict[str, Any]
) -> None:

    runtime_state["agents"]["cache"] = {

        "agent_name":

            AGENT_NAME,

        "version":

            AGENT_VERSION,

        "phase":

            AGENT_PHASE,

        "status":

            "RUNNING",

        "started_at":

            datetime.now().isoformat()

    }


# =============================================================================
# CACHE KEY GENERATOR
# =============================================================================

def generate_cache_key(
    value: str
) -> str:

    return hashlib.sha256(

        value.encode()

    ).hexdigest()


def _current_data_fingerprint() -> str:
    try:
        from services1.vector_index_cdc_service import current_csv_knowledge_fingerprint
        return str(current_csv_knowledge_fingerprint().get("fingerprint") or "unknown")
    except Exception:
        try:
            from services1.embedding_cdc_service import get_knowledge_version
            return str(get_knowledge_version() or "unknown")
        except Exception:
            return "unknown"


def _runtime_cache_dimensions(
    customer_id: str,
    query: str,
    app_version: Optional[str] = None,
    data_fingerprint: Optional[str] = None,
    model_version: Optional[str] = None,
    policy_version: Optional[str] = None,
) -> Dict[str, str]:
    return {
        "cache_version": RUNTIME_CACHE_VERSION,
        "customer_id": _canonical_part(customer_id),
        "query": _canonical_part(query),
        "app_version": _canonical_part(app_version or DEFAULT_APP_VERSION),
        "data_fingerprint": _canonical_part(data_fingerprint or _current_data_fingerprint()),
        "model_version": _canonical_part(model_version or DEFAULT_MODEL_VERSION),
        "policy_version": _canonical_part(policy_version or DEFAULT_POLICY_VERSION),
    }


def generate_runtime_cache_key(
    customer_id: str,
    query: str,
    app_version: Optional[str] = None,
    data_fingerprint: Optional[str] = None,
    model_version: Optional[str] = None,
    policy_version: Optional[str] = None,
) -> str:
    """Create a stable key for exact full-runtime reuse.

    Full-runtime cache is intentionally stricter than prompt/query cache:
    same customer + same query + same app version + same data fingerprint +
    same model version + same policy version.
    """
    material = json.dumps(
        _runtime_cache_dimensions(
            customer_id,
            query,
            app_version=app_version,
            data_fingerprint=data_fingerprint,
            model_version=model_version,
            policy_version=policy_version,
        ),
        sort_keys=True,
        separators=(",", ":"),
    )
    return generate_cache_key(material)


def _cache_telemetry(status: str, key: str, **extra: Any) -> Dict[str, Any]:
    lookups = _runtime_cache_stats["lookups"]
    hits = _runtime_cache_stats["hits"]
    telemetry = {
        "status": status,
        "cache_key": key[:12],
        "ttl_seconds": RUNTIME_CACHE_TTL_SECONDS,
        "max_entries": RUNTIME_CACHE_MAX_ENTRIES,
        "entries": len(_runtime_cache),
        "lookups": lookups,
        "cache_hits": hits,
        "cache_misses": _runtime_cache_stats["misses"],
        "expired_entries": _runtime_cache_stats["expired"],
        "evictions": _runtime_cache_stats["evictions"],
        "stores": _runtime_cache_stats["stores"],
        "cache_hit_ratio": safe_percentage(hits, lookups),
    }
    telemetry.update(extra)
    return telemetry


def _runtime_cache_path(key: str) -> Path:
    return RUNTIME_CACHE_DISK_DIR / f"{key}.json.zlib"


def _read_runtime_disk_cache(key: str, now: float) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    path = _runtime_cache_path(key)
    if not path.exists():
        return None, None
    try:
        age_seconds = max(0.0, now - path.stat().st_mtime)
        if age_seconds >= RUNTIME_CACHE_TTL_SECONDS:
            path.unlink(missing_ok=True)
            _runtime_cache_stats["expired"] += 1
            return None, _cache_telemetry("EXPIRED", key, age_seconds=round(age_seconds, 2), persistence="disk")
        payload = json.loads(zlib.decompress(path.read_bytes()).decode("utf-8"))
        _runtime_cache[key] = {
            "stored_at": now - age_seconds,
            "value": zlib.compress(json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8"), level=6),
            "encoding": "json+zlib",
            "payload_bytes": path.stat().st_size,
            "persistence": "disk",
        }
        _runtime_cache.move_to_end(key)
        return payload, _cache_telemetry(
            "HIT",
            key,
            age_seconds=round(age_seconds, 2),
            remaining_ttl_seconds=round(RUNTIME_CACHE_TTL_SECONDS - age_seconds, 2),
            payload_encoding="json+zlib",
            payload_bytes=path.stat().st_size,
            persistence="disk",
        )
    except Exception as exc:
        logger.warning("Runtime disk cache read failed for %s: %s", key[:12], exc)
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return None, None


def _write_runtime_disk_cache(key: str, runtime_state: Dict[str, Any], payload: bytes) -> None:
    try:
        RUNTIME_CACHE_DISK_DIR.mkdir(parents=True, exist_ok=True)
        target = _runtime_cache_path(key)
        temp = target.with_suffix(target.suffix + ".tmp")
        temp.write_bytes(payload)
        temp.replace(target)
    except Exception as exc:
        logger.warning("Runtime disk cache write failed for %s: %s", key[:12], exc)


def lookup_runtime_cache(
    customer_id: str,
    query: str,
    app_version: Optional[str] = None,
    data_fingerprint: Optional[str] = None,
    model_version: Optional[str] = None,
    policy_version: Optional[str] = None,
) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Return a deep-copied unexpired runtime result and real lookup telemetry."""
    dimensions = _runtime_cache_dimensions(
        customer_id,
        query,
        app_version=app_version,
        data_fingerprint=data_fingerprint,
        model_version=model_version,
        policy_version=policy_version,
    )
    key = generate_cache_key(json.dumps(dimensions, sort_keys=True, separators=(",", ":")))
    now = time.time()

    with _runtime_cache_lock:
        _runtime_cache_stats["lookups"] += 1
        entry = _runtime_cache.get(key)

        if entry is None:
            disk_value, disk_telemetry = _read_runtime_disk_cache(key, now)
            if disk_value is not None:
                _runtime_cache_stats["hits"] += 1
                disk_telemetry = {
                    **(disk_telemetry or {}),
                    "cache_hits": _runtime_cache_stats["hits"],
                    "cache_misses": _runtime_cache_stats["misses"],
                    "cache_hit_ratio": safe_percentage(_runtime_cache_stats["hits"], _runtime_cache_stats["lookups"]),
                    "entries": len(_runtime_cache),
                    "key_dimensions": dimensions,
                    "exact_match_required": list(dimensions.keys()),
                }
                return deepcopy(disk_value), disk_telemetry
            if disk_telemetry and disk_telemetry.get("status") == "EXPIRED":
                _runtime_cache_stats["misses"] += 1
                return None, disk_telemetry
            _runtime_cache_stats["misses"] += 1
            return None, _cache_telemetry("MISS", key, key_dimensions=dimensions, exact_match_required=list(dimensions.keys()))

        age_seconds = max(0.0, now - entry["stored_at"])
        if age_seconds >= RUNTIME_CACHE_TTL_SECONDS:
            _runtime_cache.pop(key, None)
            _runtime_cache_stats["expired"] += 1
            _runtime_cache_stats["misses"] += 1
            return None, _cache_telemetry("EXPIRED", key, age_seconds=round(age_seconds, 2))

        _runtime_cache.move_to_end(key)
        _runtime_cache_stats["hits"] += 1
        if entry.get("encoding") == "json+zlib":
            value = json.loads(zlib.decompress(entry["value"]).decode("utf-8"))
        else:
            value = deepcopy(entry["value"])
        return value, _cache_telemetry(
            "HIT",
            key,
            age_seconds=round(age_seconds, 2),
            remaining_ttl_seconds=round(RUNTIME_CACHE_TTL_SECONDS - age_seconds, 2),
            payload_encoding=entry.get("encoding", "deepcopy"),
            payload_bytes=entry.get("payload_bytes", 0),
            key_dimensions=dimensions,
            exact_match_required=list(dimensions.keys()),
        )


def store_runtime_cache(customer_id: str, query: str, runtime_state: Dict[str, Any]) -> Dict[str, Any]:
    """Store a completed runtime result using bounded LRU eviction."""
    dimensions = _runtime_cache_dimensions(
        customer_id,
        query,
        app_version=runtime_state.get("app_version"),
        data_fingerprint=runtime_state.get("data_fingerprint"),
        model_version=runtime_state.get("model_version"),
        policy_version=runtime_state.get("policy_version"),
    )
    key = generate_cache_key(json.dumps(dimensions, sort_keys=True, separators=(",", ":")))

    with _runtime_cache_lock:
        try:
            raw_payload = json.dumps(
                runtime_state,
                ensure_ascii=False,
                separators=(",", ":"),
                default=lambda value: value.tolist() if hasattr(value, "tolist") else str(value),
            ).encode("utf-8")
            cached_value = zlib.compress(raw_payload, level=6)
            encoding = "json+zlib"
        except (TypeError, ValueError):
            cached_value = deepcopy(runtime_state)
            encoding = "deepcopy"
        _runtime_cache[key] = {
            "stored_at": time.time(),
            "value": cached_value,
            "encoding": encoding,
            "payload_bytes": len(cached_value) if isinstance(cached_value, bytes) else 0,
            "persistence": "memory+disk",
        }
        if isinstance(cached_value, bytes):
            _write_runtime_disk_cache(key, runtime_state, cached_value)
        _runtime_cache.move_to_end(key)
        _runtime_cache_stats["stores"] += 1

        while len(_runtime_cache) > RUNTIME_CACHE_MAX_ENTRIES:
            _runtime_cache.popitem(last=False)
            _runtime_cache_stats["evictions"] += 1

        return _cache_telemetry(
            "STORED", key,
            age_seconds=0,
            remaining_ttl_seconds=RUNTIME_CACHE_TTL_SECONDS,
            payload_encoding=encoding,
            payload_bytes=_runtime_cache[key]["payload_bytes"],
            key_dimensions=dimensions,
            exact_match_required=list(dimensions.keys()),
        )


def _canonical_part(part: Any) -> str:
    if isinstance(part, (dict, list, tuple)):
        value = json.dumps(part, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)
    else:
        value = str(part or "")
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _normalized_key(*parts: Any) -> str:
    material = "|".join(_canonical_part(part) for part in parts)
    return generate_cache_key(material)


def _layer_cache_path(layer: str, key: str) -> Path:
    return LAYER_CACHE_DISK_DIR / layer / f"{key}.json.zlib"


def _read_layer_disk_cache(layer: str, key: str) -> tuple[Optional[Any], Optional[Dict[str, Any]]]:
    config = _LAYER_CONFIG[layer]
    path = _layer_cache_path(layer, key)
    if not path.exists():
        return None, None
    now = time.time()
    try:
        age = max(0.0, now - path.stat().st_mtime)
        stats = _layer_stats[layer]
        if age >= config["ttl"]:
            path.unlink(missing_ok=True)
            stats["expired"] += 1
            stats["misses"] += 1
            return None, {"layer": layer, "status": "EXPIRED", "cache_key": key[:12], "age_seconds": round(age, 2), "persistence": "disk"}
        value = json.loads(zlib.decompress(path.read_bytes()).decode("utf-8"))
        _layer_caches[layer][key] = {"stored_at": now - age, "value": deepcopy(value), "persistence": "disk"}
        _layer_caches[layer].move_to_end(key)
        stats["hits"] += 1
        return deepcopy(value), {
            "layer": layer,
            "status": "HIT",
            "cache_key": key[:12],
            "age_seconds": round(age, 2),
            "remaining_ttl_seconds": round(config["ttl"] - age, 2),
            "persistence": "disk",
        }
    except Exception as exc:
        logger.warning("%s layer disk cache read failed for %s: %s", layer, key[:12], exc)
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
        return None, None


def _write_layer_disk_cache(layer: str, key: str, value: Any) -> None:
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        target = _layer_cache_path(layer, key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix + ".tmp")
        temp.write_bytes(zlib.compress(raw, level=6))
        temp.replace(target)
    except Exception as exc:
        logger.warning("%s layer disk cache write failed for %s: %s", layer, key[:12], exc)


def _lookup_layer(layer: str, key: str) -> tuple[Optional[Any], Dict[str, Any]]:
    config = _LAYER_CONFIG[layer]
    now = time.time()
    with _runtime_cache_lock:
        stats = _layer_stats[layer]
        cache = _layer_caches[layer]
        stats["lookups"] += 1
        entry = cache.get(key)
        if entry is None:
            disk_value, disk_event = _read_layer_disk_cache(layer, key)
            if disk_value is not None:
                return disk_value, disk_event or {"layer": layer, "status": "HIT", "cache_key": key[:12], "persistence": "disk"}
            if disk_event and disk_event.get("status") == "EXPIRED":
                return None, disk_event
            stats["misses"] += 1
            return None, {"layer": layer, "status": "MISS", "cache_key": key[:12]}
        age = max(0.0, now - entry["stored_at"])
        if age >= config["ttl"]:
            cache.pop(key, None)
            stats["expired"] += 1
            stats["misses"] += 1
            return None, {"layer": layer, "status": "EXPIRED", "cache_key": key[:12], "age_seconds": round(age, 2)}
        cache.move_to_end(key)
        stats["hits"] += 1
        return deepcopy(entry["value"]), {
            "layer": layer,
            "status": "HIT",
            "cache_key": key[:12],
            "age_seconds": round(age, 2),
            "remaining_ttl_seconds": round(config["ttl"] - age, 2),
        }


def _store_layer(layer: str, key: str, value: Any) -> Dict[str, Any]:
    config = _LAYER_CONFIG[layer]
    with _runtime_cache_lock:
        cache = _layer_caches[layer]
        stats = _layer_stats[layer]
        cache[key] = {"stored_at": time.time(), "value": deepcopy(value)}
        cache.move_to_end(key)
        stats["stores"] += 1
        while len(cache) > config["max_entries"]:
            cache.popitem(last=False)
            stats["evictions"] += 1
        _write_layer_disk_cache(layer, key, value)
        return {"layer": layer, "status": "STORED", "cache_key": key[:12], "persistence": "memory+disk"}


def lookup_embedding(text: str, model_id: str = "default") -> tuple[Optional[Any], Dict[str, Any]]:
    return _lookup_layer("embedding", _normalized_key("embedding-v1", model_id, text))


def store_embedding(text: str, embedding: Any, model_id: str = "default") -> Dict[str, Any]:
    return _store_layer("embedding", _normalized_key("embedding-v1", model_id, text), embedding)


def lookup_prompt(prompt: str, *, system_prompt: str = "", model_id: str = "default", parameters: Any = "") -> tuple[Optional[Any], Dict[str, Any]]:
    return _lookup_layer("prompt", _normalized_key("prompt-v1", model_id, system_prompt, prompt, parameters))


def store_prompt(prompt: str, response: Any, *, system_prompt: str = "", model_id: str = "default", parameters: Any = "") -> Dict[str, Any]:
    return _store_layer("prompt", _normalized_key("prompt-v1", model_id, system_prompt, prompt, parameters), response)


def lookup_retrieval(query: str, *, namespace: str = "default", top_k: int = 5, index_version: str = "v1", collection_fingerprint: str = "", embedding_model: str = "", knowledge_version: str = "") -> tuple[Optional[Any], Dict[str, Any]]:
    return _lookup_layer("retrieval", _normalized_key("retrieval-v2", namespace, index_version, collection_fingerprint, embedding_model, knowledge_version, top_k, query))


def store_retrieval(query: str, documents: Any, *, namespace: str = "default", top_k: int = 5, index_version: str = "v1", collection_fingerprint: str = "", embedding_model: str = "", knowledge_version: str = "") -> Dict[str, Any]:
    return _store_layer("retrieval", _normalized_key("retrieval-v2", namespace, index_version, collection_fingerprint, embedding_model, knowledge_version, top_k, query), documents)


def lookup_kv(session_id: str, key: str) -> tuple[Optional[Any], Dict[str, Any]]:
    return _lookup_layer("kv", _normalized_key("kv-v1", session_id, key))


def store_kv(session_id: str, key: str, value: Any) -> Dict[str, Any]:
    return _store_layer("kv", _normalized_key("kv-v1", session_id, key), value)


def get_cache_registry_metrics() -> Dict[str, Any]:
    """Return an atomic snapshot of real counters for every cache layer."""
    with _runtime_cache_lock:
        layers = {}
        for name, config in _LAYER_CONFIG.items():
            stats = dict(_layer_stats[name])
            stats.update({
                "entries": len(_layer_caches[name]),
                "ttl_seconds": config["ttl"],
                "max_entries": config["max_entries"],
                "hit_ratio": safe_percentage(stats["hits"], stats["lookups"]),
            })
            layers[name] = stats
        runtime = dict(_runtime_cache_stats)
        runtime.update({
            "entries": len(_runtime_cache),
            "ttl_seconds": RUNTIME_CACHE_TTL_SECONDS,
            "max_entries": RUNTIME_CACHE_MAX_ENTRIES,
            "hit_ratio": safe_percentage(runtime["hits"], runtime["lookups"]),
            "payload_bytes": sum(entry.get("payload_bytes", 0) for entry in _runtime_cache.values()),
        })
        layers["runtime"] = runtime
        try:
            from services1.embedding_cdc_service import get_embedding_cdc_metrics
            layers["embedding_cdc"] = get_embedding_cdc_metrics()
        except Exception as exc:
            logger.warning("Embedding CDC metrics unavailable: %s", exc)
        return layers


# =============================================================================
# SAFE PERCENTAGE
# =============================================================================

def safe_percentage(
    numerator: float,
    denominator: float
) -> float:

    if denominator == 0:

        return 0.0

    return round(

        (numerator / denominator) * 100,

        2

    )


# =============================================================================
# SAFE MEAN
# =============================================================================

def safe_mean(
    values: List[float]
) -> float:

    if not values:

        return 0.0

    return round(

        statistics.mean(values),

        2

    )


# =============================================================================
# CACHE HEALTH
# =============================================================================

def determine_cache_health(
    ratio: float
) -> str:

    if ratio >= CACHE_TARGET_HIT_RATIO:

        return CACHE_HEALTHY

    if ratio >= 70:

        return CACHE_WARNING

    return CACHE_CRITICAL
# =============================================================================
# CACHE ANALYSIS ENGINE
# =============================================================================

def analyze_cache(
    runtime_state: Dict[str, Any]
) -> CacheMetrics:

    metrics = CacheMetrics()

    token_metrics = runtime_state.get(
        "token_metrics",
        {}
    )

    registry = get_cache_registry_metrics()
    tracked_layers = [registry[name] for name in ("runtime", "embedding", "prompt", "retrieval", "kv")]
    metrics.total_requests = sum(layer["lookups"] for layer in tracked_layers)
    metrics.cache_hits = sum(layer["hits"] for layer in tracked_layers)
    metrics.cache_misses = sum(layer["misses"] for layer in tracked_layers)
    metrics.cache_hit_ratio = safe_percentage(metrics.cache_hits, metrics.total_requests)
    metrics.kv_cache_hit_ratio = registry["kv"]["hit_ratio"]
    metrics.embedding_cache_hit_ratio = registry["embedding"]["hit_ratio"]
    metrics.retrieval_cache_hit_ratio = registry["retrieval"]["hit_ratio"]
    metrics.prompt_cache_hit_ratio = registry["prompt"]["hit_ratio"]
    runtime_state["cache_layers"] = registry

    total_tokens = token_metrics.get(

        "total_tokens",

        0

    )

    metrics.estimated_tokens_saved = int(

        total_tokens *

        (

            metrics.cache_hit_ratio /

            100.0

        )

    )

    average_latency = runtime_state.get(

        "performance_metrics",

        {}

    ).get(

        "average_latency_ms",

        0

    )

    metrics.estimated_latency_saved_ms = round(

        average_latency *

        (

            metrics.cache_hit_ratio /

            100.0

        ),

        2

    )

    average_token_cost = runtime_state.get(

        "cost_metrics",

        {}

    ).get(

        "cost_per_token",

        0.0

    )

    metrics.estimated_cost_saved = round(

        metrics.estimated_tokens_saved *

        average_token_cost,

        4

    )

    metrics.reuse_recommended = (

        metrics.cache_hit_ratio >=

        CACHE_TARGET_HIT_RATIO

    )

    metrics.invalidate_required = (

        metrics.cache_hit_ratio <

        50

    )

    metrics.overall_status = determine_cache_health(

        metrics.cache_hit_ratio

    )

    return metrics


# =============================================================================
# CACHE RECOMMENDATIONS
# =============================================================================

def build_cache_recommendations(
    metrics: CacheMetrics
) -> List[str]:

    recommendations = []

    if metrics.cache_hit_ratio < CACHE_TARGET_HIT_RATIO:

        recommendations.append(

            "Increase cache reuse for repeated prompts."

        )

    if metrics.embedding_cache_hit_ratio < EMBEDDING_CACHE_TARGET:

        recommendations.append(

            "Enable embedding cache reuse."

        )

    if metrics.kv_cache_hit_ratio < KV_CACHE_TARGET:

        recommendations.append(

            "Improve KV cache reuse for multi-turn conversations."

        )

    if metrics.prompt_cache_hit_ratio < PROMPT_CACHE_TARGET:

        recommendations.append(

            "Deduplicate repeated prompts before LLM execution."

        )

    if metrics.retrieval_cache_hit_ratio < RETRIEVAL_CACHE_TARGET:

        recommendations.append(

            "Cache frequently accessed retrieval results."

        )

    if metrics.invalidate_required:

        recommendations.append(

            "Invalidate stale cache entries."

        )

    if not recommendations:

        recommendations.append(

            "Cache utilization is healthy."

        )

    return recommendations
# =============================================================================
# CACHE INTELLIGENCE AGENT
# =============================================================================

def execute_cache_intelligence_agent(
    runtime_state: Dict[str, Any]
) -> Dict[str, Any]:

    start_time = time.time()

    initialize_cache_runtime(runtime_state)

    register_cache_agent(runtime_state)

    metrics = analyze_cache(runtime_state)

    recommendations = build_cache_recommendations(metrics)

    runtime_state["cache"] = {

        "overall_status":
            metrics.overall_status,

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "kv_cache_hit_ratio":
            metrics.kv_cache_hit_ratio,

        "embedding_cache_hit_ratio":
            metrics.embedding_cache_hit_ratio,

        "retrieval_cache_hit_ratio":
            metrics.retrieval_cache_hit_ratio,

        "prompt_cache_hit_ratio":
            metrics.prompt_cache_hit_ratio,

        "reuse_recommended":
            metrics.reuse_recommended,

        "invalidate_required":
            metrics.invalidate_required

    }

    runtime_state["cache_summary"] = {

        "status":
            metrics.overall_status,

        "recommendations":
            recommendations

    }

    runtime_state["cache_metrics"] = {

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "kv_cache_hit_ratio":
            metrics.kv_cache_hit_ratio,

        "embedding_cache_hit_ratio":
            metrics.embedding_cache_hit_ratio,

        "retrieval_cache_hit_ratio":
            metrics.retrieval_cache_hit_ratio,

        "prompt_cache_hit_ratio":
            metrics.prompt_cache_hit_ratio,

        "total_requests": metrics.total_requests,

        "cache_hits": metrics.cache_hits,

        "cache_misses": metrics.cache_misses,

        "layers": get_cache_registry_metrics()

    }

    runtime_state["cache_statistics"] = {

        "total_requests":
            metrics.total_requests,

        "cache_hits":
            metrics.cache_hits,

        "cache_misses":
            metrics.cache_misses,

        "estimated_tokens_saved":
            metrics.estimated_tokens_saved,

        "estimated_latency_saved_ms":
            metrics.estimated_latency_saved_ms,

        "estimated_cost_saved":
            metrics.estimated_cost_saved

    }

    runtime_state["cache_health"] = {

        "status":
            metrics.overall_status

    }

    runtime_state["cache_runtime"] = {

        "generated_at":
            datetime.now().isoformat(),

        "status":
            "COMPLETED"

    }

    runtime_state["cache_trace"] = {

        "service":
            AGENT_NAME,

        "phase":
            AGENT_PHASE,

        "status":
            "COMPLETED",

        "timestamp":
            datetime.now().isoformat()

    }

    runtime_state["cache_generated_at"] = datetime.now().isoformat()

    runtime_state["cache_success"] = True

    runtime_state["cache_duration_ms"] = round(

        (time.time() - start_time) * 1000,

        2

    )

    runtime_state["agent_trace"].append({

        "agent_name":
            AGENT_NAME,

        "phase":
            AGENT_PHASE,

        "status":
            "COMPLETED",

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "timestamp":
            datetime.now().isoformat()

    })

    runtime_state.setdefault(

        "dashboard_metrics",

        {}

    )

    runtime_state["dashboard_metrics"]["cache"] = {

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "kv_cache":
            metrics.kv_cache_hit_ratio,

        "embedding_cache":
            metrics.embedding_cache_hit_ratio,

        "retrieval_cache":
            metrics.retrieval_cache_hit_ratio,

        "prompt_cache":
            metrics.prompt_cache_hit_ratio,

        "status":
            metrics.overall_status

    }

    runtime_state.setdefault(

        "runtime_summary",

        {}

    )

    runtime_state["runtime_summary"]["cache"] = {

        "status":
            metrics.overall_status,

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "reuse_recommended":
            metrics.reuse_recommended

    }

    runtime_state["agents"]["cache"]["status"] = "COMPLETED"

    runtime_state["agents"]["cache"]["completed_at"] = (

        datetime.now().isoformat()

    )

    return {

        "success": True,

        "cache": runtime_state["cache"],

        "recommendations": recommendations,

        "metrics": runtime_state["cache_metrics"]

    }
# =============================================================================
# CACHE DECISION ENGINE
# =============================================================================

def evaluate_cache_strategy(
    runtime_state: Dict[str, Any],
    metrics: CacheMetrics
) -> Dict[str, Any]:

    decision = {

        "strategy": "REUSE",

        "reason": "",

        "action": "",

        "priority": "LOW"

    }

    # -------------------------------------------------------------
    # KV Cache
    # -------------------------------------------------------------

    if metrics.kv_cache_hit_ratio < 60:

        decision["strategy"] = "REBUILD"

        decision["reason"] = "Low KV cache reuse."

        decision["action"] = "Reset conversational KV cache."

        decision["priority"] = "HIGH"

    # -------------------------------------------------------------
    # Embedding Cache
    # -------------------------------------------------------------

    elif metrics.embedding_cache_hit_ratio < 70:

        decision["strategy"] = "REFRESH"

        decision["reason"] = "Embedding cache becoming ineffective."

        decision["action"] = "Recompute embeddings."

        decision["priority"] = "MEDIUM"

    # -------------------------------------------------------------
    # Retrieval Cache
    # -------------------------------------------------------------

    elif metrics.retrieval_cache_hit_ratio < 70:

        decision["strategy"] = "INVALIDATE"

        decision["reason"] = "Retrieval cache stale."

        decision["action"] = "Invalidate retrieval cache."

        decision["priority"] = "MEDIUM"

    # -------------------------------------------------------------
    # Prompt Cache
    # -------------------------------------------------------------

    elif metrics.prompt_cache_hit_ratio < 70:

        decision["strategy"] = "OPTIMIZE"

        decision["reason"] = "Prompt reuse is low."

        decision["action"] = "Normalize prompts before execution."

        decision["priority"] = "LOW"

    else:

        decision["strategy"] = "REUSE"

        decision["reason"] = "Caches are healthy."

        decision["action"] = "Continue cache reuse."

        decision["priority"] = "NONE"

    return decision


# =============================================================================
# CACHE SAVINGS ESTIMATION
# =============================================================================

def estimate_cache_savings(
    metrics: CacheMetrics
) -> Dict[str, Any]:

    return {

        "tokens_saved":

            metrics.estimated_tokens_saved,

        "latency_saved_ms":

            metrics.estimated_latency_saved_ms,

        "cost_saved_usd":

            round(

                metrics.estimated_cost_saved,

                4

            ),

        "estimated_llm_calls_saved":

            int(

                metrics.cache_hits

            )

    }


# =============================================================================
# CACHE RECOMMENDATION SUMMARY
# =============================================================================

def build_cache_summary(

    metrics: CacheMetrics,

    decision: Dict[str, Any]

) -> Dict[str, Any]:

    return {

        "overall_status":

            metrics.overall_status,

        "cache_hit_ratio":

            metrics.cache_hit_ratio,

        "recommended_strategy":

            decision["strategy"],

        "recommended_action":

            decision["action"],

        "priority":

            decision["priority"],

        "reuse_recommended":

            metrics.reuse_recommended,

        "invalidate_required":

            metrics.invalidate_required

    }
# =============================================================================
# CACHE INTELLIGENCE INTEGRATION
# =============================================================================

def integrate_cache_intelligence(
    runtime_state: Dict[str, Any],
    metrics: CacheMetrics,
    decision: Dict[str, Any],
    savings: Dict[str, Any]
) -> None:

    runtime_state["cache_decision"] = decision

    runtime_state["cache_savings"] = savings

    runtime_state["cache_intelligence"] = {

        "status":
            metrics.overall_status,

        "strategy":
            decision["strategy"],

        "priority":
            decision["priority"],

        "recommended_action":
            decision["action"],

        "reuse_recommended":
            metrics.reuse_recommended,

        "invalidate_required":
            metrics.invalidate_required

    }

    runtime_state.setdefault(
        "executive_package",
        {}
    )

    runtime_state["executive_package"]["cache"] = {

        "overall_status":
            metrics.overall_status,

        "cache_hit_ratio":
            metrics.cache_hit_ratio,

        "strategy":
            decision["strategy"],

        "estimated_cost_saved":
            savings["cost_saved_usd"],

        "estimated_latency_saved_ms":
            savings["latency_saved_ms"]

    }

    runtime_state.setdefault(
        "recommendation_package",
        {}
    )

    runtime_state["recommendation_package"]["cache"] = {

        "recommendation":
            decision["action"],

        "priority":
            decision["priority"],

        "reason":
            decision["reason"]

    }

    runtime_state.setdefault(
        "control_tower_summary",
        {}
    )

    runtime_state["control_tower_summary"]["cache"] = {

        "status":
            metrics.overall_status,

        "strategy":
            decision["strategy"],

        "cache_hit_ratio":
            metrics.cache_hit_ratio

    }

    runtime_state.setdefault(
        "audit_package",
        {}
    )

    runtime_state["audit_package"]["cache"] = {

        "decision":
            decision,

        "metrics":
            runtime_state["cache_metrics"],

        "statistics":
            runtime_state["cache_statistics"],

        "generated_at":
            datetime.now().isoformat()

    }

    runtime_state.setdefault(
        "runtime_footer",
        {}
    )

    runtime_state["runtime_footer"]["cache"] = {

        "tokens_saved":
            savings["tokens_saved"],

        "cost_saved_usd":
            savings["cost_saved_usd"],

        "latency_saved_ms":
            savings["latency_saved_ms"]

    }

    runtime_state.setdefault(
        "memory",
        {}
    )

    runtime_state["memory"]["cache"] = {

        "last_strategy":
            decision["strategy"],

        "last_hit_ratio":
            metrics.cache_hit_ratio,

        "last_execution":
            datetime.now().isoformat()

    }
