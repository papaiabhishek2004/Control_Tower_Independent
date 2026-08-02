"""Local-only secret lookup for independent AEGIS Control Tower."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
LOCAL_ENV_FILE = BASE_DIR / ".env.local"
LOCAL_JSON_FILE = BASE_DIR / "config" / "aegis_llm_secrets.local.json"
PLACEHOLDER_VALUES = {
    "paste_your_groq_key_here",
    "paste_your_real_groq_key_here",
    "your_real_groq_key_here",
    "your_groq_key_here",
}


def _clean(value: Any) -> str:
    text = str(value or "").strip().strip('"').strip("'")
    if text.lower() in PLACEHOLDER_VALUES:
        return ""
    return text


def local_config_value(key: str, default: str = "") -> str:
    value = _clean(os.getenv(key))
    if value:
        return value

    if LOCAL_JSON_FILE.exists():
        try:
            payload: Any = json.loads(LOCAL_JSON_FILE.read_text(encoding="utf-8"))
            value = _clean(payload.get(key) if isinstance(payload, dict) else "")
            if value:
                return value
        except Exception:
            pass

    if LOCAL_ENV_FILE.exists():
        try:
            for raw_line in LOCAL_ENV_FILE.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, raw_value = line.split("=", 1)
                if name.strip() == key:
                    value = _clean(raw_value)
                    return value or default
        except Exception:
            pass

    return default
