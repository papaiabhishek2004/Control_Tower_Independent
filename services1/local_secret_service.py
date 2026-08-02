"""Local-only secret lookup for independent AEGIS Control Tower."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[1]
LOCAL_ENV_FILE = BASE_DIR / ".env.local"
LOCAL_JSON_FILE = BASE_DIR / "config" / "aegis_llm_secrets.local.json"


def local_config_value(key: str, default: str = "") -> str:
    value = os.getenv(key)
    if value:
        return value.strip().strip('"').strip("'")

    if LOCAL_JSON_FILE.exists():
        try:
            payload: Any = json.loads(LOCAL_JSON_FILE.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and payload.get(key):
                return str(payload.get(key)).strip().strip('"').strip("'")
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
                    return raw_value.strip().strip('"').strip("'")
        except Exception:
            pass

    return default
