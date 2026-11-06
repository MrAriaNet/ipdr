"""Integrity helpers for LEA / chain-of-custody exports."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data: Dict[str, Any] | str | bytes) -> str:
    if isinstance(data, dict):
        raw = canonical_json(data).encode("utf-8")
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data
    return hashlib.sha256(raw).hexdigest()
