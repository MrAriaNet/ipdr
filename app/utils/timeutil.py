"""UTC-aware datetime helpers for IPDR / LEA time-bounded queries."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Normalize to timezone-aware UTC. Naive values are treated as UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return ensure_utc(datetime.fromisoformat(s))
