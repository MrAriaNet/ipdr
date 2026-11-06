"""
Durable ingest queue for IPDR flows and CGNAT PBA/HSL events.

Prevents silent loss when PostgreSQL is briefly unavailable:
  - In-memory queue + background worker
  - Spill to JSONL spool on disk when queue is full or DB fails
  - Automatic replay of spool files
  - Dedup for CGNAT by content_hash (short window)
  - Live counters for ops / LEA confidence
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Deque, Dict, Optional, Tuple

from app.database import SessionLocal
from app.models import CGNATPortBlock
from app.schemas import IPDRRecordCreate
from app.services.cgnat_service import CGNATService
from app.services.ipdr_service import IPDRService
from app.utils.hashutil import sha256_hex
from app.utils.logger import logger
from app.utils.timeutil import utcnow


def _spool_dir() -> Path:
    root = Path(os.getenv("IPDR_SPOOL_DIR", "data/ingest_spool"))
    root.mkdir(parents=True, exist_ok=True)
    (root / "cgnat").mkdir(exist_ok=True)
    (root / "flow").mkdir(exist_ok=True)
    return root


class DurableIngestQueue:
    def __init__(self):
        self._q: Deque[Tuple[str, Any]] = deque()
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._worker: Optional[threading.Thread] = None
        self._running = False
        self._max_memory = int(os.getenv("IPDR_INGEST_QUEUE_MAX", "50000"))
        self._dedup_ttl = int(os.getenv("IPDR_CGNAT_DEDUP_TTL_SEC", "3600"))
        self._recent_hashes: Dict[str, float] = {}
        self.stats: Dict[str, int] = {
            "cgnat_enqueued": 0,
            "cgnat_saved": 0,
            "cgnat_dedup_skipped": 0,
            "cgnat_failed": 0,
            "cgnat_spilled": 0,
            "cgnat_replayed": 0,
            "flow_enqueued": 0,
            "flow_saved": 0,
            "flow_failed": 0,
            "flow_spilled": 0,
            "flow_replayed": 0,
            "db_errors": 0,
            "worker_loops": 0,
        }

    def start(self):
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(target=self._run, daemon=True, name="durable-ingest")
        self._worker.start()
        # Replay any leftover spool on startup
        threading.Thread(target=self.replay_spool, daemon=True, name="spool-replay").start()
        logger.info(
            f"Durable ingest queue started (max={self._max_memory}, "
            f"spool={_spool_dir()})"
        )

    def stop(self, timeout: float = 10.0):
        self._running = False
        with self._cv:
            self._cv.notify_all()
        if self._worker:
            self._worker.join(timeout=timeout)

    def enqueue_cgnat(self, payload: dict) -> bool:
        return self._enqueue("cgnat", payload)

    def enqueue_flow(self, record: IPDRRecordCreate) -> bool:
        return self._enqueue("flow", record)

    def _enqueue(self, kind: str, item: Any) -> bool:
        with self._cv:
            if len(self._q) >= self._max_memory:
                # Spill immediately instead of dropping
                self._spill(kind, item)
                self.stats[f"{kind}_spilled"] += 1
                return True
            self._q.append((kind, item))
            self.stats[f"{kind}_enqueued"] += 1
            self._cv.notify()
            return True

    def _spill(self, kind: str, item: Any):
        folder = _spool_dir() / kind
        name = f"{utcnow().strftime('%Y%m%dT%H%M%S')}_{uuid.uuid4().hex[:12]}.jsonl"
        path = folder / name
        try:
            if kind == "flow" and hasattr(item, "model_dump"):
                body = item.model_dump()
            elif isinstance(item, dict):
                body = item
            else:
                body = {"raw": str(item)}
            # datetime → iso
            def _default(o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return str(o)

            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(body, default=_default) + "\n")
            logger.warning(f"Ingest spilled to {path}")
        except Exception as e:
            logger.error(f"Spool write failed ({kind}): {e}", exc_info=True)
            self.stats[f"{kind}_failed"] += 1

    def _run(self):
        while self._running:
            with self._cv:
                while not self._q and self._running:
                    self._cv.wait(timeout=1.0)
                if not self._q:
                    continue
                kind, item = self._q.popleft()
            self.stats["worker_loops"] += 1
            ok = self._persist(kind, item)
            if not ok:
                # Put back to spool for later replay
                self._spill(kind, item)
                self.stats[f"{kind}_spilled"] += 1
                time.sleep(0.5)

    def _persist(self, kind: str, item: Any) -> bool:
        db = None
        try:
            db = SessionLocal()
            if kind == "cgnat":
                return self._persist_cgnat(db, item)
            if kind == "flow":
                if isinstance(item, dict):
                    item = IPDRRecordCreate(**item)
                IPDRService.create_record(db, item)
                self.stats["flow_saved"] += 1
                return True
            return False
        except Exception as e:
            self.stats["db_errors"] += 1
            self.stats[f"{kind}_failed"] += 1
            logger.error(f"Durable ingest persist failed ({kind}): {e}", exc_info=True)
            return False
        finally:
            if db is not None:
                try:
                    db.close()
                except Exception:
                    pass

    def _persist_cgnat(self, db, payload: dict) -> bool:
        # Soft dedup: identical event hash within TTL
        h = self._payload_hash(payload)
        now = time.time()
        self._purge_dedup(now)
        if h in self._recent_hashes:
            self.stats["cgnat_dedup_skipped"] += 1
            return True
        # DB-level dedup
        existing = (
            db.query(CGNATPortBlock.id)
            .filter(CGNATPortBlock.content_hash == h)
            .first()
        )
        if existing:
            self._recent_hashes[h] = now
            self.stats["cgnat_dedup_skipped"] += 1
            return True

        # Inject hash hint via additional_info so create still computes same fields
        row = CGNATService.create_from_dict(db, payload)
        if row and row.content_hash:
            self._recent_hashes[row.content_hash] = now
        elif h:
            self._recent_hashes[h] = now
        self.stats["cgnat_saved"] += 1
        return True

    def _payload_hash(self, payload: dict) -> str:
        et = payload.get("event_time")
        if hasattr(et, "isoformat"):
            et = et.isoformat()
        return sha256_hex(
            {
                "event_time": str(et),
                "event_type": str(payload.get("event_type")),
                "inside_ip": payload.get("inside_ip"),
                "outside_ip": payload.get("outside_ip"),
                "port_start": payload.get("port_start"),
                "port_end": payload.get("port_end"),
                "port_step": payload.get("port_step") or 1,
                "port_block_size": payload.get("port_block_size"),
            }
        )

    def _purge_dedup(self, now: float):
        cut = now - self._dedup_ttl
        dead = [k for k, t in self._recent_hashes.items() if t < cut]
        for k in dead:
            del self._recent_hashes[k]

    def replay_spool(self, max_files: int = 500) -> Dict[str, int]:
        """Replay spilled JSONL files into the DB."""
        result = {"cgnat": 0, "flow": 0, "errors": 0}
        root = _spool_dir()
        for kind in ("cgnat", "flow"):
            folder = root / kind
            files = sorted(folder.glob("*.jsonl"))[:max_files]
            for path in files:
                try:
                    with open(path, encoding="utf-8") as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                    ok_all = True
                    for ln in lines:
                        data = json.loads(ln)
                        if not self._persist(kind, data):
                            ok_all = False
                            result["errors"] += 1
                            break
                        result[kind] += 1
                        self.stats[f"{kind}_replayed"] += 1
                    if ok_all:
                        path.unlink(missing_ok=True)
                except Exception as e:
                    result["errors"] += 1
                    logger.error(f"Spool replay error {path}: {e}", exc_info=True)
        if result["cgnat"] or result["flow"]:
            logger.info(f"Spool replay finished: {result}")
        return result

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            qlen = len(self._q)
        spool = _spool_dir()
        return {
            "queue_length": qlen,
            "spool_dir": str(spool.resolve()),
            "spool_cgnat_files": len(list((spool / "cgnat").glob("*.jsonl"))),
            "spool_flow_files": len(list((spool / "flow").glob("*.jsonl"))),
            "dedup_cache_size": len(self._recent_hashes),
            "stats": dict(self.stats),
            "running": self._running,
        }


# Process-wide singleton
durable_ingest = DurableIngestQueue()
