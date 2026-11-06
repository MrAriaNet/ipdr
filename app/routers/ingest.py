"""
Ingest health, spool replay, and bridge status for CGNAT HSL / NetFlow.
"""
from fastapi import APIRouter, Depends

from app.auth import AuthContext, require_role
from app.services.collector_service import collector_service
from app.services.durable_ingest import durable_ingest

router = APIRouter(prefix="/api/ingest", tags=["Ingest"])


@router.get("/status")
async def ingest_status(auth: AuthContext = Depends(require_role("ops"))):
    """Queue depth, spool files, NetFlow/HSL counters, template cache."""
    return collector_service.ingest_status()


@router.post("/replay-spool")
async def replay_spool(auth: AuthContext = Depends(require_role("admin"))):
    """Replay spilled JSONL files after DB outage."""
    return durable_ingest.replay_spool()


@router.get("/health")
async def ingest_health():
    """Unauthenticated lightweight check for monitoring."""
    snap = durable_ingest.snapshot()
    nf = collector_service.netflow_collector
    return {
        "ok": True,
        "queue_length": snap["queue_length"],
        "spool_cgnat_files": snap["spool_cgnat_files"],
        "spool_flow_files": snap["spool_flow_files"],
        "netflow_running": bool(nf and nf.running),
        "cgnat_saved": snap["stats"].get("cgnat_saved", 0),
        "cgnat_failed": snap["stats"].get("cgnat_failed", 0),
    }
