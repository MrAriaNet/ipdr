"""
API routes for managing network traffic collectors
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.collector_service import collector_service
from app.utils.logger import logger

router = APIRouter(prefix="/api/collector", tags=["Collector"])


class CollectorConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(default=2055, description="2055 NetFlow/IPFIX, 6343 sFlow, 9999 simple JSON")
    collector_type: str = Field(
        default="netflow",
        description="netflow (v1/v5/v7/v8/v9/IPFIX), sflow, or simple",
    )


@router.post("/start")
async def start_collector(config: CollectorConfig):
    """
    Start a network traffic collector

    - **netflow**: NetFlow v1/v5/v7/v8/v9 and IPFIX (default UDP 2055)
    - **sflow**: sFlow v2/v4/v5 (default UDP 6343)
    - **simple**: JSON flow collector (default UDP 9999)
    """
    try:
        ctype = config.collector_type.lower().strip()
        if ctype == "netflow":
            port = config.port or 2055
            collector_service.start_netflow_collector(host=config.host, port=port)
            return {
                "status": "started",
                "type": "netflow",
                "host": config.host,
                "port": port,
                "supports": ["v1", "v5", "v7", "v8", "v9", "ipfix"],
                "message": "NetFlow/IPFIX collector started successfully",
            }
        if ctype == "sflow":
            # Default sFlow port is 6343 when client leaves the NetFlow default
            port = 6343 if config.port == 2055 else config.port
            collector_service.start_sflow_collector(host=config.host, port=port)
            return {
                "status": "started",
                "type": "sflow",
                "host": config.host,
                "port": port,
                "supports": ["v2", "v4", "v5"],
                "message": "sFlow collector started successfully",
            }
        if ctype == "simple":
            port = 9999 if config.port == 2055 else config.port
            collector_service.start_simple_collector(host=config.host, port=port)
            return {
                "status": "started",
                "type": "simple",
                "host": config.host,
                "port": port,
                "message": "Simple flow collector started successfully",
            }
        raise HTTPException(status_code=400, detail=f"Unknown collector type: {config.collector_type}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting collector: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error starting collector: {e}")


@router.post("/stop")
async def stop_collector(
    collector_type: str = Query("all", description="netflow, sflow, simple, or all"),
):
    try:
        ctype = collector_type.lower().strip()
        if ctype == "netflow":
            collector_service.stop_netflow_collector()
            return {"status": "stopped", "type": "netflow", "message": "NetFlow collector stopped"}
        if ctype == "sflow":
            collector_service.stop_sflow_collector()
            return {"status": "stopped", "type": "sflow", "message": "sFlow collector stopped"}
        if ctype == "simple":
            collector_service.stop_simple_collector()
            return {"status": "stopped", "type": "simple", "message": "Simple collector stopped"}
        if ctype == "all":
            collector_service.stop_all()
            return {"status": "stopped", "type": "all", "message": "All collectors stopped"}
        raise HTTPException(status_code=400, detail=f"Unknown collector type: {collector_type}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping collector: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error stopping collector: {e}")


@router.get("/status")
async def get_collector_status():
    nf = collector_service.netflow_collector
    sf = collector_service.sflow_collector
    sm = collector_service.simple_collector
    return {
        "netflow": {
            "running": bool(nf and nf.running),
            "host": nf.host if nf else None,
            "port": nf.port if nf else None,
            "supports": ["v1", "v5", "v7", "v8", "v9", "ipfix"],
            "templates_cached": len(nf.templates) if nf else 0,
        },
        "sflow": {
            "running": bool(sf and sf.running),
            "host": sf.host if sf else None,
            "port": sf.port if sf else None,
            "supports": ["v2", "v4", "v5"],
        },
        "simple": {
            "running": bool(sm and sm.running),
            "host": sm.host if sm else None,
            "port": sm.port if sm else None,
        },
    }
