"""
Standalone Cisco ASR CGNAT PBA / NAT HSL bridge.

Receives NetFlow v9 HSL from ASR (`ip nat log translations flow-export v9 …`),
parses port-block allocate/deallocate, and stores via the durable ingest queue
(same DB as the API). Can run:

  1) Inside the API process (start NetFlow collector via /api/collector/start)
  2) As a separate process (recommended at high HSL rate):

       python -m app.bridges.cgnat_hsl_bridge

Env:
  DATABASE_URL, IPDR_SPOOL_DIR, IPDR_TEMPLATE_STORE
  HSL_LISTEN_HOST (default 0.0.0.0)
  HSL_LISTEN_PORT (default 2055)
"""
from __future__ import annotations

import os
import signal
import sys
import time

from dotenv import load_dotenv

load_dotenv()


def main():
    from app.collectors.netflow_collector import NetFlowCollector
    from app.services.durable_ingest import durable_ingest
    from app.utils.logger import logger

    host = os.getenv("HSL_LISTEN_HOST", "0.0.0.0")
    port = int(os.getenv("HSL_LISTEN_PORT", "2055"))

    durable_ingest.start()

    def on_flow(record):
        durable_ingest.enqueue_flow(record)

    def on_cgnat(payload: dict):
        durable_ingest.enqueue_cgnat(payload)

    collector = NetFlowCollector(
        host=host,
        port=port,
        callback=on_flow,
        cgnat_callback=on_cgnat,
    )
    collector.start()
    logger.info(
        f"CGNAT HSL bridge listening on {host}:{port} — "
        "point ASR: ip nat log translations flow-export v9 udp destination <this-host> {port}"
    )

    stop = {"flag": False}

    def _stop(*_a):
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    try:
        while not stop["flag"]:
            time.sleep(5)
            snap = durable_ingest.snapshot()
            st = collector.get_stats()
            logger.info(
                "HSL bridge heartbeat: "
                f"packets={st['packets']} cgnat={st['cgnat_records']} "
                f"flows={st['flow_records']} queue={snap['queue_length']} "
                f"saved={snap['stats'].get('cgnat_saved')} "
                f"spool_cgnat={snap['spool_cgnat_files']} "
                f"templates={st['templates_cached']}"
            )
    finally:
        collector.stop()
        durable_ingest.replay_spool()
        durable_ingest.stop()
        logger.info("CGNAT HSL bridge stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
