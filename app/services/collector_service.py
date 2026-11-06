"""
Service for managing network traffic collectors with durable ingest.
"""
from typing import Any, Dict, Optional

from app.collectors.netflow_collector import NetFlowCollector, SimpleFlowCollector
from app.collectors.sflow_collector import SFlowCollector
from app.schemas import IPDRRecordCreate
from app.services.durable_ingest import durable_ingest
from app.utils.logger import logger


class CollectorService:
    """Service for managing NetFlow/IPFIX, sFlow, simple JSON, and CGNAT PBA ingest"""

    def __init__(self):
        self.netflow_collector: Optional[NetFlowCollector] = None
        self.sflow_collector: Optional[SFlowCollector] = None
        self.simple_collector: Optional[SimpleFlowCollector] = None
        durable_ingest.start()

    def _make_flow_callback(self):
        def process_flow(record: IPDRRecordCreate):
            try:
                durable_ingest.enqueue_flow(record)
            except Exception as e:
                logger.error(f"Error enqueueing flow record: {e}", exc_info=True)

        return process_flow

    def _make_cgnat_callback(self):
        def process_cgnat(payload: dict):
            try:
                durable_ingest.enqueue_cgnat(payload)
            except Exception as e:
                logger.error(f"Error enqueueing CGNAT PBA record: {e}", exc_info=True)

        return process_cgnat

    def start_netflow_collector(self, host: str = "0.0.0.0", port: int = 2055):
        if self.netflow_collector and self.netflow_collector.running:
            logger.warning("NetFlow collector is already running")
            return
        durable_ingest.start()
        self.netflow_collector = NetFlowCollector(
            host=host,
            port=port,
            callback=self._make_flow_callback(),
            cgnat_callback=self._make_cgnat_callback(),
        )
        self.netflow_collector.start()
        logger.info(f"NetFlow/IPFIX (+CGNAT PBA HSL) collector started on {host}:{port}")

    def stop_netflow_collector(self):
        if self.netflow_collector:
            self.netflow_collector.stop()
            self.netflow_collector = None

    def start_sflow_collector(
        self,
        host: str = "0.0.0.0",
        port: int = 6343,
        extrapolate: bool = True,
    ):
        if self.sflow_collector and self.sflow_collector.running:
            logger.warning("sFlow collector is already running")
            return
        durable_ingest.start()
        self.sflow_collector = SFlowCollector(
            host=host,
            port=port,
            callback=self._make_flow_callback(),
            extrapolate=extrapolate,
        )
        self.sflow_collector.start()
        logger.info(f"sFlow collector started on {host}:{port} extrapolate={extrapolate}")

    def stop_sflow_collector(self):
        if self.sflow_collector:
            self.sflow_collector.stop()
            self.sflow_collector = None

    def start_simple_collector(self, host: str = "0.0.0.0", port: int = 9999):
        if self.simple_collector and self.simple_collector.running:
            logger.warning("Simple collector is already running")
            return
        durable_ingest.start()
        self.simple_collector = SimpleFlowCollector(
            host=host, port=port, callback=self._make_flow_callback()
        )
        self.simple_collector.start()
        logger.info(f"Simple flow collector started on {host}:{port}")

    def stop_simple_collector(self):
        if self.simple_collector:
            self.simple_collector.stop()
            self.simple_collector = None

    def stop_all(self):
        self.stop_netflow_collector()
        self.stop_sflow_collector()
        self.stop_simple_collector()

    def ingest_status(self) -> Dict[str, Any]:
        nf = self.netflow_collector
        return {
            "durable_ingest": durable_ingest.snapshot(),
            "netflow": nf.get_stats() if nf else {"running": False},
            "sflow": {
                "running": bool(self.sflow_collector and self.sflow_collector.running),
            },
            "simple": {
                "running": bool(self.simple_collector and self.simple_collector.running),
            },
        }


collector_service = CollectorService()
