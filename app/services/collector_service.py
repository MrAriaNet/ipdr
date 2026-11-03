"""
Service for managing network traffic collectors
"""
from typing import Optional

from app.collectors.netflow_collector import NetFlowCollector, SimpleFlowCollector
from app.collectors.sflow_collector import SFlowCollector
from app.schemas import IPDRRecordCreate
from app.services.ipdr_service import IPDRService
from app.database import SessionLocal
from app.utils.logger import logger


class CollectorService:
    """Service for managing NetFlow/IPFIX, sFlow, and simple JSON collectors"""

    def __init__(self):
        self.netflow_collector: Optional[NetFlowCollector] = None
        self.sflow_collector: Optional[SFlowCollector] = None
        self.simple_collector: Optional[SimpleFlowCollector] = None

    def _make_callback(self):
        def process_flow(record: IPDRRecordCreate):
            try:
                db = SessionLocal()
                try:
                    IPDRService.create_record(db, record)
                    logger.debug(f"Flow record saved: {record.source_ip} -> {record.destination_ip}")
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"Error saving flow record: {e}", exc_info=True)

        return process_flow

    def start_netflow_collector(self, host: str = "0.0.0.0", port: int = 2055):
        if self.netflow_collector and self.netflow_collector.running:
            logger.warning("NetFlow collector is already running")
            return
        self.netflow_collector = NetFlowCollector(host=host, port=port, callback=self._make_callback())
        self.netflow_collector.start()
        logger.info(f"NetFlow/IPFIX collector started on {host}:{port}")

    def stop_netflow_collector(self):
        if self.netflow_collector:
            self.netflow_collector.stop()
            self.netflow_collector = None

    def start_sflow_collector(self, host: str = "0.0.0.0", port: int = 6343):
        if self.sflow_collector and self.sflow_collector.running:
            logger.warning("sFlow collector is already running")
            return
        self.sflow_collector = SFlowCollector(host=host, port=port, callback=self._make_callback())
        self.sflow_collector.start()
        logger.info(f"sFlow collector started on {host}:{port}")

    def stop_sflow_collector(self):
        if self.sflow_collector:
            self.sflow_collector.stop()
            self.sflow_collector = None

    def start_simple_collector(self, host: str = "0.0.0.0", port: int = 9999):
        if self.simple_collector and self.simple_collector.running:
            logger.warning("Simple collector is already running")
            return
        self.simple_collector = SimpleFlowCollector(host=host, port=port, callback=self._make_callback())
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


collector_service = CollectorService()
