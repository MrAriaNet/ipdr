"""Retention purge with legal-hold protection."""
from __future__ import annotations

import os
from datetime import timedelta
from typing import Dict

from sqlalchemy.orm import Session

from app.models import CGNATPortBlock, IPDRRecord, SubscriberSession
from app.utils.logger import logger
from app.utils.timeutil import utcnow


class RetentionService:
    @staticmethod
    def retention_days(kind: str = "ipdr") -> int:
        if kind == "cgnat":
            return int(os.getenv("CGNAT_RETENTION_DAYS", os.getenv("IPDR_RETENTION_DAYS", "365")))
        if kind == "aaa":
            return int(os.getenv("AAA_RETENTION_DAYS", os.getenv("IPDR_RETENTION_DAYS", "365")))
        return int(os.getenv("IPDR_RETENTION_DAYS", "365"))

    @staticmethod
    def purge(db: Session, *, dry_run: bool = True) -> Dict[str, int]:
        """
        Delete records older than retention that are NOT on legal hold.
        dry_run=True (default) only counts candidates.
        """
        now = utcnow()
        ipdr_cut = now - timedelta(days=RetentionService.retention_days("ipdr"))
        cgnat_cut = now - timedelta(days=RetentionService.retention_days("cgnat"))
        aaa_cut = now - timedelta(days=RetentionService.retention_days("aaa"))

        ipdr_q = db.query(IPDRRecord).filter(
            IPDRRecord.session_start_time < ipdr_cut,
            IPDRRecord.legal_hold.is_(False),
        )
        cgnat_q = db.query(CGNATPortBlock).filter(
            CGNATPortBlock.event_time < cgnat_cut,
            CGNATPortBlock.legal_hold.is_(False),
        )
        aaa_q = db.query(SubscriberSession).filter(
            SubscriberSession.valid_from < aaa_cut,
            # ended sessions only; keep open sessions
            SubscriberSession.valid_to.isnot(None),
            SubscriberSession.valid_to < aaa_cut,
        )

        counts = {
            "ipdr_candidates": ipdr_q.count(),
            "cgnat_candidates": cgnat_q.count(),
            "aaa_candidates": aaa_q.count(),
            "ipdr_deleted": 0,
            "cgnat_deleted": 0,
            "aaa_deleted": 0,
            "dry_run": int(dry_run),
            "ipdr_cutoff": ipdr_cut.isoformat(),
            "cgnat_cutoff": cgnat_cut.isoformat(),
            "aaa_cutoff": aaa_cut.isoformat(),
        }

        if dry_run:
            return counts

        counts["ipdr_deleted"] = ipdr_q.delete(synchronize_session=False)
        counts["cgnat_deleted"] = cgnat_q.delete(synchronize_session=False)
        counts["aaa_deleted"] = aaa_q.delete(synchronize_session=False)
        db.commit()
        logger.warning(f"Retention purge executed: {counts}")
        return counts
