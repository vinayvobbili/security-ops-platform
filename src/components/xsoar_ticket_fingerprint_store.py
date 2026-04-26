"""
XSOAR Ticket Fingerprint Store

SQLite sidecar store for structured XSOAR ticket fingerprints.
Enables multi-dimensional similarity scoring by storing detection rule names,
security categories, hostnames, usernames, and extracted IOCs per ticket.

Follows the same pattern as TipperFingerprintStore.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
FINGERPRINT_DB_PATH = ROOT_DIRECTORY / "data" / "transient" / "xsoar_ticket_fingerprints.db"


class XsoarTicketFingerprintStore:
    """SQLite store for structured XSOAR ticket fingerprints."""

    def __init__(self, db_path: str = None):
        self.db_path = str(db_path or FINGERPRINT_DB_PATH)
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_table()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _ensure_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                ticket_id         TEXT PRIMARY KEY,
                detection_rule    TEXT,
                ticket_type       TEXT,
                security_category TEXT,
                hostname          TEXT,
                username          TEXT,
                iocs_ip           TEXT DEFAULT '[]',
                iocs_domain       TEXT DEFAULT '[]',
                iocs_hash         TEXT DEFAULT '[]',
                created_date      TEXT,
                indexed_at        TEXT
            )
        """)
        self.conn.commit()

    def upsert(self, ticket_id: str, ticket: dict, entities=None):
        """Insert or replace a ticket fingerprint.

        Args:
            ticket_id: XSOAR ticket/incident ID
            ticket: Raw ticket dict (from timeline DB or XSOAR API)
            entities: Optional ExtractedEntities from entity_extractor
        """
        from src.components.xsoar_ticket_indexer import strip_ticket_id

        name = ticket.get("name", "") or ""
        detection_rule = strip_ticket_id(name).strip()

        # Extract IOCs from entities if provided
        ips, domains, hashes = [], [], []
        if entities:
            ips = [ip.lower() for ip in (entities.ips or [])]
            domains = [d.lower() for d in (entities.domains or [])]
            all_hashes = []
            if hasattr(entities, 'hashes') and entities.hashes:
                for hash_list in entities.hashes.values():
                    all_hashes.extend(h.lower() for h in hash_list)
            hashes = list(set(all_hashes))

        self.conn.execute("""
            INSERT OR REPLACE INTO fingerprints
                (ticket_id, detection_rule, ticket_type, security_category,
                 hostname, username, iocs_ip, iocs_domain, iocs_hash,
                 created_date, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(ticket_id),
            detection_rule,
            ticket.get("type", "") or "",
            ticket.get("security_category", "") or "",
            (ticket.get("hostname", "") or "").lower(),
            (ticket.get("username", "") or "").lower(),
            json.dumps(ips),
            json.dumps(domains),
            json.dumps(hashes),
            (ticket.get("created_date", "") or "")[:19],
            datetime.now(timezone.utc).isoformat(),
        ))
        self.conn.commit()

    def get(self, ticket_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM fingerprints WHERE ticket_id = ?", (str(ticket_id),)
        ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def get_batch(self, ticket_ids: List[str]) -> Dict[str, dict]:
        if not ticket_ids:
            return {}
        placeholders = ','.join('?' * len(ticket_ids))
        rows = self.conn.execute(
            f"SELECT * FROM fingerprints WHERE ticket_id IN ({placeholders})",
            [str(tid) for tid in ticket_ids]
        ).fetchall()
        return {row['ticket_id']: self._row_to_dict(row) for row in rows}

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()
        return row[0]

    def has(self, ticket_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM fingerprints WHERE ticket_id = ?", (str(ticket_id),)
        ).fetchone()
        return row is not None

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        return {
            'ticket_id': row['ticket_id'],
            'detection_rule': row['detection_rule'],
            'ticket_type': row['ticket_type'],
            'security_category': row['security_category'],
            'hostname': row['hostname'],
            'username': row['username'],
            'iocs_ip': json.loads(row['iocs_ip']),
            'iocs_domain': json.loads(row['iocs_domain']),
            'iocs_hash': json.loads(row['iocs_hash']),
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
