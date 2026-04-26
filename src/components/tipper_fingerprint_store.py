"""
Tipper Fingerprint Store

SQLite sidecar store that persists structured entity fingerprints alongside
ChromaDB embeddings. Enables multi-dimensional similarity scoring by storing
IOC sets, MITRE techniques, actor names, and malware families per tipper.

ChromaDB metadata has a 40KB size limit, so structured data lives here instead.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ROOT_DIRECTORY = Path(__file__).parent.parent.parent
FINGERPRINT_DB_PATH = ROOT_DIRECTORY / "data" / "transient" / "tipper_fingerprints.db"


class TipperFingerprintStore:
    """SQLite store for structured tipper fingerprints."""

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
        """Create the fingerprints table if it doesn't exist."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                tipper_id   TEXT PRIMARY KEY,
                title       TEXT,
                created_date TEXT,
                iocs_ip     TEXT DEFAULT '[]',
                iocs_domain TEXT DEFAULT '[]',
                iocs_hash   TEXT DEFAULT '[]',
                iocs_url    TEXT DEFAULT '[]',
                iocs_cve    TEXT DEFAULT '[]',
                mitre_techniques TEXT DEFAULT '[]',
                threat_actors    TEXT DEFAULT '[]',
                malware_families TEXT DEFAULT '[]',
                indexed_at  TEXT
            )
        """)
        self.conn.commit()

    def upsert(self, tipper_id: str, entities, title: str = "", created_date: str = ""):
        """Insert or replace a tipper fingerprint from ExtractedEntities.

        Args:
            tipper_id: Tipper work item ID
            entities: ExtractedEntities object from entity_extractor
            title: Tipper title
            created_date: Tipper creation date
        """
        # Merge all hash types into a single list
        all_hashes = []
        if hasattr(entities, 'hashes') and entities.hashes:
            for hash_list in entities.hashes.values():
                all_hashes.extend(h.lower() for h in hash_list)

        # Normalize actors: use common_name from enriched data when available
        actors = []
        if hasattr(entities, 'threat_actors_enriched') and entities.threat_actors_enriched:
            seen = set()
            for ta in entities.threat_actors_enriched:
                name = (ta.common_name or ta.name).lower()
                if name not in seen:
                    actors.append(ta.common_name or ta.name)
                    seen.add(name)
        elif hasattr(entities, 'threat_actors'):
            actors = list(entities.threat_actors)

        self.conn.execute("""
            INSERT OR REPLACE INTO fingerprints
                (tipper_id, title, created_date,
                 iocs_ip, iocs_domain, iocs_hash, iocs_url, iocs_cve,
                 mitre_techniques, threat_actors, malware_families, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(tipper_id),
            title,
            created_date,
            json.dumps([ip.lower() for ip in (entities.ips or [])]),
            json.dumps([d.lower() for d in (entities.domains or [])]),
            json.dumps(list(set(all_hashes))),
            json.dumps([u.lower() for u in (entities.urls or [])]),
            json.dumps([c.upper() for c in (entities.cves or [])]),
            json.dumps([t.upper() for t in (entities.mitre_techniques or [])]),
            json.dumps(actors),
            json.dumps(list(entities.malware_families or [])),
            datetime.now(timezone.utc).isoformat(),
        ))
        self.conn.commit()

    def get(self, tipper_id: str) -> Optional[dict]:
        """Get fingerprint for a single tipper."""
        row = self.conn.execute(
            "SELECT * FROM fingerprints WHERE tipper_id = ?", (str(tipper_id),)
        ).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def get_batch(self, tipper_ids: List[str]) -> Dict[str, dict]:
        """Get fingerprints for multiple tippers in one query."""
        if not tipper_ids:
            return {}
        placeholders = ','.join('?' * len(tipper_ids))
        rows = self.conn.execute(
            f"SELECT * FROM fingerprints WHERE tipper_id IN ({placeholders})",
            [str(tid) for tid in tipper_ids]
        ).fetchall()
        return {row['tipper_id']: self._row_to_dict(row) for row in rows}

    def count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()
        return row[0]

    def has(self, tipper_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM fingerprints WHERE tipper_id = ?", (str(tipper_id),)
        ).fetchone()
        return row is not None

    def _row_to_dict(self, row: sqlite3.Row) -> dict:
        """Convert a database row to a fingerprint dict with parsed JSON fields."""
        return {
            'tipper_id': row['tipper_id'],
            'title': row['title'],
            'created_date': row['created_date'],
            'iocs_ip': json.loads(row['iocs_ip']),
            'iocs_domain': json.loads(row['iocs_domain']),
            'iocs_hash': json.loads(row['iocs_hash']),
            'iocs_url': json.loads(row['iocs_url']),
            'iocs_cve': json.loads(row['iocs_cve']),
            'mitre_techniques': json.loads(row['mitre_techniques']),
            'threat_actors': json.loads(row['threat_actors']),
            'malware_families': json.loads(row['malware_families']),
        }

    def get_global_entity_sets(self, exclude_tipper_id: str = None) -> dict:
        """Return sets of all entities seen across ALL tippers (for global first-time detection).

        Args:
            exclude_tipper_id: Tipper ID to exclude (the one currently being analyzed)

        Returns:
            dict with keys 'ttps', 'iocs', 'actors', 'malware' — each a set of
            normalized strings (TTPs/CVEs uppercase, everything else lowercase).
        """
        if exclude_tipper_id:
            rows = self.conn.execute(
                "SELECT mitre_techniques, iocs_ip, iocs_domain, iocs_hash, iocs_cve, "
                "threat_actors, malware_families FROM fingerprints WHERE tipper_id != ?",
                (str(exclude_tipper_id),)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT mitre_techniques, iocs_ip, iocs_domain, iocs_hash, iocs_cve, "
                "threat_actors, malware_families FROM fingerprints"
            ).fetchall()

        all_ttps: set = set()
        all_iocs: set = set()
        all_actors: set = set()
        all_malware: set = set()

        for row in rows:
            all_ttps.update(json.loads(row[0]))   # mitre_techniques (uppercase)
            all_iocs.update(json.loads(row[1]))   # iocs_ip (lowercase)
            all_iocs.update(json.loads(row[2]))   # iocs_domain
            all_iocs.update(json.loads(row[3]))   # iocs_hash
            all_iocs.update(json.loads(row[4]))   # iocs_cve (uppercase CVEs)
            all_actors.update(a.lower() for a in json.loads(row[5]))   # threat_actors
            all_malware.update(m.lower() for m in json.loads(row[6]))  # malware_families

        return {
            'ttps': all_ttps,
            'iocs': all_iocs,
            'actors': all_actors,
            'malware': all_malware,
        }

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None