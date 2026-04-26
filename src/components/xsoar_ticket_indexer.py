"""
XSOAR Ticket Similarity Indexer

Indexes closed XSOAR tickets into ChromaDB for semantic similarity search.
Used by the XSOAR triage pipeline to find "tickets like this one" and predict
impact (resolution time, severity distribution, closure outcome).

Follows the same pattern as TipperIndexer. Uses shared embedding backend factory.

Data source: reads from the xsoar_timeline_db SQLite database (already populated
by backfill_xsoar_timeline.py) instead of hitting the XSOAR API directly.
Embeds ticket type + security category for semantic clustering.

Usage:
    # Sync new closed tickets (adds only missing ones)
    python -m src.components.xsoar_ticket_indexer

    # Full rebuild (deletes and recreates collection)
    python -m src.components.xsoar_ticket_indexer rebuild

    # Search for similar tickets
    python -m src.components.xsoar_ticket_indexer search "phishing email with malicious attachment"

    # Show index stats
    python -m src.components.xsoar_ticket_indexer stats
"""

import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import chromadb

from src.components.embedding import get_embedding_function

logger = logging.getLogger(__name__)

# Paths
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
CHROMA_PATH = ROOT_DIRECTORY / "data" / "transient" / "chroma_xsoar_ticket_index"

# Collection name
COLLECTION_NAME = "xsoar_tickets"

SEVERITY_MAP = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Regex to strip leading numeric ID and optional separator from ticket names.
# Handles: "1124176 - UnusualNslookup", "138242 _AE_ Entra ID ...", "1124176 Something"
_TICKET_ID_PREFIX_RE = re.compile(r"^\d+\s*(?:[-–—]\s*|_AE_\s*)?")


def strip_ticket_id(name: str) -> str:
    """Remove the leading numeric ID prefix (and optional _AE_ tag) from a ticket name.

    '1124176 - UnusualNslookup'                    → 'UnusualNslookup'
    '138242 _AE_ Entra ID High Risk User Login'    → 'Entra ID High Risk User Login'
    '138242 Entra ID High Risk User Login'          → 'Entra ID High Risk User Login'
    'Lost or Stolen Computer'                       → 'Lost or Stolen Computer' (no-op)
    """
    return _TICKET_ID_PREFIX_RE.sub("", name).strip()


class XsoarTicketIndexer:
    """Handles indexing and similarity search for XSOAR tickets using ChromaDB."""

    def __init__(self):
        self.chroma_path = str(CHROMA_PATH)
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = get_embedding_function()
        self._fingerprint_store = None

    @property
    def fingerprint_store(self):
        if self._fingerprint_store is None:
            from src.components.xsoar_ticket_fingerprint_store import XsoarTicketFingerprintStore
            self._fingerprint_store = XsoarTicketFingerprintStore()
        return self._fingerprint_store

    @property
    def client(self) -> chromadb.PersistentClient:
        """Lazy-load ChromaDB client."""
        if self._client is None:
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        """Get or create the XSOAR tickets collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={
                    "hnsw:space": "cosine",
                    "description": "XSOAR ticket embeddings for similarity search",
                }
            )
        return self._collection

    # -------------------------------------------------------------------------
    # Fetch closed tickets from the timeline SQLite DB
    # -------------------------------------------------------------------------
    def fetch_historical_tickets(self, days_back: int = 1200) -> List[dict]:
        """Fetch closed tickets from the xsoar_timeline_db SQLite database.

        Args:
            days_back: How far back to fetch (default 1 year)

        Returns:
            List of ticket row dicts from the timeline DB
        """
        from services.xsoar_timeline_db import get_connection

        cutoff = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S")

        with get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM xsoar_tickets"
                " WHERE created_date >= ?"
                " AND closed_date IS NOT NULL AND closed_date != ''"
                " AND owner IS NOT NULL AND TRIM(owner) != ''",
                (cutoff,),
            )
            tickets = [dict(row) for row in cursor.fetchall()]

        logger.info(f"Fetched {len(tickets)} owned closed tickets from timeline DB (last {days_back} days)")
        return tickets

    # -------------------------------------------------------------------------
    # Extract text for embedding
    # -------------------------------------------------------------------------
    @staticmethod
    def extract_ticket_text(ticket: dict) -> str:
        """Extract text from a timeline DB row for embedding.

        Uses: name (sans ID prefix), details, user_notes, close_notes,
        and type.  Truncates long fields so the combined text stays
        within the all-minilm token window (~256 tokens).
        """
        name = strip_ticket_id(ticket.get("name", "") or "")
        ticket_type = ticket.get("type", "") or ""
        details = (ticket.get("details", "") or "")[:300]
        user_notes = (ticket.get("user_notes", "") or "")[:200]
        close_notes = (ticket.get("close_notes", "") or "")[:200]

        parts = [p for p in [name, details, user_notes, close_notes, ticket_type] if p.strip()]
        return " ".join(parts)

    def prepare_ticket_metadata(self, ticket: dict) -> dict:
        """Build flat metadata dict from a timeline DB row."""
        name = ticket.get("name", "") or ""
        return {
            "id": str(ticket.get("id", "")),
            "name": name[:200],
            "severity": ticket.get("severity", 0),
            "security_category": ticket.get("security_category", "") or "",
            "detection_source": ticket.get("detection_source", "") or "",
            "created_date": ticket.get("created_date", "")[:19] if ticket.get("created_date") else "",
            "closed_date": ticket.get("closed_date", "")[:19] if ticket.get("closed_date") else "",
            "resolution_hours": ticket.get("resolution_time_hours") or 0.0,
            "status": ticket.get("status", 0),
            "close_reason": ticket.get("close_reason", "") or "",
            "impact": ticket.get("impact", "") or "",
            "owner": ticket.get("owner", "") or "",
        }

    # -------------------------------------------------------------------------
    # Sync tickets (upsert new ones only)
    # -------------------------------------------------------------------------
    def sync_tickets(self, days_back: int = 1200) -> int:
        """Sync closed tickets from timeline DB to ChromaDB (incremental upsert).

        Args:
            days_back: How far back to fetch

        Returns:
            Number of tickets added
        """
        logger.info("=" * 60)
        logger.info("XSOAR TICKET INDEX SYNC STARTING")
        logger.info("=" * 60)

        tickets = self.fetch_historical_tickets(days_back)
        if not tickets:
            logger.warning("No tickets to sync")
            return 0

        # Get existing IDs in ChromaDB
        existing_ids = set()
        try:
            result = self.collection.get(include=[])
            existing_ids = set(result["ids"]) if result["ids"] else set()
            logger.info(f"ChromaDB has {len(existing_ids)} existing tickets")
        except Exception as e:
            logger.warning(f"Could not get existing IDs: {e}")

        # Find new tickets
        new_tickets = [
            t for t in tickets
            if str(t.get("id", "")) and str(t.get("id", "")) not in existing_ids
        ]

        if not new_tickets:
            logger.info("No new tickets to add")
            logger.info("=" * 60)
            return 0

        logger.info(f"Found {len(new_tickets)} new tickets to add")
        return self._index_tickets(new_tickets)

    # -------------------------------------------------------------------------
    # Full rebuild (delete and recreate)
    # -------------------------------------------------------------------------
    def rebuild_index(self, days_back: int = 1200) -> bool:
        """Full rebuild: delete collection and recreate from scratch.

        Args:
            days_back: How far back to fetch

        Returns:
            True if successful
        """
        logger.info("=" * 60)
        logger.info("XSOAR TICKET INDEX FULL REBUILD STARTING")
        logger.info("=" * 60)

        # Delete existing collection
        try:
            self.client.delete_collection(COLLECTION_NAME)
            self._collection = None
            logger.info(f"Deleted existing collection: {COLLECTION_NAME}")
        except Exception as e:
            logger.warning(f"Could not delete collection (may not exist): {e}")

        tickets = self.fetch_historical_tickets(days_back)
        if not tickets:
            logger.error("No tickets to index")
            return False

        count = self._index_tickets(tickets, use_add=True)
        if count > 0:
            logger.info("=" * 60)
            logger.info("XSOAR TICKET INDEX FULL REBUILD COMPLETED")
            logger.info("=" * 60)
            return True
        return False

    def _index_tickets(self, tickets: List[dict], use_add: bool = False) -> int:
        """Process and index tickets into ChromaDB in batches.

        Embeds using the configured embedding backend and inserts in chunks
        to handle large datasets (87k+ tickets) without memory issues.

        Args:
            tickets: List of timeline DB row dicts
            use_add: If True, use collection.add() instead of upsert()

        Returns:
            Number of tickets indexed
        """
        import time

        EMBED_BATCH = 10   # texts per embedding call
        CHROMA_BATCH = 500  # rows per ChromaDB insert

        # Phase 1: Prepare all documents and metadata
        ids = []
        documents = []
        metadatas = []

        for i, ticket in enumerate(tickets):
            ticket_id = str(ticket.get("id", ""))
            if not ticket_id:
                continue

            try:
                text = self.extract_ticket_text(ticket)
                meta = self.prepare_ticket_metadata(ticket)
                ids.append(ticket_id)
                documents.append(text)
                metadatas.append(meta)

                # Fingerprint: extract IOCs from details for multi-dimensional scoring
                details = (ticket.get("details", "") or "").strip()
                entities = None
                if details:
                    try:
                        from src.utils.entity_extractor import extract_entities
                        entities = extract_entities(details, include_apt_database=False)
                    except Exception:
                        pass
                self.fingerprint_store.upsert(ticket_id, ticket, entities)
            except Exception as e:
                logger.error(f"Failed to process ticket {ticket_id}: {e}")

        if not ids:
            logger.warning("No tickets processed successfully")
            return 0

        total = len(ids)
        logger.info(f"Embedding + indexing {total} tickets (batch={EMBED_BATCH})...")

        # Phase 2: Embed in batches and insert into ChromaDB in chunks
        indexed = 0
        start_time = time.time()

        for chunk_start in range(0, total, CHROMA_BATCH):
            chunk_end = min(chunk_start + CHROMA_BATCH, total)
            chunk_ids = ids[chunk_start:chunk_end]
            chunk_docs = documents[chunk_start:chunk_end]
            chunk_metas = metadatas[chunk_start:chunk_end]
            chunk_embeddings = []

            # Embed this chunk in sub-batches
            for batch_start in range(0, len(chunk_docs), EMBED_BATCH):
                batch_texts = chunk_docs[batch_start:batch_start + EMBED_BATCH]
                try:
                    batch_embeddings = self._embedding_fn(batch_texts)
                    chunk_embeddings.extend(batch_embeddings)
                except Exception as e:
                    logger.error(f"Batch embedding failed at offset {chunk_start + batch_start}: {e}")
                    # Fall back to single-call for this batch
                    for text in batch_texts:
                        chunk_embeddings.append(self._embedding_fn([text])[0])

            # Insert chunk into ChromaDB
            try:
                if use_add:
                    self.collection.add(
                        ids=chunk_ids, documents=chunk_docs,
                        metadatas=chunk_metas, embeddings=chunk_embeddings,
                    )
                else:
                    self.collection.upsert(
                        ids=chunk_ids, documents=chunk_docs,
                        metadatas=chunk_metas, embeddings=chunk_embeddings,
                    )
                indexed += len(chunk_ids)
            except Exception as e:
                logger.error(f"ChromaDB insert failed at chunk {chunk_start}: {e}", exc_info=True)
                continue

            elapsed = time.time() - start_time
            rate = indexed / elapsed if elapsed > 0 else 0
            eta = (total - indexed) / rate / 60 if rate > 0 else 0
            logger.info(f"  Indexed {indexed}/{total} ({rate:.0f}/s, ETA {eta:.0f}m)")

        elapsed = time.time() - start_time
        logger.info(f"Successfully indexed {indexed} tickets in {elapsed / 60:.1f} min")
        return indexed

    # -------------------------------------------------------------------------
    # Search for similar tickets (pure vector similarity)
    # -------------------------------------------------------------------------
    def find_similar_tickets(
        self, query_text: str, k: int = 5, min_similarity: float = 0.80,
        where: Optional[dict] = None,
    ) -> List[dict]:
        """Find tickets similar to the given text using semantic vector similarity.

        All indexed tickets are closed, so no where-filter needed.

        Args:
            query_text: Text to search for (ticket name/details/category)
            k: Number of similar tickets to return
            min_similarity: Minimum cosine similarity (0-1) to include a result.
                Results below this threshold are suppressed as low-quality matches.
            where: Optional Chroma metadata filter (e.g. {"impact": "Benign True Positive"}).

        Returns:
            List of dicts with metadata, similarity_score, distance
        """
        count = self.collection.count()
        if count == 0:
            raise RuntimeError("No tickets in index. Run sync or rebuild first.")
        logger.info(f"Searching ticket index ({count} tickets)")

        # Strip ticket-ID prefix from query too (defensive — pipeline already strips)
        clean_query = strip_ticket_id(query_text)
        # Clean HTML artifacts
        clean_query = re.sub(r'<[^>]+>', ' ', clean_query)
        clean_query = re.sub(r'&nbsp;', ' ', clean_query)
        clean_query = re.sub(r'\s+', ' ', clean_query).strip()
        logger.debug(f"Clean query ({len(clean_query)} chars): {clean_query[:100]}...")

        # Generate query embedding
        try:
            query_embedding = self._embedding_fn([clean_query])[0]
        except Exception as e:
            raise RuntimeError(f"Failed to generate query embedding: {e}")

        # Vector similarity search
        try:
            query_kwargs = {
                "query_embeddings": [query_embedding],
                "n_results": k,
                "include": ["metadatas", "documents", "distances"],
            }
            if where:
                query_kwargs["where"] = where
            results = self.collection.query(**query_kwargs)
        except Exception as e:
            raise RuntimeError(f"Vector search failed: {e}")

        if not results["ids"] or not results["ids"][0]:
            logger.warning("No similar tickets found")
            return []

        similar_tickets = []
        for i, doc_id in enumerate(results["ids"][0]):
            distance = results["distances"][0][i] if results["distances"] else 0
            similarity = 1 - distance  # cosine distance → similarity

            if similarity < min_similarity:
                continue

            similar_tickets.append({
                "metadata": results["metadatas"][0][i],
                "similarity_score": round(similarity, 3),
                "distance": round(distance, 3),
            })

        if len(similar_tickets) < k:
            logger.info(
                f"Similarity threshold ({min_similarity:.0%}) filtered results: "
                f"{len(similar_tickets)}/{len(results['ids'][0])} passed"
            )

        similar_tickets.sort(key=lambda x: x["similarity_score"], reverse=True)
        return similar_tickets

    # -------------------------------------------------------------------------
    # Index stats
    # -------------------------------------------------------------------------
    def get_index_stats(self) -> dict:
        """Get statistics about the current index."""
        try:
            count = self.collection.count()
            return {
                "status": "available",
                "ticket_count": count,
                "fingerprint_count": self.fingerprint_store.count(),
                "storage_path": self.chroma_path,
                "collection_name": COLLECTION_NAME,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# -------------------------------------------------------------------------
# CLI entry points
# -------------------------------------------------------------------------
def sync_xsoar_ticket_index(days_back: int = 1200) -> int:
    """Entry point for syncing tickets (adds new ones only)."""
    indexer = XsoarTicketIndexer()
    added = indexer.sync_tickets(days_back=days_back)
    print(f"Sync complete: {added} new tickets added")
    return added


def rebuild_xsoar_ticket_index(days_back: int = 1200) -> bool:
    """Entry point for full rebuild (deletes and recreates)."""
    indexer = XsoarTicketIndexer()
    success = indexer.rebuild_index(days_back=days_back)
    if success:
        stats = indexer.get_index_stats()
        print(f"Index rebuilt: {stats.get('ticket_count', 0)} tickets")
    else:
        print("Failed to rebuild XSOAR ticket index")
    return success


def search_similar(query: str, k: int = 5) -> List[dict]:
    """CLI search for testing."""
    indexer = XsoarTicketIndexer()
    print(f"\nSearching for tickets similar to: '{query[:80]}...'\n")

    try:
        results = indexer.find_similar_tickets(query, k=k)
        print(f"Top {len(results)} similar tickets:\n")
        for i, result in enumerate(results, 1):
            meta = result["metadata"]
            print(f"{i}. [{meta['id']}] {meta['name'][:60]}...")
            print(f"   Similarity: {result['similarity_score']:.1%}")
            print(f"   Category: {meta.get('security_category', 'N/A')}")
            print(f"   Resolution: {meta.get('resolution_hours', 'N/A')}h")
            print()
        return results
    except RuntimeError as e:
        print(f"Error: {e}")
        print("Run 'python -m src.components.xsoar_ticket_indexer rebuild' first.")
        return []


def backfill_fingerprints(days_back: int = 1200) -> int:
    """Backfill fingerprints for tickets already indexed but missing from fingerprint store."""
    from src.utils.entity_extractor import extract_entities

    indexer = XsoarTicketIndexer()
    tickets = indexer.fetch_historical_tickets(days_back)
    count = 0
    for ticket in tickets:
        ticket_id = str(ticket.get("id", ""))
        if not ticket_id or indexer.fingerprint_store.has(ticket_id):
            continue
        details = (ticket.get("details", "") or "").strip()
        entities = None
        if details:
            try:
                entities = extract_entities(details, include_apt_database=False)
            except Exception:
                pass
        indexer.fingerprint_store.upsert(ticket_id, ticket, entities)
        count += 1
        if count % 1000 == 0:
            logger.info(f"Backfilled {count} fingerprints...")
    logger.info(f"Backfill complete: {count} fingerprints added (total: {indexer.fingerprint_store.count()})")
    return count


def show_stats():
    """Show index statistics."""
    indexer = XsoarTicketIndexer()
    stats = indexer.get_index_stats()
    print("\nXSOAR Ticket Index Stats:")
    print("-" * 40)
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print()


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "search":
            query = " ".join(sys.argv[2:]) or "phishing email with malicious attachment"
            search_similar(query)
        elif command == "stats":
            show_stats()
        elif command == "rebuild":
            rebuild_xsoar_ticket_index(days_back=1200)
        elif command == "sync":
            sync_xsoar_ticket_index(days_back=1200)
        elif command == "backfill-fingerprints":
            count = backfill_fingerprints(days_back=1200)
            indexer = XsoarTicketIndexer()
            print(f"Backfill complete: {count} fingerprints created (total: {indexer.fingerprint_store.count()})")
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python -m src.components.xsoar_ticket_indexer           # Sync (incremental)")
            print("  python -m src.components.xsoar_ticket_indexer rebuild   # Full rebuild")
            print("  python -m src.components.xsoar_ticket_indexer sync      # Same as default")
            print("  python -m src.components.xsoar_ticket_indexer search <query>")
            print("  python -m src.components.xsoar_ticket_indexer backfill-fingerprints")
            print("  python -m src.components.xsoar_ticket_indexer stats")
    else:
        sync_xsoar_ticket_index(days_back=1200)
