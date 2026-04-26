"""
Tipper Similarity Indexer

Indexes historical threat tippers from AZDO into ChromaDB for
semantic similarity search when analyzing new tippers.

Uses pure vector similarity (no keyword matching) for accurate
semantic matching of threat content. The embedding model understands
threat concepts and finds genuinely similar tippers based on meaning,
not superficial keyword overlap.

Key features:
- Strips CTI boilerplate (CSS, section headers, metadata) before embedding
- Uses sentence transformer embeddings via Ollama
- ChromaDB with automatic persistence - no manual rebuilds needed
- New tippers are upserted incrementally

Usage:
    # Sync new tippers (adds only missing ones)
    python -m src.components.tipper_indexer

    # Full rebuild (deletes and recreates collection)
    python -m src.components.tipper_indexer rebuild

    # Search for similar tippers
    python -m src.components.tipper_indexer search "APT group using Cobalt Strike"
"""

import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

import chromadb
import requests

import services.azdo as azdo
from data.data_maps import azdo_area_paths
from src.components.embedding import (
    OllamaEmbeddingFunction,
    SentenceTransformerEmbeddingFunction,
    get_embedding_function,
)

logger = logging.getLogger(__name__)

# Paths
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
CHROMA_PATH = ROOT_DIRECTORY / "data" / "transient" / "chroma_tipper_index"

# Collection name
COLLECTION_NAME = "threat_tippers"
STAGING_COLLECTION_NAME = "threat_tippers_staging"

# Batch size for remote embedding calls — sending all docs in one POST hangs
# the mac-m3 mlx-lm server past its 600s timeout when there are many tippers.
EMBEDDING_BATCH_SIZE = 50


class TipperIndexer:
    """Handles indexing and similarity search for threat tippers using ChromaDB."""

    def __init__(self):
        self.chroma_path = str(CHROMA_PATH)
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = get_embedding_function()
        # Fingerprint store for structured entity data (IOCs, TTPs, actors)
        from src.components.tipper_fingerprint_store import TipperFingerprintStore
        self.fingerprint_store = TipperFingerprintStore()

    @property
    def client(self) -> chromadb.PersistentClient:
        """Lazy-load ChromaDB client."""
        if self._client is None:
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        """Get or create the tipper collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={
                    "hnsw:space": "cosine",
                    "description": "Threat tipper embeddings for similarity search",
                }
            )
        return self._collection

    # -------------------------------------------------------------------------
    # Fetch tippers from AZDO
    # -------------------------------------------------------------------------
    def fetch_historical_tippers(self, days_back: int = 365) -> List[dict]:
        """
        Fetch ALL tippers from AZDO for the specified time period.

        Args:
            days_back: How far back to fetch (default 1 year)

        Returns:
            List of tipper work items from AZDO
        """
        area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')

        query = f"""
            SELECT [System.Id], [System.Title], [System.Description],
                   [System.CreatedDate], [System.Tags], [System.State],
                   [System.AssignedTo], [Microsoft.VSTS.Common.ClosedDate]
            FROM WorkItems
            WHERE [System.AreaPath] UNDER '{area_path}'
              AND [System.CreatedDate] >= @Today-{days_back}
            ORDER BY [System.CreatedDate] DESC
        """

        logger.info(f"Fetching tippers from last {days_back} days...")
        work_items = azdo.fetch_work_items(query)

        if not work_items:
            logger.warning("No tippers found matching query")
            return []

        logger.info(f"Fetched {len(work_items)} tippers from AZDO")
        return work_items

    # -------------------------------------------------------------------------
    # Extract text for embedding
    # -------------------------------------------------------------------------
    def extract_tipper_text(self, tipper: dict, entities=None) -> str:
        """
        Extract meaningful text from a tipper for embedding.

        Strips HTML, CTI boilerplate, and structural formatting to focus
        on the actual threat content for semantic similarity matching.

        When entities are provided, prepends structured high-signal fields
        (actor names, malware families, MITRE techniques, top IOCs) with
        repetition to give them proportional weight against the narrative
        prose in the embedding space.
        """
        fields = tipper.get('fields', {})

        title = fields.get('System.Title', '')
        description = fields.get('System.Description', '')
        tags = fields.get('System.Tags', '')

        # Clean HTML from description
        if description:
            description = re.sub(r'<[^>]+>', ' ', description)
            description = re.sub(r'\s+', ' ', description).strip()

            # Remove common CTI boilerplate that adds noise to embeddings
            boilerplate_patterns = [
                # CSS style blocks
                r'p\.MsoNormal.*?font-family:[^}]+\}',
                r'div\.WordSection\d+\s*\{\s*\}',
                r'span\.\w+Char\s*\{[^}]+\}',
                r'\.MsoChpDefault\s*\{[^}]+\}',
                r'a:link[^}]+\}',
                r'code\s*\{[^}]+\}',
                # Section headers that appear in every tipper
                r'\bTHREAT ACTION\b',
                r'\bTHREAT SUMMARY\b',
                r'\bAttack Overview\b',
                r'\bTechnical Analysis\b',
                r'\bImpact Assessment\b',
                r'\bTHREAT ACTOR / MALWARE FAMILY\b',
                r'\bINDICATORS OF COMPROMISE \(IOCs\)\b',
                r'\bTotal IOCs:\s*\d+',
                # Metadata labels
                r'\bDate:\s*\w+\s+\d+,\s*\d{4}',
                r'\bSeverity:\s*(High|Medium|Low|Informational|Critical)',
                r'\bClassification:\s*TLP:\w+',
                # Non-breaking spaces and formatting artifacts
                r'&nbsp;',
            ]

            for pattern in boilerplate_patterns:
                description = re.sub(pattern, ' ', description, flags=re.IGNORECASE)

            # Normalize whitespace after boilerplate removal
            description = re.sub(r'\s+', ' ', description).strip()

        # Clean the title - remove severity prefix brackets
        clean_title = re.sub(r'^\[(HIGH|MEDIUM|LOW|INFORMATIONAL|MED)\]\s*', '', title, flags=re.IGNORECASE)
        clean_title = re.sub(r'^CTI Threat Tipper:\s*', '', clean_title, flags=re.IGNORECASE)

        # Build embedding text - focus on semantic content, not structure
        text_parts = []

        # Prepend structured entity emphasis for better embedding discrimination.
        # Repeating actor/malware names 3x gives them proportional weight against
        # the narrative prose, so embeddings differentiate "BlackSanta campaign"
        # from "NANOREMOTE campaign" even when the surrounding text is similar.
        if entities:
            emphasis_parts = []
            # Actor names (3x repetition — strongest discriminator)
            actors = []
            if hasattr(entities, 'threat_actors_enriched') and entities.threat_actors_enriched:
                actors = [ta.common_name or ta.name for ta in entities.threat_actors_enriched]
            elif hasattr(entities, 'threat_actors') and entities.threat_actors:
                actors = list(entities.threat_actors)
            if actors:
                actor_str = ', '.join(actors)
                emphasis_parts.extend([f"Threat actors: {actor_str}"] * 3)

            # Malware families (3x repetition)
            if hasattr(entities, 'malware_families') and entities.malware_families:
                malware_str = ', '.join(entities.malware_families)
                emphasis_parts.extend([f"Malware: {malware_str}"] * 3)

            # MITRE techniques (1x — many are shared across campaigns)
            if hasattr(entities, 'mitre_techniques') and entities.mitre_techniques:
                emphasis_parts.append(f"MITRE: {', '.join(entities.mitre_techniques[:15])}")

            # Top IOCs (1x — IPs and domains for campaign fingerprinting)
            top_iocs = []
            if hasattr(entities, 'ips') and entities.ips:
                top_iocs.extend(entities.ips[:10])
            if hasattr(entities, 'domains') and entities.domains:
                top_iocs.extend(entities.domains[:10])
            if top_iocs:
                emphasis_parts.append(f"IOCs: {', '.join(top_iocs)}")

            if emphasis_parts:
                text_parts.append('. '.join(emphasis_parts))

        if clean_title:
            text_parts.append(clean_title)

        # Include meaningful tags (filter out generic ones)
        if tags:
            generic_tags = {'cti', 'high', 'medium', 'low', 'informational', 'critical'}
            meaningful_tags = [
                t.strip() for t in tags.split(';')
                if t.strip().lower() not in generic_tags
            ]
            if meaningful_tags:
                text_parts.append(' '.join(meaningful_tags))

        if description:
            # Truncate to 2000 chars for embedding efficiency
            text_parts.append(description[:2000])

        return ' '.join(text_parts)

    def prepare_tipper_metadata(self, tipper: dict) -> dict:
        """Extract metadata to store alongside the embedding."""
        fields = tipper.get('fields', {})

        # Extract display name from AssignedTo (can be dict with displayName or plain string)
        assigned_to = fields.get('System.AssignedTo', '') or ''
        if isinstance(assigned_to, dict):
            assigned_to = assigned_to.get('displayName', '')

        return {
            'id': str(tipper.get('id', '')),
            'title': fields.get('System.Title', ''),
            'created_date': fields.get('System.CreatedDate', ''),
            'closed_date': fields.get('Microsoft.VSTS.Common.ClosedDate', '') or '',
            'state': fields.get('System.State', ''),
            'tags': fields.get('System.Tags', '') or '',
            'assigned_to': assigned_to,
            'url': tipper.get('url', '') or '',
        }

    # -------------------------------------------------------------------------
    # Sync tippers (upsert new ones only)
    # -------------------------------------------------------------------------
    def sync_tippers(self, days_back: int = 365) -> int:
        """
        Sync tippers from AZDO to ChromaDB.

        Only upserts tippers that are new or updated. Much faster than
        a full rebuild since we skip existing tippers.

        Args:
            days_back: How far back to fetch from AZDO

        Returns:
            Number of tippers added/updated
        """
        logger.info("=" * 60)
        logger.info("TIPPER SYNC STARTING")
        logger.info("=" * 60)

        # Fetch tippers from AZDO
        tippers = self.fetch_historical_tippers(days_back)
        if not tippers:
            logger.warning("No tippers to sync")
            return 0

        # Get existing IDs and titles in ChromaDB
        existing_ids = set()
        existing_titles = set()
        try:
            result = self.collection.get(include=['metadatas'])
            existing_ids = set(result['ids']) if result['ids'] else set()
            if result.get('metadatas'):
                existing_titles = {
                    m.get('title', '') for m in result['metadatas'] if m.get('title')
                }
            logger.info(f"ChromaDB has {len(existing_ids)} existing tippers")
        except Exception as e:
            logger.warning(f"Could not get existing IDs: {e}")

        # Find new tippers (skip if ID already indexed or title already indexed)
        new_tippers = []
        for tipper in tippers:
            tipper_id = str(tipper.get('id', ''))
            title = tipper.get('fields', {}).get('System.Title', '')
            if tipper_id and tipper_id not in existing_ids:
                if title and title in existing_titles:
                    logger.info(f"Skipping tipper #{tipper_id} — title already indexed: {title[:60]}")
                else:
                    new_tippers.append(tipper)

        if not new_tippers:
            logger.info("No new tippers to add")
            logger.info("=" * 60)
            return 0

        logger.info(f"Found {len(new_tippers)} new tippers to add")

        # Deduplicate by title - the tipper creation process sometimes creates
        # duplicates with the same title at the same time. Keep only the highest
        # ID (newest) to avoid indexing duplicates that would falsely match each other.
        seen_titles = set()
        unique_tippers = []
        # Sort descending by ID so we keep the highest ID for each title
        for tipper in sorted(new_tippers, key=lambda t: int(t.get('id', 0)), reverse=True):
            title = tipper.get('fields', {}).get('System.Title', '')
            if title and title not in seen_titles:
                seen_titles.add(title)
                unique_tippers.append(tipper)
            elif title:
                logger.info(f"Skipping duplicate tipper #{tipper.get('id')} (same title, keeping higher ID)")

        if len(unique_tippers) < len(new_tippers):
            logger.info(f"Deduplicated: {len(new_tippers)} → {len(unique_tippers)} unique tippers")
        new_tippers = unique_tippers

        # Process and upsert new tippers
        ids = []
        documents = []
        metadatas = []

        for i, tipper in enumerate(new_tippers):
            tipper_id = str(tipper.get('id', ''))

            if (i + 1) % 20 == 0 or i == 0:
                logger.info(f"Processing tipper {i + 1}/{len(new_tippers)}...")

            try:
                # Extract entities for structured fingerprint and embedding emphasis
                entities = self._extract_entities_for_tipper(tipper)
                text = self.extract_tipper_text(tipper, entities=entities)
                meta = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(meta)

                # Store structured fingerprint in sidecar DB
                if entities:
                    title = tipper.get('fields', {}).get('System.Title', '')
                    created = tipper.get('fields', {}).get('System.CreatedDate', '')
                    self.fingerprint_store.upsert(tipper_id, entities, title, created)

            except Exception as e:
                logger.error(f"Failed to process tipper {tipper_id}: {e}")
                continue

        if not ids:
            logger.warning("No tippers processed successfully")
            return 0

        # Upsert to ChromaDB (generates embeddings automatically)
        logger.info(f"Upserting {len(ids)} tippers to ChromaDB...")
        try:
            # Generate embeddings
            embeddings = self._embedding_fn(documents)

            self.collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"Successfully added {len(ids)} tippers")
            logger.info(f"Fingerprint store: {self.fingerprint_store.count()} tippers")
            logger.info("=" * 60)
            logger.info("TIPPER SYNC COMPLETED")
            logger.info("=" * 60)
            return len(ids)

        except Exception as e:
            logger.error(f"Failed to upsert tippers: {e}", exc_info=True)
            return 0

    # -------------------------------------------------------------------------
    # Full rebuild (delete and recreate)
    # -------------------------------------------------------------------------
    def rebuild_index(self, days_back: int = 365) -> bool:
        """
        Full rebuild: Delete collection and recreate from scratch.

        Use this only when needed (schema change, corruption, etc.).
        Normal operation should use sync_tippers().

        Args:
            days_back: How far back to fetch

        Returns:
            True if successful
        """
        logger.info("=" * 60)
        logger.info("FULL INDEX REBUILD STARTING")
        logger.info("=" * 60)

        # Build into a staging collection so a mid-rebuild failure leaves the
        # current index intact. Drop any leftover staging from a prior failed run.
        try:
            self.client.delete_collection(STAGING_COLLECTION_NAME)
            logger.info(f"Cleared leftover staging collection: {STAGING_COLLECTION_NAME}")
        except Exception:
            pass

        staging_collection = self.client.create_collection(
            name=STAGING_COLLECTION_NAME,
            metadata={
                "hnsw:space": "cosine",
                "description": "Threat tipper embeddings — staging build",
            },
        )

        # Fetch all tippers
        tippers = self.fetch_historical_tippers(days_back)
        if not tippers:
            logger.error("No tippers to index")
            return False

        # Deduplicate by title - keep only the highest ID for each title
        seen_titles = set()
        unique_tippers = []
        for tipper in sorted(tippers, key=lambda t: int(t.get('id', 0)), reverse=True):
            title = tipper.get('fields', {}).get('System.Title', '')
            if title and title not in seen_titles:
                seen_titles.add(title)
                unique_tippers.append(tipper)

        if len(unique_tippers) < len(tippers):
            logger.info(f"Deduplicated: {len(tippers)} → {len(unique_tippers)} unique tippers")
        tippers = unique_tippers

        logger.info(f"Processing {len(tippers)} tippers for indexing...")

        # Prepare data
        ids = []
        documents = []
        metadatas = []

        for i, tipper in enumerate(tippers):
            tipper_id = str(tipper.get('id', ''))

            if (i + 1) % 50 == 0 or i == 0:
                logger.info(f"Processing tipper {i + 1}/{len(tippers)}...")

            try:
                # Extract entities for structured fingerprint and embedding emphasis
                entities = self._extract_entities_for_tipper(tipper)
                text = self.extract_tipper_text(tipper, entities=entities)
                metadata = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(metadata)

                # Store structured fingerprint in sidecar DB
                if entities:
                    title = tipper.get('fields', {}).get('System.Title', '')
                    created = tipper.get('fields', {}).get('System.CreatedDate', '')
                    self.fingerprint_store.upsert(tipper_id, entities, title, created)

            except Exception as e:
                logger.error(f"Failed to process tipper {tipper_id}: {e}")
                continue

        if not ids:
            logger.error("No tippers processed successfully")
            return False

        # Embed and add to staging in batches — a single 700+ doc embedding
        # request blows past the 600s remote-server timeout.
        logger.info(f"Embedding {len(ids)} tippers in batches of {EMBEDDING_BATCH_SIZE}...")
        try:
            for start in range(0, len(ids), EMBEDDING_BATCH_SIZE):
                end = start + EMBEDDING_BATCH_SIZE
                batch_ids = ids[start:end]
                batch_docs = documents[start:end]
                batch_metas = metadatas[start:end]

                logger.info(f"  Embedding batch {start + 1}-{min(end, len(ids))}/{len(ids)}")
                batch_embeddings = self._embedding_fn(batch_docs)
                staging_collection.add(
                    ids=batch_ids,
                    documents=batch_docs,
                    metadatas=batch_metas,
                    embeddings=batch_embeddings,
                )

            # All batches embedded. Atomically swap staging into prod by
            # dropping the live collection and copying staging contents into
            # a fresh COLLECTION_NAME (Chroma has no rename).
            logger.info("All batches embedded. Swapping staging → live collection.")
            try:
                self.client.delete_collection(COLLECTION_NAME)
            except Exception:
                pass

            live_collection = self.client.create_collection(
                name=COLLECTION_NAME,
                metadata={
                    "hnsw:space": "cosine",
                    "description": "Threat tipper embeddings for similarity search",
                },
            )
            staged = staging_collection.get(include=["embeddings", "documents", "metadatas"])
            live_collection.add(
                ids=staged["ids"],
                documents=staged["documents"],
                metadatas=staged["metadatas"],
                embeddings=staged["embeddings"],
            )
            self._collection = live_collection

            # Drop staging now that prod is populated.
            try:
                self.client.delete_collection(STAGING_COLLECTION_NAME)
            except Exception:
                pass

            logger.info(f"Indexed {len(ids)} tippers successfully")
            logger.info(f"Fingerprint store: {self.fingerprint_store.count()} tippers")
            logger.info("=" * 60)
            logger.info("FULL INDEX REBUILD COMPLETED")
            logger.info("=" * 60)
            return True

        except Exception as e:
            logger.error(f"Failed to create index: {e}", exc_info=True)
            logger.error(
                f"Live collection '{COLLECTION_NAME}' was NOT modified. "
                f"Staging collection '{STAGING_COLLECTION_NAME}' left in place for inspection."
            )
            return False

    # -------------------------------------------------------------------------
    # Search for similar tippers (pure vector similarity)
    # -------------------------------------------------------------------------
    def find_similar_tippers(self, query_text: str, k: int = 5, query_entities=None) -> List[dict]:
        """
        Find tippers similar to the given text using multi-signal similarity.

        Stage 1: Vector similarity via ChromaDB embeddings (narrative similarity)
        Stage 2: Structured scoring via fingerprint store (IOC, TTP, actor/malware overlap)

        The composite score blends both signals so analysts get a meaningful
        similarity percentage backed by a per-dimension breakdown.

        Args:
            query_text: Text to search for (new tipper title/description)
            k: Number of similar tippers to return
            query_entities: Optional ExtractedEntities for the query tipper.
                           When provided, enables multi-signal scoring.

        Returns:
            List of similar tipper dicts with similarity_score (composite),
            narrative_similarity, and similarity_breakdown fields.
        """
        # Check if collection has data
        try:
            count = self.collection.count()
            if count == 0:
                raise RuntimeError("No tippers in index. Run sync_tippers() first.")
            logger.info(f"Searching tipper index ({count} tippers)")
        except Exception as e:
            raise RuntimeError(f"Could not access tipper index: {e}")

        # Clean the query text using the same preprocessing as indexed tippers
        clean_query = self._clean_query_text(query_text)
        logger.debug(f"Clean query ({len(clean_query)} chars): {clean_query[:100]}...")

        # Generate query embedding
        try:
            query_embedding = self._embedding_fn([clean_query])[0]
        except Exception as e:
            raise RuntimeError(f"Failed to generate query embedding: {e}")

        # Vector similarity search (all tippers — state shown in Related Tickets)
        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=k,
                include=['metadatas', 'documents', 'distances']
            )
        except Exception as e:
            raise RuntimeError(f"Vector search failed: {e}")

        if not results['ids'] or not results['ids'][0]:
            logger.warning("No similar tippers found")
            return []

        # Build query fingerprint from entities (if available)
        query_fingerprint = None
        if query_entities:
            from src.components.tipper_similarity import fingerprint_from_entities
            query_fingerprint = fingerprint_from_entities(query_entities)

        # Fetch candidate fingerprints in bulk
        candidate_ids = [
            results['metadatas'][0][i].get('id', '')
            for i in range(len(results['ids'][0]))
        ]
        candidate_fingerprints = {}
        if query_fingerprint:
            try:
                candidate_fingerprints = self.fingerprint_store.get_batch(candidate_ids)
            except Exception as e:
                logger.warning(f"Could not fetch fingerprints (falling back to narrative-only): {e}")

        # Convert results to standardized format with multi-signal scoring
        from src.components.tipper_similarity import compute_similarity_breakdown, SimilarityBreakdown
        similar_tippers = []
        for i, doc_id in enumerate(results['ids'][0]):
            distance = results['distances'][0][i] if results['distances'] else 0
            narrative_similarity = 1 - distance  # Cosine distance → similarity

            meta = results['metadatas'][0][i]
            candidate_id = meta.get('id', '')

            # Compute multi-signal breakdown if fingerprints are available
            breakdown = None
            composite_score = narrative_similarity  # Default: narrative only
            if query_fingerprint and candidate_id in candidate_fingerprints:
                breakdown = compute_similarity_breakdown(
                    query_fingerprint,
                    candidate_fingerprints[candidate_id],
                    narrative_similarity,
                )
                composite_score = breakdown.composite_score

            similar_tippers.append({
                'metadata': meta,
                'similarity_score': round(composite_score, 3),
                'narrative_similarity': round(narrative_similarity, 3),
                'similarity_breakdown': breakdown,
                'distance': round(distance, 3),
                'matched_content': results['documents'][0][i][:500] if results['documents'] else ""
            })

        # Re-sort by composite score (may differ from narrative-only ordering)
        similar_tippers.sort(key=lambda x: x['similarity_score'], reverse=True)

        if query_fingerprint and candidate_fingerprints:
            logger.info(f"Multi-signal scoring applied ({len(candidate_fingerprints)} fingerprints matched)")

        return similar_tippers

    def _clean_query_text(self, text: str) -> str:
        """
        Clean query text using the same preprocessing as indexed tippers.

        Ensures query embeddings match the format of stored embeddings.
        """
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Remove CSS style blocks and formatting
        boilerplate_patterns = [
            r'p\.MsoNormal.*?font-family:[^}]+\}',
            r'div\.WordSection\d+\s*\{\s*\}',
            r'span\.\w+Char\s*\{[^}]+\}',
            r'\.MsoChpDefault\s*\{[^}]+\}',
            r'a:link[^}]+\}',
            r'code\s*\{[^}]+\}',
            r'\bTHREAT ACTION\b',
            r'\bTHREAT SUMMARY\b',
            r'\bAttack Overview\b',
            r'\bTechnical Analysis\b',
            r'\bImpact Assessment\b',
            r'\bTHREAT ACTOR / MALWARE FAMILY\b',
            r'\bINDICATORS OF COMPROMISE \(IOCs\)\b',
            r'\bTotal IOCs:\s*\d+',
            r'\bDate:\s*\w+\s+\d+,\s*\d{4}',
            r'\bSeverity:\s*(High|Medium|Low|Informational|Critical)',
            r'\bClassification:\s*TLP:\w+',
            r'&nbsp;',
        ]

        for pattern in boilerplate_patterns:
            text = re.sub(pattern, ' ', text, flags=re.IGNORECASE)

        # Remove severity prefix from titles
        text = re.sub(r'\[(HIGH|MEDIUM|LOW|INFORMATIONAL|MED)\]\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'CTI Threat Tipper:\s*', '', text, flags=re.IGNORECASE)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    # -------------------------------------------------------------------------
    # Entity extraction helper
    # -------------------------------------------------------------------------
    def _extract_entities_for_tipper(self, tipper: dict):
        """Extract entities from a tipper for fingerprinting and embedding emphasis.

        Uses full description (not truncated embedding text) for best extraction.
        Returns ExtractedEntities or None if extraction fails.
        """
        try:
            from src.utils.entity_extractor import extract_entities
            description = tipper.get('fields', {}).get('System.Description', '')
            if not description:
                return None
            # Clean HTML for entity extraction
            clean_text = re.sub(r'<[^>]+>', ' ', description)
            clean_text = re.sub(r'\s+', ' ', clean_text).strip()
            return extract_entities(clean_text, include_apt_database=True)
        except Exception as e:
            logger.debug(f"Entity extraction failed for tipper: {e}")
            return None

    # -------------------------------------------------------------------------
    # Index stats
    # -------------------------------------------------------------------------
    def get_index_stats(self) -> dict:
        """Get statistics about the current index."""
        try:
            count = self.collection.count()
            return {
                'status': 'available',
                'tipper_count': count,
                'storage_path': self.chroma_path,
                'collection_name': COLLECTION_NAME
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}


# -------------------------------------------------------------------------
# CLI Entry Points
# -------------------------------------------------------------------------
def sync_tipper_index(days_back: int = 365) -> int:
    """Entry point for syncing tippers (adds new ones only)."""
    indexer = TipperIndexer()
    added = indexer.sync_tippers(days_back=days_back)
    print(f"Sync complete: {added} new tippers added")
    return added


def rebuild_tipper_index(days_back: int = 365) -> bool:
    """Entry point for full rebuild (deletes and recreates)."""
    indexer = TipperIndexer()
    success = indexer.rebuild_index(days_back=days_back)

    if success:
        stats = indexer.get_index_stats()
        print(f"Index rebuilt: {stats.get('tipper_count', 0)} tippers")
    else:
        print("Failed to rebuild tipper index")

    return success


def search_similar(query: str, k: int = 5) -> List[dict]:
    """CLI search for testing."""
    indexer = TipperIndexer()

    print(f"\nSearching for tippers similar to: '{query[:50]}...'\n")

    try:
        results = indexer.find_similar_tippers(query, k=k)

        print(f"Top {len(results)} similar tippers:\n")
        for i, result in enumerate(results, 1):
            meta = result['metadata']
            breakdown = result.get('similarity_breakdown')
            print(f"{i}. [{meta['id']}] {meta['title'][:60]}...")
            if breakdown:
                print(f"   Composite: {result['similarity_score']:.0%}  "
                      f"[Narrative: {breakdown.narrative_similarity:.0%} | "
                      f"IOC: {breakdown.shared_ioc_count} shared | "
                      f"TTP: {breakdown.shared_ttp_count} shared | "
                      f"Actor: {', '.join(breakdown.shared_actors[:2]) or 'none'}]")
            else:
                print(f"   Similarity: {result['similarity_score']:.1%} (narrative only)")
            print(f"   Tags: {meta.get('tags', 'N/A')[:50]}")
            print(f"   Created: {meta.get('created_date', 'N/A')[:10]}")
            print()

        return results

    except RuntimeError as e:
        print(f"Error: {e}")
        print("Run 'python -m src.components.tipper_indexer' first to sync tippers.")
        return []


def backfill_fingerprints(days_back: int = 365):
    """Backfill fingerprint store for existing indexed tippers."""
    indexer = TipperIndexer()

    print("Backfilling fingerprint store from AZDO tippers...")
    tippers = indexer.fetch_historical_tippers(days_back)
    if not tippers:
        print("No tippers found")
        return

    added = 0
    skipped = 0
    for i, tipper in enumerate(tippers):
        tipper_id = str(tipper.get('id', ''))
        if not tipper_id:
            continue

        if indexer.fingerprint_store.has(tipper_id):
            skipped += 1
            continue

        if (i + 1) % 50 == 0:
            print(f"  Processing {i + 1}/{len(tippers)}...")

        entities = indexer._extract_entities_for_tipper(tipper)
        if entities:
            title = tipper.get('fields', {}).get('System.Title', '')
            created = tipper.get('fields', {}).get('System.CreatedDate', '')
            indexer.fingerprint_store.upsert(tipper_id, entities, title, created)
            added += 1

    print(f"Backfill complete: {added} fingerprints added, {skipped} already existed")
    print(f"Fingerprint store total: {indexer.fingerprint_store.count()}")


def show_stats():
    """Show index statistics."""
    indexer = TipperIndexer()
    stats = indexer.get_index_stats()

    print("\nTipper Index Stats:")
    print("-" * 40)
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"  fingerprint_count: {indexer.fingerprint_store.count()}")
    print()


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "search":
            query = " ".join(sys.argv[2:]) or "phishing campaign targeting finance"
            search_similar(query)
        elif command == "stats":
            show_stats()
        elif command == "rebuild":
            rebuild_tipper_index(days_back=365)
        elif command == "backfill-fingerprints":
            backfill_fingerprints(days_back=365)
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python -m src.components.tipper_indexer                    # Sync new tippers")
            print("  python -m src.components.tipper_indexer rebuild            # Full rebuild")
            print("  python -m src.components.tipper_indexer backfill-fingerprints  # Backfill fingerprint store")
            print("  python -m src.components.tipper_indexer search <query>")
            print("  python -m src.components.tipper_indexer stats")
    else:
        # Default: sync tippers (incremental)
        sync_tipper_index(days_back=365)
