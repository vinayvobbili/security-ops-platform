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
import math
import re
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

import chromadb
import requests

import services.azdo as azdo
from data.data_maps import azdo_area_paths

logger = logging.getLogger(__name__)

# Paths
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
CHROMA_PATH = ROOT_DIRECTORY / "data" / "transient" / "chroma_tipper_index"

# Collection name
COLLECTION_NAME = "threat_tippers"


class OllamaEmbeddingFunction:
    """Custom embedding function using Ollama API."""

    def __init__(self, model: str = None):
        # Use config if no model specified
        if model is None:
            from my_config import get_config
            config = get_config()
            model = config.ollama_embedding_model or "all-minilm:l6-v2"
        self.model = model
        self.api_url = "http://localhost:11434/api/embeddings"

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""
        embeddings = []
        for text in input:
            embedding = self._embed_single(text)
            embeddings.append(embedding)
        return embeddings

    def _embed_single(self, text: str, max_retries: int = 3) -> List[float]:
        """Generate embedding for a single text."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "prompt": text},
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                return result["embedding"]
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed text: {e}")


class TipperIndexer:
    """Handles indexing and similarity search for threat tippers using ChromaDB."""

    def __init__(self):
        self.chroma_path = str(CHROMA_PATH)
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = OllamaEmbeddingFunction()

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
                metadata={"description": "Threat tipper embeddings for similarity search"}
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
                   [Microsoft.VSTS.Common.ClosedDate]
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
    def extract_tipper_text(self, tipper: dict) -> str:
        """
        Extract meaningful text from a tipper for embedding.

        Strips HTML, CTI boilerplate, and structural formatting to focus
        on the actual threat content for semantic similarity matching.
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

        return {
            'id': str(tipper.get('id', '')),
            'title': fields.get('System.Title', ''),
            'created_date': fields.get('System.CreatedDate', ''),
            'closed_date': fields.get('Microsoft.VSTS.Common.ClosedDate', '') or '',
            'state': fields.get('System.State', ''),
            'tags': fields.get('System.Tags', '') or '',
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

        # Get existing IDs in ChromaDB
        existing_ids = set()
        try:
            # Get all existing IDs (ChromaDB returns all if no filter)
            result = self.collection.get()
            existing_ids = set(result['ids']) if result['ids'] else set()
            logger.info(f"ChromaDB has {len(existing_ids)} existing tippers")
        except Exception as e:
            logger.warning(f"Could not get existing IDs: {e}")

        # Find new tippers
        new_tippers = []
        for tipper in tippers:
            tipper_id = str(tipper.get('id', ''))
            if tipper_id and tipper_id not in existing_ids:
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
                text = self.extract_tipper_text(tipper)
                meta = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(meta)

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

        # Delete existing collection
        try:
            self.client.delete_collection(COLLECTION_NAME)
            self._collection = None  # Reset cached collection
            logger.info(f"Deleted existing collection: {COLLECTION_NAME}")
        except Exception as e:
            logger.warning(f"Could not delete collection (may not exist): {e}")

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
                text = self.extract_tipper_text(tipper)
                metadata = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(metadata)

            except Exception as e:
                logger.error(f"Failed to process tipper {tipper_id}: {e}")
                continue

        if not ids:
            logger.error("No tippers processed successfully")
            return False

        # Add to ChromaDB
        logger.info(f"Adding {len(ids)} tippers to ChromaDB...")
        try:
            # Generate embeddings
            embeddings = self._embedding_fn(documents)

            self.collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )

            logger.info(f"Indexed {len(ids)} tippers successfully")
            logger.info("=" * 60)
            logger.info("FULL INDEX REBUILD COMPLETED")
            logger.info("=" * 60)
            return True

        except Exception as e:
            logger.error(f"Failed to create index: {e}", exc_info=True)
            return False

    # -------------------------------------------------------------------------
    # Search for similar tippers (pure vector similarity)
    # -------------------------------------------------------------------------
    def find_similar_tippers(self, query_text: str, k: int = 5) -> List[dict]:
        """
        Find tippers similar to the given text using semantic vector similarity.

        Uses embedding-based similarity search for accurate semantic matching.
        No keyword matching - relies purely on the embedding model to understand
        threat content and find genuinely similar tippers.

        Args:
            query_text: Text to search for (new tipper title/description)
            k: Number of similar tippers to return

        Returns:
            List of similar tipper metadata with similarity scores (0.0 to 1.0)
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

        # Vector similarity search
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

        # Convert results to standardized format
        similar_tippers = []
        for i, doc_id in enumerate(results['ids'][0]):
            distance = results['distances'][0][i] if results['distances'] else 0

            # Convert L2 distance to similarity score using exponential decay
            # Ollama embeddings are not normalized, so L2 distances are large (100-400+)
            # Scale factor of 300 gives good differentiation:
            #   - distance ~160 (very similar) → ~60% similarity
            #   - distance ~280 (somewhat related) → ~40% similarity
            #   - distance ~400 (unrelated) → ~25% similarity
            similarity = math.exp(-distance / 300)

            similar_tippers.append({
                'metadata': results['metadatas'][0][i],
                'similarity_score': round(similarity, 3),
                'distance': round(distance, 3),
                'matched_content': results['documents'][0][i][:500] if results['documents'] else ""
            })

        # Sort by similarity descending (should already be sorted, but ensure)
        similar_tippers.sort(key=lambda x: x['similarity_score'], reverse=True)

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
            print(f"{i}. [{meta['id']}] {meta['title'][:60]}...")
            print(f"   Similarity: {result['similarity_score']:.1%}")
            print(f"   Tags: {meta.get('tags', 'N/A')[:50]}")
            print(f"   Created: {meta.get('created_date', 'N/A')[:10]}")
            print()

        return results

    except RuntimeError as e:
        print(f"Error: {e}")
        print("Run 'python -m src.components.tipper_indexer' first to sync tippers.")
        return []


def show_stats():
    """Show index statistics."""
    indexer = TipperIndexer()
    stats = indexer.get_index_stats()

    print("\nTipper Index Stats:")
    print("-" * 40)
    for key, value in stats.items():
        print(f"  {key}: {value}")
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
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python -m src.components.tipper_indexer           # Sync new tippers")
            print("  python -m src.components.tipper_indexer rebuild   # Full rebuild")
            print("  python -m src.components.tipper_indexer search <query>")
            print("  python -m src.components.tipper_indexer stats")
    else:
        # Default: sync tippers (incremental)
        sync_tipper_index(days_back=365)
