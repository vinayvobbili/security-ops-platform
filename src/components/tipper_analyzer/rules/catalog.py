"""ChromaDB-backed detection rules catalog.

Provides semantic search over detection rules from all platforms.
Follows the same pattern as tipper_indexer.py.
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional, Any

import chromadb

from .models import DetectionRule, RuleSearchResult, RuleCatalogSearchResult

logger = logging.getLogger(__name__)

# Paths
ROOT_DIRECTORY = Path(__file__).parent.parent.parent.parent
CHROMA_PATH = ROOT_DIRECTORY / "data" / "transient" / "chroma_rules_catalog"
COLLECTION_NAME = "detection_rules"


class RulesCatalog:
    """ChromaDB-backed searchable catalog of detection rules."""

    def __init__(self):
        self.chroma_path = str(CHROMA_PATH)
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = None

    def _get_embedding_fn(self):
        """Lazy-load the embedding function (reuses OllamaEmbeddingFunction from tipper_indexer)."""
        if self._embedding_fn is None:
            from src.components.tipper_indexer import OllamaEmbeddingFunction
            self._embedding_fn = OllamaEmbeddingFunction()
        return self._embedding_fn

    @property
    def client(self) -> chromadb.PersistentClient:
        """Lazy-load ChromaDB client."""
        if self._client is None:
            CHROMA_PATH.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        """Get or create the rules collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"description": "Detection rules from QRadar, CrowdStrike, Tanium"}
            )
        return self._collection

    def upsert_rules(self, rules: List[DetectionRule]) -> int:
        """Upsert rules into the ChromaDB collection.

        Args:
            rules: List of DetectionRule objects to upsert

        Returns:
            Number of rules upserted
        """
        if not rules:
            return 0

        embedding_fn = self._get_embedding_fn()

        # Process in batches to avoid memory issues
        batch_size = 50
        total_upserted = 0

        for i in range(0, len(rules), batch_size):
            batch = rules[i:i + batch_size]

            ids = [r.rule_id for r in batch]
            documents = [r.to_search_text() for r in batch]
            metadatas = [r.to_metadata() for r in batch]

            try:
                embeddings = embedding_fn(documents)
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    metadatas=metadatas,
                    embeddings=embeddings,
                )
                total_upserted += len(batch)
            except Exception as e:
                logger.error(f"Failed to upsert batch {i//batch_size}: {e}")
                continue

        logger.info(f"Upserted {total_upserted}/{len(rules)} rules into catalog")
        return total_upserted

    def search(self, query: str, k: int = 10, platform: str = None) -> RuleCatalogSearchResult:
        """Search the catalog using hybrid keyword + vector search.

        Args:
            query: Search query text
            k: Number of results to return
            platform: Optional platform filter ("qradar", "crowdstrike", "tanium")

        Returns:
            RuleCatalogSearchResult with matched rules
        """
        if self.collection.count() == 0:
            return RuleCatalogSearchResult(query=query, platform_filter=platform or "")

        results: List[RuleSearchResult] = []
        seen_ids = set()

        # Phase 1: Keyword search (exact matches in name/metadata)
        keyword_results = self._keyword_search(query, k=k * 2, platform=platform)
        for rule, score in keyword_results:
            if rule.rule_id not in seen_ids:
                results.append(RuleSearchResult(rule=rule, score=score, match_type="keyword"))
                seen_ids.add(rule.rule_id)

        # Phase 2: Vector search
        try:
            embedding_fn = self._get_embedding_fn()
            query_embedding = embedding_fn([query])[0]

            where_filter = None
            if platform:
                where_filter = {"platform": platform}

            chroma_results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=min(k * 2, self.collection.count()),
                where=where_filter,
                include=["metadatas", "documents", "distances"]
            )

            if chroma_results and chroma_results.get("ids"):
                for idx, rule_id in enumerate(chroma_results["ids"][0]):
                    if rule_id in seen_ids:
                        continue

                    metadata = chroma_results["metadatas"][0][idx]
                    distance = chroma_results["distances"][0][idx]
                    similarity = 1 / (1 + distance)

                    rule = self._metadata_to_rule(metadata)
                    results.append(RuleSearchResult(rule=rule, score=similarity, match_type="vector"))
                    seen_ids.add(rule_id)

        except Exception as e:
            logger.warning(f"Vector search failed (continuing with keyword results): {e}")

        # Sort by score descending and limit to k
        results.sort(key=lambda r: r.score, reverse=True)
        results = results[:k]

        return RuleCatalogSearchResult(
            query=query,
            results=results,
            total_found=len(results),
            platform_filter=platform or "",
        )

    def _keyword_search(self, query: str, k: int = 20, platform: str = None) -> List[tuple]:
        """Keyword-based search on rule names and metadata.

        Returns list of (DetectionRule, score) tuples.
        """
        matches = []
        query_lower = query.lower()
        query_terms = query_lower.split()

        # Get all documents with metadata
        try:
            where_filter = {"platform": platform} if platform else None
            all_docs = self.collection.get(
                where=where_filter,
                include=["metadatas", "documents"],
                limit=self.collection.count(),
            )
        except Exception:
            return []

        if not all_docs or not all_docs.get("ids"):
            return []

        for idx, rule_id in enumerate(all_docs["ids"]):
            metadata = all_docs["metadatas"][idx]
            document = (all_docs["documents"][idx] or "").lower()
            name = metadata.get("name", "").lower()
            tags = metadata.get("tags", "").lower()
            malware = metadata.get("malware_families", "").lower()
            actors = metadata.get("threat_actors", "").lower()

            # Score based on term matches
            score = 0.0
            for term in query_terms:
                if term in name:
                    score += 0.4  # Name match is strongest
                if term in malware:
                    score += 0.3
                if term in actors:
                    score += 0.3
                if term in tags:
                    score += 0.2
                if term in document:
                    score += 0.1

            if score > 0:
                rule = self._metadata_to_rule(metadata)
                matches.append((rule, min(score, 1.0)))

        # Sort by score and return top k
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:k]

    def _metadata_to_rule(self, metadata: Dict[str, Any]) -> DetectionRule:
        """Convert ChromaDB metadata dict back to a DetectionRule."""
        return DetectionRule(
            rule_id=metadata.get("rule_id", ""),
            platform=metadata.get("platform", ""),
            name=metadata.get("name", ""),
            description="",  # Not stored in metadata to save space
            rule_type=metadata.get("rule_type", ""),
            enabled=metadata.get("enabled", "True") == "True",
            severity=metadata.get("severity", ""),
            tags=[t.strip() for t in metadata.get("tags", "").split(",") if t.strip()],
            malware_families=[m.strip() for m in metadata.get("malware_families", "").split(",") if m.strip()],
            threat_actors=[a.strip() for a in metadata.get("threat_actors", "").split(",") if a.strip()],
            mitre_techniques=[t.strip() for t in metadata.get("mitre_techniques", "").split(",") if t.strip()],
            created_date=metadata.get("created_date", ""),
            modified_date=metadata.get("modified_date", ""),
        )

    def rebuild(self, rules: List[DetectionRule]) -> int:
        """Full collection rebuild (delete and recreate).

        Args:
            rules: Complete list of rules to index

        Returns:
            Number of rules indexed
        """
        logger.info("Rebuilding rules catalog (full rebuild)...")
        try:
            self.client.delete_collection(COLLECTION_NAME)
            self._collection = None  # Reset cached collection
        except Exception:
            pass  # Collection might not exist

        return self.upsert_rules(rules)

    def get_stats(self) -> Dict[str, Any]:
        """Get catalog statistics.

        Returns:
            Dict with count, platform breakdown, etc.
        """
        total = self.collection.count()

        if total == 0:
            return {"total": 0, "platforms": {}, "status": "empty"}

        # Get platform breakdown
        platforms = {}
        for platform in ["qradar", "crowdstrike", "tanium"]:
            try:
                result = self.collection.get(
                    where={"platform": platform},
                    include=[],
                    limit=total,
                )
                platforms[platform] = len(result.get("ids", []))
            except Exception:
                platforms[platform] = 0

        return {
            "total": total,
            "platforms": platforms,
            "status": "ready",
            "storage_path": self.chroma_path,
        }
