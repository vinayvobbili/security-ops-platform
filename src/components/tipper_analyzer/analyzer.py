"""
Core TipperAnalyzer class for tipper novelty analysis.

This module contains the main analysis logic for determining tipper novelty
against historical data.
"""

import logging
import re
import time
from typing import List, Dict, Optional, Any

import services.azdo as azdo
from src.components.tipper_indexer import TipperIndexer
from my_config import get_config

from .models import NoveltyAnalysis, NoveltyLLMResponse, IOCHuntResult, DEFAULT_QRADAR_HUNT_HOURS, DEFAULT_CROWDSTRIKE_HUNT_HOURS
from .formatters import (
    format_analysis_for_display,
    format_analysis_for_azdo,
    format_hunt_results_for_azdo,
    format_single_tool_hunt_for_azdo,
)
from .hunting import hunt_iocs

logger = logging.getLogger(__name__)


class TipperAnalyzer:
    """Analyzes tippers for novelty against historical data."""

    def __init__(self):
        self.indexer = TipperIndexer()
        self._llm = None

    @property
    def llm(self):
        """Lazy load LLM with higher temperature for analysis."""
        if self._llm is None:
            from src.components.tipper_analyzer.llm_init import get_llm_with_temperature
            self._llm = get_llm_with_temperature(0.4)
        return self._llm

    # -------------------------------------------------------------------------
    # Entity History from Similar Tippers
    # -------------------------------------------------------------------------
    def build_entity_history(self, similar_tippers: List[Dict], exclude_tipper_id: str = None) -> tuple:
        """
        Build IOC and malware history in a single pass (one AZDO fetch per tipper).

        Args:
            similar_tippers: List of similar tipper results from find_similar_tippers
            exclude_tipper_id: Tipper ID to exclude (current tipper being analyzed)

        Returns:
            Tuple of (ioc_history, malware_history, history_dates) where:
            - ioc_history: dict mapping entity value (lowercase) -> list of tipper IDs
            - malware_history: dict mapping malware name -> list of tipper IDs
            - history_dates: dict mapping tipper_id -> created_date string
        """
        from src.utils.entity_extractor import extract_entities

        ioc_to_tippers: Dict[str, List[str]] = {}
        malware_to_tippers: Dict[str, List[str]] = {}
        tipper_dates: Dict[str, str] = {}

        for similar in similar_tippers:
            tipper_id = str(similar['metadata'].get('id', ''))
            if not tipper_id:
                continue

            # Skip the current tipper being analyzed
            if exclude_tipper_id and tipper_id == str(exclude_tipper_id):
                continue

            # Fetch full tipper from AZDO (single fetch for both IOCs and malware)
            tipper = self.fetch_tipper_by_id(tipper_id)
            if not tipper:
                logger.debug(f"Could not fetch tipper {tipper_id} for entity history")
                continue

            # Collect created date for recency display
            created_date = tipper.get('fields', {}).get('System.CreatedDate', '')
            if created_date:
                tipper_dates[tipper_id] = created_date

            description = tipper.get('fields', {}).get('System.Description', '')
            if not description:
                continue

            # Extract all entities at once
            entities = extract_entities(description, include_apt_database=False)

            # Collect IOCs
            all_iocs = set()
            all_iocs.update(ip.lower() for ip in entities.ips)
            all_iocs.update(domain.lower() for domain in entities.domains)
            all_iocs.update(h.lower() for h in entities.hashes.get('md5', []))
            all_iocs.update(h.lower() for h in entities.hashes.get('sha1', []))
            all_iocs.update(h.lower() for h in entities.hashes.get('sha256', []))
            all_iocs.update(cve.upper() for cve in entities.cves)

            for ioc in all_iocs:
                if ioc not in ioc_to_tippers:
                    ioc_to_tippers[ioc] = []
                if tipper_id not in ioc_to_tippers[ioc]:
                    ioc_to_tippers[ioc].append(tipper_id)

            # NOTE: Malware family collection removed - vector similarity handles this

        if ioc_to_tippers:
            logger.info(f"Built entity history: {len(ioc_to_tippers)} IOCs across {len(tipper_dates)} tippers")

        return ioc_to_tippers, malware_to_tippers, tipper_dates

    # -------------------------------------------------------------------------
    # Recorded Future Enrichment
    # -------------------------------------------------------------------------
    def enrich_entities_with_rf(self, entities) -> Dict[str, Any]:
        """
        Enrich extracted entities with Recorded Future intelligence.

        Gracefully handles API failures - returns empty dict if RF unavailable.
        Uses parallel API calls for improved performance.

        Args:
            entities: ExtractedEntities object from entity_extractor

        Returns:
            Dictionary with RF enrichment data for each entity type
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from services.recorded_future import RecordedFutureClient

        try:
            client = RecordedFutureClient()
            if not client.is_configured():
                logger.debug("Recorded Future API not configured, skipping enrichment")
                return {}
        except Exception as e:
            logger.warning(f"Could not initialize RF client: {e}")
            return {}

        enrichment = {'actors': [], 'iocs': [], 'extracted_actors': []}

        # Store local APT database info for actors (aliases, region)
        if hasattr(entities, 'threat_actors_enriched'):
            for actor in entities.threat_actors_enriched:
                enrichment['extracted_actors'].append({
                    'name': actor.name,
                    'common_name': actor.common_name,
                    'region': actor.region,
                    'all_names': actor.all_names,
                    'aliases_display': actor.get_aliases_display(max_aliases=5),
                })

        # Define enrichment tasks for parallel execution
        def enrich_actors():
            """Enrich threat actors with RF."""
            actors = []
            if not entities.threat_actors:
                return actors
            logger.info(f"Enriching {len(entities.threat_actors)} threat actor(s) with RF...")
            for actor_name in entities.threat_actors:
                try:
                    result = client.lookup_actor_by_name(actor_name)
                    if 'error' not in result:
                        if result.get('match') == 'single':
                            actor = result.get('actor', {})
                            summary = client.extract_actor_summary(actor)
                            actors.append(summary)
                        elif result.get('match') == 'multiple':
                            actor_list = result.get('actors', [])
                            if actor_list:
                                summary = client.extract_actor_summary(actor_list[0])
                                actors.append(summary)
                except Exception as e:
                    logger.warning(f"RF actor lookup failed for {actor_name}: {e}")
            return actors

        def enrich_ips():
            """Enrich IPs with RF."""
            iocs = []
            if not entities.ips:
                return iocs
            try:
                logger.info(f"Enriching {len(entities.ips)} IP(s) with RF...")
                result = client.enrich_ips(entities.ips)
                if 'error' not in result:
                    ioc_results = client.extract_enrichment_results(result)
                    for ioc in ioc_results:
                        ioc['ioc_type'] = 'IP'
                        iocs.append(ioc)
            except Exception as e:
                logger.warning(f"RF IP enrichment failed: {e}")
            return iocs

        def enrich_domains():
            """Enrich domains with RF."""
            iocs = []
            if not entities.domains:
                return iocs
            try:
                logger.info(f"Enriching {len(entities.domains)} domain(s) with RF...")
                result = client.enrich_domains(entities.domains)
                if 'error' not in result:
                    ioc_results = client.extract_enrichment_results(result)
                    for ioc in ioc_results:
                        ioc['ioc_type'] = 'Domain'
                        iocs.append(ioc)
            except Exception as e:
                logger.warning(f"RF domain enrichment failed: {e}")
            return iocs

        def enrich_hashes():
            """Enrich hashes with RF."""
            iocs = []
            all_hashes = (
                entities.hashes.get('md5', []) +
                entities.hashes.get('sha1', []) +
                entities.hashes.get('sha256', [])
            )
            if not all_hashes:
                return iocs
            try:
                logger.info(f"Enriching {len(all_hashes)} hash(es) with RF...")
                result = client.enrich_hashes(all_hashes)
                if 'error' not in result:
                    ioc_results = client.extract_enrichment_results(result)
                    for ioc in ioc_results:
                        ioc['ioc_type'] = 'Hash'
                        iocs.append(ioc)
            except Exception as e:
                logger.warning(f"RF hash enrichment failed: {e}")
            return iocs

        def enrich_cves():
            """Enrich CVEs with RF."""
            iocs = []
            if not entities.cves:
                return iocs
            try:
                logger.info(f"Enriching {len(entities.cves)} CVE(s) with RF...")
                result = client.enrich(vulnerabilities=entities.cves)
                if 'error' not in result:
                    ioc_results = client.extract_enrichment_results(result)
                    for ioc in ioc_results:
                        ioc['ioc_type'] = 'CVE'
                        iocs.append(ioc)
            except Exception as e:
                logger.warning(f"RF CVE enrichment failed: {e}")
            return iocs

        # Run all enrichment tasks in parallel
        logger.info("Running RF enrichment in parallel...")
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_task = {
                executor.submit(enrich_actors): 'actors',
                executor.submit(enrich_ips): 'ips',
                executor.submit(enrich_domains): 'domains',
                executor.submit(enrich_hashes): 'hashes',
                executor.submit(enrich_cves): 'cves',
            }

            for future in as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    result = future.result()
                    if task_name == 'actors':
                        enrichment['actors'].extend(result)
                    else:
                        enrichment['iocs'].extend(result)
                except Exception as e:
                    logger.warning(f"RF {task_name} enrichment task failed: {e}")

        # Filter to only high-risk IOCs for display
        enrichment['high_risk_iocs'] = [
            ioc for ioc in enrichment['iocs']
            if ioc.get('risk_score', 0) >= 25  # Medium or higher
        ]

        actor_count = len(enrichment['actors'])
        ioc_count = len(enrichment['high_risk_iocs'])
        if actor_count or ioc_count:
            logger.info(f"RF enrichment complete: {actor_count} actors, {ioc_count} notable IOCs")

        return enrichment

    # -------------------------------------------------------------------------
    # Fetch tipper by ID from AZDO
    # -------------------------------------------------------------------------
    def fetch_tipper_by_id(self, tipper_id: str, require_area_path: bool = True) -> Optional[Dict]:
        """Fetch a single tipper from AZDO by ID.

        Args:
            tipper_id: The work item ID to fetch
            require_area_path: If True, only returns work items under the Threat Hunting
                              area path. This prevents typos from fetching unrelated work items.
        """
        from data.data_maps import azdo_area_paths

        area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')

        if require_area_path:
            query = f"""
                SELECT [System.Id], [System.Title], [System.Description],
                       [System.CreatedDate], [System.Tags], [System.State]
                FROM WorkItems
                WHERE [System.Id] = {tipper_id}
                  AND [System.AreaPath] UNDER '{area_path}'
            """
        else:
            query = f"""
                SELECT [System.Id], [System.Title], [System.Description],
                       [System.CreatedDate], [System.Tags], [System.State]
                FROM WorkItems
                WHERE [System.Id] = {tipper_id}
            """

        logger.debug(f"Fetching tipper {tipper_id} from AZDO...")
        results = azdo.fetch_work_items(query)

        if results:
            logger.debug(f"Found tipper {tipper_id}")
            return results[0]

        if require_area_path:
            logger.warning(f"Tipper {tipper_id} not found in Threat Hunting area path")
        else:
            logger.warning(f"Tipper {tipper_id} not found in AZDO")
        return None

    # -------------------------------------------------------------------------
    # Build the analysis prompt
    # -------------------------------------------------------------------------
    def _build_analysis_prompt(
        self,
        new_tipper: Dict,
        similar_tippers: List[Dict],
        rf_enrichment: Dict[str, Any] = None
    ) -> str:
        """Build a structured prompt for the LLM to analyze novelty."""
        fields = new_tipper.get('fields', {})

        # Clean description HTML
        description = fields.get('System.Description', 'No description')
        if description:
            description = re.sub(r'<[^>]+>', ' ', description)
            description = re.sub(r'\s+', ' ', description).strip()

        prompt = f"""You are a threat intelligence analyst. Analyze this NEW tipper against historical similar tippers to determine how novel it is.

## NEW TIPPER (the one to analyze)
**ID**: {new_tipper.get('id', 'Unknown')}
**Title**: {fields.get('System.Title', 'No title')}
**Tags**: {fields.get('System.Tags', 'None')}
**Description**:
{description[:3000]}

---

## SIMILAR HISTORICAL TIPPERS (from our database)

**Similarity Score Guide:**
- 55%+ = Highly similar (likely same campaign/actor)
- 45-55% = Moderately similar (related threat type)
- 35-45% = Loosely related (some shared concepts)
- <35% = Low relevance (different threat category)
"""

        if similar_tippers:
            for similar in similar_tippers:
                meta = similar['metadata']
                tipper_id = meta.get('id', 'Unknown')
                prompt += f"""
### Ticket #{tipper_id} (Similarity: {similar['similarity_score']:.0%})
- **Title**: {meta.get('title', 'No title')}
- **Tags**: {meta.get('tags', 'None')}
- **Created**: {meta.get('created_date', 'Unknown')[:10]}
- **Preview**: {similar.get('matched_content', '')[:500]}
"""
        else:
            prompt += "\n**No similar tippers found in historical database.**\n"

        # Add threat intelligence section (local APT DB + Recorded Future)
        has_extracted = rf_enrichment and rf_enrichment.get('extracted_actors')
        has_rf_actors = rf_enrichment and rf_enrichment.get('actors')
        has_rf_iocs = rf_enrichment and rf_enrichment.get('high_risk_iocs')

        if has_extracted or has_rf_actors or has_rf_iocs:
            prompt += """
---

## THREAT INTELLIGENCE
"""
            # Add extracted threat actors with local alias info
            if has_extracted:
                prompt += "\n### Threat Actors Identified\n"
                for actor in rf_enrichment['extracted_actors']:
                    name = actor.get('name', 'Unknown')
                    common_name = actor.get('common_name', '')
                    region = actor.get('region', '')
                    aliases = actor.get('aliases_display', '')

                    if common_name and common_name != name:
                        prompt += f"- **{name}** (Common Name: {common_name})\n"
                    else:
                        prompt += f"- **{name}**\n"

                    if region:
                        prompt += f"  - Region: {region}\n"
                    if aliases:
                        prompt += f"  - Also Known As: {aliases}\n"

            # Add Recorded Future actor intel (risk scores, targets)
            if has_rf_actors:
                prompt += "\n### Recorded Future Actor Intelligence\n"
                for actor in rf_enrichment['actors']:
                    name = actor.get('name', 'Unknown')
                    risk = actor.get('risk_score', 'N/A')
                    aliases = actor.get('common_names', [])[:3]
                    categories = actor.get('categories', [])
                    targets = actor.get('target_industries', [])[:3]

                    prompt += f"- **{name}** (RF Risk: {risk}/99)\n"
                    if aliases:
                        prompt += f"  - AKA: {', '.join(aliases)}\n"
                    if categories:
                        prompt += f"  - Category: {', '.join(categories)}\n"
                    if targets:
                        prompt += f"  - Targets: {', '.join(targets)}\n"

            # Add IOC intel (high risk only)
            if rf_enrichment.get('high_risk_iocs'):
                prompt += "\n### Notable IOCs Found\n"
                for ioc in rf_enrichment['high_risk_iocs'][:10]:
                    ioc_type = ioc.get('ioc_type', 'Unknown')
                    value = ioc.get('value', 'Unknown')
                    risk = ioc.get('risk_score', 0)
                    level = ioc.get('risk_level', 'Unknown')
                    rules = ioc.get('rules', [])[:2]

                    prompt += f"- **{value}** ({ioc_type}) - Risk: {risk}/99 ({level})\n"
                    if rules:
                        prompt += f"  - Evidence: {', '.join(rules)}\n"

        prompt += """
---

## YOUR TASK

Analyze the NEW tipper against the historical tippers above and provide:

1. **NOVELTY SCORE** (1-10):
   - 1-3: "Seen Before" - Nearly identical to a past tipper, same actor/campaign
   - 4-5: "Familiar" - Similar patterns but some variations
   - 6-7: "Mostly New" - New elements but some familiar aspects
   - 8-10: "Net New" - New threat actor, new TTPs, new campaign

2. **SUMMARY**: Write a 2-3 sentence executive summary. Describe: What is the threat? Who is the actor (if known)? How does it relate to the historical tippers? Reference specific ticket IDs when comparing (e.g., "similar to #1243497").

3. **RECOMMENDATION**: One of:
   - "PRIORITIZE - Novel threat requiring deep investigation"
   - "STANDARD - Review and leverage past analysis"
   - "EXPEDITE - Familiar pattern, apply known playbook"

4. **WHAT'S NEW**: List 1-3 specific elements that make this tipper NOVEL (leave empty if nothing is new):
   - Examples: "New threat actor: APT47", "Novel supply chain attack vector", "First campaign targeting healthcare sector"

5. **WHAT'S FAMILIAR**: List 1-3 specific elements that connect this to PAST tippers (leave empty if nothing is familiar):
   - Reference specific ticket IDs when comparing (e.g., "Same Octo Tempest campaign from #1237886", "Identical phishing TTPs to #1240351")

Focus on the narrative analysis. IOC overlaps are computed separately and will supplement your analysis.
"""
        return prompt

    # -------------------------------------------------------------------------
    # Build analysis from structured LLM response
    # -------------------------------------------------------------------------
    def _build_analysis_from_response(
        self,
        llm_response: NoveltyLLMResponse,
        tipper: Dict,
        similar_tippers: List[Dict],
        ioc_history: Dict[str, List[str]],
        malware_history: Dict[str, List[str]],
        entities,
    ) -> NoveltyAnalysis:
        """Convert LLM response to NoveltyAnalysis.

        LLM provides: novelty_score, novelty_label, summary, recommendation
        Python computes: what_is_new, what_is_familiar, related_tickets
        """
        fields = tipper.get('fields', {})
        tipper_id = str(tipper.get('id', 'Unknown'))
        tipper_title = fields.get('System.Title', 'No title')

        # Parse and format created date: MM/DD/YYYY HH:MM AM/PM ET
        raw_date = fields.get('System.CreatedDate', '')
        if raw_date:
            try:
                from datetime import datetime
                import pytz
                dt = datetime.fromisoformat(raw_date.replace('Z', '+00:00'))
                eastern = pytz.timezone('US/Eastern')
                dt_eastern = dt.astimezone(eastern)
                created_date = dt_eastern.strftime('%m/%d/%Y %I:%M %p ET')
            except Exception:
                created_date = raw_date[:16].replace('T', ' ')
        else:
            created_date = ''

        # --- PYTHON-COMPUTED: Related tickets from vector search ---
        # Only include tickets with similarity >= 55% and limit to top 3 most relevant
        MIN_RELATED_SIMILARITY = 0.55
        MAX_RELATED_TICKETS = 5
        related_tickets = []
        for similar in similar_tippers[:10]:
            similarity_score = similar.get('similarity_score', 0)
            if similarity_score < MIN_RELATED_SIMILARITY:
                continue  # Skip low-similarity results
            meta = similar.get('metadata', {})
            ticket_id = str(meta.get('id', ''))
            if ticket_id and ticket_id != tipper_id:
                related_tickets.append({
                    'id': ticket_id,
                    'title': meta.get('title', ''),
                    'similarity': similarity_score,  # Include for display
                })
                if len(related_tickets) >= MAX_RELATED_TICKETS:
                    break  # Stop after top 3

        # --- PYTHON-COMPUTED: What's Familiar (IOCs in CURRENT tipper that were seen before) ---
        # Only show IOCs that appear in BOTH the current tipper AND historical tippers
        what_is_familiar = []

        # Add LLM-generated reasons for what's familiar
        if llm_response.whats_familiar_reasons:
            what_is_familiar.extend(llm_response.whats_familiar_reasons)

        if ioc_history and entities:
            # Get IOCs from the CURRENT tipper
            current_iocs = set()
            current_iocs.update(ioc.lower() for ioc in entities.ips)
            current_iocs.update(ioc.lower() for ioc in entities.domains)
            for hash_list in entities.hashes.values():
                current_iocs.update(ioc.lower() for ioc in hash_list)

            # Find IOCs that are in BOTH current tipper AND historical tippers
            history_iocs_lower = {ioc.lower(): ioc for ioc in ioc_history.keys()}
            shared_iocs = current_iocs & set(history_iocs_lower.keys())

            if shared_iocs:
                from services.virustotal import VirusTotalClient
                vt_client = VirusTotalClient()

                # Separate by type for VT filtering
                shared_domains = [ioc for ioc in shared_iocs if '.' in ioc and not ioc.replace('.', '').isdigit() and len(ioc) < 64]
                shared_ips = [ioc for ioc in shared_iocs if ioc.replace('.', '').isdigit()]
                shared_hashes = [ioc for ioc in shared_iocs if len(ioc) in (32, 40, 64) and ioc.isalnum()]

                # Filter to only huntworthy IOCs (have VT detections)
                logger.info(f"Filtering {len(shared_domains)} shared domains, {len(shared_ips)} shared IPs via VT...")
                huntworthy = vt_client.filter_huntworthy_iocs(
                    domains=shared_domains[:30],
                    ips=shared_ips[:20],
                    hashes=shared_hashes[:20],
                    max_checks=50,
                )
                huntworthy_set = set(huntworthy['domains'] + huntworthy['ips'] + huntworthy['hashes'])

                # Group huntworthy shared IOCs by the tickets they appeared in
                ticket_iocs = {}  # ticket_id -> list of IOCs
                for ioc_lower in shared_iocs:
                    if ioc_lower not in huntworthy_set:
                        continue  # Skip benign IOCs
                    # Get original case IOC and its ticket IDs
                    original_ioc = history_iocs_lower.get(ioc_lower, ioc_lower)
                    ticket_ids = ioc_history.get(original_ioc, [])
                    for tid in ticket_ids:
                        if tid not in ticket_iocs:
                            ticket_iocs[tid] = []
                        ticket_iocs[tid].append(original_ioc)

                # Create familiar items with ticket references
                for tid, iocs in sorted(ticket_iocs.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
                    ioc_sample = iocs[:3]
                    ioc_display = ', '.join(f"`{ioc[:20]}...`" if len(ioc) > 20 else f"`{ioc}`" for ioc in ioc_sample)
                    more = f" (+{len(iocs) - 3} more)" if len(iocs) > 3 else ""
                    what_is_familiar.append(f"Shared IOCs with #{tid}: {ioc_display}{more}")

        # NOTE: Malware family matching removed - vector similarity handles this better.
        # If two tippers mention "ClawdBot", ChromaDB embeddings will match them.

        # --- PYTHON-COMPUTED: What's New (IOCs/entities NOT seen before) ---
        what_is_new = []

        # Add LLM-generated reasons for what's new
        if llm_response.whats_new_reasons:
            what_is_new.extend(llm_response.whats_new_reasons)

        if entities:
            all_current_iocs = set()
            all_current_iocs.update(entities.ips)
            all_current_iocs.update(entities.domains)
            for hash_list in entities.hashes.values():
                all_current_iocs.update(hash_list)

            seen_iocs = set(ioc_history.keys()) if ioc_history else set()
            new_iocs = all_current_iocs - seen_iocs

            if new_iocs:
                # Filter new IOCs through VT to exclude benign domains
                from services.virustotal import VirusTotalClient
                vt_client = VirusTotalClient()

                new_domains = [ioc for ioc in new_iocs if '.' in ioc and not ioc.replace('.', '').isdigit() and len(ioc) < 64]
                new_ips = [ioc for ioc in new_iocs if ioc.replace('.', '').isdigit()]
                new_hashes = [ioc for ioc in new_iocs if len(ioc) in (32, 40, 64) and ioc.isalnum()]

                logger.info(f"Filtering {len(new_domains)} new domains, {len(new_ips)} new IPs via VT...")
                huntworthy_new = vt_client.filter_huntworthy_iocs(
                    domains=new_domains[:30],
                    ips=new_ips[:20],
                    hashes=new_hashes[:20],
                    max_checks=50,
                )
                huntworthy_new_set = set(huntworthy_new['domains'] + huntworthy_new['ips'] + huntworthy_new['hashes'])

                # Only include huntworthy new IOCs
                filtered_new_iocs = [ioc for ioc in new_iocs if ioc in huntworthy_new_set or ioc.lower() in huntworthy_new_set]

                if filtered_new_iocs:
                    new_sample = filtered_new_iocs[:5]
                    new_display = ', '.join(f"`{ioc[:20]}...`" if len(ioc) > 20 else f"`{ioc}`" for ioc in new_sample)
                    more = f" (+{len(filtered_new_iocs) - 5} more)" if len(filtered_new_iocs) > 5 else ""
                    what_is_new.append(f"First-time IOCs: {new_display}{more}")

        # Log raw LLM response at debug level
        logger.debug(f"Raw LLM response: {llm_response.model_dump_json()}")

        return NoveltyAnalysis(
            tipper_id=tipper_id,
            tipper_title=tipper_title,
            created_date=created_date,
            novelty_score=llm_response.novelty_score,
            novelty_label=llm_response.novelty_label,
            summary=llm_response.summary,
            what_is_new=what_is_new,
            what_is_familiar=what_is_familiar,
            related_tickets=related_tickets,
            recommendation=llm_response.recommendation,
            raw_llm_response=llm_response.model_dump_json(indent=2),
        )

    # -------------------------------------------------------------------------
    # Generate Actionable Steps
    # -------------------------------------------------------------------------
    def _generate_actionable_steps(
        self,
        analysis: NoveltyAnalysis,
        entities,
        rf_enrichment: Dict[str, Any],
        mitre_gaps: List[str],
    ) -> List[Dict[str, str]]:
        """Generate specific actionable recommendations based on analysis.

        Returns list of dicts with keys: action, priority, detail
        """
        steps = []

        # High-risk IOCs to block
        if rf_enrichment and rf_enrichment.get('high_risk_iocs'):
            high_risk = [ioc for ioc in rf_enrichment['high_risk_iocs'] if ioc.get('risk_score', 0) >= 65]
            if high_risk:
                ips_to_block = [ioc['value'] for ioc in high_risk if ioc.get('ioc_type') == 'IP'][:5]
                domains_to_block = [ioc['value'] for ioc in high_risk if ioc.get('ioc_type') == 'Domain'][:5]

                if ips_to_block:
                    steps.append({
                        'action': 'Block high-risk IPs',
                        'priority': 'HIGH',
                        'detail': f"Add to firewall blocklist: {', '.join(ips_to_block)}"
                    })
                if domains_to_block:
                    steps.append({
                        'action': 'Block malicious domains',
                        'priority': 'HIGH',
                        'detail': f"Add to DNS sinkhole/blocklist: {', '.join(domains_to_block)}"
                    })

        # MITRE detection gaps
        if mitre_gaps:
            # Group by tactic category if possible
            steps.append({
                'action': 'Create detection rules',
                'priority': 'MEDIUM',
                'detail': f"No existing coverage for: {', '.join(mitre_gaps[:5])}"
            })

        # Novel threat - recommend deeper investigation
        if analysis.novelty_score >= 7:
            steps.append({
                'action': 'Conduct threat hunt',
                'priority': 'HIGH',
                'detail': 'Novel threat identified - proactive hunt recommended for historical activity'
            })
        elif analysis.novelty_score >= 5 and analysis.related_tickets:
            ticket_refs = ', '.join(f"#{t.get('id', '')}" for t in analysis.related_tickets[:3])
            steps.append({
                'action': 'Review related tickets',
                'priority': 'MEDIUM',
                'detail': f"Check tickets {ticket_refs} for prior analysis"
            })

        # CVEs to patch
        if entities and entities.cves:
            steps.append({
                'action': 'Verify patch status',
                'priority': 'HIGH' if len(entities.cves) > 2 else 'MEDIUM',
                'detail': f"Check vulnerability status for: {', '.join(entities.cves[:5])}"
            })

        # Add IOCs to watchlist (for lower risk)
        if rf_enrichment and rf_enrichment.get('high_risk_iocs'):
            medium_risk = [ioc for ioc in rf_enrichment['high_risk_iocs']
                          if 25 <= ioc.get('risk_score', 0) < 65]
            if medium_risk:
                steps.append({
                    'action': 'Add to watchlist',
                    'priority': 'LOW',
                    'detail': f"{len(medium_risk)} medium-risk IOCs for monitoring"
                })

        return steps

    # -------------------------------------------------------------------------
    # Main analysis method
    # -------------------------------------------------------------------------
    def analyze_tipper(
        self,
        tipper_id: str = None,
        tipper_text: str = None,
        similar_count: int = 10
    ) -> NoveltyAnalysis:
        """
        Analyze a tipper for novelty.

        Args:
            tipper_id: AZDO work item ID (fetches from AZDO)
            tipper_text: Raw text to analyze (alternative to ID)
            similar_count: Number of similar tippers to retrieve

        Returns:
            NoveltyAnalysis with scores, findings, and recommendations
        """
        # Get the tipper data
        if tipper_id:
            logger.info(f"Analyzing tipper #{tipper_id}...")
            tipper = self.fetch_tipper_by_id(tipper_id)
            if not tipper:
                raise ValueError(f"Tipper {tipper_id} not found in AZDO")
            query_text = self.indexer.extract_tipper_text(tipper)
        elif tipper_text:
            logger.info("Analyzing raw threat text...")
            tipper = {
                'id': 'text-input',
                'fields': {
                    'System.Title': tipper_text[:100],
                    'System.Description': tipper_text,
                    'System.Tags': ''
                }
            }
            query_text = tipper_text
        else:
            raise ValueError("Must provide either tipper_id or tipper_text")

        # Find similar tippers
        logger.info("Searching for similar historical tippers...")
        try:
            similar_tippers = self.indexer.find_similar_tippers(query_text, k=similar_count)

            # Filter out the current tipper if it's in the results (self-match from cache)
            if tipper_id:
                similar_tippers = [
                    t for t in similar_tippers
                    if str(t.get('metadata', {}).get('id', '')) != str(tipper_id)
                ]

            # Filter out low-similarity matches (noise reduction)
            # Keep matches above 35% similarity - below this threshold, matches are
            # typically unrelated threats that happen to share generic terminology
            MIN_SIMILARITY = 0.35
            similar_tippers = [
                t for t in similar_tippers
                if t.get('similarity_score', 0) >= MIN_SIMILARITY
            ]
            logger.info(f"Found {len(similar_tippers)} similar tippers (≥{MIN_SIMILARITY:.0%} similarity)")
        except RuntimeError as e:
            logger.warning(f"Could not search index: {e}")
            similar_tippers = []

        # Build IOC and malware history from similar tippers (single pass)
        # Exclude current tipper to avoid marking its own IOCs/malware as "familiar"
        ioc_history = {}
        malware_history = {}
        history_dates = {}
        if similar_tippers:
            logger.info("Building entity history from similar tippers...")
            try:
                ioc_history, malware_history, history_dates = self.build_entity_history(
                    similar_tippers, exclude_tipper_id=tipper_id
                )
            except Exception as e:
                logger.warning(f"Could not build entity history: {e}")

        # Extract entities and enrich with Recorded Future
        # Use full description for entity extraction (query_text is truncated for embedding)
        rf_enrichment = {}
        entities = None
        try:
            from src.utils.entity_extractor import extract_entities
            full_description = tipper.get('fields', {}).get('System.Description', '')
            entity_text = full_description if full_description else query_text
            logger.info("Extracting entities from tipper text...")
            entities = extract_entities(entity_text)

            if not entities.is_empty():
                logger.info(f"Entities found: {entities.summary()}")
                rf_enrichment = self.enrich_entities_with_rf(entities)
            else:
                logger.info("No entities found to enrich")
        except Exception as e:
            logger.warning(f"Entity extraction/enrichment failed (continuing without): {e}")

        # Compute MITRE ATT&CK coverage gaps (check directly against rules catalog)
        mitre_techniques = []
        mitre_covered = []
        mitre_gaps = []
        mitre_rules = {}  # technique_id -> [rule info dicts]
        rules_by_term = {}  # Keep for compatibility

        if entities and entities.mitre_techniques:
            mitre_techniques = entities.mitre_techniques
            logger.info(f"Found {len(mitre_techniques)} MITRE techniques in tipper: {', '.join(mitre_techniques[:5])}")

            # Get all techniques covered by our detection rules catalog
            catalog = None
            try:
                from src.components.tipper_analyzer.rules.catalog import RulesCatalog
                catalog = RulesCatalog()
                covered_by_rules = catalog.get_covered_techniques()
            except Exception as e:
                logger.debug(f"Rules catalog unavailable: {e}")
                covered_by_rules = set()

            # Determine which tipper techniques are covered vs gaps
            for tech in mitre_techniques:
                if tech.upper() in covered_by_rules:
                    mitre_covered.append(tech)
                else:
                    mitre_gaps.append(tech)

            # Fetch the actual rules for covered techniques
            if mitre_covered and catalog:
                try:
                    rules_by_tech = catalog.get_rules_by_technique(mitre_covered)
                    for tech, rules in rules_by_tech.items():
                        # Convert DetectionRule objects to simple dicts for storage
                        mitre_rules[tech] = [
                            {
                                'name': r.name,
                                'platform': r.platform,
                                'rule_type': r.rule_type or 'rule',
                                'severity': r.severity or '',
                            }
                            for r in rules[:5]  # Limit to 5 rules per technique
                        ]
                    logger.info(f"Retrieved rules for {len(mitre_rules)} covered MITRE techniques")
                except Exception as e:
                    logger.warning(f"Failed to get rules by technique: {e}")

            if mitre_gaps:
                logger.info(f"MITRE gaps ({len(mitre_gaps)}): {', '.join(mitre_gaps[:5])}{'...' if len(mitre_gaps) > 5 else ''}")
            else:
                logger.info("All MITRE techniques have existing detection coverage")

        # Build prompt and call LLM
        # Filter similar_tippers to the same criteria used for Related Tickets display
        # This ensures LLM only references tickets that will actually be shown
        MIN_RELATED_SIMILARITY = 0.55
        MAX_RELATED_TICKETS = 5
        tippers_for_llm = [
            t for t in similar_tippers
            if t.get('similarity_score', 0) >= MIN_RELATED_SIMILARITY
        ][:MAX_RELATED_TICKETS]
        prompt = self._build_analysis_prompt(tipper, tippers_for_llm, rf_enrichment)
        logger.debug(f"Analysis prompt ({len(prompt)} chars): {prompt[:500]}...")

        logger.info("Generating novelty analysis with LLM...")
        if not self.llm:
            raise RuntimeError("LLM not initialized. Ensure Pokedex state manager is running.")

        start_time = time.time()

        # Use structured output to guarantee valid JSON response
        structured_llm = self.llm.with_structured_output(NoveltyLLMResponse)
        logger.info("Sending request to LLM (this may take 30-60 seconds)...")
        llm_response = structured_llm.invoke(prompt)
        generation_time = time.time() - start_time
        logger.info(f"LLM response received in {generation_time:.1f}s")

        # Convert structured response to NoveltyAnalysis (Python computes overlaps)
        analysis = self._build_analysis_from_response(
            llm_response, tipper, similar_tippers, ioc_history, malware_history, entities
        )
        analysis.generation_time = generation_time
        analysis.rf_enrichment = rf_enrichment  # Attach RF enrichment to analysis
        analysis.ioc_history = ioc_history  # Attach IOC history for novelty display
        analysis.malware_history = malware_history  # Attach malware history for novelty display
        analysis.history_dates = history_dates  # Attach tipper dates for recency display

        # Store current tipper's malware families and total IOC counts
        if entities is not None:
            analysis.current_malware = entities.malware_families
            analysis.total_iocs_extracted = {
                'ips': len(entities.ips),
                'domains': len(entities.domains),
                'urls': len(entities.urls),
                'filenames': len(entities.filenames),
                'hashes': (len(entities.hashes.get('md5', [])) +
                          len(entities.hashes.get('sha1', [])) +
                          len(entities.hashes.get('sha256', []))),
                'cves': len(entities.cves),
            }
        # Store detection rules coverage results
        if rules_by_term:
            analysis.existing_rules = rules_by_term

        # Store MITRE coverage analysis
        analysis.mitre_techniques = mitre_techniques
        analysis.mitre_covered = mitre_covered
        analysis.mitre_gaps = mitre_gaps
        analysis.mitre_rules = mitre_rules

        # Generate actionable steps based on analysis findings
        analysis.actionable_steps = self._generate_actionable_steps(
            analysis=analysis,
            entities=entities,
            rf_enrichment=rf_enrichment,
            mitre_gaps=mitre_gaps,
        )

        logger.info(f"Analysis complete: {analysis.novelty_label} ({analysis.novelty_score}/10)")

        return analysis

    # -------------------------------------------------------------------------
    # Format output for display (delegates to formatters module)
    # -------------------------------------------------------------------------
    def format_analysis_for_display(self, analysis: NoveltyAnalysis, source: str = "on-demand") -> str:
        """Format analysis result for human-readable display."""
        return format_analysis_for_display(analysis, source)

    def format_analysis_for_azdo(self, analysis: NoveltyAnalysis) -> str:
        """Format analysis as HTML for AZDO comment."""
        return format_analysis_for_azdo(analysis)

    def post_analysis_to_tipper(self, analysis: NoveltyAnalysis) -> bool:
        """
        Post the analysis as a comment on the AZDO tipper.

        Args:
            analysis: The NoveltyAnalysis to post

        Returns:
            True if comment was posted successfully
        """
        if analysis.tipper_id == 'text-input':
            logger.warning("Cannot post comment - analysis was from text input, not a real tipper")
            return False

        from services.azdo import add_comment_to_work_item

        html_comment = self.format_analysis_for_azdo(analysis)

        logger.info(f"Posting analysis to tipper #{analysis.tipper_id}...")
        result = add_comment_to_work_item(int(analysis.tipper_id), html_comment)

        if result:
            logger.info(f"Successfully posted analysis to tipper #{analysis.tipper_id}")
            return True
        else:
            logger.error(f"Failed to post analysis to tipper #{analysis.tipper_id}")
            return False

    # -------------------------------------------------------------------------
    # IOC Section Extraction
    # -------------------------------------------------------------------------
    def _extract_ioc_section(self, description: str) -> str:
        """Extract only the IOC section from a tipper description.

        Tippers have a dedicated 'INDICATORS OF COMPROMISE (IOCs)' section
        that contains the actual IOCs to hunt. This prevents extracting
        benign domains/IPs mentioned in the narrative text.

        Args:
            description: Full tipper HTML description

        Returns:
            Text from the IOC section only, or full description if no IOC section found
        """
        import re

        # Strip HTML tags
        text = re.sub(r'<[^>]+>', ' ', description)
        text = re.sub(r'&nbsp;', ' ', text)
        text = re.sub(r'\s+', ' ', text)

        # Look for IOC section markers
        ioc_markers = [
            r'INDICATORS?\s+OF\s+COMPROMISE',
            r'IOCs?\s*:',
            r'Indicators?\s*:',
        ]

        ioc_start = -1
        for marker in ioc_markers:
            match = re.search(marker, text, re.IGNORECASE)
            if match:
                ioc_start = match.start()
                break

        if ioc_start == -1:
            # No IOC section found, return full text
            logger.debug("No IOC section found, using full description")
            return text

        # Find end of IOC section (next major section or end)
        # Note: &amp; may appear as literal text after HTML tag stripping
        end_markers = [
            r'MITRE\s+ATT(?:&amp;|&)?CK',
            r'DETECTION\s+RECOMMENDATIONS?',
            r'RECOMMENDATIONS?',
            r'REFERENCES?',
            r'APPENDIX',
        ]

        ioc_end = len(text)
        for marker in end_markers:
            match = re.search(marker, text[ioc_start + 50:], re.IGNORECASE)
            if match:
                potential_end = ioc_start + 50 + match.start()
                if potential_end < ioc_end:
                    ioc_end = potential_end

        ioc_section = text[ioc_start:ioc_end]
        logger.debug(f"Extracted IOC section: {len(ioc_section)} chars")
        return ioc_section

    # -------------------------------------------------------------------------
    # IOC Hunting (delegates to hunting module)
    # -------------------------------------------------------------------------
    def hunt_iocs(
        self,
        tipper_id: str = None,
        tipper_text: str = None,
        qradar_hours: int = DEFAULT_QRADAR_HUNT_HOURS,
        crowdstrike_hours: int = DEFAULT_CROWDSTRIKE_HUNT_HOURS,
        tools: List[str] = None,
        on_tool_complete=None,
    ) -> IOCHuntResult:
        """
        Hunt for tipper IOCs across multiple security tools.

        Args:
            tipper_id: Azure DevOps tipper work item ID
            tipper_text: Raw tipper text (alternative to tipper_id)
            qradar_hours: Hours to search back in QRadar (default 7 days)
            crowdstrike_hours: Hours to search back in CrowdStrike (default 30 days)
            tools: List of tools to hunt in (default: all)
                   Options: "qradar", "crowdstrike", "abnormal"
            on_tool_complete: Optional callback called when each tool finishes.
                              Used to post each tool's results as a separate AZDO comment.

        Returns:
            IOCHuntResult with hits from all tools
        """
        from datetime import datetime
        from src.utils.entity_extractor import extract_entities

        # Get tipper details
        if tipper_id:
            tipper = self.fetch_tipper_by_id(tipper_id)
            if not tipper:
                return IOCHuntResult(
                    tipper_id=tipper_id,
                    tipper_title="Unknown",
                    hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    total_iocs_searched=0,
                    total_hits=0,
                    errors=[f"Could not fetch tipper #{tipper_id}"]
                )
            title = tipper.get('fields', {}).get('System.Title', 'Unknown')
            description = tipper.get('fields', {}).get('System.Description', '')
        else:
            tipper_id = 'text-input'
            title = 'Text Input'
            description = tipper_text or ''

        # Extract IOCs only from the IOC section (not full description)
        ioc_section = self._extract_ioc_section(description)
        entities = extract_entities(ioc_section, include_apt_database=False)

        return hunt_iocs(
            entities=entities,
            tipper_id=tipper_id,
            tipper_title=title,
            qradar_hours=qradar_hours,
            crowdstrike_hours=crowdstrike_hours,
            tools=tools,
            on_tool_complete=on_tool_complete,
        )

    def format_hunt_results_for_azdo(self, result: IOCHuntResult) -> str:
        """Format IOC hunt results as HTML for AZDO comment."""
        return format_hunt_results_for_azdo(result)

    def post_hunt_results_to_tipper(self, result: IOCHuntResult, rf_enrichment: dict = None) -> bool:
        """Post IOC hunt results as a comment on the AZDO tipper."""
        if result.tipper_id == 'text-input':
            logger.warning("Cannot post hunt results - input was text, not a real tipper")
            return False

        from services.azdo import add_comment_to_work_item

        html_comment = format_hunt_results_for_azdo(result, rf_enrichment=rf_enrichment)

        logger.info(f"Posting IOC hunt results to tipper #{result.tipper_id}...")
        posted = add_comment_to_work_item(int(result.tipper_id), html_comment)

        if posted:
            logger.info(f"Successfully posted hunt results to tipper #{result.tipper_id}")
            return True
        else:
            logger.error(f"Failed to post hunt results to tipper #{result.tipper_id}")
            return False

    # -------------------------------------------------------------------------
    # Full Analysis Flow (analyze + post + hunt + post)
    # -------------------------------------------------------------------------
    def analyze_and_post(self, tipper_id: str, source: str = "command", room_id: str = None) -> dict:
        """
        Full tipper analysis flow: analyze, post to AZDO, return brief summary immediately.
        IOC hunt runs in background and posts results to AZDO when done.

        Args:
            tipper_id: The AZDO tipper work item ID
            source: Source identifier for display formatting ("command", "hourly", etc.)
            room_id: Optional Webex room ID; if provided, a follow-up message is sent after hunt results are posted

        Returns:
            dict with 'content' (brief Webex output), 'analysis' object, and token metrics
        """
        import threading

        # Run the analysis
        analysis = self.analyze_tipper(tipper_id=tipper_id)

        # Post full analysis to AZDO
        azdo_ok = self.post_analysis_to_tipper(analysis)
        if azdo_ok:
            logger.info(f"Posted analysis to AZDO tipper #{tipper_id}")
        else:
            logger.warning(f"Failed to post analysis to AZDO tipper #{tipper_id}")

        # Build full Webex output (returned immediately, IOC hunt runs in background)
        display_output = self.format_analysis_for_display(analysis, source=source)

        if not azdo_ok:
            display_output += "\n⚠️ _Failed to post analysis to AZDO work item_\n"

        # Launch IOC hunt in background thread
        # Each tool posts its results as a SEPARATE AZDO comment when it completes
        rf_enrichment = analysis.rf_enrichment

        def _run_ioc_hunt():
            from services.azdo import add_comment_to_work_item

            def _post_tool_result(tool_result, tid, ttitle, hours, total_iocs, searched_iocs):
                """Callback: post each tool's results immediately when it completes."""
                try:
                    html = format_single_tool_hunt_for_azdo(
                        tool_result=tool_result,
                        tipper_id=tid,
                        tipper_title=ttitle,
                        search_hours=hours,
                        total_iocs_searched=total_iocs,
                        searched_iocs=searched_iocs,
                        rf_enrichment=rf_enrichment,
                    )
                    if add_comment_to_work_item(int(tid), html):
                        logger.info(f"[bg] Posted {tool_result.tool_name} results ({tool_result.total_hits} hits) to #{tid}")
                    else:
                        logger.warning(f"[bg] Failed to post {tool_result.tool_name} results to #{tid}")
                except Exception as e:
                    logger.error(f"[bg] Error posting {tool_result.tool_name} results: {e}")

            try:
                logger.info(f"[bg] Running IOC hunt for tipper #{tipper_id}...")
                # Each tool's results are posted via _post_tool_result callback as they complete
                hunt_result = self.hunt_iocs(
                    tipper_id=tipper_id,
                    on_tool_complete=_post_tool_result,
                )

                if hunt_result.total_hits > 0:
                    logger.warning(f"[bg] IOC HITS FOUND for tipper #{tipper_id}: {hunt_result.total_hits} total hits")

                # Send Webex notification with combined summary after all hunts complete
                if room_id:
                    logger.info(f"[bg] Sending hunt summary to Webex room_id: {room_id}")
                    try:
                        from webexpythonsdk import WebexAPI
                        from my_config import get_config
                        from .formatters import format_hunt_results_for_webex
                        config = get_config()
                        azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"
                        msg = format_hunt_results_for_webex(hunt_result, tipper_id, azdo_url)
                        webex = WebexAPI(access_token=config.webex_bot_access_token_pokedex)
                        webex.messages.create(roomId=room_id, markdown=msg)
                        logger.info(f"[bg] Sent hunt summary to Webex for #{tipper_id}")
                    except Exception as wx_err:
                        logger.warning(f"[bg] Failed to send Webex notification: {wx_err}")

            except Exception as hunt_err:
                logger.error(f"[bg] IOC hunt failed for tipper #{tipper_id}: {hunt_err}")

        hunt_thread = threading.Thread(target=_run_ioc_hunt, daemon=True, name=f"ioc-hunt-{tipper_id}")
        hunt_thread.start()

        return {
            'content': display_output,
            'analysis': analysis,
            'input_tokens': analysis.input_tokens,
            'output_tokens': analysis.output_tokens,
            'total_tokens': analysis.total_tokens,
            'prompt_time': analysis.prompt_time,
            'generation_time': analysis.generation_time,
            'tokens_per_sec': analysis.tokens_per_sec
        }
