"""
Core TipperAnalyzer class for tipper novelty analysis.

This module contains the main analysis logic for determining tipper novelty
against historical data.
"""

import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import List, Dict, Optional, Any

import services.azdo as azdo
from src.components.tipper_indexer import TipperIndexer
from .formatters import (
    format_analysis_for_display,
    format_analysis_for_azdo,
    format_hunt_results_for_azdo,
    format_exposure_for_azdo,
    format_exposure_for_webex,
    format_veracode_exposure_for_azdo,
    format_veracode_exposure_for_webex,
    format_jfrog_exposure_for_azdo,
    format_jfrog_exposure_for_webex,
    format_behavioral_hunt_for_azdo,
    format_behavioral_hunt_for_webex,
)
from .hunting import hunt_iocs, run_behavioral_hunt
from .models import (
    NoveltyAnalysis, NoveltyLLMResponse, IOCHuntResult, BehavioralHuntResult,
    DEFAULT_QRADAR_HUNT_HOURS, DEFAULT_CROWDSTRIKE_HUNT_HOURS, DEFAULT_THREAT_HUNT_HOURS,
)

logger = logging.getLogger(__name__)

# Maximum time (seconds) to wait for an LLM response before giving up.
# Prevents the bot from hanging for hours if the Mac/Ollama tunnel is down.
LLM_TIMEOUT_SECONDS = 300

# Per-attempt deadline for the novelty pass. The compact template output stops
# cleanly in ~20-40s; a longer wait means the model is wedged/truncating, so cut
# it and retry rather than burn the whole run's budget on one attempt.
NOVELTY_LLM_ATTEMPT_TIMEOUT = 90
NOVELTY_LLM_MAX_ATTEMPTS = 3


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
        Build IOC, malware, TTP, and actor history in a single pass (one AZDO fetch per tipper).

        Args:
            similar_tippers: List of similar tipper results from find_similar_tippers
            exclude_tipper_id: Tipper ID to exclude (current tipper being analyzed)

        Returns:
            Tuple of (ioc_history, malware_history, history_dates, ttp_history, actor_history) where:
            - ioc_history: dict mapping entity value (lowercase) -> list of tipper IDs
            - malware_history: dict mapping malware name -> list of tipper IDs
            - history_dates: dict mapping tipper_id -> created_date string
            - ttp_history: dict mapping MITRE technique ID (uppercase) -> list of tipper IDs
            - actor_history: dict mapping actor name (lowercase) -> list of tipper IDs
        """
        from src.utils.entity_extractor import extract_entities

        ioc_to_tippers: Dict[str, List[str]] = {}
        malware_to_tippers: Dict[str, List[str]] = {}
        ttp_to_tippers: Dict[str, List[str]] = {}
        actor_to_tippers: Dict[str, List[str]] = {}
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

            # Collect malware families
            for family in entities.malware_families:
                if family not in malware_to_tippers:
                    malware_to_tippers[family] = []
                if tipper_id not in malware_to_tippers[family]:
                    malware_to_tippers[family].append(tipper_id)

            # Collect MITRE techniques
            for technique in entities.mitre_techniques:
                tech_upper = technique.upper()
                if tech_upper not in ttp_to_tippers:
                    ttp_to_tippers[tech_upper] = []
                if tipper_id not in ttp_to_tippers[tech_upper]:
                    ttp_to_tippers[tech_upper].append(tipper_id)

            # Collect threat actors
            actor_names = set()
            if entities.threat_actors_enriched:
                for ta in entities.threat_actors_enriched:
                    actor_names.add((ta.common_name or ta.name).lower())
            elif entities.threat_actors:
                actor_names.update(a.lower() for a in entities.threat_actors)
            for actor in actor_names:
                if actor not in actor_to_tippers:
                    actor_to_tippers[actor] = []
                if tipper_id not in actor_to_tippers[actor]:
                    actor_to_tippers[actor].append(tipper_id)

        if ioc_to_tippers or malware_to_tippers or ttp_to_tippers or actor_to_tippers:
            logger.info(
                f"Built entity history: {len(ioc_to_tippers)} IOCs, {len(malware_to_tippers)} malware, "
                f"{len(ttp_to_tippers)} TTPs, {len(actor_to_tippers)} actors across {len(tipper_dates)} tippers"
            )

        return ioc_to_tippers, malware_to_tippers, tipper_dates, ttp_to_tippers, actor_to_tippers

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
            rf_enrichment: Dict[str, Any] = None,
            veracode_exposure: Dict[str, Any] = None
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
                breakdown = similar.get('similarity_breakdown')
                # Show multi-signal context if available
                if breakdown:
                    signals = []
                    signals.append(f"Narrative: {breakdown.narrative_similarity:.0%}")
                    if breakdown.shared_ioc_count:
                        signals.append(f"IOC: {breakdown.shared_ioc_count} shared")
                    else:
                        signals.append("IOC: 0 shared")
                    if breakdown.shared_ttp_count:
                        signals.append(f"TTP: {breakdown.shared_ttp_count} shared")
                    if breakdown.shared_actors:
                        signals.append(f"Actor: {', '.join(breakdown.shared_actors[:2])}")
                    if breakdown.shared_malware:
                        signals.append(f"Malware: {', '.join(breakdown.shared_malware[:2])}")
                    signal_str = ' | '.join(signals)
                    prompt += f"""
### Ticket #{tipper_id} (Composite: {similar['similarity_score']:.0%} | {signal_str})
- **Title**: {meta.get('title', 'No title')}
- **Tags**: {meta.get('tags', 'None')}
- **Created**: {meta.get('created_date', 'Unknown')[:10]}
- **Preview**: {similar.get('matched_content', '')[:500]}
"""
                else:
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

        # Internal application exposure from Veracode SCA — which of OUR own
        # applications carry an open-source component affected by a CVE in this
        # tipper. This is confirmed first-party exposure, so it should weigh
        # heavily on severity and the recommended response.
        if veracode_exposure and veracode_exposure.get('exposed'):
            cves = veracode_exposure.get('cves') or {}
            packages = veracode_exposure.get('packages') or {}
            n = veracode_exposure.get('affected_app_count', 0)
            prompt += "\n---\n\n## INTERNAL APPLICATION EXPOSURE (Veracode SCA)\n"
            prompt += (
                f"\n{n} of our own application(s) carry an open-source component "
                "matching this tipper, per Veracode Software Composition Analysis.\n"
            )
            if cves:
                prompt += "\nAffected by CVE(s) in this tipper:\n"
                for cve_id in sorted(cves.keys()):
                    names = sorted({a.get('application') or '?' for a in cves[cve_id]})
                    shown = ", ".join(names[:25])
                    if len(names) > 25:
                        shown += f", +{len(names) - 25} more"
                    prompt += f"- **{cve_id}** → {shown}\n"
            if packages:
                prompt += "\nCarrying a named package from this tipper (open SCA finding):\n"
                for pkg in sorted(packages.keys()):
                    names = sorted({a.get('application') or '?' for a in packages[pkg]})
                    shown = ", ".join(names[:25])
                    if len(names) > 25:
                        shown += f", +{len(names) - 25} more"
                    prompt += f"- **{pkg}** → {shown}\n"
            prompt += (
                "\nTreat this as **confirmed internal exposure** (not hypothetical) "
                "when judging novelty, severity, and recommended actions.\n"
            )

        prompt += """
---

## YOUR TASK

Analyze the NEW tipper against the historical tippers above and provide:

1. **NOVELTY SCORE** (1-10) — base this ONLY on similarity to the historical tippers above, NOT your own knowledge:
   - 1-3: "Seen Before" - Nearly identical to a historical tipper above, same actor/campaign
   - 4-5: "Familiar" - Similar patterns to historical tippers above but some variations
   - 6-7: "Mostly New" - New elements with some overlap to historical tippers above
   - 8-10: "Net New" - No meaningful overlap with historical tippers above
   - If no historical tippers were provided, the score should be 8-10.

2. **SUMMARY**: Write a 2-3 sentence executive summary. Describe: What is the threat? Who is the actor (if known)? How does it relate to the historical tippers? Reference specific ticket IDs when comparing (e.g., "similar to #1243497").

3. **RECOMMENDATION**: One of:
   - "PRIORITIZE - Novel threat requiring deep investigation"
   - "STANDARD - Review and leverage past analysis"
   - "EXPEDITE - Familiar pattern, apply known playbook"

4. **WHAT'S NEW**: List 1-3 specific elements that make this tipper NOVEL (leave empty if nothing is new):
   - Examples: "New threat actor: APT47", "Novel supply chain attack vector", "First campaign targeting healthcare sector"

5. **WHAT'S FAMILIAR**: List 1-3 specific elements that connect this to the HISTORICAL TIPPERS shown above (leave empty if nothing is familiar):
   - ONLY base this on the historical tippers provided above. Do NOT use your own knowledge to determine familiarity.
   - If no similar historical tippers were provided, this list MUST be empty.
   - Reference specific ticket IDs (e.g., "Same Octo Tempest campaign from #1237886", "Identical phishing TTPs to #1240351")

6. **VULNERABLE PRODUCTS** (vulnerable_products): Extract CVE-less vulnerable products. Default is EMPTY. Populate only when every check below passes.

   **CHECK #1 — CVE EXCLUSION (most important, do this FIRST):**
   Scan the entire tipper for any CVE-YYYY-NNNNN pattern. For each candidate product you're thinking of extracting, ask: "Does any CVE in this tipper cover this product?" If YES — even if the CVE is 5 paragraphs away, even if the product also has an explicit version range, even if the tipper reads like a vulnerability advisory — DROP IT. CVEs are extracted to a separate field and drive the same downstream correlation. Duplicating them here causes false-positive asset scans.

   If the tipper's whole narrative is "$PRODUCT has vulnerability CVE-YYYY-NNNNN" then vulnerable_products must be EMPTY. Only when a product's vulnerability has NO corresponding CVE anywhere in the text does it belong here.

   **CHECK #2 — DEFENDER ASSET:**
   The product must be something a defender would deploy or run (server software, application, library, OS, firmware, appliance). Exclude:
   - Tools the attacker USES as tradecraft ("actor deploys Cobalt Strike" — not vulnerable, just operated by attacker).
   - Products the attacker TARGETS without a direct vulnerability claim against the product ("malicious Chrome extensions steal sessions" — Chrome is not stated as vulnerable).
   - Attacker-owned infrastructure ("attacker's VPS runs Laravel Ignition" — attacker's own server, not a defender asset).
   - Domains, URLs, IP addresses, hostnames.
   - Generic categories ("Linux servers", "web applications", "RDP").
   - Victims of credential theft / session hijacking / social engineering — not vulnerability claims.

   **CHECK #3 — VULNERABILITY IS IN THE PRODUCT ITSELF, NOT ITS DISTRIBUTION CHANNEL:**
   The tipper must claim a defect inside the product's own code, config, or design. Supply-chain incidents — where the *hosting infrastructure*, *update server*, *package registry*, *code-signing cert*, or *download site* was compromised to ship a trojanized build — do NOT qualify. The legitimate product has no flaw in these cases; the issue is a poisoned distribution channel. Omit the product.

   **WRONG examples — every one of these was extracted by a prior run and was wrong:**
   - Title "Marimo Authentication Bypass Exploit (CVE-2026-39987)" + body "affecting Marimo versions 0.20.4 and earlier" → CVE present → vulnerable_products MUST be empty.
   - Title "Critical Authentication Bypass in nginx-ui (CVE-2026-33032)" + body "nginx-ui v2.3.4" → CVE present → empty.
   - Body "actively exploiting CVE-2026-35616 and CVE-2026-21643 in FortiClient Enterprise Management Server (EMS) versions 7.4.5 through 7.4.6" → CVEs present → empty. The version range does NOT override CVE exclusion.
   - Body "108 malicious Chrome extensions harvest Google account identities" → Chrome not vulnerable → empty.
   - Body "exposed attack server running Ubuntu 20.04 LTS with OpenSSH 8.2p1" → attacker infra → empty.
   - Title "Notepad++ Supply Chain Attack via Compromised Hosting Infrastructure" + body "threat actors compromised shared hosting to distribute malicious Notepad++ updates" → supply-chain compromise of the *distribution channel*, not a flaw in Notepad++ itself → empty.

   **RIGHT examples:**
   - Body "exploits an unpatched vulnerability in Adobe Reader 26.00121367; no CVE has been assigned" + NO CVE anywhere in tipper → product=Adobe Reader, vendor=Adobe, version_constraint=26.00121367.
   - Body "Apache Struts versions before 2.5.30 are vulnerable" with NO CVE anywhere in tipper → product=Apache Struts, version_constraint=< 2.5.30.

Focus on the narrative analysis. IOC overlaps are computed separately and will supplement your analysis.
"""
        return prompt

    # -------------------------------------------------------------------------
    # Build analysis from structured LLM response
    # -------------------------------------------------------------------------
    def _generate_novelty_response(self, prompt: str):
        """Primary novelty generator: plain invoke + concise JSON template + fence strip.

        We deliberately do NOT use ``with_structured_output(method="json_mode")``
        here. langchain's json_mode injects the verbose JSON Schema, and
        GLM-4.7-Flash responds by echoing the schema back instead of an instance —
        slow (it generates to the token cap) and reliably unparseable (returns
        None). A concise *filled-in template* elicits a valid object in one shot.

        ``self.llm`` is the the chat model (GPT-4.1 primary, m1 GLM
        fallback): a plain invoke falls over to m1 on a the LLM gateway failure, while a
        parse failure just retries the primary. The concise-template approach
        works on either backend. Returns a NoveltyLLMResponse, or None if every
        attempt fails (caller then posts a degraded card).
        """
        from my_bot.utils.llm_factory import strip_json_fence

        schema_prompt = (
            prompt
            + "\n\n## OUTPUT FORMAT (CRITICAL)\n"
            "Return ONLY a JSON object (no markdown fences, no commentary) with "
            "EXACTLY these keys:\n"
            "{\n"
            '  "novelty_score": <integer 1-10>,\n'
            '  "novelty_label": <one of "Seen Before","Familiar","Mostly New","Net New">,\n'
            '  "summary": "<2-3 sentence executive summary>",\n'
            '  "recommendation": "<one of \'PRIORITIZE - ...\', \'STANDARD - ...\', \'EXPEDITE - ...\'>",\n'
            '  "whats_new_reasons": ["<reason>"],\n'
            '  "whats_familiar_reasons": ["<reason>"],\n'
            '  "vulnerable_products": [{"product": "<name>", "vendor": "<name or null>", "version_constraint": "<range or null>"}]\n'
            "}\n"
            "For vulnerable_products use the empty list [] unless the tipper names a "
            "product as vulnerable with NO CVE assigned (see instructions above); each "
            "entry MUST be an object with those keys, never a bare string.\n"
            "Start with `{` and end with `}`."
        )
        for attempt in range(NOVELTY_LLM_MAX_ATTEMPTS):
            # Fresh executor per attempt with shutdown(wait=False): if an invoke
            # wedges, future.result() times out and we move on without blocking
            # on the orphaned thread (the http client kills it at its own timeout).
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(self.llm.invoke, schema_prompt)
                raw = future.result(timeout=NOVELTY_LLM_ATTEMPT_TIMEOUT)
                content = getattr(raw, "content", None) or str(raw)
                cleaned = strip_json_fence(content)
                return NoveltyLLMResponse.model_validate_json(cleaned)
            except FuturesTimeoutError:
                logger.warning(
                    f"Novelty LLM attempt {attempt + 1}/{NOVELTY_LLM_MAX_ATTEMPTS} "
                    f"timed out after {NOVELTY_LLM_ATTEMPT_TIMEOUT}s"
                )
            except Exception as gen_err:
                logger.warning(
                    f"Novelty LLM attempt {attempt + 1}/{NOVELTY_LLM_MAX_ATTEMPTS} "
                    f"failed: {type(gen_err).__name__}: {str(gen_err)[:160]}"
                )
            finally:
                executor.shutdown(wait=False)
        return None

    def _build_analysis_from_response(
            self,
            llm_response: NoveltyLLMResponse,
            tipper: Dict,
            similar_tippers: List[Dict],
            ioc_history: Dict[str, List[str]],
            malware_history: Dict[str, List[str]],
            entities,
            ttp_history: Dict[str, List[str]] = None,
            actor_history: Dict[str, List[str]] = None,
            global_entity_sets: Dict = None,
    ) -> NoveltyAnalysis:
        """Convert LLM response to NoveltyAnalysis.

        LLM provides: novelty_score, novelty_label, summary, recommendation
        Python computes: what_is_new, what_is_familiar, related_tickets

        global_entity_sets: sets of all TTPs/IOCs/actors seen across ALL indexed tippers.
        Used for "first-time" (What's New) detection so that an entity seen in an
        unrelated tipper isn't falsely labelled first-time just because it didn't surface
        in the top-K cosine similarity results.
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
        # Only include tickets with similarity >= 35% and limit to top 5 most relevant
        MIN_RELATED_SIMILARITY = 0.35
        MAX_RELATED_TICKETS = 5
        related_tickets = []
        for similar in similar_tippers[:10]:
            similarity_score = similar.get('similarity_score', 0)
            if similarity_score < MIN_RELATED_SIMILARITY:
                continue  # Skip low-similarity results
            meta = similar.get('metadata', {})
            ticket_id = str(meta.get('id', ''))
            if ticket_id and ticket_id != tipper_id:
                ticket_data = {
                    'id': ticket_id,
                    'title': meta.get('title', ''),
                    'similarity': similarity_score,  # Composite score for display
                    'narrative_similarity': similar.get('narrative_similarity', similarity_score),
                    'similarity_breakdown': similar.get('similarity_breakdown'),
                    'created_date': meta.get('created_date', ''),
                    'state': meta.get('state', ''),
                    'tags': meta.get('tags', ''),
                    'assigned_to': meta.get('assigned_to', ''),
                }
                related_tickets.append(ticket_data)
                if len(related_tickets) >= MAX_RELATED_TICKETS:
                    break  # Stop after top 3

        # --- PYTHON-COMPUTED: What's Familiar (IOCs in CURRENT tipper that were seen before) ---
        # Only show IOCs that appear in BOTH the current tipper AND historical tippers
        what_is_familiar = []

        # Add LLM-generated reasons for what's familiar
        if llm_response is not None and llm_response.whats_familiar_reasons:
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

        # If what_is_familiar is still empty but related tickets exist, note the narrative-level
        # similarity so the section doesn't contradict the Related Tickets shown below it.
        if not what_is_familiar and related_tickets:
            refs = ', '.join(f"#{t['id']} ({int(t['similarity'] * 100)}%)" for t in related_tickets[:3])
            what_is_familiar.append(
                f"Narrative-level similarity to: {refs} (different attack vector/malware family — no shared IOCs or TTPs)"
            )

        # --- PYTHON-COMPUTED: What's New (IOCs/entities NOT seen before) ---
        what_is_new = []

        # Add LLM-generated reasons for what's new
        if llm_response is not None and llm_response.whats_new_reasons:
            what_is_new.extend(llm_response.whats_new_reasons)

        if entities:
            all_current_iocs = set()
            all_current_iocs.update(entities.ips)
            all_current_iocs.update(entities.domains)
            for hash_list in entities.hashes.values():
                all_current_iocs.update(hash_list)

            # Use global IOC set when available; fall back to similarity-based history
            seen_iocs = (
                global_entity_sets.get('iocs', set()) if global_entity_sets
                else set(ioc_history.keys()) if ioc_history else set()
            )
            new_iocs = {ioc.lower() for ioc in all_current_iocs} - seen_iocs

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

        # --- PYTHON-COMPUTED: First-time MITRE TTPs (not seen in ANY indexed tipper) ---
        if entities and entities.mitre_techniques:
            # Use global TTP set when available; fall back to similarity-based history
            seen_ttps = (
                global_entity_sets.get('ttps', set()) if global_entity_sets
                else set(ttp_history.keys()) if ttp_history else set()
            )
            current_ttps = {t.upper() for t in entities.mitre_techniques}
            new_ttps = current_ttps - seen_ttps
            if new_ttps:
                ttp_sample = sorted(new_ttps)[:5]
                ttp_display = ', '.join(f"`{t}`" for t in ttp_sample)
                more = f" (+{len(new_ttps) - 5} more)" if len(new_ttps) > 5 else ""
                what_is_new.append(f"First-time TTPs: {ttp_display}{more}")

        # --- PYTHON-COMPUTED: First-time threat actors (not seen in ANY indexed tipper) ---
        if entities:
            current_actors = set()
            if entities.threat_actors_enriched:
                for ta in entities.threat_actors_enriched:
                    current_actors.add((ta.common_name or ta.name).lower())
            elif entities.threat_actors:
                current_actors.update(a.lower() for a in entities.threat_actors)
            if current_actors:
                # Use global actor set when available; fall back to similarity-based history
                seen_actors = (
                    global_entity_sets.get('actors', set()) if global_entity_sets
                    else set(actor_history.keys()) if actor_history else set()
                )
                new_actors = current_actors - seen_actors
                if new_actors:
                    # Display with original casing
                    actor_display = ', '.join(f"`{a}`" for a in sorted(new_actors)[:5])
                    more = f" (+{len(new_actors) - 5} more)" if len(new_actors) > 5 else ""
                    what_is_new.append(f"First-time actors: {actor_display}{more}")

        # Degraded path: novelty LLM produced no parseable output on either Mac.
        # Post a card from the deterministic signals (IOC/TTP/actor overlap +
        # vector similarity) rather than dropping it entirely.
        if llm_response is None:
            return NoveltyAnalysis(
                tipper_id=tipper_id,
                tipper_title=tipper_title,
                created_date=created_date,
                novelty_score=0,
                novelty_label="Analysis Unavailable",
                summary=(
                    "⚠️ Automated novelty analysis was unavailable for this tipper — "
                    "the LLM produced no parseable response on both the primary (m1) "
                    "and secondary (studio1) models. The signals below are computed "
                    "deterministically from IOC/TTP/actor overlap and vector similarity; "
                    "review manually."
                ),
                what_is_new=what_is_new,
                what_is_familiar=what_is_familiar,
                related_tickets=related_tickets,
                recommendation="STANDARD - Review manually; LLM summary unavailable",
                raw_llm_response="",
                vulnerable_products=[],
            )

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
            vulnerable_products=[vp.model_dump() for vp in llm_response.vulnerable_products],
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
            similar_count: int = 20
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

        # Extract entities FIRST — needed for both multi-signal similarity search
        # and Recorded Future enrichment. Uses full description (not truncated query_text).
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

        # Veracode SCA exposure — do any of OUR applications carry an open-source
        # component affected by a CVE in this tipper? Computed here (before the
        # prompt) so the LLM can reason about confirmed first-party exposure. The
        # CVE->apps index is cached (6h TTL), so this is a dict lookup after the
        # first build. Best-effort; never blocks analysis.
        veracode_exposure = None
        try:
            cve_ids = list(entities.cves) if entities else []
            packages = list(getattr(entities, "packages", []) or []) if entities else []
            if cve_ids or packages:
                from services.veracode import exposure as veracode_exposure_lookup
                veracode_exposure = veracode_exposure_lookup(cve_ids=cve_ids, packages=packages)
                if veracode_exposure.get('exposed'):
                    logger.info(
                        f"Veracode SCA: {veracode_exposure.get('affected_app_count')} app(s) exposed "
                        f"across {len(veracode_exposure.get('cves') or {})} CVE(s) + "
                        f"{len(veracode_exposure.get('packages') or {})} named package(s)"
                    )
        except Exception as e:
            logger.warning(f"Veracode SCA exposure check failed (continuing without): {e}")

        # JFrog Xray exposure — sibling to Veracode, but for build/registry
        # artifacts: do any of our JFrog artifacts ship a component affected by a
        # CVE in this tipper? Answered on demand via the Xray Reports API (inert
        # until the token carries the Manage-Reports permission). Best-effort;
        # never blocks analysis.
        jfrog_exposure = None
        try:
            if cve_ids:
                from services.jfrog import exposure as jfrog_exposure_lookup
                jfrog_exposure = jfrog_exposure_lookup(cve_ids=cve_ids)
                if jfrog_exposure.get('exposed'):
                    logger.info(
                        f"JFrog Xray: {jfrog_exposure.get('affected_artifact_count')} artifact(s) "
                        f"exposed across {len(jfrog_exposure.get('cves') or {})} CVE(s)"
                    )
        except Exception as e:
            logger.warning(f"JFrog Xray exposure check failed (continuing without): {e}")

        # Find similar tippers with multi-signal scoring
        # Pass entities so find_similar_tippers can compute IOC/TTP/actor overlap
        logger.info("Searching for similar historical tippers...")
        try:
            similar_tippers = self.indexer.find_similar_tippers(
                query_text, k=similar_count, query_entities=entities
            )

            # Filter out the current tipper if it's in the results (self-match from cache)
            if tipper_id:
                similar_tippers = [
                    t for t in similar_tippers
                    if str(t.get('metadata', {}).get('id', '')) != str(tipper_id)
                ]

            # Filter out low-similarity matches (noise reduction)
            # Keep matches above 35% composite similarity
            MIN_SIMILARITY = 0.35
            similar_tippers = [
                t for t in similar_tippers
                if t.get('similarity_score', 0) >= MIN_SIMILARITY
            ]
            logger.info(f"Found {len(similar_tippers)} similar tippers (≥{MIN_SIMILARITY:.0%} similarity)")
        except RuntimeError as e:
            logger.warning(f"Could not search index: {e}")
            similar_tippers = []

        # Build IOC, malware, TTP, and actor history from similar tippers (single pass)
        # Used for "What's Familiar" (overlaps with specific related tickets)
        ioc_history = {}
        malware_history = {}
        history_dates = {}
        ttp_history = {}
        actor_history = {}
        if similar_tippers:
            logger.info("Building entity history from similar tippers...")
            try:
                ioc_history, malware_history, history_dates, ttp_history, actor_history = self.build_entity_history(
                    similar_tippers, exclude_tipper_id=tipper_id
                )
            except Exception as e:
                logger.warning(f"Could not build entity history: {e}")

        # Global entity sets from ALL tippers — used for "first-time" (What's New) detection.
        # This is separate from similar_tippers: a TTP seen in an unrelated tipper still
        # shouldn't be labelled "first-time" just because it didn't surface in the top-K results.
        global_entity_sets = {}
        try:
            global_entity_sets = self.indexer.fingerprint_store.get_global_entity_sets(
                exclude_tipper_id=tipper_id
            )
            logger.info(
                f"Global entity sets: {len(global_entity_sets.get('ttps', set()))} TTPs, "
                f"{len(global_entity_sets.get('iocs', set()))} IOCs, "
                f"{len(global_entity_sets.get('actors', set()))} actors across all tippers"
            )
        except Exception as e:
            logger.warning(f"Could not fetch global entity sets (falling back to similar-only): {e}")

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
        # Use same threshold as Related Tickets display so LLM can reference all shown tickets
        MIN_RELATED_SIMILARITY = 0.35
        MAX_RELATED_TICKETS = 5
        tippers_for_llm = [
            t for t in similar_tippers
            if t.get('similarity_score', 0) >= MIN_RELATED_SIMILARITY
        ][:MAX_RELATED_TICKETS]
        prompt = self._build_analysis_prompt(tipper, tippers_for_llm, rf_enrichment, veracode_exposure)
        logger.debug(f"Analysis prompt ({len(prompt)} chars): {prompt[:500]}...")

        logger.info("Generating novelty analysis with LLM...")
        if not self.llm:
            raise RuntimeError("LLM not initialized. Ensure Pokedex state manager is running.")

        start_time = time.time()

        # Generate the structured novelty response via a concise template + fence
        # strip (NOT json_mode — see _generate_novelty_response for why GLM can't
        # handle langchain's schema injection). self.llm fails over to studio1
        # Qwen only on a connection error.
        llm_response = self._generate_novelty_response(prompt)
        generation_time = time.time() - start_time

        if llm_response is None:
            # No parseable JSON after retries (+ Qwen failover if GLM was down).
            # Don't drop the ticket — _build_analysis_from_response posts a
            # degraded card from the deterministic (Python-computed) signals.
            logger.error(
                f"Novelty LLM produced no parseable JSON after {generation_time:.1f}s "
                "(retries + studio1 failover) — building card from deterministic signals only"
            )
        else:
            logger.info(f"LLM response received in {generation_time:.1f}s")

        # Convert structured response to NoveltyAnalysis (Python computes overlaps)
        analysis = self._build_analysis_from_response(
            llm_response, tipper, similar_tippers, ioc_history, malware_history, entities,
            ttp_history=ttp_history, actor_history=actor_history,
            global_entity_sets=global_entity_sets,
        )
        analysis.generation_time = generation_time
        analysis.rf_enrichment = rf_enrichment  # Attach RF enrichment to analysis
        analysis.veracode_exposure = veracode_exposure  # Reused by post_exposure_to_tipper (avoids re-lookup)
        analysis.jfrog_exposure = jfrog_exposure  # Reused by post_exposure_to_tipper (avoids re-lookup)
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

        # Attach extracted entities so downstream consumers (CVE exposure thread,
        # IOC hunt) can read entities.cves etc. without re-extracting.
        analysis.entities = entities

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

        # Register this tipper's hashes for daily replay so hosts offline at
        # hunt time still get swept on subsequent days. Best-effort: a failure
        # here must not block the hourly hunt + Webex notification path.
        try:
            from src.components.tipper_replay import enqueue as enqueue_replay
            replay_iocs = [(h, "hash") for kind in ("sha256", "sha1", "md5")
                           for h in (entities.hashes.get(kind) or [])]
            if replay_iocs and tipper_id != "text-input":
                enqueue_replay(str(tipper_id), title, replay_iocs)
        except Exception as exc:
            logger.warning(f"tipper-replay enqueue skipped for #{tipper_id}: {exc}")

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
    # Behavioral Threat Hunting (LLM-authored TTP queries; distinct from IOC sweep)
    # -------------------------------------------------------------------------
    def run_threat_hunt(
            self,
            tipper_id: str = None,
            tipper_text: str = None,
            hours: int = DEFAULT_THREAT_HUNT_HOURS,
            platforms: list = None,
    ) -> BehavioralHuntResult:
        """Author + validate + execute behavioral (TTP) hunts for a tipper.

        Unlike hunt_iocs (which sweeps known indicators), this reasons over the
        full tipper narrative to write behavioral hunt queries, repairs them via
        the LLM on validation/compile errors, and runs the valid ones. By default
        it auto-runs across BOTH SIEMs — CrowdStrike LogScale (CQL) and Cortex
        XSIAM (XQL) — tagging each hunt with its dialect.
        """
        from datetime import datetime

        if tipper_id:
            tipper = self.fetch_tipper_by_id(tipper_id)
            if not tipper:
                return BehavioralHuntResult(
                    tipper_id=str(tipper_id), tipper_title="Unknown",
                    hunt_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    search_hours=hours, errors=[f"Could not fetch tipper #{tipper_id}"],
                )
            title = tipper.get('fields', {}).get('System.Title', 'Unknown')
            narrative = tipper.get('fields', {}).get('System.Description', '')
        else:
            tipper_id = 'text-input'
            title = 'Text Input'
            narrative = tipper_text or ''

        # Behavioral hunts reason over the FULL narrative (not just the IOC block),
        # and reuse the analyzer's in-house FailoverChatModel. Auto-run on every
        # configured SIEM dialect.
        return run_behavioral_hunt(
            tipper_id=tipper_id,
            tipper_title=title,
            narrative=narrative,
            hours=hours,
            llm=self.llm,
            platforms=platforms,
        )

    def post_threat_hunt_to_tipper(self, result: BehavioralHuntResult) -> bool:
        """Post behavioral threat-hunt results as a (separate, clearly-labelled) AZDO comment."""
        if result.tipper_id == 'text-input':
            logger.warning("Cannot post threat-hunt results - input was text, not a real tipper")
            return False
        from services.azdo import add_comment_to_work_item
        html_comment = format_behavioral_hunt_for_azdo(result)
        logger.info(f"Posting behavioral threat-hunt results to tipper #{result.tipper_id}...")
        posted = add_comment_to_work_item(int(result.tipper_id), html_comment)
        if posted:
            logger.info(f"Successfully posted threat-hunt results to tipper #{result.tipper_id}")
        else:
            logger.error(f"Failed to post threat-hunt results to tipper #{result.tipper_id}")
        return bool(posted)

    def post_exposure_to_tipper(self, tipper_id: str, cve_ids: list,
                                 parent_id: str = None,
                                 vulnerable_products: list = None,
                                 veracode_exposure: dict = None,
                                 jfrog_exposure: dict = None) -> bool:
        """Correlate CVEs against Tanium installed software and comment on the tipper.

        Always posts an AZDO comment — including the "nothing to check" stub
        when the tipper has no CVEs and no vulnerable_products, so the audit
        trail on the story shows we considered exposure. When there are
        findings, also sends a loud Webex notification to the tipper analysis
        room — threaded as a reply to parent_id when provided so it appears
        under the original analysis message instead of as a standalone room post.

        Returns True if the AZDO comment was posted, False otherwise.
        """
        vulnerable_products = vulnerable_products or []
        if tipper_id == 'text-input':
            logger.warning("Cannot post exposure - input was text, not a real tipper")
            return False

        try:
            from src.components.cve_exposure import correlate_cves, CorrelationResult
            from services.azdo import add_comment_to_work_item
            from my_config import get_config
            config = get_config()

            if not cve_ids and not vulnerable_products:
                logger.info(
                    f"[exposure] Nothing to check for tipper #{tipper_id} "
                    f"(no CVEs, no vulnerable_products) — posting stub"
                )
                result = CorrelationResult(records=[], scanned=False, skip_reason="no_input")
            else:
                from services.tanium import TaniumClient
                logger.info(
                    f"[exposure] Correlating {len(cve_ids)} CVE(s) + "
                    f"{len(vulnerable_products)} tipper-flagged product(s) for tipper #{tipper_id}..."
                )
                client = TaniumClient(instance="cloud")
                result = correlate_cves(
                    cve_ids,
                    tanium_client=client,
                    vulnerable_products=vulnerable_products,
                )
            records = result.records

            html_comment = format_exposure_for_azdo(cve_ids, result)

            # Veracode SCA exposure — sibling to the Tanium endpoint check: which
            # of our *applications* carry an open-source component affected by
            # these CVE(s). Reuse the value computed during analysis (passed in)
            # when available; otherwise compute now. Either way the CVE->apps
            # index is cached (6h TTL), so this never blocks the Tanium comment.
            if veracode_exposure is None and cve_ids:
                try:
                    from services.veracode import cve_exposure as veracode_cve_exposure
                    veracode_exposure = veracode_cve_exposure(cve_ids)
                except Exception as vc_err:
                    logger.warning(f"[exposure] Veracode SCA check failed for #{tipper_id}: {vc_err}")
            if veracode_exposure:
                try:
                    vc_html = format_veracode_exposure_for_azdo(veracode_exposure)
                    if vc_html:
                        html_comment = html_comment + "\n" + vc_html
                except Exception as vc_err:
                    logger.warning(f"[exposure] Veracode AZDO formatting failed for #{tipper_id}: {vc_err}")

            # JFrog Xray exposure — registry/build-artifact sibling to Veracode.
            # Reuse the value computed during analysis; otherwise compute now.
            if jfrog_exposure is None and cve_ids:
                try:
                    from services.jfrog import cve_exposure as jfrog_cve_exposure
                    jfrog_exposure = jfrog_cve_exposure(cve_ids)
                except Exception as jf_err:
                    logger.warning(f"[exposure] JFrog Xray check failed for #{tipper_id}: {jf_err}")
            if jfrog_exposure:
                try:
                    jf_html = format_jfrog_exposure_for_azdo(jfrog_exposure)
                    if jf_html:
                        html_comment = html_comment + "\n" + jf_html
                except Exception as jf_err:
                    logger.warning(f"[exposure] JFrog AZDO formatting failed for #{tipper_id}: {jf_err}")

            posted = add_comment_to_work_item(int(tipper_id), html_comment)
            confirmed = sum(1 for r in records if r.confidence == "confirmed")
            if posted:
                logger.info(
                    f"[exposure] Posted to tipper #{tipper_id}: "
                    f"{confirmed} confirmed, {len(records)-confirmed} potential "
                    f"(scanned={result.scanned}, skip_reason={result.skip_reason})"
                )
            else:
                logger.error(f"[exposure] Failed to post AZDO comment on tipper #{tipper_id}")

            # Loud Webex notification only on findings — reply-threaded to the
            # tipper analysis room. Both Detection Engineering / Threat Hunting
            # and Platform / Vulnerability Management teams read this room, so
            # a single send reaches both audiences.
            veracode_webex = format_veracode_exposure_for_webex(veracode_exposure) if veracode_exposure else ""
            jfrog_webex = format_jfrog_exposure_for_webex(jfrog_exposure) if jfrog_exposure else ""
            extra_webex = "\n\n".join(b for b in (veracode_webex, jfrog_webex) if b)
            if records or extra_webex:
                try:
                    from webexpythonsdk import WebexAPI
                    azdo_url = (
                        f"https://dev.azure.com/{config.azdo_org}/"
                        f"{config.azdo_de_project}/_workitems/edit/{tipper_id}"
                    )
                    webex_md = format_exposure_for_webex(cve_ids, records, tipper_id, azdo_url) if records else ""
                    if extra_webex:
                        if webex_md:
                            webex_md = webex_md + "\n\n" + extra_webex
                        else:
                            webex_md = (
                                f"🛡️ CVE exposure for tipper [#{tipper_id}]({azdo_url})\n\n"
                                + extra_webex
                            )
                    if webex_md:
                        tipper_room = getattr(config, "webex_room_id_threat_tipper_analysis", None)
                        if tipper_room:
                            kwargs = {"roomId": tipper_room, "markdown": webex_md}
                            if parent_id:
                                kwargs["parentId"] = parent_id
                            WebexAPI(access_token=config.webex_bot_access_token_pokedex).messages.create(**kwargs)
                            logger.info(
                                f"[exposure] Sent to tipper analysis room "
                                f"(reply={'yes' if parent_id else 'no'})"
                            )
                        else:
                            logger.warning("[exposure] webex_room_id_threat_tipper_analysis not configured")
                except Exception as wx_err:
                    logger.warning(f"[exposure] Webex notification failed for #{tipper_id}: {wx_err}")

            return posted
        except Exception as e:
            logger.error(f"[exposure] Correlation failed for tipper #{tipper_id}: {e}", exc_info=True)
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

        # Send the primary analysis message to the tipper analysis room and
        # capture its ID — used as parentId so follow-up exposure messages
        # appear as a reply chain under the analysis instead of separate posts.
        parent_msg_id = None
        try:
            from my_config import get_config as _get_config
            from .utils import linkify_work_items_markdown
            _cfg = _get_config()
            tipper_room = getattr(_cfg, "webex_room_id_threat_tipper_analysis", None)
            if tipper_room:
                from webexpythonsdk import WebexAPI
                from .webex_retry import send_with_retry
                webex_md = linkify_work_items_markdown(display_output)
                webex = WebexAPI(access_token=_cfg.webex_bot_access_token_pokedex)
                msg = send_with_retry(webex, tipper_room, webex_md)
                parent_msg_id = getattr(msg, "id", None)
                logger.info(f"Sent analysis to tipper analysis room (msg_id={parent_msg_id})")
        except Exception as wx_err:
            # In-process retries exhausted (e.g. a longer Webex egress outage).
            # Park this card so the next scheduled run re-sends it instead of
            # silently dropping it from the room.
            logger.warning(f"Failed to send analysis to tipper room: {wx_err}")
            try:
                from .webex_retry import enqueue_failed
                enqueue_failed(tipper_id)
            except Exception as q_err:  # noqa: BLE001
                logger.warning(f"Failed to enqueue tipper #{tipper_id} for retry: {q_err}")

        # Launch IOC hunt in background thread
        # Posts one combined comment after all tools complete
        rf_enrichment = analysis.rf_enrichment

        def _run_ioc_hunt():
            try:
                logger.info(f"[bg] Running IOC hunt for tipper #{tipper_id}...")
                hunt_result = self.hunt_iocs(tipper_id=tipper_id)

                if hunt_result.total_hits > 0:
                    logger.warning(f"[bg] IOC HITS FOUND for tipper #{tipper_id}: {hunt_result.total_hits} total hits")

                # Post one combined comment to AZDO
                self.post_hunt_results_to_tipper(hunt_result, rf_enrichment=rf_enrichment)

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

        # Behavioral threat hunt — LLM-authored TTP queries, distinct from the IOC
        # sweep above. Runs in its own thread and posts a separate, clearly-labelled
        # AZDO comment + Webex summary.
        def _run_threat_hunt():
            try:
                logger.info(f"[bg] Running behavioral threat hunt for tipper #{tipper_id}...")
                th_result = self.run_threat_hunt(tipper_id=tipper_id)

                if th_result.total_hits > 0:
                    logger.warning(f"[bg] BEHAVIORAL HUNT HITS for tipper #{tipper_id}: {th_result.total_hits} event(s)")

                # Only comment when there's something to say (hunts authored or errors)
                if th_result.hunts or th_result.errors:
                    self.post_threat_hunt_to_tipper(th_result)

                if room_id and th_result.hunts:
                    try:
                        from webexpythonsdk import WebexAPI
                        from my_config import get_config
                        config = get_config()
                        azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"
                        msg = format_behavioral_hunt_for_webex(th_result, tipper_id, azdo_url)
                        WebexAPI(access_token=config.webex_bot_access_token_pokedex).messages.create(
                            roomId=room_id, markdown=msg)
                        logger.info(f"[bg] Sent threat-hunt summary to Webex for #{tipper_id}")
                    except Exception as wx_err:
                        logger.warning(f"[bg] Failed to send threat-hunt Webex notification: {wx_err}")
            except Exception as th_err:
                logger.error(f"[bg] Behavioral threat hunt failed for tipper #{tipper_id}: {th_err}")

        threat_hunt_thread = threading.Thread(target=_run_threat_hunt, daemon=True, name=f"threat-hunt-{tipper_id}")
        threat_hunt_thread.start()

        # CVE exposure correlation — independent of IOC hunt, runs in parallel.
        # Always posts an AZDO comment (stub when there's nothing to check) so
        # the story has a visible audit trail either way.
        cve_ids = list(analysis.entities.cves) if analysis.entities else []
        vp = list(getattr(analysis, "vulnerable_products", []) or [])

        veracode_exposure = getattr(analysis, "veracode_exposure", None)
        jfrog_exposure = getattr(analysis, "jfrog_exposure", None)

        def _run_exposure():
            try:
                self.post_exposure_to_tipper(
                    tipper_id, cve_ids, parent_id=parent_msg_id,
                    vulnerable_products=vp,
                    veracode_exposure=veracode_exposure,
                    jfrog_exposure=jfrog_exposure,
                )
            except Exception as exp_err:
                logger.error(f"[bg] CVE exposure failed for #{tipper_id}: {exp_err}")
                try:
                    from src.components.cve_exposure.alerts import notify_dev_space
                    notify_dev_space(
                        "exposure_thread_crashed",
                        "Exposure background thread crashed",
                        f"Tipper #{tipper_id} CVE exposure handler raised "
                        f"`{type(exp_err).__name__}: {exp_err}`. The tipper still "
                        f"got its main analysis + IOC hunt, but no exposure comment "
                        f"was posted. Subsequent tippers will keep trying.",
                    )
                except Exception:
                    pass
        exposure_thread = threading.Thread(
            target=_run_exposure, daemon=True, name=f"cve-exposure-{tipper_id}"
        )
        exposure_thread.start()

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
