"""
AttackIQ BAS API Client

Provides integration with AttackIQ's Breach and Attack Simulation platform
for automated assessment creation from tipper MITRE techniques.

API reference: AttackIQ Enterprise Platform API v1.1.4
Rate limit: 21 requests/minute (3s between requests)
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

RATE_LIMIT_DELAY = 3  # seconds between requests (21 req/min limit)

# Upper bound on the designated test asset group's resolved membership. The
# whole tenant is a handful of dedicated AttackIQ actors, so a group at/above
# this size means someone pointed the run at "everything" — refuse it. This is
# the real safety property: runs only ever touch the small, deliberately
# curated test group, never the broad fleet. (The one-scenario / one-test
# guards separately bound WHAT runs.)
MAX_TEST_GROUP_ASSETS = 5


class AttackIQClient:
    """Client for interacting with the AttackIQ BAS API."""

    def __init__(self):
        self.config = get_config()
        self.api_key = self.config.attackiq_api_key
        self.base_url = (self.config.attackiq_base_url or '').rstrip('/')
        self.timeout = 30
        self._tag_cache: Dict[str, str] = {}  # {technique_id_lower: tag_uuid}
        self._last_request_time = 0.0

        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Token {self.api_key}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            })

        if not self.api_key:
            logger.warning("AttackIQ API key not configured")

    def is_configured(self) -> bool:
        """Check if the client is properly configured."""
        return bool(self.api_key and self.base_url)

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.time()

    def _request(self, method: str, endpoint: str, params: dict = None,
                 json: dict = None) -> Dict[str, Any]:
        """Make an authenticated request to the AttackIQ API.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE)
            endpoint: API endpoint path (e.g., '/v1/tags')
            params: Query parameters
            json: JSON body for POST/PUT/PATCH

        Returns:
            Response JSON or {"error": "..."} on failure
        """
        if not self.is_configured():
            return {"error": "AttackIQ API not configured"}

        self._rate_limit()

        url = f"{self.base_url}{endpoint}"

        try:
            logger.debug(f"AttackIQ {method} {endpoint}")
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json,
                timeout=self.timeout,
            )
            response.raise_for_status()
            if response.status_code == 204:
                return {"success": True}
            return response.json()

        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            if status_code == 401:
                return {"error": "Invalid AttackIQ API key (401 Unauthorized)"}
            elif status_code == 403:
                return {"error": "Insufficient permissions (403 Forbidden)"}
            elif status_code == 404:
                return {"error": f"Resource not found: {endpoint}"}
            elif status_code == 429:
                return {"error": "AttackIQ API rate limit exceeded (429)"}
            else:
                logger.error(f"AttackIQ API error: {status_code} for {endpoint}")
                return {"error": f"AttackIQ API error: {status_code}"}

        except requests.exceptions.Timeout:
            logger.error(f"AttackIQ API request timed out: {endpoint}")
            return {"error": "Request timed out"}

        except requests.exceptions.RequestException as e:
            logger.error(f"AttackIQ request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    def _paginate(self, endpoint: str, params: dict = None) -> list:
        """Auto-paginate through all results for a list endpoint.

        Follows 'next' links and collects all 'results'.
        Respects rate limit between pages.

        Args:
            endpoint: API endpoint path
            params: Initial query parameters

        Returns:
            Combined list of all result items
        """
        all_results = []
        current_endpoint = endpoint
        current_params = params

        while current_endpoint:
            data = self._request('GET', current_endpoint, params=current_params)

            if 'error' in data:
                logger.warning(f"Pagination error on {current_endpoint}: {data['error']}")
                break

            results = data.get('results', [])
            all_results.extend(results)

            # Follow next link
            next_url = data.get('next')
            if next_url:
                # next_url is a full URL; extract the path+query portion
                if next_url.startswith(self.base_url):
                    current_endpoint = next_url[len(self.base_url):]
                else:
                    current_endpoint = next_url
                current_params = None  # params are embedded in the next URL
            else:
                current_endpoint = None

        return all_results

    # --- Tag Lookup (with cache) ---

    def get_mitre_tag_uuid(self, technique_id: str) -> Optional[str]:
        """Look up the AttackIQ tag UUID for a MITRE technique ID.

        Searches tags with tag_set_name == "ATT&CK Techniques" matching the
        technique (these are the tags that actually link to scenarios; the
        "MITRE ID" tag set holds unrelated values).

        Args:
            technique_id: MITRE technique ID (e.g., "T1059", "T1059.001")

        Returns:
            Tag UUID string, or None if not found
        """
        key = technique_id.lower()
        if key in self._tag_cache:
            return self._tag_cache[key]

        # AttackIQ tags use lowercase 't' prefix: t1059, t1059.001
        tag_name = f"t{key.lstrip('tT')}"
        data = self._request('GET', '/v1/tags', params={'name': tag_name})

        if 'error' in data:
            logger.debug(f"Tag lookup failed for {technique_id}: {data['error']}")
            return None

        # Filter for the ATT&CK Techniques tag set (the scenario-linked one)
        results = data.get('results', [])
        for tag in results:
            if tag.get('tag_set_name', '').upper() == 'ATT&CK TECHNIQUES':
                uuid = tag.get('id')
                if uuid:
                    self._tag_cache[key] = uuid
                    return uuid

        logger.debug(f"No ATT&CK Techniques tag found for {technique_id}")
        return None

    def get_scenario_uuids_for_techniques(self, technique_ids: List[str],
                                          platform: str = None) -> Dict[str, List[str]]:
        """Map MITRE technique IDs to AttackIQ scenario UUIDs.

        For each technique, looks up the tag UUID then queries scenarios tagged with it.

        Args:
            technique_ids: List of MITRE technique IDs (e.g., ["T1059", "T1059.001"])
            platform: optional OS filter ('windows' / 'linux' / 'macos'). When set,
                only scenarios whose `supported_platforms` advertise that OS are
                returned — so a Linux run fires a Linux-compatible scenario rather
                than a Windows one that would come back "Not Configured".

        Returns:
            Dict mapping technique_id -> list of scenario UUIDs
        """
        plat = (platform or '').strip().lower() or None
        # AttackIQ's supported_platforms is keyed at the DISTRO level
        # (windows, osx, debian, ubuntu, redhat, centos, amazon, ...) — there is
        # no generic "linux" key. Expand the caller's coarse platform to the set
        # of distro keys that satisfy it.
        plat_keys = None
        if plat == 'linux':
            plat_keys = {'linux', 'redhat', 'rhel', 'centos', 'debian', 'ubuntu',
                         'amazon', 'fedora', 'suse', 'oracle', 'kali'}
        elif plat == 'macos':
            plat_keys = {'macos', 'osx'}
        elif plat:
            plat_keys = {plat}

        def _matches(scenario: dict) -> bool:
            if not plat_keys:
                return True
            sp = scenario.get('supported_platforms') or {}
            return bool(plat_keys & {k.lower() for k in sp.keys()})

        result = {}
        for tech_id in technique_ids:
            # AttackIQ only tags scenarios at the parent-technique level, so a
            # sub-technique (T1059.001) has no tag of its own. Try the exact ID
            # first, then fall back to its parent (T1059) — the finest scenario
            # granularity the library actually offers.
            candidates = [tech_id]
            if '.' in tech_id:
                candidates.append(tech_id.split('.')[0])

            scenario_ids: List[str] = []
            for candidate in candidates:
                tag_uuid = self.get_mitre_tag_uuid(candidate)
                if not tag_uuid:
                    continue
                # When filtering by platform, scan a wider page so a matching
                # distro scenario isn't missed beyond the default 10-per-page.
                # Large tags (thousands of scenarios) can 504 on a big page, so
                # fall back to progressively smaller pages on error.
                page_sizes = [50, 20] if plat_keys else [None]
                data = None
                for ps in page_sizes:
                    params = {'tag': tag_uuid}
                    if ps:
                        params['page_size'] = ps
                    data = self._request('GET', '/v1/scenarios', params=params)
                    if 'error' not in data:
                        break
                if not data or 'error' in data:
                    continue
                scenario_ids = [s['id'] for s in data.get('results', [])
                                if s.get('id') and _matches(s)]
                if scenario_ids:
                    if candidate != tech_id:
                        logger.info(f"{tech_id}: no scenarios; using parent {candidate} ({len(scenario_ids)})")
                    break

            result[tech_id] = scenario_ids

        return result

    # --- Assessment CRUD ---

    def list_templates(self) -> list:
        """List all available assessment templates (paginated).

        Returns:
            List of assessment template dicts
        """
        return self._paginate('/v1/assessment_templates')

    def create_assessment(self, name: str, description: str,
                          template_id: str) -> Dict[str, Any]:
        """Create a new assessment from a template.

        Args:
            name: Assessment name
            description: Assessment description
            template_id: UUID of the template to create from

        Returns:
            Created assessment dict or error
        """
        resp = self._request('POST', '/v1/assessments/project_from_template', json={
            'template': template_id,
            'project_name': name,
        })
        # API returns {"project_id": "..."}; expose as 'id' for downstream callers.
        if isinstance(resp, dict) and 'id' not in resp and resp.get('project_id'):
            resp['id'] = resp['project_id']
        return resp

    def create_test(self, assessment_id: str, name: str) -> Dict[str, Any]:
        """Create a test within an assessment.

        Args:
            assessment_id: UUID of the parent assessment
            name: Test name

        Returns:
            Created test dict or error
        """
        return self._request('POST', '/v1/tests', json={
            'project': assessment_id,
            'name': name,
        })

    def add_scenarios_to_test(self, test_id: str,
                              scenario_ids: List[str]) -> Dict[str, Any]:
        """Add scenarios to a test in bulk.

        Args:
            test_id: UUID of the test
            scenario_ids: List of scenario UUIDs to add

        Returns:
            Response dict or error
        """
        return self._request('POST', f'/v1/tests/{test_id}/bulk_add_scenarios', json={
            'include': scenario_ids,
        })

    def set_assessment_assets(self, assessment_id: str,
                              asset_group_id: str) -> Dict[str, Any]:
        """Set the default asset group for an assessment.

        Args:
            assessment_id: UUID of the assessment
            asset_group_id: UUID of the asset group

        Returns:
            Response dict or error
        """
        return self._request('POST', f'/v1/assessments/{assessment_id}/update_defaults', json={
            'default_asset_group': asset_group_id,
        })

    def list_assets(self) -> list:
        """List all available assets (paginated).

        Returns:
            List of asset dicts
        """
        return self._paginate('/v1/assets')

    # --- Execution ---

    def is_test_runnable(self, test_id: str) -> bool:
        """Check if a test is ready to run.

        Args:
            test_id: UUID of the test

        Returns:
            True if the test is runnable
        """
        data = self._request('GET', f'/v1/tests/{test_id}')
        if 'error' in data:
            return False
        return data.get('runnable', False)

    def run_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """Run all tests in an assessment.

        Args:
            assessment_id: UUID of the assessment

        Returns:
            Response dict or error
        """
        return self._request('POST', f'/v1/assessments/{assessment_id}/run_all')

    def run_single_scenario(self, scenario_id: str, label: str,
                            asset_group_id: str, dry_run: bool = False) -> Dict[str, Any]:
        """Fire exactly ONE scenario at the small, operator-designated test
        asset group — the only sanctioned in-app execution path.

        This is the dangerous primitive (it launches a real adversary TTP at
        live host(s) and generates SOC tickets), so the blast radius is enforced
        by *construction* and re-checked before the trigger:

          1. Refuse unless an asset group is supplied.
          2. The group must resolve to 1..MAX_TEST_GROUP_ASSETS assets — small
             enough to be a deliberately-curated test group, never the fleet.
          3. Build a throwaway assessment from the verified-empty template and
             assert it starts with ZERO tests (catches a template that would
             inject extra scenarios).
          4. Add a single test holding the single scenario id passed in.
          5. Assert the project now has EXACTLY ONE test.
          6. Bind the designated group as the default target.
          7. Only then run. On any mismatch, delete the throwaway and abort —
             nothing fires.

        AttackIQ runs each scenario only on platform-compatible assets, so a
        mixed Windows+Linux test group will execute a Windows scenario on the
        Windows host and no-op ("Not Configured") on the Linux one.

        Args:
            scenario_id: the one AttackIQ scenario UUID to execute
            label: human label for the throwaway assessment
            asset_group_id: operator-designated small test asset group
            dry_run: build + run all guards but DELETE instead of firing
                     (used to validate the path without launching a TTP)

        Returns:
            Dict with assessment_id / run result, or {'error': ...}
        """
        if not self.is_configured():
            return {"error": "AttackIQ API not configured"}
        if not asset_group_id:
            return {"error": "No designated test asset group configured — refusing to run"}
        if not scenario_id:
            return {"error": "No scenario specified"}

        # Guard 2: the designated test group must be small (1..MAX). AttackIQ
        # reports the resolved membership count as `num_assets` (groups can be
        # dynamic / rule-based, so there's no static `assets` list on the detail
        # object). Fall back to enumerating members if that field is ever absent.
        group = self.get_asset_group(asset_group_id)
        if 'error' in group:
            return {"error": f"Asset group lookup failed: {group['error']}"}
        asset_count = group.get('num_assets')
        if asset_count is None:
            assets = group.get('assets')
            if isinstance(assets, list):
                asset_count = len(assets)
            else:
                listing = self._request('GET', '/v1/assets', params={'asset_group': asset_group_id})
                asset_count = listing.get('count') if isinstance(listing, dict) else None
        if not isinstance(asset_count, int) or not (1 <= asset_count <= MAX_TEST_GROUP_ASSETS):
            return {"error": f"Designated asset group must contain 1..{MAX_TEST_GROUP_ASSETS} assets, found {asset_count} — refusing to run (guards against pointing at an all-assets group)"}

        # Guard 3: build from the verified-empty template.
        templates = self.list_templates()
        if not templates:
            return {"error": "No assessment templates available"}
        template_id = templates[0].get('id')

        assessment = self.create_assessment(f"BAS run — {label[:80]}", "Gated single-scenario run", template_id)
        if 'error' in assessment:
            return assessment
        assessment_id = assessment.get('id')
        if not assessment_id:
            return {"error": "Assessment created but no ID returned"}

        try:
            pre_tests = self.list_project_tests(assessment_id)
            if len(pre_tests) != 0:
                self.delete_assessment(assessment_id)
                return {"error": f"Template is not empty ({len(pre_tests)} tests) — aborted, nothing ran"}

            # Guard 4: one test, one scenario.
            test = self.create_test(assessment_id, f"{label[:80]} — single")
            if 'error' in test:
                self.delete_assessment(assessment_id)
                return {"error": f"Test creation failed: {test['error']}"}
            test_id = test.get('id')
            add = self.add_scenarios_to_test(test_id, [scenario_id])
            if isinstance(add, dict) and add.get('error'):
                self.delete_assessment(assessment_id)
                return {"error": f"Scenario add failed: {add['error']}"}

            # Guard 5: exactly one test now.
            post_tests = self.list_project_tests(assessment_id)
            if len(post_tests) != 1:
                self.delete_assessment(assessment_id)
                return {"error": f"Blast-radius check failed: expected 1 test, found {len(post_tests)} — aborted, nothing ran"}

            # Guard 6: bind the one-asset group.
            bind = self.set_assessment_assets(assessment_id, asset_group_id)
            if isinstance(bind, dict) and bind.get('error'):
                self.delete_assessment(assessment_id)
                return {"error": f"Asset binding failed: {bind['error']}"}

            if dry_run:
                self.delete_assessment(assessment_id)
                return {
                    "dry_run": True,
                    "ok": True,
                    "scenario_id": scenario_id,
                    "asset_group_id": asset_group_id,
                    "asset_count": asset_count,
                    "tests": len(post_tests),
                    "note": "All guards passed; throwaway deleted, nothing fired.",
                }

            # Guard 7: fire (one scenario, one asset).
            run = self.run_assessment(assessment_id)
            if isinstance(run, dict) and run.get('error'):
                self.delete_assessment(assessment_id)
                return {"error": f"Run failed to launch: {run['error']}"}

            return {
                "ok": True,
                "assessment_id": assessment_id,
                "assessment_url": f"{self.base_url}/assessments/{assessment_id}",
                "test_id": test_id,
                "scenario_id": scenario_id,
                "asset_group_id": asset_group_id,
                "run": run,
            }
        except Exception as e:
            # Best-effort cleanup so a half-built throwaway never lingers runnable.
            try:
                self.delete_assessment(assessment_id)
            except Exception:
                pass
            logger.error(f"run_single_scenario failed: {e}", exc_info=True)
            return {"error": f"Run aborted: {e}"}

    def _verify_test_group_size(self, asset_group_id: str):
        """Resolve an asset group's membership and confirm it's a small
        (1..MAX_TEST_GROUP_ASSETS) curated test group. Returns
        (asset_count, None) on success or (None, error_str) on refusal.

        AttackIQ reports the resolved membership as `num_assets` (groups can be
        dynamic / rule-based, so there's no static `assets` list on the detail
        object); fall back to enumerating members if that field is absent.
        """
        group = self.get_asset_group(asset_group_id)
        if 'error' in group:
            return None, f"Asset group lookup failed: {group['error']}"
        asset_count = group.get('num_assets')
        if asset_count is None:
            assets = group.get('assets')
            if isinstance(assets, list):
                asset_count = len(assets)
            else:
                listing = self._request('GET', '/v1/assets', params={'asset_group': asset_group_id})
                asset_count = listing.get('count') if isinstance(listing, dict) else None
        if not isinstance(asset_count, int) or not (1 <= asset_count <= MAX_TEST_GROUP_ASSETS):
            return None, (f"Designated asset group must contain 1..{MAX_TEST_GROUP_ASSETS} "
                          f"assets, found {asset_count} — refusing to run (guards against "
                          f"pointing at an all-assets group)")
        return asset_count, None

    def fire_built_assessment(self, assessment_id: str, asset_group_id: str,
                              dry_run: bool = False) -> Dict[str, Any]:
        """Fire an ALREADY-BUILT tipper assessment at the small test group.

        Unlike `run_single_scenario` (which builds a throwaway one-scenario
        project), this runs an existing tipper assessment whole — `run_all`
        fires every matched scenario it already holds. The blast radius is
        still bounded by *construction*: we re-verify the bound target is the
        small (1..MAX_TEST_GROUP_ASSETS) curated test group before triggering,
        and each scenario only executes on platform-compatible hosts in it.

        This is the auto-fire primitive the nightly de-scheduler pass uses to
        close the tipper→validation loop. The hosts are SOC-approved test
        actors (runs raise no SOC tickets), so no per-fire coordination is
        needed — but blast-radius hygiene is enforced regardless.

        Args:
            assessment_id: UUID of an existing (built) assessment.
            asset_group_id: the small operator-designated test asset group.
            dry_run: bind + run all guards but DO NOT trigger run_all.

        Returns:
            {'ok': True, 'assessment_id', 'asset_count', 'run'} or {'error': ...}.
        """
        if not self.is_configured():
            return {"error": "AttackIQ API not configured"}
        if not assessment_id:
            return {"error": "No assessment specified"}
        if not asset_group_id:
            return {"error": "No designated test asset group configured — refusing to run"}

        asset_count, err = self._verify_test_group_size(asset_group_id)
        if err:
            return {"error": err}

        bind = self.set_assessment_assets(assessment_id, asset_group_id)
        if isinstance(bind, dict) and bind.get('error'):
            return {"error": f"Asset binding failed: {bind['error']}"}

        if dry_run:
            return {"dry_run": True, "ok": True, "assessment_id": assessment_id,
                    "asset_group_id": asset_group_id, "asset_count": asset_count,
                    "note": "Bound to test group and guards passed; run_all NOT triggered."}

        run = self.run_assessment(assessment_id)
        if isinstance(run, dict) and run.get('error'):
            return {"error": f"Run failed to launch: {run['error']}"}
        return {"ok": True, "assessment_id": assessment_id,
                "asset_group_id": asset_group_id, "asset_count": asset_count, "run": run}

    def get_test_status(self, test_id: str) -> Dict[str, Any]:
        """Get the current status of a test.

        Args:
            test_id: UUID of the test

        Returns:
            Status dict or error
        """
        return self._request('GET', f'/v1/tests/{test_id}/get_status')

    def get_results(self, assessment_id: str) -> list:
        """Get all results for an assessment (paginated).

        Args:
            assessment_id: UUID of the assessment

        Returns:
            List of result dicts
        """
        return self._paginate('/v1/results', params={'assessment': assessment_id})

    def list_recent_results(self, max_pages: int = 20) -> list:
        """Pull recent results across all projects, capped at max_pages.

        Read-only. Used by the validation poller to backfill detection
        outcomes from existing run history. Each result carries
        detection_outcome / outcome_description / asset_hostname / scenario.
        """
        all_results = []
        endpoint = '/v1/results'
        params = {'page_size': 100, 'ordering': '-modified'}
        pages = 0
        while endpoint and pages < max_pages:
            data = self._request('GET', endpoint, params=params)
            if 'error' in data:
                logger.warning(f"Results poll error: {data['error']}")
                break
            all_results.extend(data.get('results', []))
            next_url = data.get('next')
            if next_url:
                endpoint = next_url[len(self.base_url):] if next_url.startswith(self.base_url) else next_url
                params = None
            else:
                endpoint = None
            pages += 1
        return all_results

    def get_asset_group(self, asset_group_id: str) -> Dict[str, Any]:
        """Fetch an asset group's detail (used to verify its asset count)."""
        return self._request('GET', f'/v1/asset_groups/{asset_group_id}')

    def list_project_tests(self, assessment_id: str) -> list:
        """List the tests belonging to an assessment/project."""
        data = self._request('GET', '/v1/tests', params={'project': assessment_id, 'page_size': 100})
        if 'error' in data:
            return []
        return data.get('results', [])

    def delete_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """Delete an assessment (cascades to its tests). Returns {'success': True}."""
        return self._request('DELETE', f'/v1/assessments/{assessment_id}')

    # --- High-level orchestration ---

    def create_tipper_assessment(self, azdo_id: int, title: str,
                                 technique_ids: List[str],
                                 template_id: str = None,
                                 asset_group_id: str = None) -> Dict[str, Any]:
        """Create an AttackIQ assessment for a tipper's MITRE techniques.

        End-to-end orchestration:
        1. Map techniques to scenarios via tag lookup
        2. Create assessment from template
        3. Create test within assessment
        4. Add matched scenarios to test
        5. Optionally set asset group

        Args:
            azdo_id: Azure DevOps tipper work item ID
            title: Tipper title
            technique_ids: List of MITRE technique IDs from the tipper
            template_id: Optional assessment template UUID (uses first available if None)
            asset_group_id: Optional asset group UUID

        Returns:
            Dict with assessment_id, assessment_url, test_id, scenarios_matched,
            scenarios_total, techniques_without_scenarios, or {"error": "..."}
        """
        if not self.is_configured():
            return {"error": "AttackIQ API not configured"}

        # Step 1: Map techniques to scenarios
        logger.info(f"Mapping {len(technique_ids)} techniques to AttackIQ scenarios for tipper {azdo_id}")
        tech_to_scenarios = self.get_scenario_uuids_for_techniques(technique_ids)

        all_scenario_ids = []
        techniques_without = []
        for tech_id, scenario_ids in tech_to_scenarios.items():
            if scenario_ids:
                all_scenario_ids.extend(scenario_ids)
            else:
                techniques_without.append(tech_id)

        # Deduplicate scenarios
        all_scenario_ids = list(dict.fromkeys(all_scenario_ids))

        if not all_scenario_ids:
            logger.warning(f"No AttackIQ scenarios found for tipper {azdo_id} techniques")
            return {
                "error": "No scenarios found for any techniques",
                "techniques_without_scenarios": techniques_without,
            }

        # Step 2: Get template ID if not provided
        if not template_id:
            templates = self.list_templates()
            if not templates:
                return {"error": "No assessment templates available"}
            template_id = templates[0].get('id')
            if not template_id:
                return {"error": "Failed to get template ID"}

        # Step 3: Create assessment
        assessment_name = f"Tipper {azdo_id} - {title[:80]}"
        assessment_desc = (
            f"Auto-generated BAS assessment for Azure DevOps tipper #{azdo_id}. "
            f"Techniques: {', '.join(technique_ids[:20])}"
        )
        assessment = self.create_assessment(assessment_name, assessment_desc, template_id)
        if 'error' in assessment:
            return assessment

        assessment_id = assessment.get('id')
        if not assessment_id:
            return {"error": "Assessment created but no ID returned"}

        assessment_url = f"{self.base_url}/assessments/{assessment_id}"

        # Step 4: Create test within assessment
        test = self.create_test(assessment_id, f"Tipper {azdo_id} Validation")
        if 'error' in test:
            return {"error": f"Test creation failed: {test['error']}", "assessment_id": assessment_id}

        test_id = test.get('id')

        # Step 5: Add scenarios to test
        if test_id and all_scenario_ids:
            add_result = self.add_scenarios_to_test(test_id, all_scenario_ids)
            if 'error' in add_result:
                logger.warning(f"Failed to add scenarios to test: {add_result['error']}")

        # Step 6: Optionally set asset group
        if asset_group_id:
            asset_result = self.set_assessment_assets(assessment_id, asset_group_id)
            if 'error' in asset_result:
                logger.warning(f"Failed to set asset group: {asset_result['error']}")

        result = {
            "assessment_id": assessment_id,
            "assessment_url": assessment_url,
            "test_id": test_id,
            "scenarios_matched": len(all_scenario_ids),
            "scenarios_total": sum(len(s) for s in tech_to_scenarios.values()),
            "techniques_without_scenarios": techniques_without,
            # technique -> [scenario_ids]; lets the caller persist the reverse
            # index for the validation overlay without a second tag lookup.
            "scenario_map": tech_to_scenarios,
        }

        logger.info(
            f"AttackIQ assessment created for tipper {azdo_id}: "
            f"{len(all_scenario_ids)} scenarios from {len(technique_ids)} techniques"
        )
        return result


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    client = AttackIQClient()

    if not client.is_configured():
        print("AttackIQ API key not configured")
        print("Set ATTACKIQ_API_KEY and ATTACKIQ_BASE_URL in your environment")
        sys.exit(0)

    print("AttackIQ Client Connectivity Test")
    print("=" * 50)

    # Test: list templates
    print("\n1. Listing assessment templates...")
    templates = client.list_templates()
    if isinstance(templates, list):
        print(f"   Found {len(templates)} templates")
        for t in templates[:3]:
            print(f"   - {t.get('name', 'unnamed')} ({t.get('id', 'no-id')})")
    else:
        print(f"   Error: {templates}")

    # Test: tag lookup for T1059 (Command and Scripting Interpreter)
    print("\n2. Looking up MITRE tag for T1059...")
    tag_uuid = client.get_mitre_tag_uuid("T1059")
    if tag_uuid:
        print(f"   Tag UUID: {tag_uuid}")
    else:
        print("   Tag not found (may need different technique ID)")

    print("\n" + "=" * 50)
    print("Tests complete!")
