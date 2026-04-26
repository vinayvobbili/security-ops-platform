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

        Searches tags with tag_set_name == "MITRE ID" matching the technique.

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

        # Filter for MITRE ID tag set
        results = data.get('results', [])
        for tag in results:
            if tag.get('tag_set_name', '').upper() == 'MITRE ID':
                uuid = tag.get('id')
                if uuid:
                    self._tag_cache[key] = uuid
                    return uuid

        logger.debug(f"No MITRE ID tag found for {technique_id}")
        return None

    def get_scenario_uuids_for_techniques(self, technique_ids: List[str]) -> Dict[str, List[str]]:
        """Map MITRE technique IDs to AttackIQ scenario UUIDs.

        For each technique, looks up the tag UUID then queries scenarios tagged with it.

        Args:
            technique_ids: List of MITRE technique IDs (e.g., ["T1059", "T1059.001"])

        Returns:
            Dict mapping technique_id -> list of scenario UUIDs
        """
        result = {}
        for tech_id in technique_ids:
            tag_uuid = self.get_mitre_tag_uuid(tech_id)
            if not tag_uuid:
                result[tech_id] = []
                continue

            data = self._request('GET', '/v1/scenarios', params={'tag': tag_uuid})
            if 'error' in data:
                result[tech_id] = []
                continue

            scenarios = data.get('results', [])
            result[tech_id] = [s['id'] for s in scenarios if s.get('id')]

        return result

    # --- Assessment CRUD ---

    def list_templates(self) -> list:
        """List all available assessment templates (paginated).

        Returns:
            List of assessment template dicts
        """
        return self._paginate('/v1/assessment-templates')

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
        return self._request('POST', '/v1/assessments/project/from_template', json={
            'template_id': template_id,
            'name': name,
            'description': description,
        })

    def create_test(self, assessment_id: str, name: str) -> Dict[str, Any]:
        """Create a test within an assessment.

        Args:
            assessment_id: UUID of the parent assessment
            name: Test name

        Returns:
            Created test dict or error
        """
        return self._request('POST', '/v1/tests', json={
            'assessment': assessment_id,
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
            'scenario_ids': scenario_ids,
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
        data = self._request('GET', f'/v1/tests/{test_id}/is_runnable')
        if 'error' in data:
            return False
        return data.get('is_runnable', False)

    def run_assessment(self, assessment_id: str) -> Dict[str, Any]:
        """Run all tests in an assessment.

        Args:
            assessment_id: UUID of the assessment

        Returns:
            Response dict or error
        """
        return self._request('POST', f'/v1/assessments/{assessment_id}/run_all')

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
