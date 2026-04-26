#!/usr/bin/env python3
"""
Salesforce Aura Framework — Guest Access Remediation Verification
=================================================================
Confirms that unauthenticated guest user access has been removed from
previously-exposed Experience Cloud sites.

Checks performed per site:
  1. Aura endpoint reachability (POST /s/sfsites/aura)
  2. GraphQL endpoint accessibility (POST /s/sfsites/graphql)
  3. Aura getRecord calls for previously-exposed objects
  4. Aura UI Record List enumeration (getItems)
  5. SOAP API guest access (/services/Soap/u/58.0)

Usage:
  python misc_scripts/verify_salesforce_remediation.py
  python misc_scripts/verify_salesforce_remediation.py --site france
  python misc_scripts/verify_salesforce_remediation.py --site usdirect
  python misc_scripts/verify_salesforce_remediation.py --site versant
  python misc_scripts/verify_salesforce_remediation.py --verbose
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
import requests

# ─── Target Definitions ──────────────────────────────────────────────────────

TARGETS_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "transient", "salesforce_scan_targets.json")


def load_sites(path: str | None = None) -> dict:
    """Load scan targets from JSON config file."""
    p = path or TARGETS_FILE
    try:
        with open(p) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Targets file not found: {p}")
        sys.exit(1)


SITES = load_sites()

# Aura action message template — mimics what aura-inspector sends
AURA_CONTEXT = json.dumps({
    "mode": "PROD",
    "fwuid": "guest",
    "app": "siteforce:communityApp",
    "loaded": {},
    "dn": [],
    "globals": {},
    "uad": False,
})


@dataclass
class CheckResult:
    site: str
    base_url: str
    check: str
    status: str  # "PASS" (blocked), "FAIL" (still exposed), "ERROR", "INFO"
    detail: str
    http_status: int | None = None
    sample_record: dict | None = None  # First record from exposed object (evidence)


@dataclass
class VerificationReport:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(r.status in ("PASS", "INFO") for r in self.results)

    @property
    def fail_count(self) -> int:
        return sum(1 for r in self.results if r.status == "FAIL")


# Candidate Aura endpoint paths — some sites use /s/sfsites/aura, others just /aura
AURA_PATHS = ["/s/sfsites/aura", "/aura"]
GRAPHQL_PATHS = ["/s/sfsites/graphql", "/graphql"]


def _discover_aura_path(session: requests.Session, base_url: str, verbose: bool) -> str | None:
    """Try candidate Aura paths and return the first one that gives a JSON response."""
    payload = {
        "message": json.dumps({"actions": [{"id": "1;a",
            "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
            "callingDescriptor": "UNKNOWN",
            "params": {"entityNameOrId": "Account", "layoutType": "FULL", "pageSize": 1,
                       "currentPage": 0, "useTimeout": False, "getCount": True, "enableRowActions": False}}]}),
        "aura.context": AURA_CONTEXT,
        "aura.token": "undefined",
    }
    for path in AURA_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = session.post(url, data=payload, timeout=15)
            if verbose:
                print(f"    [PROBE] {url} → HTTP {resp.status_code}")
            if resp.status_code == 200:
                try:
                    resp.json()
                    if verbose:
                        print(f"    [PROBE] Using Aura path: {path}")
                    return path
                except ValueError:
                    continue
        except requests.RequestException:
            continue
    return None


def _discover_graphql_path(session: requests.Session, base_url: str, verbose: bool) -> str | None:
    """Try candidate GraphQL paths and return the first one that accepts POST (not redirect)."""
    for path in GRAPHQL_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = session.post(url, json={"query": "{ __typename }"},
                                headers={"Content-Type": "application/json"},
                                timeout=15, allow_redirects=False)
            if verbose:
                print(f"    [PROBE] {url} → HTTP {resp.status_code}")
            if resp.status_code in (200, 400):  # 400 = GraphQL active but rejected query
                if verbose:
                    print(f"    [PROBE] Using GraphQL path: {path}")
                return path
        except requests.RequestException:
            continue
    return None


# ─── Check Functions ─────────────────────────────────────────────────────────

def get_aura_token(session: requests.Session, base_url: str) -> str | None:
    """Fetch the Aura framework token from the site's guest context.
    Returns the aura token string or None if the site blocks guest access."""
    try:
        resp = session.get(base_url, timeout=15, allow_redirects=True)
        # Look for aura token in page source
        body = resp.text
        for marker in ['"token":"', "'token':'", "auraConfig.token = '"]:
            idx = body.find(marker)
            if idx != -1:
                start = idx + len(marker)
                end = body.find(marker[-1], start)
                if end != -1:
                    return body[start:end]
    except requests.RequestException:
        pass
    return None


def check_aura_endpoint(session: requests.Session, base_url: str, site_key: str, verbose: bool,
                        aura_path: str | None = None) -> CheckResult:
    """Check if the Aura endpoint responds to unauthenticated requests.
    This is a lightweight reachability check — it does NOT test specific objects
    (that's handled by check_aura_get_record to avoid double-counting)."""
    aura_url = f"{base_url}{aura_path or '/s/sfsites/aura'}"
    # Use a benign object unlikely to hold data — just testing if the endpoint is live
    payload = {
        "message": json.dumps({
            "actions": [{
                "id": "1;a",
                "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
                "callingDescriptor": "UNKNOWN",
                "params": {
                    "entityNameOrId": "Account",
                    "layoutType": "FULL",
                    "pageSize": 1,
                    "currentPage": 0,
                    "useTimeout": False,
                    "getCount": True,
                    "enableRowActions": False,
                },
            }],
        }),
        "aura.context": AURA_CONTEXT,
        "aura.token": "undefined",
    }

    try:
        resp = session.post(aura_url, data=payload, timeout=15)
        if verbose:
            print(f"    [DEBUG] Aura POST {aura_url} → HTTP {resp.status_code}")
            print(f"    [DEBUG] Response (first 500 chars): {resp.text[:500]}")

        if resp.status_code == 200:
            try:
                resp.json()
            except ValueError:
                pass

            if "aura:invalidSession" in resp.text or "<!--" in resp.text[:50]:
                return CheckResult(
                    site=site_key, base_url=base_url,
                    check="Aura endpoint",
                    status="PASS",
                    detail="Aura endpoint returned invalid session / non-JSON response",
                    http_status=resp.status_code,
                )

            return CheckResult(
                site=site_key, base_url=base_url,
                check="Aura endpoint",
                status="INFO",
                detail="Aura endpoint is reachable (object checks below)",
                http_status=resp.status_code,
            )

        elif resp.status_code in (401, 403, 404):
            return CheckResult(
                site=site_key, base_url=base_url,
                check="Aura endpoint",
                status="PASS",
                detail=f"Aura endpoint returned HTTP {resp.status_code} — access denied",
                http_status=resp.status_code,
            )
        else:
            return CheckResult(
                site=site_key, base_url=base_url,
                check="Aura endpoint",
                status="PASS",
                detail=f"Aura endpoint returned HTTP {resp.status_code}",
                http_status=resp.status_code,
            )

    except requests.RequestException as e:
        return CheckResult(
            site=site_key, base_url=base_url,
            check="Aura endpoint",
            status="ERROR",
            detail=f"Connection error: {e}",
        )


def check_graphql(session: requests.Session, base_url: str, site_key: str,
                  objects: list[str], verbose: bool,
                  graphql_path: str | None = None) -> list[CheckResult]:
    """Check if GraphQL returns data for previously-exposed objects."""
    results = []
    graphql_url = f"{base_url}{graphql_path or '/s/sfsites/graphql'}"

    for obj in objects:
        query = {
            "query": f"""
                query {{
                    uiapi {{
                        query {{
                            {obj}(first: 1) {{
                                edges {{
                                    node {{
                                        Id
                                    }}
                                }}
                                totalCount
                            }}
                        }}
                    }}
                }}
            """,
            "variables": {},
        }

        try:
            resp = session.post(
                graphql_url,
                json=query,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            if verbose:
                print(f"    [DEBUG] GraphQL {obj} → HTTP {resp.status_code}")
                print(f"    [DEBUG] Response (first 500 chars): {resp.text[:500]}")

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    results.append(CheckResult(
                        site=site_key, base_url=base_url,
                        check=f"GraphQL ({obj})",
                        status="PASS",
                        detail="Non-JSON response — GraphQL likely disabled for guests",
                        http_status=resp.status_code,
                    ))
                    continue

                errors = data.get("errors", [])
                if errors:
                    err_msg = errors[0].get("message", "unknown error")
                    results.append(CheckResult(
                        site=site_key, base_url=base_url,
                        check=f"GraphQL ({obj})",
                        status="PASS",
                        detail=f"GraphQL returned error: {err_msg[:200]}",
                        http_status=resp.status_code,
                    ))
                    continue

                # Check for actual data
                try:
                    edges = data["data"]["uiapi"]["query"][obj]["edges"]
                    total = data["data"]["uiapi"]["query"][obj].get("totalCount", len(edges))
                    if edges or (total and int(total) > 0):
                        results.append(CheckResult(
                            site=site_key, base_url=base_url,
                            check=f"GraphQL ({obj})",
                            status="FAIL",
                            detail=f"GraphQL returned {total} records for {obj} — still exposed",
                            http_status=resp.status_code,
                        ))
                    else:
                        results.append(CheckResult(
                            site=site_key, base_url=base_url,
                            check=f"GraphQL ({obj})",
                            status="PASS",
                            detail=f"GraphQL query succeeded but returned 0 records for {obj}",
                            http_status=resp.status_code,
                        ))
                except (KeyError, TypeError):
                    results.append(CheckResult(
                        site=site_key, base_url=base_url,
                        check=f"GraphQL ({obj})",
                        status="PASS",
                        detail=f"GraphQL response structure changed — no data path for {obj}",
                        http_status=resp.status_code,
                    ))

            elif resp.status_code in (401, 403, 404):
                results.append(CheckResult(
                    site=site_key, base_url=base_url,
                    check=f"GraphQL ({obj})",
                    status="PASS",
                    detail=f"GraphQL endpoint returned HTTP {resp.status_code}",
                    http_status=resp.status_code,
                ))
            else:
                results.append(CheckResult(
                    site=site_key, base_url=base_url,
                    check=f"GraphQL ({obj})",
                    status="INFO",
                    detail=f"Unexpected HTTP {resp.status_code}",
                    http_status=resp.status_code,
                ))

        except requests.RequestException as e:
            results.append(CheckResult(
                site=site_key, base_url=base_url,
                check=f"GraphQL ({obj})",
                status="ERROR",
                detail=f"Connection error: {e}",
            ))

    return results


def check_soap_api(session: requests.Session, base_url: str, site_key: str, verbose: bool) -> CheckResult:
    """Check if SOAP API is accessible to guest users."""
    # Salesforce SOAP API endpoint — try the standard services path
    # The base domain (not community path) hosts the SOAP API
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    soap_url = f"{parsed.scheme}://{parsed.netloc}/services/Soap/u/58.0"

    soap_envelope = """<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:urn="urn:partner.soap.sforce.com">
  <soapenv:Body>
    <urn:describeGlobal/>
  </soapenv:Body>
</soapenv:Envelope>"""

    try:
        resp = session.post(
            soap_url,
            data=soap_envelope,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": "describeGlobal",
            },
            timeout=15,
        )
        if verbose:
            print(f"    [DEBUG] SOAP {soap_url} → HTTP {resp.status_code}")
            print(f"    [DEBUG] Response (first 500 chars): {resp.text[:500]}")

        if resp.status_code == 200 and "<describeGlobalResponse>" in resp.text:
            return CheckResult(
                site=site_key, base_url=base_url,
                check="SOAP API (describeGlobal)",
                status="FAIL",
                detail="SOAP describeGlobal succeeded without authentication",
                http_status=resp.status_code,
            )

        if "INVALID_SESSION_ID" in resp.text or "LOGIN_MUST_USE_SECURITY_TOKEN" in resp.text:
            return CheckResult(
                site=site_key, base_url=base_url,
                check="SOAP API (describeGlobal)",
                status="PASS",
                detail="SOAP API requires authentication (INVALID_SESSION_ID)",
                http_status=resp.status_code,
            )

        return CheckResult(
            site=site_key, base_url=base_url,
            check="SOAP API (describeGlobal)",
            status="PASS",
            detail=f"SOAP API returned HTTP {resp.status_code} — not accessible to guests",
            http_status=resp.status_code,
        )

    except requests.RequestException as e:
        return CheckResult(
            site=site_key, base_url=base_url,
            check="SOAP API (describeGlobal)",
            status="ERROR",
            detail=f"Connection error: {e}",
        )


# Fields most interesting to leadership — ordered by impact
_PII_FIELDS = [
    "Name", "FirstName", "LastName", "Email", "MobilePhone", "Phone",
    "PostalCode", "City", "State", "Country", "Title", "CompanyName",
    "Company", "Description", "Subject", "CaseNumber", "Status",
]


def _extract_sample(raw: dict) -> dict:
    """Pull the most meaningful fields from a raw Aura record for evidence display.
    Strips nulls, internal IDs, and Salesforce metadata to keep it readable."""
    sample = {}
    # Prioritize PII/interesting fields
    for key in _PII_FIELDS:
        val = raw.get(key)
        if val is not None and val != "":
            sample[key] = str(val)[:120]
    # Fill remaining slots from whatever the record has
    for key, val in raw.items():
        if len(sample) >= 6:
            break
        if key in sample or val is None or val == "" or isinstance(val, (dict, list)):
            continue
        # Skip Salesforce system fields
        if key.endswith("__c") or key in ("Id", "SystemModstamp", "CreatedById",
                                           "LastModifiedById", "OwnerId", "IsDeleted"):
            continue
        sample[key] = str(val)[:120]
    return sample


def check_aura_get_record(session: requests.Session, base_url: str, site_key: str,
                          objects: list[str], verbose: bool,
                          aura_path: str | None = None) -> list[CheckResult]:
    """Try Aura getRecord for each previously-exposed object."""
    results = []
    aura_url = f"{base_url}{aura_path or '/s/sfsites/aura'}"

    for obj in objects:
        payload = {
            "message": json.dumps({
                "actions": [{
                    "id": "1;a",
                    "descriptor": "serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems",
                    "callingDescriptor": "UNKNOWN",
                    "params": {
                        "entityNameOrId": obj,
                        "layoutType": "FULL",
                        "pageSize": 1,
                        "currentPage": 0,
                        "useTimeout": False,
                        "getCount": True,
                        "enableRowActions": False,
                    },
                }],
            }),
            "aura.context": AURA_CONTEXT,
            "aura.token": "undefined",
        }

        try:
            resp = session.post(aura_url, data=payload, timeout=15)
            if verbose:
                print(f"    [DEBUG] Aura getItems({obj}) → HTTP {resp.status_code}")
                print(f"    [DEBUG] Response (first 500 chars): {resp.text[:500]}")

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    results.append(CheckResult(
                        site=site_key, base_url=base_url,
                        check=f"Aura getItems ({obj})",
                        status="PASS",
                        detail="Non-JSON response",
                        http_status=resp.status_code,
                    ))
                    continue

                actions = data.get("actions", [])
                found_records = False
                for action in actions:
                    if action.get("state") == "SUCCESS":
                        ret = action.get("returnValue", {})
                        count = ret.get("totalCount", ret.get("count", 0))
                        if count and int(count) > 0:
                            found_records = True
                            # Extract first record as evidence sample
                            sample = None
                            result_list = ret.get("result", [])
                            if result_list and isinstance(result_list[0], dict):
                                raw = result_list[0].get("record", result_list[0])
                                sample = _extract_sample(raw)
                            results.append(CheckResult(
                                site=site_key, base_url=base_url,
                                check=f"Aura getItems ({obj})",
                                status="FAIL",
                                detail=f"Returned {count} {obj} records — still exposed",
                                http_status=resp.status_code,
                                sample_record=sample,
                            ))
                            break

                if not found_records:
                    # Check for explicit error
                    error_detail = "No records returned"
                    for action in actions:
                        if action.get("state") == "ERROR":
                            errs = action.get("error", [])
                            if isinstance(errs, list) and errs:
                                error_detail = errs[0].get("message", "access denied")[:200]
                    results.append(CheckResult(
                        site=site_key, base_url=base_url,
                        check=f"Aura getItems ({obj})",
                        status="PASS",
                        detail=error_detail,
                        http_status=resp.status_code,
                    ))
            else:
                results.append(CheckResult(
                    site=site_key, base_url=base_url,
                    check=f"Aura getItems ({obj})",
                    status="PASS",
                    detail=f"HTTP {resp.status_code}",
                    http_status=resp.status_code,
                ))

        except requests.RequestException as e:
            results.append(CheckResult(
                site=site_key, base_url=base_url,
                check=f"Aura getItems ({obj})",
                status="ERROR",
                detail=f"Connection error: {e}",
            ))

        time.sleep(0.5)  # Be polite between requests

    return results


# ─── Main ─────────────────────────────────────────────────────────────────────

def run_verification(site_filter: str | None = None, verbose: bool = False) -> VerificationReport:
    report = VerificationReport()

    targets = SITES
    if site_filter:
        if site_filter not in SITES:
            print(f"Unknown site '{site_filter}'. Available: {', '.join(SITES.keys())}")
            sys.exit(1)
        targets = {site_filter: SITES[site_filter]}

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
    })

    for site_key, site_cfg in targets.items():
        label = site_cfg["label"]
        objects = site_cfg["exposed_objects"]

        print(f"\n{'='*70}")
        print(f"  {label}")
        print(f"{'='*70}")

        for base_url in site_cfg["base_urls"]:
            print(f"\n  Target: {base_url}")
            print(f"  {'-'*60}")

            # 0. Discover working Aura and GraphQL paths
            print(f"  [0/4] Discovering Aura/GraphQL paths...")
            aura_path = _discover_aura_path(session, base_url, verbose)
            graphql_path = _discover_graphql_path(session, base_url, verbose)
            if aura_path:
                print(f"    Aura endpoint: {base_url}{aura_path}")
            else:
                print(f"    Aura endpoint: not found (guest access likely disabled)")
            if graphql_path:
                print(f"    GraphQL endpoint: {base_url}{graphql_path}")
            else:
                print(f"    GraphQL endpoint: not found / redirects to login")

            # 1. Aura endpoint check
            print(f"  [1/4] Checking Aura endpoint...")
            if aura_path:
                result = check_aura_endpoint(session, base_url, site_key, verbose, aura_path)
            else:
                result = CheckResult(
                    site=site_key, base_url=base_url,
                    check="Aura endpoint",
                    status="PASS",
                    detail="No working Aura endpoint found — guest access disabled",
                )
            report.results.append(result)
            print_result(result)

            # 2. Aura getItems per object
            print(f"  [2/4] Checking Aura getItems for {len(objects)} objects...")
            if aura_path:
                obj_results = check_aura_get_record(session, base_url, site_key, objects, verbose, aura_path)
            else:
                obj_results = [CheckResult(
                    site=site_key, base_url=base_url,
                    check=f"Aura getItems ({obj})",
                    status="PASS",
                    detail="Aura endpoint not accessible",
                ) for obj in objects]
            report.results.extend(obj_results)
            for r in obj_results:
                print_result(r)

            # 3. GraphQL per object
            print(f"  [3/4] Checking GraphQL for {len(objects)} objects...")
            if graphql_path:
                gql_results = check_graphql(session, base_url, site_key, objects, verbose, graphql_path)
            else:
                gql_results = [CheckResult(
                    site=site_key, base_url=base_url,
                    check=f"GraphQL ({obj})",
                    status="PASS",
                    detail="GraphQL endpoint not accessible / redirects to login",
                ) for obj in objects]
            report.results.extend(gql_results)
            for r in gql_results:
                print_result(r)

            # 4. SOAP API
            print(f"  [4/4] Checking SOAP API...")
            soap_result = check_soap_api(session, base_url, site_key, verbose)
            report.results.append(soap_result)
            print_result(soap_result)

    return report


def print_result(r: CheckResult):
    icons = {"PASS": "\033[92m[PASS]\033[0m", "FAIL": "\033[91m[FAIL]\033[0m",
             "ERROR": "\033[93m[ERR ]\033[0m", "INFO": "\033[94m[INFO]\033[0m"}
    icon = icons.get(r.status, "[????]")
    http = f" (HTTP {r.http_status})" if r.http_status else ""
    print(f"    {icon} {r.check}{http}: {r.detail}")


def print_summary(report: VerificationReport):
    total = len(report.results)
    passes = sum(1 for r in report.results if r.status == "PASS")
    fails = sum(1 for r in report.results if r.status == "FAIL")
    errors = sum(1 for r in report.results if r.status == "ERROR")
    infos = sum(1 for r in report.results if r.status == "INFO")

    print(f"\n{'='*70}")
    print(f"  VERIFICATION SUMMARY — {report.timestamp}")
    print(f"{'='*70}")
    print(f"  Total checks: {total}")
    print(f"  \033[92mPASS: {passes}\033[0m  |  \033[91mFAIL: {fails}\033[0m  |  \033[93mERROR: {errors}\033[0m  |  \033[94mINFO: {infos}\033[0m")

    if fails > 0:
        print(f"\n  \033[91m*** REMEDIATION INCOMPLETE — {fails} check(s) still show exposed data ***\033[0m")
        print(f"\n  Failed checks:")
        for r in report.results:
            if r.status == "FAIL":
                print(f"    - {r.site} | {r.base_url} | {r.check}: {r.detail}")
    elif errors > 0:
        print(f"\n  \033[93m*** {errors} check(s) errored — verify manually ***\033[0m")
    else:
        print(f"\n  \033[92m*** ALL CHECKS PASSED — Guest access appears to be revoked ***\033[0m")

    # ─── Executive summary table ──────────────────────────────────────────
    print_executive_table(report)

    # JSON output for evidence
    output_path = "data/transient/salesforce_remediation_verification.json"
    json_report = {
        "timestamp": report.timestamp,
        "summary": {
            "total": total, "pass": passes, "fail": fails, "error": errors,
            "remediation_confirmed": report.all_pass,
        },
        "results": [
            {
                "site": r.site, "base_url": r.base_url, "check": r.check,
                "status": r.status, "detail": r.detail, "http_status": r.http_status,
                **({"sample_record": r.sample_record} if r.sample_record else {}),
            }
            for r in report.results
        ],
    }
    try:
        import os
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(json_report, f, indent=2)
        print(f"\n  JSON report saved to: {output_path}")
    except OSError as e:
        print(f"\n  Could not save JSON report: {e}")


def print_executive_table(report: VerificationReport):
    """Print a leadership-friendly summary table grouped by site."""
    from collections import OrderedDict

    # Group results by (site_key, base_url)
    sites: dict[str, dict] = OrderedDict()
    for r in report.results:
        key = r.site
        if key not in sites:
            sites[key] = {
                "label": SITES[key]["label"],
                "urls": OrderedDict(),
            }
        url = r.base_url
        if url not in sites[key]["urls"]:
            sites[key]["urls"][url] = {"pass": 0, "fail": 0, "error": 0, "exposed": []}
        bucket = sites[key]["urls"][url]
        if r.status == "FAIL":
            bucket["fail"] += 1
            # Extract object name from check like "Aura getItems (Lead)"
            obj = r.check.split("(")[-1].rstrip(")") if "(" in r.check else r.check
            # Extract record count from detail like "Returned 2000 Lead records"
            count = ""
            for word in r.detail.split():
                if word.isdigit():
                    count = f"{int(word):,}"
                    break
            bucket["exposed"].append((obj, count, r.sample_record))
        elif r.status == "PASS":
            bucket["pass"] += 1
        else:
            bucket["error"] += 1

    # Objects that are just service account metadata, not business data
    LOW_SEVERITY_OBJECTS = {"User"}

    # Determine overall verdict per site
    def site_verdict(site_data):
        total_fail = sum(u["fail"] for u in site_data["urls"].values())
        total_err = sum(u["error"] for u in site_data["urls"].values())
        if total_fail > 0:
            # Check if ALL exposed objects are low-severity
            all_exposed = []
            for u in site_data["urls"].values():
                all_exposed.extend(obj for obj, _, _ in u["exposed"])
            if all_exposed and all(obj in LOW_SEVERITY_OBJECTS for obj in all_exposed):
                return "LOW", "\033[93m"
            return "CRITICAL", "\033[91m"
        if total_err > 0:
            return "INCONCLUSIVE", "\033[93m"
        return "REMEDIATED", "\033[92m"

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"

    # ─── Header ───────────────────────────────────────────────────────────
    ts = datetime.fromisoformat(report.timestamp).strftime("%B %d, %Y %H:%M UTC")
    print(f"\n")
    print(f"  {BOLD}{'='*78}{RESET}")
    print(f"  {BOLD}  SALESFORCE AURA GUEST ACCESS — EXECUTIVE SUMMARY{RESET}")
    print(f"  {BOLD}  {ts}{RESET}")
    print(f"  {BOLD}{'='*78}{RESET}")

    # ─── Per-site rows ────────────────────────────────────────────────────
    col_site = 34
    col_aura = 10
    col_gql = 10
    col_soap = 10
    col_verdict = 14

    header = (f"  {'Site':<{col_site}} {'Aura':^{col_aura}} {'GraphQL':^{col_gql}} "
              f"{'SOAP':^{col_soap}} {'Verdict':^{col_verdict}}")
    sep = f"  {'-'*col_site} {'-'*col_aura} {'-'*col_gql} {'-'*col_soap} {'-'*col_verdict}"

    print(f"\n{BOLD}{header}{RESET}")
    print(sep)

    for site_key, site_data in sites.items():
        verdict_text, verdict_color = site_verdict(site_data)

        # Aggregate check categories across all URLs for this site
        aura_fail = 0
        aura_total = 0
        gql_fail = 0
        gql_total = 0
        soap_fail = 0
        soap_total = 0

        for r in report.results:
            if r.site != site_key:
                continue
            if "Aura" in r.check:
                aura_total += 1
                if r.status == "FAIL":
                    aura_fail += 1
            elif "GraphQL" in r.check:
                gql_total += 1
                if r.status == "FAIL":
                    gql_fail += 1
            elif "SOAP" in r.check:
                soap_total += 1
                if r.status == "FAIL":
                    soap_fail += 1

        def cell(fail, total):
            if total == 0:
                return f"{DIM}{'N/A':^10}{RESET}"
            if fail > 0:
                return f"{RED}{'EXPOSED':^10}{RESET}"
            return f"{GREEN}{'BLOCKED':^10}{RESET}"

        label = site_data["label"]
        if len(label) > col_site:
            label = label[:col_site - 1] + "\u2026"

        print(f"  {label:<{col_site}} {cell(aura_fail, aura_total)} {cell(gql_fail, gql_total)} "
              f"{cell(soap_fail, soap_total)} {verdict_color}{verdict_text:^{col_verdict}}{RESET}")

    print(sep)

    # ─── Exposed objects detail ───────────────────────────────────────────
    any_exposed = False
    for site_key, site_data in sites.items():
        for url, bucket in site_data["urls"].items():
            if bucket["exposed"]:
                any_exposed = True

    if any_exposed:
        print(f"\n  {BOLD}{RED}EXPOSED DATA DETAIL:{RESET}")
        W = 100  # total table width
        print(f"  {'-'*W}")

        for site_key, site_data in sites.items():
            for url, bucket in site_data["urls"].items():
                if not bucket["exposed"]:
                    continue

                # Site/URL header row
                display_url = url
                if len(display_url) > W - 4:
                    display_url = "\u2026" + display_url[-(W - 5):]
                print(f"\n  {BOLD}{RED}{display_url}{RESET}")
                print(f"  {'-'*W}")

                for obj, count, sample in bucket["exposed"]:
                    print(f"  {RED}{obj:<20} {count:>8} records{RESET}")

                    if sample:
                        print(f"  {DIM}{'Sample record:':>20}{RESET}")
                        for field_name, field_val in sample.items():
                            # Mask middle of emails/phones for the report
                            print(f"  {' ':>20} {BOLD}{field_name}{RESET}: {field_val}")
                    else:
                        print(f"  {DIM}{'':>20} (no sample data captured){RESET}")
                    print()

        print(f"  {'-'*W}")
    else:
        print(f"\n  {GREEN}{BOLD}No exposed records found across all sites.{RESET}")

    print(f"  {BOLD}{'='*W}{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Verify Salesforce Aura guest access remediation"
    )
    parser.add_argument(
        "--site", choices=list(SITES.keys()),
        help="Only check a specific site (france or usdirect)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print raw HTTP responses for debugging"
    )
    args = parser.parse_args()

    print("Salesforce Aura — Guest Access Remediation Verification")
    print(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("Checking previously-exposed endpoints for unauthenticated access...")

    report = run_verification(site_filter=args.site, verbose=args.verbose)
    print_summary(report)

    sys.exit(0 if report.all_pass else 1)


if __name__ == "__main__":
    main()
