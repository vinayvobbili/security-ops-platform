#!/usr/bin/env python3
"""Quick script to test Abnormal Security API tokens."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import my_config FIRST to set SSL environment variables
import requests

# ============================================================
# SSL Configuration
# ============================================================
PROJECT_ROOT = Path(__file__).parent.parent
CA_BUNDLE = PROJECT_ROOT / 'data' / 'certs' / 'custom-ca-bundle.pem'

# ============================================================
# PASTE YOUR API TOKENS HERE (one per line)
# ============================================================
TOKENS_TO_TEST = [
    # Paste your tokens here, one per line
]


# ============================================================


def check_token(token: str, index: int) -> bool:
    """Test an Abnormal Security API token."""
    url = 'https://api.abnormalplatform.com/v1/threats'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    params = {'pageSize': 1}

    print(f"\n{'=' * 60}")
    print(f"Testing Token #{index + 1}")
    print(f"Preview: {token[:30]}...")
    print(f"Length: {len(token)}")
    print(f"{'=' * 60}")

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10, verify=str(CA_BUNDLE))
        print(f"Status Code: {response.status_code}")

        if response.status_code == 200:
            print("✅ SUCCESS! Token is valid and has permissions.")
            data = response.json()
            print(f"Response keys: {list(data.keys())}")
            if 'threats' in data:
                print(f"Number of threats: {len(data['threats'])}")
            return True
        elif response.status_code == 401:
            print("❌ INVALID: Token is not authenticated properly")
        elif response.status_code == 403:
            print("❌ FORBIDDEN: Token lacks required permissions")
            print(f"Response: {response.text}")
        else:
            print(f"❌ ERROR: Unexpected status code")
            print(f"Response: {response.text[:200]}")
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

    return False


if __name__ == '__main__':
    print("=" * 60)
    print("Abnormal Security API Token Tester")
    print("=" * 60)

    # Filter out empty strings and comments
    tokens = [t.strip() for t in TOKENS_TO_TEST if t.strip() and not t.strip().startswith('#')]

    if not tokens:
        print("\n⚠️  No tokens to test!")
        print("Please edit this file and add tokens to the TOKENS_TO_TEST list.")
        sys.exit(1)

    print(f"\nTesting {len(tokens)} token(s)...\n")

    working_tokens = []

    for i, token in enumerate(tokens):
        if check_token(token, i):
            working_tokens.append(token)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Tested: {len(tokens)} token(s)")
    print(f"Working: {len(working_tokens)} token(s)")
    print(f"Failed: {len(tokens) - len(working_tokens)} token(s)")

    if working_tokens:
        print("\n✅ WORKING TOKEN(S) FOUND!")
        print("\nUpdate your .secrets file with:")
        for token in working_tokens:
            print(f"ABNORMAL_SECURITY_API_KEY={token}")

        print("\nThen re-encrypt:")
        print("bash scripts/encrypt_secrets.sh")
    else:
        print("\n❌ No working tokens found.")
        print("Please check with your Abnormal Security administrator.")

    print("=" * 60)
