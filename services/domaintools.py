"""DomainTools Integration for domain/IP threat intelligence.

Wraps the DomainTools v1 API (Domain Reputation, Parsed Whois, Domain Profile)
for use as an additional IOC-enrichment source alongside VirusTotal, Recorded
Future, AbuseIPDB, etc.

Auth: DomainTools "signed" authentication (HMAC-SHA1 over
``api_username + timestamp + uri``). The secret key is therefore NEVER placed
in the request URL — only the username, a UTC timestamp, and the derived
signature ride along. This deliberately avoids the cleartext-key-in-proxy-logs
exposure that the unsigned ``?api_key=`` form causes.

Credentials come from config (``domaintools_api_username`` /
``domaintools_api_key``, sourced from DOMAINTOOLS_API_USERNAME /
DOMAINTOOLS_API_KEY). Every failure mode — missing creds, rotated/invalid key
(401/403), rate limit, network error — degrades gracefully to a structured
error dict; nothing here raises, so a key rotation just makes the source go
quiet rather than breaking callers.

Docs: https://docs.domaintools.com/api/
"""

import hashlib
import hmac
import logging
from datetime import UTC, datetime
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

DOMAINTOOLS_API_BASE = "https://api.domaintools.com"
TIMEOUT = 30


class DomainToolsClient:
    """Client for the DomainTools v1 API using signed authentication."""

    def __init__(
        self,
        api_username: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        """Initialize the DomainTools client.

        Args:
            api_username: DomainTools account username. Falls back to config
                (``domaintools_api_username``) when omitted.
            api_key: DomainTools secret key. Falls back to config
                (``domaintools_api_key``) when omitted.
        """
        if api_username is None or api_key is None:
            config = get_config()
            api_username = api_username or getattr(config, "domaintools_api_username", None)
            api_key = api_key or getattr(config, "domaintools_api_key", None)

        self.api_username = api_username
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def is_configured(self) -> bool:
        """True when both username and key are present."""
        return bool(self.api_username and self.api_key)

    def _signed_params(self, uri: str) -> dict[str, str]:
        """Build the signed-auth params for a given request URI (path only).

        signature = HMAC-SHA1(key, api_username + timestamp + uri), hex.
        The key never leaves this process — only the signature is transmitted.
        """
        timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        to_sign = f"{self.api_username}{timestamp}{uri}"
        signature = hmac.new(
            self.api_key.encode("utf-8"),
            to_sign.encode("utf-8"),
            hashlib.sha1,
        ).hexdigest()
        return {
            "api_username": self.api_username,
            "signature": signature,
            "timestamp": timestamp,
        }

    def _signed_get(self, uri: str, extra_params: Optional[dict] = None) -> dict[str, Any]:
        """Perform a signed GET against ``uri`` (a path like ``/v1/reputation/``).

        Returns the parsed JSON on success, or a structured error dict on any
        failure. Never raises.
        """
        if not self.is_configured():
            return {
                "success": False,
                "configured": False,
                "error": "DomainTools API credentials not configured "
                "(set DOMAINTOOLS_API_USERNAME and DOMAINTOOLS_API_KEY)",
            }

        params = self._signed_params(uri)
        if extra_params:
            params.update(extra_params)

        try:
            resp = self.session.get(
                f"{DOMAINTOOLS_API_BASE}{uri}",
                params=params,
                timeout=TIMEOUT,
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"DomainTools request failed ({uri}): {e}")
            return {"success": False, "error": f"network error: {e}", "unavailable": True}

        # Auth failures are the expected outcome if/when the key is rotated —
        # surface them as a clean, non-fatal "auth_failed" rather than an error
        # the caller has to special-case.
        if resp.status_code in (401, 403):
            # Surface DomainTools' own reason (e.g. "credentials ... do not
            # match an active account") so an inactive/expired subscription is
            # distinguishable from a rotated key in logs and callers.
            detail = ""
            try:
                detail = (resp.json().get("error", {}) or {}).get("message", "")
            except Exception:
                pass
            logger.warning(
                f"DomainTools auth/entitlement failed ({resp.status_code}) on {uri}: "
                f"{detail or 'no detail'}"
            )
            return {
                "success": False,
                "auth_failed": True,
                "status_code": resp.status_code,
                "error": "DomainTools auth/entitlement failed: "
                + (detail or "key rotated/invalid or product not licensed"),
            }
        if resp.status_code == 429:
            return {"success": False, "rate_limited": True, "error": "DomainTools rate limit exceeded"}
        if resp.status_code != 200:
            # DomainTools returns a JSON error body; include it when present.
            detail = ""
            try:
                detail = (resp.json().get("error", {}) or {}).get("message", "")
            except Exception:
                detail = resp.text[:200]
            return {
                "success": False,
                "status_code": resp.status_code,
                "error": f"HTTP {resp.status_code}{': ' + detail if detail else ''}",
            }

        try:
            return {"success": True, **resp.json()}
        except ValueError:
            return {"success": False, "error": "DomainTools returned non-JSON response"}

    def reputation(self, domain: str) -> dict[str, Any]:
        """Domain Reputation: risk score (0-100) + contributing reasons.

        Args:
            domain: The domain to score (e.g. "example.com").

        Returns:
            On success: {"success": True, "domain", "risk_score", "reasons",
            "raw"}. On failure: a structured error dict (see _signed_get).
        """
        domain = (domain or "").strip().lower()
        if not domain:
            return {"success": False, "error": "no domain provided"}

        result = self._signed_get("/v1/reputation/", {"domain": domain})
        if not result.get("success"):
            return {**result, "domain": domain}

        # Normalize the useful bits while keeping the raw response.
        response = result.get("response", {}) or {}
        return {
            "success": True,
            "domain": domain,
            "risk_score": response.get("risk_score"),
            "reasons": response.get("reasons", []),
            "raw": response,
        }

    def parsed_whois(self, domain: str) -> dict[str, Any]:
        """Parsed Whois: registrant, registrar, dates, name servers.

        Args:
            domain: The domain to look up.
        """
        domain = (domain or "").strip().lower()
        if not domain:
            return {"success": False, "error": "no domain provided"}
        result = self._signed_get(f"/v1/{domain}/whois/parsed")
        return {**result, "domain": domain}

    def domain_profile(self, domain: str) -> dict[str, Any]:
        """Domain Profile: overview (registrant, server, related, SEO).

        Args:
            domain: The domain to profile.
        """
        domain = (domain or "").strip().lower()
        if not domain:
            return {"success": False, "error": "no domain provided"}
        result = self._signed_get(f"/v1/{domain}/")
        return {**result, "domain": domain}


# Singleton instance
_client: Optional[DomainToolsClient] = None


def get_client() -> DomainToolsClient:
    """Get the singleton DomainToolsClient instance."""
    global _client
    if _client is None:
        _client = DomainToolsClient()
    return _client


def reputation(domain: str) -> dict[str, Any]:
    """Convenience: Domain Reputation for a single domain."""
    return get_client().reputation(domain)


def parsed_whois(domain: str) -> dict[str, Any]:
    """Convenience: Parsed Whois for a single domain."""
    return get_client().parsed_whois(domain)


def domain_profile(domain: str) -> dict[str, Any]:
    """Convenience: Domain Profile for a single domain."""
    return get_client().domain_profile(domain)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    client = DomainToolsClient()

    if not client.is_configured():
        print("ERROR: DOMAINTOOLS_API_USERNAME / DOMAINTOOLS_API_KEY not configured")
        sys.exit(1)

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"DomainTools reputation for {target}")
    print("=" * 50)
    r = client.reputation(target)
    if r.get("success"):
        print(f"  risk_score: {r.get('risk_score')}")
        print(f"  reasons:    {r.get('reasons')}")
    else:
        print(f"  FAILED: {r.get('error')}  (auth_failed={r.get('auth_failed')})")
