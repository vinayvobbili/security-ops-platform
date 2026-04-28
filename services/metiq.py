"""the internal LLM gateway Innovation API Client.

Provides integration with the company's the internal LLM gateway LLM gateway for:
- Chat completions with conversation history
- Streaming support (if available)

API Documentation: https://dev.azure.com/the company-US/DevX-AI-Agents/_wiki/wikis/DevX-AI-Agents-Wiki
"""

import logging
import os
from typing import Any, Optional

import requests

from my_config import get_config

logger = logging.getLogger(__name__)

TIMEOUT = 60


class the internal LLM gatewayClient:
    """Client for interacting with the the internal LLM gateway Innovation API."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        use_case_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        subscription_key: Optional[str] = None,
    ):
        config = get_config()

        self.api_key = api_key or getattr(config, "metiq_api_key", None)
        self.use_case_id = use_case_id or getattr(config, "metiq_use_case_id", None)
        self.subscription_key = subscription_key or getattr(config, "ocp_apim_subscription_key", None)

        endpoint = endpoint or getattr(config, "metiq_endpoint", None) or ""
        self.endpoint = endpoint.rstrip("/")

        self.session = requests.Session()
        self.session.verify = os.getenv("DISABLE_SSL_VERIFY", "").lower() != "true"

        # Route through SOCKS proxy (SSH tunnel to Mac on corp network)
        # the internal LLM gateway is a corp-internal API — not reachable from lab-vm without proxy.
        # The proxy chain may intercept TLS, so disable verify when proxied.
        proxy = (getattr(config, "m3_proxy", None) or "").strip()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify = False
            logger.info("the internal LLM gateway: using proxy %s", proxy)

        if self.api_key:
            self.session.headers.update({
                "api-key": self.api_key,
                "Content-Type": "application/json",
                "Cache-Control": "no-cache",
            })
        if self.subscription_key:
            self.session.headers["Ocp-Apim-Subscription-Key"] = self.subscription_key

    def is_configured(self) -> bool:
        """Check if the client has all required credentials configured."""
        return bool(self.api_key and self.use_case_id and self.subscription_key and self.endpoint)

    def _chat_url(self) -> str:
        return f"{self.endpoint}/api/usecases/{self.use_case_id}/chat"

    def chat(
        self,
        message: str,
        history: Optional[list[dict[str, Any]]] = None,
        filters: Optional[list[dict[str, Any]]] = None,
        intent: str = "",
        timeout: int = TIMEOUT,
    ) -> dict[str, Any]:
        """Send a chat message to the internal LLM gateway.

        Args:
            message: The user message to send.
            history: Previous conversation messages (pass the full exchange list).
            filters: Optional content filters for RAG applications.
            intent: Optional intent hint for the model.
            timeout: Request timeout in seconds.

        Returns:
            The API response dict with keys: role, content, created, id,
            tokensUsed, intent, filters, highlights, context.
        """
        if not self.is_configured():
            raise ValueError("the internal LLM gateway client is not fully configured — check METIQ_API_KEY, METIQ_USE_CASE_ID, OCP_APIM_SUBSCRIPTION_KEY, and APIM_ENDPOINT")

        payload = {
            "prompt": {
                "role": "User",
                "content": message,
                "intent": intent,
            },
            "history": history or [],
            "filters": filters or [],
        }

        resp = self.session.post(self._chat_url(), json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()

    def chat_multi_turn(
        self,
        messages: list[str],
        filters: Optional[list[dict[str, Any]]] = None,
        timeout: int = TIMEOUT,
    ) -> list[dict[str, Any]]:
        """Send multiple messages in sequence, building history automatically.

        Args:
            messages: List of user messages to send in order.
            filters: Optional content filters.
            timeout: Request timeout per call.

        Returns:
            List of API response dicts, one per message.
        """
        history: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []

        for msg in messages:
            resp = self.chat(msg, history=history, filters=filters, timeout=timeout)
            responses.append(resp)
            # Append the user message and agent response to history
            history.append({"role": "User", "content": msg})
            history.append(resp)

        return responses
