"""Platform fetchers for detection rules catalog.

Each fetcher normalizes platform-specific rules into DetectionRule objects.
"""

from typing import List, Dict, Callable

from ..models import DetectionRule


# Registry of available fetchers
FETCHER_REGISTRY: Dict[str, Callable[[], List[DetectionRule]]] = {}


def register_fetcher(platform: str):
    """Decorator to register a fetcher function."""
    def decorator(func):
        FETCHER_REGISTRY[platform] = func
        return func
    return decorator


def get_fetcher(platform: str) -> Callable[[], List[DetectionRule]]:
    """Get a fetcher function by platform name."""
    if platform not in FETCHER_REGISTRY:
        raise ValueError(f"Unknown platform: {platform}. Available: {list(FETCHER_REGISTRY.keys())}")
    return FETCHER_REGISTRY[platform]


def get_all_platforms() -> List[str]:
    """Get list of all registered platform names."""
    return list(FETCHER_REGISTRY.keys())


# Import fetchers to trigger registration
from . import qradar, crowdstrike, tanium  # noqa: E402, F401
