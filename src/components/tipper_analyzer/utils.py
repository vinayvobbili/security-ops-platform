"""Utility functions for tipper analysis."""

import re
from typing import List, Dict, Callable

from my_config import get_config


def defang_ioc(value: str, ioc_type: str) -> str:
    """Defang IOCs for safe display in messages (prevents accidental clicks)."""
    if ioc_type == 'IP':
        return value.replace('.', '[.]')
    elif ioc_type == 'Domain':
        return value.replace('.', '[.]')
    elif ioc_type == 'URL':
        return value.replace('http', 'hxxp').replace('.', '[.]')
    return value


def linkify_work_items_html(text: str) -> str:
    """Convert work item references like #12345 to Azure DevOps hyperlinks."""
    config = get_config()
    org = config.azdo_org
    project = config.azdo_de_project

    def replace_match(match):
        work_item_id = match.group(1)
        url = f"https://dev.azure.com/{org}/{project}/_workitems/edit/{work_item_id}"
        return f'<a href="{url}">#{work_item_id}</a>'

    return re.sub(r'#(\d+)', replace_match, text)


def linkify_work_items_markdown(text: str) -> str:
    """Convert work item references like #12345 to markdown hyperlinks."""
    config = get_config()
    org = config.azdo_org
    project = config.azdo_de_project

    def replace_match(match):
        work_item_id = match.group(1)
        url = f"https://dev.azure.com/{org}/{project}/_workitems/edit/{work_item_id}"
        return f'[#{work_item_id}]({url})'

    return re.sub(r'#(\d+)', replace_match, text)


def split_by_history(
    items: List,
    history: Dict,
    key_fn: Callable = lambda x: x.lower()
) -> tuple:
    """
    Split items into new vs familiar based on history lookup.

    Args:
        items: List of items to split
        history: Dict mapping key -> list of tipper IDs
        key_fn: Function to extract lookup key from item (default: lowercase)

    Returns:
        Tuple of (new_items, familiar_items) where familiar_items is list of (item, tipper_ids)
    """
    new_items = []
    familiar_items = []

    for item in items:
        key = key_fn(item)
        seen_in = history.get(key, [])
        if seen_in:
            familiar_items.append((item, seen_in))
        else:
            new_items.append(item)

    return new_items, familiar_items


def format_tipper_refs(tipper_ids: List[str], max_refs: int = 3, html: bool = False) -> str:
    """Format tipper references as comma-separated list."""
    refs = tipper_ids[:max_refs]
    if html:
        return ", ".join(linkify_work_items_html(f"#{tid}") for tid in refs)
    return ", ".join(f"#{tid}" for tid in refs)


def get_risk_emoji(score: int) -> str:
    """Get emoji indicator based on risk score."""
    if score >= 65:
        return "🔴"
    elif score >= 25:
        return "🟠"
    return "🟢"


def get_risk_colors(score: int) -> tuple:
    """Get text and background colors based on risk score.

    Returns:
        Tuple of (text_color, background_color) for HTML styling
    """
    if score >= 65:
        return "#c62828", "#ffebee"  # Dark red text, light red background
    elif score >= 25:
        return "#ef6c00", "#fff3e0"  # Dark orange text, light orange background
    return "#2e7d32", "#e8f5e9"  # Dark green text, light green background
