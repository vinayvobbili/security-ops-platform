"""Adaptive Card helper functions for domain monitoring alerts.

This module provides reusable functions for building Webex Adaptive Cards
used in domain monitoring alerts.
"""

import logging
from typing import Callable

from webexteamssdk import WebexTeamsAPI
from webexpythonsdk.models.cards import (
    AdaptiveCard, TextBlock, ColumnSet, Column, Container,
    options, HorizontalAlignment, VerticalContentAlignment,
)

from .config import get_active_room_id
from src.utils.webex_utils import send_message_with_retry, send_card_with_retry

logger = logging.getLogger(__name__)


def get_container_style(style: str):
    """Get the appropriate Container style for colored headers.

    Webex Adaptive Cards support these built-in Container styles:
    - ATTENTION: Red/critical alerts
    - WARNING: Yellow/warning alerts
    - ACCENT: Blue/informational
    - EMPHASIS: Gray/neutral

    Args:
        style: One of 'red', 'yellow', 'blue', 'gray', 'purple', 'green'

    Returns:
        ContainerStyle option for the specified color theme
    """
    style_map = {
        "red": options.ContainerStyle.ATTENTION,
        "yellow": options.ContainerStyle.WARNING,
        "blue": options.ContainerStyle.ACCENT,
        "gray": options.ContainerStyle.EMPHASIS,
        "purple": options.ContainerStyle.ATTENTION,  # Closest match
        "green": options.ContainerStyle.GOOD if hasattr(options.ContainerStyle, 'GOOD') else options.ContainerStyle.ACCENT,
    }
    return style_map.get(style, options.ContainerStyle.ACCENT)


def send_adaptive_card(webex_api: WebexTeamsAPI, card: AdaptiveCard, fallback_text: str) -> None:
    """Send an adaptive card with fallback text."""
    room_id = get_active_room_id()
    try:
        send_card_with_retry(
            webex_api,
            room_id,
            text=fallback_text,
            attachments=[{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card.to_dict()
            }]
        )
    except Exception as e:
        logger.error(f"Failed to send adaptive card: {e}")
        # Fallback to Markdown
        send_message_with_retry(webex_api, room_id, markdown=fallback_text)


def create_header_block(title: str, subtitle: str = None, color: options.Colors = None) -> list:
    """Create a styled header block for cards."""
    if color is None:
        color = options.Colors.ACCENT
    blocks = [
        TextBlock(
            text=title,
            size=options.FontSize.LARGE,
            weight=options.FontWeight.BOLDER,
            color=color,
            wrap=True
        )
    ]
    if subtitle:
        blocks.append(TextBlock(
            text=subtitle,
            size=options.FontSize.SMALL,
            isSubtle=True,
            wrap=True
        ))
    return blocks


def create_stat_columns(stats: list[tuple]) -> ColumnSet:
    """Create a row of stat boxes.

    Args:
        stats: List of (value, label, color) tuples

    Returns:
        ColumnSet with stat boxes
    """
    columns = []
    for value, label, _color in stats:
        # Note: _color is available for future use if adaptive cards support custom colors
        columns.append(Column(
            width="auto",
            items=[
                TextBlock(
                    text=str(value),
                    size=options.FontSize.EXTRA_LARGE,
                    weight=options.FontWeight.BOLDER,
                    horizontalAlignment=HorizontalAlignment.CENTER
                ),
                TextBlock(
                    text=label,
                    size=options.FontSize.SMALL,
                    horizontalAlignment=HorizontalAlignment.CENTER,
                    isSubtle=True
                )
            ],
            verticalContentAlignment=VerticalContentAlignment.CENTER
        ))
    return ColumnSet(columns=columns)


def create_findings_table(findings: list, columns_def: list[tuple]) -> list:
    """Create a table-like display using ColumnSets.

    Args:
        findings: List of finding dicts
        columns_def: List of (header, width, key) tuples where key can be
                     a string for dict lookup or a callable

    Returns:
        List of ColumnSet items for the table
    """
    items = []

    # Header row
    header_cols = [
        Column(
            width=width,
            items=[TextBlock(
                text=header,
                weight=options.FontWeight.BOLDER,
                size=options.FontSize.SMALL
            )]
        )
        for header, width, _ in columns_def
    ]
    items.append(ColumnSet(columns=header_cols))

    # Data rows (limit to 8)
    for finding in findings[:8]:
        row_cols = []
        for _, width, key in columns_def:
            if callable(key):
                value = key(finding)
            else:
                value = finding.get(key, "-")
            row_cols.append(Column(
                width=width,
                items=[TextBlock(text=str(value)[:50], wrap=True, size=options.FontSize.SMALL)]
            ))
        items.append(ColumnSet(columns=row_cols))

    return items


def create_footer(timestamp: str) -> list:
    """Create a footer with timestamp."""
    items = [
        TextBlock(
            text=f"Detected at {timestamp}",
            size=options.FontSize.SMALL,
            isSubtle=True,
            horizontalAlignment=HorizontalAlignment.RIGHT
        )
    ]
    return items
