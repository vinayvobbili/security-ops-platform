"""Adaptive card definitions for Toodles bot.

This package contains all card definitions organized by functionality:
- ticket_cards: XSOAR ticket and hunt creation cards
- azdo_cards: Azure DevOps work item cards
- testing_cards: Approved testing management cards
- import_cards: Ticket import cards
- tuning_cards: Tuning request cards
- url_cards: URL block verdict cards
- domain_cards: Domain lookalike scanning cards
- birthday_cards: Birthday and anniversary cards
- navigation_cards: Main navigation/options card
"""

from .ticket_cards import NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT
from .azdo_cards import AZDO_CARD
from .testing_cards import APPROVED_TESTING_CARD
from .import_cards import TICKET_IMPORT_CARD
from .tuning_cards import TUNING_REQUEST_CARD
from .url_cards import URL_BLOCK_VERDICT_CARD
from .domain_cards import DOMAIN_LOOKALIKE_CARD
from .birthday_cards import BIRTHDAY_ANNIVERSARY_CARD
from .navigation_cards import all_options_card, get_all_options_card

__all__ = [
    # Ticket/Hunt cards
    'NEW_TICKET_CARD',
    'IOC_HUNT',
    'THREAT_HUNT',
    # Azure DevOps cards
    'AZDO_CARD',
    # Testing cards
    'APPROVED_TESTING_CARD',
    # Import cards
    'TICKET_IMPORT_CARD',
    # Tuning cards
    'TUNING_REQUEST_CARD',
    # URL cards
    'URL_BLOCK_VERDICT_CARD',
    # Domain cards
    'DOMAIN_LOOKALIKE_CARD',
    # Birthday cards
    'BIRTHDAY_ANNIVERSARY_CARD',
    # Navigation
    'all_options_card',
    'get_all_options_card',
]
