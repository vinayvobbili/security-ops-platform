"""Adaptive card definitions for Aide bot.

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
- contacts_cards: Escalation contacts menu and add form
"""

from .ticket_cards import NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT
from .azdo_cards import AZDO_CARD
from .testing_cards import APPROVED_TESTING_CARD
from .import_cards import TICKET_IMPORT_CARD
from .tuning_cards import TUNING_REQUEST_CARD
from .domain_cards import DOMAIN_LOOKALIKE_CARD
from .birthday_cards import BIRTHDAY_ANNIVERSARY_CARD
from .crowdstrike_cards import BROWSER_HISTORY_CARD, FILE_PULL_CARD
from .block_url_cards import BLOCK_URL_FORM_CARD
from .navigation_cards import all_options_card, get_all_options_card
from .ticket_cannon_cards import TICKET_CANNON_CARD, NOISE_SUPPRESSOR_CARD
from .contacts_cards import CONTACTS_MENU_CARD, build_contacts_add_card
from .poi_cards import POI_INVESTIGATE_CARD

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
    # Domain cards
    'DOMAIN_LOOKALIKE_CARD',
    # Birthday cards
    'BIRTHDAY_ANNIVERSARY_CARD',
    # CrowdStrike cards
    'BROWSER_HISTORY_CARD',
    'FILE_PULL_CARD',
    # Block URL
    'BLOCK_URL_FORM_CARD',
    # Navigation
    'all_options_card',
    'get_all_options_card',
    # Ticket Cannon cards
    'TICKET_CANNON_CARD',
    'NOISE_SUPPRESSOR_CARD',
    # Contacts cards
    'CONTACTS_MENU_CARD',
    'build_contacts_add_card',
    # Person of Interest OSINT
    'POI_INVESTIGATE_CARD',
]
