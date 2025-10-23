# Toodles Bot Refactoring Plan

## Executive Summary

The `webex_bots/toodles.py` file contains **2,325 lines** with significant code duplication. This refactoring plan identifies **8 major duplication patterns** that, when addressed, could reduce the file size by approximately **53% (~1,233 lines)** while improving maintainability and code quality.

---

## Current State Analysis

### Statistics
- **Total lines:** 2,325
- **Total Command classes:** 26
- **Commands with empty `execute()`:** 9
- **Decorator repetitions:** 21 identical `@log_activity` decorators
- **Card definitions:** ~990 lines (42% of file)

---

## Identified Duplication Patterns

### Pattern #1: Repetitive Decorator with Same Parameters ⚠️ HIGH IMPACT

**Occurrences:** 21 times throughout Command classes

**Current Code:**
```python
@log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
def execute(self, message, attachment_actions, activity):
    ...
```

**Problem:** Every command repeats the same decorator with identical parameters.

**Refactored Code:**
```python
# In src/utils/toodles_decorators.py
from src.utils.logging_utils import log_activity
from my_config import get_config

CONFIG = get_config()

def toodles_log_activity(func):
    """Decorator for Toodles bot activity logging with pre-configured parameters"""
    return log_activity(
        bot_access_token=CONFIG.webex_bot_access_token_toodles,
        log_file_name="toodles_activity_log.csv"
    )(func)
```

**Usage in commands:**
```python
from src.utils.toodles_decorators import toodles_log_activity

class CreateXSOARTicket(Command):
    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        ...
```

**Impact:** Saves ~21 lines, improves readability, centralizes configuration

---

### Pattern #2: Identical `__init__` Structure ⚠️ MEDIUM-HIGH IMPACT

**Occurrences:** 26 times (all Command classes)

**Current Code:**
```python
class GetNewXTicketForm(Command):
    def __init__(self):
        super().__init__(
            card=NEW_TICKET_CARD,
            command_keyword="get_x_ticket_form",
            help_message="Create X Ticket 𝑿",
            delete_previous_message=True
        )

    @log_activity(...)
    def execute(self, message, attachment_actions, activity):
        pass
```

**Refactored Code:**
```python
# In webex_bots/base/toodles_command.py
from webex_bot.models.command import Command
from src.utils.toodles_decorators import toodles_log_activity

class ToodlesCommand(Command):
    """
    Base class for Toodles commands with common configuration.

    Subclasses should define class attributes:
    - command_keyword: str (required)
    - help_message: str (optional)
    - card: dict or AdaptiveCard (optional)
    - delete_previous_message: bool (default: True)
    - exact_command_keyword_match: bool (default: True)
    """
    command_keyword = None
    help_message = None
    card = None
    delete_previous_message = True
    exact_command_keyword_match = True

    def __init__(self):
        if self.command_keyword is None:
            raise ValueError(f"{self.__class__.__name__} must define command_keyword")

        super().__init__(
            command_keyword=self.command_keyword,
            help_message=self.help_message,
            card=self.card,
            delete_previous_message=self.delete_previous_message,
            exact_command_keyword_match=self.exact_command_keyword_match
        )

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        """Override this method to implement command logic"""
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement execute() method"
        )


class CardOnlyCommand(ToodlesCommand):
    """Base class for commands that only display a card with no execute logic"""

    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        pass  # Card-only commands don't need execute logic
```

**Usage:**
```python
from webex_bots.base.toodles_command import CardOnlyCommand
from webex_bots.cards.ticket_cards import NEW_TICKET_CARD

class GetNewXTicketForm(CardOnlyCommand):
    command_keyword = "get_x_ticket_form"
    help_message = "Create X Ticket 𝑿"
    card = NEW_TICKET_CARD

# That's it! No __init__ or execute() needed
```

**Impact:** Saves ~130 lines, enforces consistency, reduces boilerplate

---

### Pattern #3: Empty `execute()` Methods ⚠️ MEDIUM IMPACT

**Occurrences:** 9 times

**Affected Commands:**
- URLs (line 1268)
- GetNewXTicketForm (line 1299)
- IOC (line 1346)
- ThreatHunt (line 1388)
- GetApprovedTestingCard (line 1516)
- RemoveApprovedTestingEntry (line 1731)
- GetAllOptions (line 1829)
- GetSearchXSOARCard (line 1921)
- GetUrlBlockVerdictForm (line 2147)

**Current Code:**
```python
@log_activity(bot_access_token=CONFIG.webex_bot_access_token_toodles, log_file_name="toodles_activity_log.csv")
def execute(self, message, attachment_actions, activity):
    pass
```

**Solution:** Use `CardOnlyCommand` base class from Pattern #2

**Impact:** Saves ~27 lines, makes intent clear

---

### Pattern #4: Duplicate Input Validation ⚠️ MEDIUM IMPACT

**Occurrences:** 3 times (lines 1323, 1369, 1410)

**Current Code:**
```python
# CreateXSOARTicket (line 1323)
if attachment_actions.inputs['title'].strip() == "" or attachment_actions.inputs['details'].strip() == "":
    return "Please fill in both fields to create a new ticket."

# IOCHunt (line 1369)
if attachment_actions.inputs['ioc_hunt_title'].strip() == "" or attachment_actions.inputs['ioc_hunt_iocs'].strip() == "":
    return "Please fill in both fields to create a new ticket."

# CreateThreatHunt (line 1410)
if attachment_actions.inputs['threat_hunt_title'].strip() == "" or attachment_actions.inputs['threat_hunt_desc'].strip() == "":
    return "Please fill in both fields to create a new ticket."
```

**Refactored Code:**
```python
# In src/utils/webex_validation.py
def validate_required_inputs(attachment_actions, field_names, error_message=None):
    """
    Validate that required input fields are not empty.

    Args:
        attachment_actions: Webex attachment_actions object
        field_names: List of field names to validate (or single string)
        error_message: Custom error message (optional)

    Returns:
        tuple: (is_valid: bool, error_message: str or None)

    Example:
        valid, error = validate_required_inputs(
            attachment_actions,
            ['title', 'details'],
            "Please fill in both title and details."
        )
        if not valid:
            return error
    """
    if isinstance(field_names, str):
        field_names = [field_names]

    empty_fields = []
    for field in field_names:
        value = attachment_actions.inputs.get(field, '').strip()
        if not value:
            empty_fields.append(field)

    if empty_fields:
        if error_message is None:
            field_list = ", ".join(empty_fields)
            error_message = f"Please fill in the following required fields: {field_list}"
        return False, error_message

    return True, None
```

**Usage:**
```python
from src.utils.webex_validation import validate_required_inputs

class CreateXSOARTicket(ToodlesCommand):
    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions,
            ['title', 'details'],
            "Please fill in both fields to create a new ticket."
        )
        if not valid:
            return error

        # Continue with ticket creation...
```

**Impact:** Saves ~15 lines, provides better error messages, reusable

---

### Pattern #5: XSOAR Incident Creation ⚠️ HIGH IMPACT

**Occurrences:** 3 times (lines 1328, 1373, 1414)

**Current Code:**
```python
# CreateXSOARTicket
incident = {
    'name': attachment_actions.inputs['title'].strip(),
    'details': attachment_actions.inputs['details'].strip() + f"\nSubmitted by: {activity['actor']['emailAddress']}",
    'CustomFields': {...}
}
result = incident_handler.create(incident)
new_incident_id = result.get('id')
incident_url = CONFIG.xsoar_prod_ui_base_url + '/Custom/caseinfoid/' + new_incident_id
return f"{activity['actor']['displayName']}, Ticket [#{new_incident_id}]({incident_url}) has been created in XSOAR Prod."
```

**Refactored Code:**
```python
# In src/utils/xsoar_helpers.py
from my_config import get_config

CONFIG = get_config()

def create_incident_with_response(
    incident_handler,
    incident_dict,
    activity,
    success_message_template,
    append_submitter=True
):
    """
    Create XSOAR incident and return formatted response.

    Args:
        incident_handler: XSOAR incident handler instance
        incident_dict: Incident data dictionary
        activity: Webex activity object
        success_message_template: Template string with placeholders:
            {actor}, {ticket_no}, {ticket_url}, {ticket_title}
        append_submitter: Whether to append submitter to details (default: True)

    Returns:
        str: Formatted success message

    Example:
        return create_incident_with_response(
            incident_handler,
            {
                'name': title,
                'details': details,
                'CustomFields': {...}
            },
            activity,
            "{actor}, Ticket [#{ticket_no}]({ticket_url}) has been created."
        )
    """
    # Append submitter info if requested
    if append_submitter and 'details' in incident_dict:
        submitter_email = activity['actor']['emailAddress']
        incident_dict['details'] += f"\nSubmitted by: {submitter_email}"

    # Create incident
    result = incident_handler.create(incident_dict)
    ticket_no = result.get('id')
    ticket_url = f"{CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{ticket_no}"
    ticket_title = incident_dict.get('name', '')

    # Format response
    return success_message_template.format(
        actor=activity['actor']['displayName'],
        ticket_no=ticket_no,
        ticket_url=ticket_url,
        ticket_title=ticket_title
    )


def build_incident_url(incident_id):
    """Build XSOAR incident URL from ID"""
    return f"{CONFIG.xsoar_prod_ui_base_url}/Custom/caseinfoid/{incident_id}"
```

**Usage:**
```python
from src.utils.xsoar_helpers import create_incident_with_response

class CreateXSOARTicket(ToodlesCommand):
    @toodles_log_activity
    def execute(self, message, attachment_actions, activity):
        valid, error = validate_required_inputs(
            attachment_actions, ['title', 'details']
        )
        if not valid:
            return error

        incident = {
            'name': attachment_actions.inputs['title'].strip(),
            'details': attachment_actions.inputs['details'].strip(),
            'CustomFields': {
                'detectionsource': attachment_actions.inputs['detection_source'],
                'isusercontacted': False,
                'securitycategory': 'CAT-5: Scans/Probes/Attempted Access'
            }
        }

        return create_incident_with_response(
            incident_handler,
            incident,
            activity,
            "{actor}, Ticket [#{ticket_no}]({ticket_url}) has been created in XSOAR Prod."
        )
```

**Impact:** Saves ~40 lines, centralizes URL building, consistent formatting

---

### Pattern #6: Repetitive User Display Name in Responses ⚠️ LOW IMPACT

**Occurrences:** 10+ times throughout

**Current Code:**
```python
return f"{activity['actor']['displayName']}, <message>"
```

**Refactored Code:**
```python
# In src/utils/webex_responses.py
def format_user_response(activity, message):
    """
    Format response with user's display name prefix.

    Args:
        activity: Webex activity object
        message: Response message

    Returns:
        str: Formatted response with user name

    Example:
        return format_user_response(activity, "Ticket has been created.")
        # Returns: "John Doe, Ticket has been created."
    """
    display_name = activity['actor']['displayName']
    return f"{display_name}, {message}"


def get_user_email(activity):
    """Extract user email from activity"""
    return activity['actor']['emailAddress']


def get_user_display_name(activity):
    """Extract user display name from activity"""
    return activity['actor']['displayName']
```

**Usage:**
```python
from src.utils.webex_responses import format_user_response

return format_user_response(activity, "Your request has been processed.")
```

**Impact:** Saves ~10 lines, improves consistency

---

### Pattern #7: Webex Message Creation ⚠️ LOW IMPACT

**Occurrences:** 3 times (lines 1481, 1670, 2125)

**Current Code:**
```python
webex_api.messages.create(
    roomId=CONFIG.webex_room_id_automation_engineering,
    markdown=f"{submitter_display_name} has created..."
)
```

**Note:** This pattern is already fairly clean. Consider extracting common room IDs to constants if used frequently, but this is low priority.

**Optional Helper:**
```python
# In src/utils/webex_responses.py
def send_notification(webex_api, room_id, message, markdown=None):
    """
    Send notification to a Webex room.

    Args:
        webex_api: WebexAPI instance
        room_id: Room ID to send to
        message: Plain text message
        markdown: Optional markdown formatted message
    """
    return webex_api.messages.create(
        roomId=room_id,
        text=message,
        markdown=markdown or message
    )
```

---

### Pattern #8: Large Card Definitions ⚠️ CRITICAL IMPACT

**Occurrences:** Lines 200-1190 (990 lines = 42% of file!)

**Current Structure:**
```
webex_bots/toodles.py
  Lines 200-432:  NEW_TICKET_CARD
  Lines 434-477:  IOC_HUNT
  Lines 479-521:  THREAT_HUNT
  Lines 523-649:  AZDO_CARD
  Lines 651-889:  APPROVED_TESTING_CARD
  Lines 891-929:  TICKET_IMPORT_CARD
  Lines 931-977:  TUNING_REQUEST_CARD
  Lines 979-1016: URL_BLOCK_VERDICT_CARD
  Lines 1018-1190: all_options_card
```

**Proposed Structure:**
```
webex_bots/
├── cards/
│   ├── __init__.py           # Export all cards
│   ├── ticket_cards.py       # NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT
│   ├── azdo_cards.py          # AZDO_CARD
│   ├── testing_cards.py       # APPROVED_TESTING_CARD
│   ├── tuning_cards.py        # TUNING_REQUEST_CARD
│   ├── import_cards.py        # TICKET_IMPORT_CARD
│   ├── url_cards.py           # URL_BLOCK_VERDICT_CARD
│   └── navigation_cards.py    # all_options_card
└── toodles.py                 # Main bot logic
```

**File: webex_bots/cards/__init__.py**
```python
"""
Adaptive card definitions for Toodles bot.
"""

from .ticket_cards import NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT
from .azdo_cards import AZDO_CARD
from .testing_cards import APPROVED_TESTING_CARD
from .tuning_cards import TUNING_REQUEST_CARD
from .import_cards import TICKET_IMPORT_CARD
from .url_cards import URL_BLOCK_VERDICT_CARD
from .navigation_cards import all_options_card

__all__ = [
    'NEW_TICKET_CARD',
    'IOC_HUNT',
    'THREAT_HUNT',
    'AZDO_CARD',
    'APPROVED_TESTING_CARD',
    'TUNING_REQUEST_CARD',
    'TICKET_IMPORT_CARD',
    'URL_BLOCK_VERDICT_CARD',
    'all_options_card',
]
```

**File: webex_bots/cards/ticket_cards.py**
```python
"""
Adaptive cards for XSOAR ticket creation.
"""

NEW_TICKET_CARD = {
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "type": "AdaptiveCard",
    "version": "1.3",
    "body": [
        # ... (move card definition here)
    ]
}

IOC_HUNT = {
    # ... (move card definition here)
}

THREAT_HUNT = {
    # ... (move card definition here)
}
```

**Usage in toodles.py:**
```python
from webex_bots.cards import (
    NEW_TICKET_CARD,
    IOC_HUNT,
    THREAT_HUNT,
    AZDO_CARD,
    APPROVED_TESTING_CARD,
    TUNING_REQUEST_CARD,
    TICKET_IMPORT_CARD,
    URL_BLOCK_VERDICT_CARD,
    all_options_card
)

class GetNewXTicketForm(CardOnlyCommand):
    command_keyword = "get_x_ticket_form"
    help_message = "Create X Ticket 𝑿"
    card = NEW_TICKET_CARD  # Clean import
```

**Impact:**
- Removes 990 lines from main file
- Each card in its own logical module
- Easy to find and edit specific cards
- Better separation of concerns

---

## Impact Summary

| Pattern | Lines Saved | Complexity Reduction | Priority |
|---------|-------------|---------------------|----------|
| #1: Decorator | ~21 lines | High | 🔴 HIGH |
| #2: `__init__` boilerplate | ~130 lines | High | 🔴 HIGH |
| #3: Empty execute() | ~27 lines | Medium | 🟡 MEDIUM |
| #4: Input validation | ~15 lines | Medium | 🟡 MEDIUM |
| #5: XSOAR incident creation | ~40 lines | High | 🔴 HIGH |
| #6: User responses | ~10 lines | Low | 🟢 LOW |
| #7: Webex messages | ~5 lines | Low | 🟢 LOW |
| #8: Card extraction | ~990 lines | Critical | 🔴 CRITICAL |
| **TOTAL** | **~1,238 lines** | **File size reduced by ~53%** | |

---

## Recommended Implementation Order

### Phase 1: Extract Static Definitions (Quick Wins)
**Priority:** 🔴 CRITICAL
**Estimated Time:** 1-2 hours
**Impact:** Immediate 990 line reduction

1. **Create cards directory structure**
   ```bash
   mkdir -p webex_bots/cards
   touch webex_bots/cards/__init__.py
   ```

2. **Extract card definitions** (Pattern #8)
   - Create `ticket_cards.py` (NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT)
   - Create `azdo_cards.py` (AZDO_CARD)
   - Create `testing_cards.py` (APPROVED_TESTING_CARD)
   - Create `tuning_cards.py` (TUNING_REQUEST_CARD)
   - Create `import_cards.py` (TICKET_IMPORT_CARD)
   - Create `url_cards.py` (URL_BLOCK_VERDICT_CARD)
   - Create `navigation_cards.py` (all_options_card)
   - Update `__init__.py` to export all cards

3. **Update imports in toodles.py**
   ```python
   from webex_bots.cards import (
       NEW_TICKET_CARD, IOC_HUNT, THREAT_HUNT,
       AZDO_CARD, APPROVED_TESTING_CARD, ...
   )
   ```

4. **Test:** Verify all cards still work

---

### Phase 2: Create Base Infrastructure (Foundation)
**Priority:** 🔴 HIGH
**Estimated Time:** 2-3 hours
**Impact:** Sets up infrastructure for all other improvements

1. **Create decorator** (Pattern #1)
   - Create `src/utils/toodles_decorators.py`
   - Implement `toodles_log_activity` decorator
   - Test with one command first

2. **Create base command classes** (Pattern #2)
   - Create `webex_bots/base/` directory
   - Implement `ToodlesCommand` base class
   - Implement `CardOnlyCommand` subclass
   - Document usage with docstrings

3. **Test:** Convert 2-3 commands to use new base classes

---

### Phase 3: Create Helper Functions (Utilities)
**Priority:** 🔴 HIGH
**Estimated Time:** 1-2 hours
**Impact:** Reduces duplication in command logic

1. **Create validation helpers** (Pattern #4)
   - Create `src/utils/webex_validation.py`
   - Implement `validate_required_inputs()`
   - Test with existing validation code

2. **Create XSOAR helpers** (Pattern #5)
   - Create `src/utils/xsoar_helpers.py`
   - Implement `create_incident_with_response()`
   - Implement `build_incident_url()`
   - Test with CreateXSOARTicket command

3. **Create response formatters** (Pattern #6)
   - Create `src/utils/webex_responses.py`
   - Implement `format_user_response()`
   - Implement getter functions

4. **Test:** Update 2-3 commands to use helpers

---

### Phase 4: Refactor All Commands (Systematic Cleanup)
**Priority:** 🟡 MEDIUM
**Estimated Time:** 3-4 hours
**Impact:** Complete transformation

1. **Convert all commands to use base classes** (Pattern #2, #3)
   - Update each command class one at a time
   - Run tests after each conversion
   - Commit after each successful conversion

2. **Replace decorators** (Pattern #1)
   - Find/replace `@log_activity(bot_access_token=...)`
   - Replace with `@toodles_log_activity`

3. **Replace validation code** (Pattern #4)
   - Update CreateXSOARTicket
   - Update IOCHunt
   - Update CreateThreatHunt

4. **Replace XSOAR incident creation** (Pattern #5)
   - Update CreateXSOARTicket
   - Update IOCHunt
   - Update CreateThreatHunt

5. **Replace response formatting** (Pattern #6)
   - Update all commands that use `activity['actor']['displayName']`

---

### Phase 5: Final Cleanup and Testing
**Priority:** 🟢 LOW
**Estimated Time:** 1 hour
**Impact:** Polish and verification

1. **Remove unused imports**
2. **Update docstrings**
3. **Run full test suite**
4. **Update documentation**
5. **Code review**

---

## Testing Strategy

### Unit Tests
Create tests for new utilities:
```python
# tests/utils/test_webex_validation.py
def test_validate_required_inputs_all_valid():
    # Test with all fields filled
    pass

def test_validate_required_inputs_missing_field():
    # Test with missing field
    pass

# tests/utils/test_xsoar_helpers.py
def test_create_incident_with_response():
    # Test incident creation and response formatting
    pass
```

### Integration Tests
Test commands after refactoring:
```python
# tests/commands/test_create_xsoar_ticket.py
def test_create_ticket_success():
    # Test successful ticket creation
    pass

def test_create_ticket_missing_fields():
    # Test validation error handling
    pass
```

### Manual Testing Checklist
After each phase:
- [ ] Bot starts without errors
- [ ] All commands appear in help menu
- [ ] Cards display correctly
- [ ] Form submission works
- [ ] Error messages display correctly
- [ ] Logging still works

---

## Rollback Plan

If issues occur during refactoring:

1. **Git is your friend:** Commit after each successful phase
   ```bash
   git commit -m "Phase 1 complete: Extracted card definitions"
   ```

2. **Keep original file:** Before starting, create backup
   ```bash
   cp webex_bots/toodles.py webex_bots/toodles.py.backup
   ```

3. **Rollback command:**
   ```bash
   git revert <commit-hash>
   ```

---

## Expected Final Structure

```
webex_bots/
├── base/
│   ├── __init__.py
│   └── toodles_command.py         # ToodlesCommand, CardOnlyCommand
├── cards/
│   ├── __init__.py                # Export all cards
│   ├── ticket_cards.py            # XSOAR ticket cards
│   ├── azdo_cards.py              # Azure DevOps cards
│   ├── testing_cards.py           # Approved testing cards
│   ├── tuning_cards.py            # Tuning request cards
│   ├── import_cards.py            # Import ticket cards
│   ├── url_cards.py               # URL verdict cards
│   └── navigation_cards.py        # Navigation/options cards
├── commands/                       # Optional future: split commands by domain
│   ├── __init__.py
│   ├── xsoar_commands.py          # XSOAR-related commands
│   ├── oncall_commands.py         # On-call commands
│   ├── crowdstrike_commands.py    # CrowdStrike commands
│   └── misc_commands.py           # Miscellaneous commands
└── toodles.py                      # Main bot (now ~1,000 lines!)

src/utils/
├── toodles_decorators.py          # toodles_log_activity
├── webex_validation.py            # validate_required_inputs
├── webex_responses.py             # format_user_response, etc.
└── xsoar_helpers.py               # create_incident_with_response, etc.
```

---

## Benefits After Refactoring

### Maintainability
- ✅ Each card in its own file (easy to find and edit)
- ✅ Command classes reduced to ~10-15 lines each
- ✅ Common logic centralized in utilities
- ✅ Clear separation of concerns

### Readability
- ✅ Main file reduced from 2,325 to ~1,000 lines
- ✅ Commands follow consistent patterns
- ✅ Less boilerplate, more business logic

### Testability
- ✅ Helper functions can be unit tested
- ✅ Base classes reduce test duplication
- ✅ Mocking is easier with utilities

### Extensibility
- ✅ Adding new commands is straightforward
- ✅ New card types fit into existing structure
- ✅ Validation logic is reusable

---

## Notes and Considerations

### Breaking Changes
None expected if done carefully. All changes are internal refactoring.

### Performance Impact
Negligible. Additional imports have minimal overhead.

### Dependencies
No new external dependencies required. Uses existing project structure.

### Documentation
Update README.md with new file structure and examples of adding commands.

---

## Questions to Consider Before Starting

1. **Are there existing tests?** If yes, ensure they still pass after each phase.

2. **Is this bot actively used in production?** If yes, consider:
   - Refactoring in a feature branch
   - Gradual rollout
   - More extensive testing

3. **Are other bots in the project similar?** If yes, consider:
   - Creating a shared base package
   - Reusing utilities across all bots

4. **Do you want to split commands into separate modules too?** (Optional Phase 6)
   - Groups related commands together
   - Further reduces main file size
   - Makes codebase easier to navigate

---

## Conclusion

This refactoring plan will reduce the `toodles.py` file from **2,325 lines to approximately 1,000 lines** (57% reduction) while improving:
- Code maintainability
- Readability
- Testability
- Consistency
- Developer experience

The phased approach allows for incremental progress with testing after each phase, minimizing risk.

**Estimated Total Time:** 8-12 hours spread across multiple sessions

**Recommended Schedule:**
- Session 1 (2h): Phase 1 - Extract cards
- Session 2 (3h): Phase 2 - Create base infrastructure
- Session 3 (2h): Phase 3 - Create helpers
- Session 4 (4h): Phase 4 - Refactor commands
- Session 5 (1h): Phase 5 - Final cleanup

Good luck with the refactoring! 🚀
