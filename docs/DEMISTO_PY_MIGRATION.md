# Migration Plan: Custom XSOAR Client → Official demisto-py SDK

## Overview
Migrate from custom `services/xsoar.py` implementation to the official Palo Alto Networks `demisto-py` SDK.

## Backup Status
✅ Backup created: `services/xsoar.py.backup` (26KB, 2024-10-31 08:02)

## Installation (Pending - Network Issues)

```bash
# When network access is available:
.venv/bin/pip install demisto-py

# Or from GitHub:
.venv/bin/pip install git+https://github.com/demisto/demisto-py.git
```

## Current Implementation Analysis

### Classes and Methods Used

#### **TicketHandler** (Primary class)
- `get_tickets(query, period=None, size=20000, paginate=True)` - Search for incidents
- `_fetch_paginated(query, period, page_size=5000)` - Paginated search
- `_fetch_from_api(query, period, size)` - Direct API search
- `get_entries(incident_id)` - Get incident entries/comments
- `create(payload)` - Create new incident in prod
- `create_in_dev(payload)` - Create new incident in dev
- `link_tickets(parent_ticket_id, link_ticket_id)` - Link incidents
- `add_participant(ticket_id, participant_email_address)` - Add participant
- `get_participants(incident_id)` - Get incident participants
- `complete_task(incident_id, task_id, response_value)` - Complete playbook task

#### **ListHandler** (Secondary class)
- `get_all_lists()` - Get all XSOAR lists
- `get_list_data_by_name(list_name)` - Get specific list data
- `get_list_version_by_name(list_name)` - Get list version
- `save(list_name, list_data)` - Save list as JSON
- `save_as_text(list_name, list_data)` - Save list as text
- `add_item_to_list(list_name, new_entry)` - Add item to list

#### **Standalone Functions**
- `get_case_data_with_notes(incident_id)` - Get incident with notes
- `get_user_notes(incident_id)` - Get formatted user notes
- `get_case_data(incident_id)` - Get incident details
- `import_ticket(source_ticket_number, requestor_email_address)` - Import from prod to dev

### Current Custom Features
1. **Retry Logic**
   - 429 rate limiting: up to 5 retries with exponential backoff (2, 4, 8, 16, 32 sec)
   - 502/503/504 server errors: up to 3 retries with backoff (5, 10, 20 sec)
   - Connection errors: handled by http_utils.py

2. **Pagination**
   - Page size: 5000 records per page
   - Max pages: 100
   - Inter-page delay: 1 second

3. **Timeouts**
   - Large queries: 600 seconds (10 minutes)

4. **Environment Separation**
   - Separate prod/dev configurations
   - Different auth headers for prod vs dev

### Usage Across Codebase (28 files)

**Heavy users:**
- `src/secops.py` - Shift change announcements, metrics
- `src/charts/inflow.py` - Chart generation
- `src/components/ticket_cache.py` - Ticket caching
- `web/web_server.py` - Web API endpoints
- Various other charts and components

## demisto-py SDK API Reference

### Configuration

```python
import demisto_client

# Production environment
api_instance = demisto_client.configure(
    base_url='https://api-msoar.crtx.us.paloaltonetworks.com',
    api_key='YOUR_API_KEY',
    verify_ssl=False
)

# Or using auth_id (for XSIAM)
api_instance = demisto_client.configure(
    base_url='https://api-msoar.crtx.us.paloaltonetworks.com',
    api_key='YOUR_API_KEY',
    api_key_id='YOUR_AUTH_ID',
    verify_ssl=False
)
```

### Key SDK Methods (Based on XSOAR API)

#### Incidents
```python
# Search incidents (equivalent to get_tickets)
search_filter = {
    'query': 'type:METCIRT -owner:""',
    'page': 0,
    'size': 100,
    'sort': [{'field': 'created', 'asc': False}]
}
response = api_instance.search_incidents(filter=search_filter)

# Get incident by ID
incident = api_instance.get_incident(incident_id='12345')

# Create incident
incident_data = {
    'name': 'Test Incident',
    'type': 'METCIRT',
    'severity': 3
}
response = api_instance.create_incident(create_incident_request=incident_data)

# Update incident
api_instance.update_incident(incident_id='12345', update_request=update_data)
```

#### Investigation/Entries
```python
# Get investigation (incident with entries)
investigation = api_instance.investigation_inv_id_post(inv_id='12345', body={})

# Add entry/note
entry_data = {
    'investigationId': '12345',
    'data': 'This is a note',
    'markdown': True
}
api_instance.create_incident_entry(entry=entry_data)
```

#### Lists
```python
# Get all lists
lists = api_instance.get_lists()

# Get specific list
list_data = api_instance.get_list(list_id='METCIRT Blocked Domains')

# Update list
api_instance.update_list(list_id='METCIRT Blocked Domains', list_data=data)
```

## Migration Strategy

### Phase 1: Wrapper Approach (Minimal Disruption)
Keep existing API, replace internals with demisto-py

**Pros:**
- No changes to 28 dependent files
- Gradual migration
- Easy rollback

**Cons:**
- Still maintaining wrapper code
- Not leveraging full SDK benefits

### Phase 2: Direct Migration (Recommended Long-term)
Replace all calls with direct demisto-py usage

**Pros:**
- Cleaner code
- Full SDK features
- Official support

**Cons:**
- Requires updating 28 files
- More testing needed

## Recommended Approach: Hybrid

1. **Immediate** (Phase 1): Wrap demisto-py in existing classes
2. **Gradual** (Phase 2): Migrate high-value files to direct SDK usage
3. **Eventually**: Deprecate wrapper entirely

## Implementation Plan

### Step 1: Install demisto-py
```bash
.venv/bin/pip install demisto-py
```

### Step 2: Create New xsoar.py with Wrapper

```python
import demisto_client
import logging
from my_config import get_config

log = logging.getLogger(__name__)
CONFIG = get_config()

# Initialize clients
prod_client = demisto_client.configure(
    base_url=CONFIG.xsoar_prod_api_base_url,
    api_key=CONFIG.xsoar_prod_auth_key,
    api_key_id=CONFIG.xsoar_prod_auth_id,
    verify_ssl=False
)

dev_client = demisto_client.configure(
    base_url=CONFIG.xsoar_dev_api_base_url,
    api_key=CONFIG.xsoar_dev_auth_key,
    api_key_id=CONFIG.xsoar_dev_auth_id,
    verify_ssl=False
)

class TicketHandler:
    def __init__(self):
        self.client = prod_client

    def get_tickets(self, query, period=None, size=20000, paginate=True):
        """Fetch security incidents from XSOAR using demisto-py"""
        full_query = query + f' -category:job -type:"{CONFIG.team_name} Ticket QA" -type:"{CONFIG.team_name} SNOW Whitelist Request"'

        if paginate:
            return self._fetch_paginated(full_query, period, size)
        return self._fetch_direct(full_query, period, size)

    def _fetch_paginated(self, query, period, page_size=5000):
        """Fetch with pagination using demisto-py"""
        all_tickets = []
        page = 0
        max_pages = 100

        while page < max_pages:
            search_filter = {
                'query': query,
                'page': page,
                'size': page_size,
                'sort': [{'field': 'created', 'asc': False}]
            }
            if period:
                search_filter['period'] = period

            try:
                response = self.client.search_incidents(filter=search_filter)
                data = response.data if hasattr(response, 'data') else []

                if not data:
                    break

                all_tickets.extend(data)
                log.debug(f"Fetched page {page}: {len(data)} tickets (total: {len(all_tickets)})")

                if len(data) < page_size:
                    break

                page += 1

            except demisto_client.ApiException as e:
                log.error(f"API error on page {page}: {e}")
                if e.status in [429, 502, 503, 504]:
                    # Retry logic here
                    pass
                break

        return all_tickets

    # ... other methods ...

class ListHandler:
    def __init__(self):
        self.client = prod_client

    def get_all_lists(self):
        """Get all lists using demisto-py"""
        try:
            return self.client.get_lists()
        except demisto_client.ApiException as e:
            log.error(f"Error fetching lists: {e}")
            return []

    # ... other methods ...
```

### Step 3: Test Core Functionality
```python
# Test script
from services.xsoar import TicketHandler, ListHandler

handler = TicketHandler()
tickets = handler.get_tickets('type:METCIRT -owner:""', paginate=True)
print(f"Fetched {len(tickets)} tickets")

list_handler = ListHandler()
lists = list_handler.get_all_lists()
print(f"Found {len(lists)} lists")
```

### Step 4: Gradual Rollout
1. Test in dev environment
2. Monitor for errors
3. Deploy to production
4. Monitor performance

## Benefits of Migration

1. **Reduced Maintenance** - No more custom HTTP handling
2. **Official Support** - Bug fixes and updates from Palo Alto
3. **Better Error Handling** - SDK handles edge cases
4. **Type Safety** - Better IDE autocomplete and type checking
5. **Documentation** - Official API docs and examples
6. **Future-Proof** - Stays current with XSOAR API changes

## Risks & Mitigation

| Risk | Mitigation |
|------|-----------|
| Breaking changes in dependent files | Use wrapper approach initially |
| SDK bugs or limitations | Keep backup, easy rollback |
| Performance differences | Benchmark before/after |
| Authentication issues | Test thoroughly in dev first |
| Lost custom features (retry logic) | Implement in wrapper layer |

## Testing Checklist

- [ ] Install demisto-py successfully
- [ ] Configure prod and dev clients
- [ ] Test incident search with pagination
- [ ] Test incident creation
- [ ] Test list operations
- [ ] Test entry/note operations
- [ ] Test participant operations
- [ ] Verify error handling
- [ ] Performance benchmarks
- [ ] Integration tests with dependent files

## Rollback Plan

If issues arise:
1. Restore from backup: `cp services/xsoar.py.backup services/xsoar.py`
2. Uninstall demisto-py: `.venv/bin/pip uninstall demisto-py`
3. Restart services

## Next Steps

1. ✅ Backup created
2. ⏳ Install demisto-py (waiting for network access)
3. ⏳ Implement wrapper version
4. ⏳ Test with small subset of functionality
5. ⏳ Deploy and monitor

## References

- Official SDK: https://github.com/demisto/demisto-py
- PyPI package: https://pypi.org/project/demisto-py/
- XSOAR API Docs: https://xsoar.pan.dev/docs/reference/api/
- Current implementation: `services/xsoar.py.backup`
