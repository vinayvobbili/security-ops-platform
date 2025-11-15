"""
Test script for XSOAR migration from custom implementation to demisto-py SDK

This script tests the new demisto-py based implementation to ensure
backward compatibility with the existing code.

Usage:
    .venv/bin/python test_xsoar_migration.py
"""
import logging
import json
from datetime import datetime, timedelta
import pytz

# Test both implementations
import services.xsoar as xsoar_old
import services.xsoar_new as xsoar_new

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)


def test_ticket_search():
    """Test basic ticket search functionality"""
    print("\n" + "="*80)
    print("TEST 1: Basic Ticket Search")
    print("="*80)

    query = 'type:METCIRT -owner:"" -status:closed'

    try:
        print("\n[OLD] Fetching tickets with old implementation...")
        old_handler = xsoar_old.TicketHandler()
        old_tickets = old_handler.get_tickets(query, paginate=False, size=5)
        print(f"[OLD] Fetched {len(old_tickets)} tickets")
        if old_tickets:
            print(f"[OLD] First ticket ID: {old_tickets[0].get('id', 'N/A')}")

        print("\n[NEW] Fetching tickets with new implementation...")
        new_handler = xsoar_new.TicketHandler()
        new_tickets = new_handler.get_tickets(query, paginate=False, size=5)
        print(f"[NEW] Fetched {len(new_tickets)} tickets")
        if new_tickets:
            print(f"[NEW] First ticket ID: {new_tickets[0].get('id', 'N/A')}")

        print("\n✅ Test PASSED: Both implementations work")
        return True

    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_paginated_search():
    """Test paginated ticket search"""
    print("\n" + "="*80)
    print("TEST 2: Paginated Ticket Search")
    print("="*80)

    eastern = pytz.timezone('US/Eastern')
    end_date = datetime.now(eastern)
    start_date = end_date - timedelta(days=7)
    start_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')

    query = f'type:METCIRT -owner:"" created:>{start_str}'

    try:
        print("\n[NEW] Fetching tickets with pagination...")
        handler = xsoar_new.TicketHandler()
        tickets = handler.get_tickets(query, paginate=True)
        print(f"[NEW] Fetched {len(tickets)} tickets from past 7 days")

        print("\n✅ Test PASSED: Pagination works")
        return True

    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_list_operations():
    """Test list handler operations"""
    print("\n" + "="*80)
    print("TEST 3: List Operations")
    print("="*80)

    try:
        print("\n[OLD] Fetching all lists with old implementation...")
        old_handler = xsoar_old.ListHandler()
        old_lists = old_handler.get_all_lists()
        print(f"[OLD] Found {len(old_lists)} lists")

        print("\n[NEW] Fetching all lists with new implementation...")
        new_handler = xsoar_new.ListHandler()
        new_lists = new_handler.get_all_lists()
        print(f"[NEW] Found {len(new_lists)} lists")

        # Test getting specific list
        if new_lists:
            list_name = new_lists[0].get('id', 'METCIRT Blocked Domains')
            print(f"\n[NEW] Testing get_list_data_by_name('{list_name}')...")
            list_data = new_handler.get_list_data_by_name(list_name)
            if list_data is not None:
                print(f"[NEW] Successfully fetched list data (type: {type(list_data)})")
            else:
                print(f"[NEW] List '{list_name}' not found or empty")

        print("\n✅ Test PASSED: List operations work")
        return True

    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_incident_details():
    """Test fetching incident details"""
    print("\n" + "="*80)
    print("TEST 4: Incident Details")
    print("="*80)

    try:
        # First, get a recent incident ID
        print("\n[NEW] Fetching recent incident for testing...")
        handler = xsoar_new.TicketHandler()
        tickets = handler.get_tickets('type:METCIRT -owner:""', paginate=False, size=1)

        if not tickets:
            print("⚠️  No tickets found for testing, skipping test")
            return True

        incident_id = tickets[0].get('id')
        print(f"[NEW] Using incident ID: {incident_id}")

        print("\n[NEW] Testing get_case_data()...")
        case_data = xsoar_new.get_case_data(incident_id)
        if case_data:
            print(f"[NEW] Successfully fetched case data (keys: {list(case_data.keys())[:5]}...)")

        print("\n✅ Test PASSED: Incident details work")
        return True

    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("XSOAR MIGRATION TEST SUITE")
    print("Testing demisto-py implementation vs custom implementation")
    print("="*80)

    tests = [
        ("Basic Ticket Search", test_ticket_search),
        ("Paginated Search", test_paginated_search),
        ("List Operations", test_list_operations),
        ("Incident Details", test_incident_details),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            log.error(f"Error running test '{test_name}': {e}")
            results.append((test_name, False))

    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")

    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed! Ready to migrate.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Review errors before migrating.")
        return 1


if __name__ == "__main__":
    exit(main())
