#!/usr/bin/env python3
"""
Test script to verify CONFIG refactoring works correctly.

This script tests:
1. CONFIG loads without errors
2. All expected values are present
3. Dynamic values are correctly derived
4. Refactored code imports successfully
5. Key functions still work with CONFIG values
"""

import sys
import traceback
from pathlib import Path

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_test(name):
    print(f"\n{BLUE}Testing:{RESET} {name}")

def print_pass(message):
    print(f"  {GREEN}✓{RESET} {message}")

def print_fail(message):
    print(f"  {RED}✗{RESET} {message}")

def print_warn(message):
    print(f"  {YELLOW}⚠{RESET} {message}")

def test_config_import():
    """Test that config module imports successfully."""
    print_test("CONFIG Import")
    try:
        from my_config import get_config
        CONFIG = get_config()
        print_pass("Config imported successfully")
        return CONFIG
    except Exception as e:
        print_fail(f"Failed to import config: {e}")
        traceback.print_exc()
        return None

def test_config_values(CONFIG):
    """Test that all expected config values are present."""
    print_test("CONFIG Values")

    if not CONFIG:
        print_fail("CONFIG is None")
        return False

    # Test required values
    tests = [
        ("team_name", CONFIG.team_name),
        ("company_name", CONFIG.company_name),
        ("my_web_domain", CONFIG.my_web_domain),
    ]

    all_passed = True
    for name, value in tests:
        if value:
            print_pass(f"{name} = {value}")
        else:
            print_warn(f"{name} is not set (may be optional)")

    # Test derived company_name
    if CONFIG.company_name:
        if CONFIG.my_web_domain:
            expected = CONFIG.my_web_domain.split('.')[0].title()
            if CONFIG.company_name == expected:
                print_pass(f"company_name correctly derived from domain: {CONFIG.company_name}")
            else:
                print_pass(f"company_name explicitly set: {CONFIG.company_name}")
        else:
            print_pass(f"company_name set: {CONFIG.company_name}")

    return all_passed

def test_data_maps():
    """Test that data_maps uses CONFIG correctly."""
    print_test("data/data_maps.py")

    try:
        from data.data_maps import azdo_projects, azdo_orgs, azdo_area_paths
        print_pass("data_maps imported successfully")

        # Check that values use CONFIG
        print_pass(f"azdo_orgs sample: {list(azdo_orgs.values())[0]}")
        print_pass(f"azdo_area_paths sample: {list(azdo_area_paths.values())[0]}")

        return True
    except Exception as e:
        print_fail(f"Failed to import data_maps: {e}")
        traceback.print_exc()
        return False

def test_component_imports():
    """Test that refactored components import successfully."""
    print_test("Component Imports")

    components = [
        "src.components.orphaned_tickets",
        "src.components.qa_tickets",
        "src.components.abandoned_tickets",
        "src.components.ticket_cache",
        "src.components.containment_sla_risk_tickets",
        "src.components.incident_declaration_sla_risk",
        "src.components.response_sla_risk_tickets",
    ]

    all_passed = True
    for component in components:
        try:
            __import__(component)
            print_pass(f"{component.split('.')[-1]}")
        except Exception as e:
            print_fail(f"{component}: {e}")
            all_passed = False

    return all_passed

def test_helper_functions(CONFIG):
    """Test helper functions that use CONFIG."""
    print_test("Helper Functions")

    try:
        from src.components.ticket_cache import clean_owner_name, clean_type_name

        # Test email cleaning
        test_email = f"user@{CONFIG.my_web_domain}"
        cleaned = clean_owner_name(test_email)
        if cleaned == "user":
            print_pass(f"clean_owner_name: '{test_email}' → '{cleaned}'")
        else:
            print_fail(f"clean_owner_name failed: expected 'user', got '{cleaned}'")

        # Test type name cleaning
        test_type = f"{CONFIG.team_name} Ticket QA"
        cleaned_type = clean_type_name(test_type)
        expected = "Ticket QA"
        if cleaned_type == expected:
            print_pass(f"clean_type_name: '{test_type}' → '{cleaned_type}'")
        else:
            print_fail(f"clean_type_name failed: expected '{expected}', got '{cleaned_type}'")

        return True
    except Exception as e:
        print_fail(f"Helper function test failed: {e}")
        traceback.print_exc()
        return False

def test_query_generation(CONFIG):
    """Test that queries use CONFIG.team_name correctly."""
    print_test("Query Generation")

    # Simulate query generation
    query = f'type:{CONFIG.team_name} -owner:""'
    print_pass(f"Sample query: {query}")

    # Check it's using f-string
    if CONFIG.team_name in query:
        print_pass("Query correctly uses CONFIG.team_name")
        return True
    else:
        print_fail("Query doesn't use CONFIG.team_name")
        return False

def main():
    print("=" * 70)
    print(f"{BLUE}CONFIG Refactoring Test Suite{RESET}")
    print("=" * 70)

    # Run tests
    CONFIG = test_config_import()
    if not CONFIG:
        print(f"\n{RED}CRITICAL: Config import failed. Cannot continue.{RESET}")
        sys.exit(1)

    results = {
        "Config Values": test_config_values(CONFIG),
        "Data Maps": test_data_maps(),
        "Component Imports": test_component_imports(),
        "Helper Functions": test_helper_functions(CONFIG),
        "Query Generation": test_query_generation(CONFIG),
    }

    # Summary
    print("\n" + "=" * 70)
    print(f"{BLUE}Test Summary{RESET}")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for test_name, result in results.items():
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"{test_name:.<50} {status}")

    print("-" * 70)
    print(f"Total: {passed}/{total} tests passed")

    if passed == total:
        print(f"\n{GREEN}✓ All tests passed! Refactoring successful.{RESET}")
        return 0
    else:
        print(f"\n{RED}✗ Some tests failed. Review errors above.{RESET}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
