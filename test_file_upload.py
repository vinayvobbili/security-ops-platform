#!/usr/bin/env python3
"""
Test script to verify file upload to XSOAR attachments vs war room.

This script demonstrates the difference between:
1. /incident/upload/{id} -> ATTACHMENTS field
2. /entry/upload/{id} -> War room (Evidence/Indicators)
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.xsoar import TicketHandler
from src.utils.xsoar_enums import XsoarEnvironment
from datetime import datetime
import json
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    # Configuration
    ticket_id = '1380362'  # Replace with your test ticket ID
    test_file_path = "/tmp/test_attachment.txt"

    # Create a test file
    if not os.path.exists(test_file_path):
        with open(test_file_path, 'w') as f:
            f.write("This is a test attachment file.\n")
            f.write(f"Created at: {datetime.now()}\n")
        print(f"✓ Created test file: {test_file_path}")
    else:
        print(f"✓ Using existing test file: {test_file_path}")

    # Initialize handler for DEV environment
    dev_ticket_handler = TicketHandler(XsoarEnvironment.DEV)

    # Test 1: Upload to ATTACHMENTS field
    print("\n" + "="*70)
    print("TEST 1: Uploading to ATTACHMENTS field")
    print(f"Endpoint: /incident/upload/{ticket_id}")
    print("Expected: File should appear in ATTACHMENTS section")
    print("="*70)
    try:
        result = dev_ticket_handler.upload_file_to_attachment(
            ticket_id,
            test_file_path,
            "Test file uploaded to ATTACHMENTS field"
        )
        print(f"✓ SUCCESS!")
        print(f"Response: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 2: Upload to war room
    print("\n" + "="*70)
    print("TEST 2: Uploading to WAR ROOM")
    print(f"Endpoint: /entry/upload/{ticket_id}")
    print("Expected: File should appear in Evidence/Indicators, NOT in ATTACHMENTS")
    print("="*70)
    try:
        result = dev_ticket_handler.upload_file_to_war_room(
            ticket_id,
            test_file_path,
            "Test file uploaded to war room"
        )
        print(f"✓ SUCCESS!")
        print(f"Response: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Test 3: Using the wrapper method (defaults to attachment)
    print("\n" + "="*70)
    print("TEST 3: Using upload_file_to_ticket() wrapper (defaults to attachment)")
    print("="*70)
    try:
        result = dev_ticket_handler.upload_file_to_ticket(
            ticket_id,
            test_file_path,
            "Test via wrapper method"
        )
        print(f"✓ SUCCESS!")
        print(f"Response: {json.dumps(result, indent=2)}")
    except Exception as e:
        print(f"✗ ERROR: {e}")
        import traceback
        traceback.print_exc()

    # Summary
    print("\n" + "="*70)
    print("VERIFICATION CHECKLIST:")
    print("="*70)
    print(f"Go to XSOAR DEV ticket: {ticket_id}")
    print(f"")
    print(f"Expected results:")
    print(f"  1. ATTACHMENTS section: should have 2 files")
    print(f"     - 'test_attachment.txt' (from Test 1)")
    print(f"     - 'test_attachment.txt' (from Test 3)")
    print(f"")
    print(f"  2. Evidence/Indicators: should have 1 file")
    print(f"     - 'test_attachment.txt' (from Test 2)")
    print(f"")
    print("="*70)

if __name__ == "__main__":
    main()
