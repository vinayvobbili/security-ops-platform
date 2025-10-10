#!/usr/bin/env python3
"""
Check audit logs for age encryption key access.

This script parses auditd logs to show who accessed the encryption key,
when, and what they did with it.

Usage:
    python scripts/check_key_access.py
    python scripts/check_key_access.py --last 24h
    python scripts/check_key_access.py --suspicious
    python scripts/check_key_access.py --summary
"""

import argparse
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import re


def run_ausearch(time_range=None):
    """Run ausearch command and return output."""
    cmd = ['sudo', 'ausearch', '-k', 'age_key_access', '-i']

    if time_range:
        cmd.extend(['-ts', time_range])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0 and "no matches" in result.stdout.lower():
            return None

        return result.stdout
    except FileNotFoundError:
        print("Error: auditd not installed or ausearch command not found")
        print("Run: sudo apt install auditd")
        sys.exit(1)


def parse_audit_events(output):
    """Parse audit log output into structured events."""
    if not output:
        return []

    events = []
    current_event = {}

    for line in output.split('\n'):
        line = line.strip()

        if not line:
            if current_event:
                events.append(current_event)
                current_event = {}
            continue

        # Parse key=value pairs
        if 'type=' in line:
            # New event
            if current_event:
                events.append(current_event)
                current_event = {}

        # Extract relevant fields
        if 'msg=audit' in line:
            # Extract timestamp
            time_match = re.search(r'audit\((\d+\.\d+):', line)
            if time_match:
                timestamp = float(time_match.group(1))
                current_event['timestamp'] = datetime.fromtimestamp(timestamp)

        if 'auid=' in line:
            # Authenticated user ID
            match = re.search(r'auid=(\S+)', line)
            if match:
                current_event['auid'] = match.group(1)

        if 'uid=' in line:
            # User ID
            match = re.search(r'uid=(\S+)', line)
            if match:
                current_event['uid'] = match.group(1)

        if 'comm=' in line:
            # Command/process
            match = re.search(r'comm="([^"]+)"', line)
            if match:
                current_event['command'] = match.group(1)

        if 'exe=' in line:
            # Executable path
            match = re.search(r'exe="([^"]+)"', line)
            if match:
                current_event['exe'] = match.group(1)

        if 'name=' in line:
            # File name
            match = re.search(r'name="([^"]+)"', line)
            if match:
                current_event['filename'] = match.group(1)

        if 'ppid=' in line:
            # Parent process ID
            match = re.search(r'ppid=(\d+)', line)
            if match:
                current_event['ppid'] = match.group(1)

    if current_event:
        events.append(current_event)

    return events


def is_suspicious(event):
    """Detect potentially suspicious access patterns."""
    suspicious_flags = []

    # Root access (might be legitimate, but worth noting)
    if event.get('uid') == 'root' or event.get('auid') == 'root':
        suspicious_flags.append("root_access")

    # Access from unexpected commands
    command = event.get('command', '').lower()
    exe = event.get('exe', '').lower()

    suspicious_commands = ['cat', 'cp', 'scp', 'rsync', 'curl', 'wget', 'nc', 'netcat']
    for suspicious_cmd in suspicious_commands:
        if suspicious_cmd in command or suspicious_cmd in exe:
            suspicious_flags.append(f"suspicious_command:{suspicious_cmd}")

    # Check for repeated access in short time
    # (would need to track multiple events)

    return suspicious_flags


def display_events(events, show_suspicious_only=False):
    """Display events in a readable format."""
    if not events:
        print("No audit events found for the age encryption key.")
        print()
        print("This could mean:")
        print("  - Audit logging is not set up (run: bash scripts/setup_key_audit.sh)")
        print("  - The key has not been accessed yet")
        print("  - No events match your time filter")
        return

    print(f"\n{'='*80}")
    print(f"Age Encryption Key Access Log ({len(events)} events)")
    print(f"{'='*80}\n")

    for i, event in enumerate(events, 1):
        suspicious = is_suspicious(event)

        if show_suspicious_only and not suspicious:
            continue

        timestamp = event.get('timestamp', 'Unknown')
        user = event.get('uid', 'Unknown')
        command = event.get('command', 'Unknown')
        exe = event.get('exe', 'Unknown')

        # Highlight suspicious events
        marker = "🚨 SUSPICIOUS" if suspicious else "✓"

        print(f"{marker} Event #{i}")
        print(f"  Time:     {timestamp}")
        print(f"  User:     {user}")
        print(f"  Command:  {command}")
        print(f"  Exe:      {exe}")

        if suspicious:
            print(f"  Flags:    {', '.join(suspicious)}")

        print()


def display_summary(events):
    """Display summary statistics."""
    if not events:
        print("No audit events to summarize.")
        return

    # Count by user
    users = defaultdict(int)
    commands = defaultdict(int)
    suspicious_count = 0

    for event in events:
        user = event.get('uid', 'Unknown')
        command = event.get('command', 'Unknown')
        users[user] += 1
        commands[command] += 1

        if is_suspicious(event):
            suspicious_count += 1

    # Time range
    timestamps = [e['timestamp'] for e in events if 'timestamp' in e]
    if timestamps:
        first = min(timestamps)
        last = max(timestamps)

    print(f"\n{'='*80}")
    print(f"Audit Summary")
    print(f"{'='*80}\n")

    print(f"Total Events:     {len(events)}")
    print(f"Suspicious:       {suspicious_count}")

    if timestamps:
        print(f"Time Range:       {first} to {last}")

    print(f"\nAccess by User:")
    for user, count in sorted(users.items(), key=lambda x: x[1], reverse=True):
        print(f"  {user:20s} {count:4d} accesses")

    print(f"\nAccess by Command:")
    for cmd, count in sorted(commands.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {cmd:30s} {count:4d} times")

    print()


def main():
    parser = argparse.ArgumentParser(
        description='Check audit logs for age encryption key access'
    )
    parser.add_argument(
        '--last',
        help='Show events from last X time (e.g., 1h, 24h, 7d)',
        default=None
    )
    parser.add_argument(
        '--suspicious',
        action='store_true',
        help='Show only suspicious access patterns'
    )
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Show summary statistics only'
    )
    parser.add_argument(
        '--today',
        action='store_true',
        help='Show only today\'s events'
    )

    args = parser.parse_args()

    # Determine time range
    time_range = None
    if args.today:
        time_range = 'today'
    elif args.last:
        time_range = args.last

    # Get audit logs
    print("Fetching audit logs...")
    output = run_ausearch(time_range)

    # Parse events
    events = parse_audit_events(output)

    # Display results
    if args.summary:
        display_summary(events)
    else:
        display_events(events, show_suspicious_only=args.suspicious)

        if not args.suspicious and events:
            suspicious_count = sum(1 for e in events if is_suspicious(e))
            if suspicious_count > 0:
                print(f"⚠️  Found {suspicious_count} potentially suspicious events")
                print(f"   Run with --suspicious flag to see them")
                print()


if __name__ == '__main__':
    main()
