#!/usr/bin/env python3
"""
Monitor age encryption key access and send alerts for suspicious activity.

This script is designed to run periodically (via cron) to check for
suspicious access to the encryption key and send notifications.

Usage:
    python scripts/monitor_key_access.py
    python scripts/monitor_key_access.py --alert-webex
    python scripts/monitor_key_access.py --alert-email

Cron example (check every hour):
    0 * * * * cd /home/vinay/pub/IR && python scripts/monitor_key_access.py --alert-webex
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
import os

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


STATE_FILE = project_root / 'data' / 'transient' / 'key_access_state.json'


def load_state():
    """Load last check state."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {'last_check': None, 'last_alert': None, 'event_count': 0}


def save_state(state):
    """Save check state."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def get_recent_events(since_time=None):
    """Get audit events since last check."""
    if since_time is None:
        # Default to last hour
        since_time = datetime.now() - timedelta(hours=1)

    # Format time for ausearch
    time_str = since_time.strftime('%m/%d/%Y %H:%M:%S')

    cmd = [
        'sudo', 'ausearch',
        '-k', 'age_key_access',
        '-ts', time_str,
        '-i'
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            return []

        return result.stdout
    except Exception as e:
        print(f"Error fetching audit logs: {e}")
        return []


def analyze_events(audit_output):
    """Analyze events for suspicious patterns."""
    if not audit_output:
        return {
            'total': 0,
            'suspicious': [],
            'legitimate': 0
        }

    lines = audit_output.split('\n')

    suspicious = []
    total = 0
    legitimate_commands = ['python', 'age', '.venv']

    for line in lines:
        if 'type=SYSCALL' in line or 'type=PATH' in line:
            total += 1

            # Check for suspicious indicators
            is_suspicious = False
            reason = []

            # Root access
            if 'uid=root' in line or 'auid=root' in line:
                reason.append('root_access')

            # Suspicious commands
            if 'comm="cat"' in line and 'key.txt' in line:
                is_suspicious = True
                reason.append('direct_cat_of_key')

            if 'comm="cp"' in line or 'comm="scp"' in line:
                is_suspicious = True
                reason.append('copy_attempt')

            if 'comm="curl"' in line or 'comm="wget"' in line:
                is_suspicious = True
                reason.append('network_tool_access')

            # Check if it's from legitimate application
            is_legitimate = any(cmd in line for cmd in legitimate_commands)

            if is_suspicious and not is_legitimate:
                suspicious.append({
                    'line': line,
                    'reason': reason,
                    'timestamp': datetime.now()
                })

    return {
        'total': total,
        'suspicious': suspicious,
        'legitimate': total - len(suspicious)
    }


def send_webex_alert(analysis):
    """Send alert to Webex."""
    try:
        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        webex_api = WebexAPI(config.webex_bot_access_token_toodles)

        message = f"""🚨 **Security Alert: Age Key Access**

Detected {len(analysis['suspicious'])} suspicious access attempts to encryption key!

**Details:**
- Total events: {analysis['total']}
- Suspicious: {len(analysis['suspicious'])}
- Legitimate: {analysis['legitimate']}

**Suspicious Activity:**
"""
        for i, event in enumerate(analysis['suspicious'][:5], 1):
            reasons = ', '.join(event['reason'])
            message += f"\n{i}. {reasons}"

        message += "\n\nRun `python scripts/check_key_access.py --suspicious` for details."

        webex_api.messages.create(
            roomId=config.webex_room_id_vinay_test_space,
            markdown=message
        )

        print("✓ Webex alert sent")
        return True

    except Exception as e:
        print(f"Failed to send Webex alert: {e}")
        return False


def send_email_alert(analysis):
    """Send alert via email (if configured)."""
    try:
        from my_config import get_config
        # You'd implement email sending here using your preferred method
        # (mailersend, SMTP, etc.)

        print("Email alerts not yet implemented")
        return False

    except Exception as e:
        print(f"Failed to send email alert: {e}")
        return False


def send_console_alert(analysis):
    """Print alert to console."""
    print("\n" + "="*80)
    print("🚨 SECURITY ALERT: Suspicious Age Key Access Detected")
    print("="*80)
    print()
    print(f"Total events:      {analysis['total']}")
    print(f"Suspicious events: {len(analysis['suspicious'])}")
    print(f"Legitimate events: {analysis['legitimate']}")
    print()

    if analysis['suspicious']:
        print("Suspicious activity detected:")
        for i, event in enumerate(analysis['suspicious'][:10], 1):
            reasons = ', '.join(event['reason'])
            print(f"  {i}. {reasons}")

        print()
        print("Run for full details:")
        print("  python scripts/check_key_access.py --suspicious")
        print()


def main():
    parser = argparse.ArgumentParser(
        description='Monitor age encryption key access for suspicious activity'
    )
    parser.add_argument(
        '--alert-webex',
        action='store_true',
        help='Send alerts to Webex'
    )
    parser.add_argument(
        '--alert-email',
        action='store_true',
        help='Send alerts via email'
    )
    parser.add_argument(
        '--threshold',
        type=int,
        default=1,
        help='Minimum suspicious events to trigger alert (default: 1)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Check but don\'t send alerts'
    )

    args = parser.parse_args()

    # Load previous state
    state = load_state()

    # Determine time range to check
    if state['last_check']:
        last_check = datetime.fromisoformat(state['last_check'])
    else:
        # First run, check last hour
        last_check = datetime.now() - timedelta(hours=1)

    print(f"Checking key access since: {last_check}")

    # Get recent events
    audit_output = get_recent_events(last_check)

    # Analyze for suspicious patterns
    analysis = analyze_events(audit_output)

    print(f"Found {analysis['total']} events ({len(analysis['suspicious'])} suspicious)")

    # Update state
    new_state = {
        'last_check': datetime.now().isoformat(),
        'last_alert': state.get('last_alert'),
        'event_count': state.get('event_count', 0) + analysis['total']
    }

    # Send alerts if threshold met
    if len(analysis['suspicious']) >= args.threshold:
        send_console_alert(analysis)

        if not args.dry_run:
            alert_sent = False

            if args.alert_webex:
                alert_sent = send_webex_alert(analysis) or alert_sent

            if args.alert_email:
                alert_sent = send_email_alert(analysis) or alert_sent

            if alert_sent:
                new_state['last_alert'] = datetime.now().isoformat()

    else:
        print("No suspicious activity detected")

    # Save state
    save_state(new_state)


if __name__ == '__main__':
    main()
