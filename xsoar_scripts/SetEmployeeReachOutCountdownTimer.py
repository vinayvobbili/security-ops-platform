"""
XSOAR Script: Set Employee Reach Out Countdown Timer

Generates a countdown timer URL for the employee reach out email.
The countdown timer displays the time remaining for the employee to respond (4 hours).

This script calculates the deadline (current time + 4 hours) and creates a URL
that points to the web server's countdown timer endpoint.

Usage:
    Place this script in XSOAR and call it before sending the employee reach out email:
    !SetEmployeeReachOutCountdownTimer

The script will set the following context variables:
    - COUNTDOWN_TIMER_URL: The full URL to the countdown timer image
    - RESPONSE_DEADLINE: The deadline timestamp (ISO 8601 format)

Example output context:
    {
        "COUNTDOWN_TIMER_URL": "http://your-server.com/api/countdown-timer?deadline=2025-11-11T15:00:00-05:00&title=Time%20to%20Respond",
        "RESPONSE_DEADLINE": "2025-11-11T15:00:00-05:00"
    }
"""
from datetime import datetime, timedelta
from urllib.parse import quote

import pytz

# Configuration
WEB_SERVER_BASE_URL = "http://metcirt-lab-12.internal.company.com"  # Update this to your web server URL
RESPONSE_WINDOW_HOURS = 4  # Number of hours for employee to respond
TIMER_TITLE = "Time to Respond"


def generate_countdown_timer_url():
    """Generate the countdown timer URL with deadline parameter.

    Returns:
        tuple: (countdown_timer_url, deadline_iso)
    """
    # Get current time in Eastern Time
    eastern = pytz.timezone('US/Eastern')
    now = datetime.now(eastern)

    # Calculate deadline (current time + response window)
    deadline = now + timedelta(hours=RESPONSE_WINDOW_HOURS)

    # Format deadline as ISO 8601
    deadline_iso = deadline.isoformat()

    # URL encode the title
    encoded_title = quote(TIMER_TITLE)

    # Construct the countdown timer URL
    countdown_url = f"{WEB_SERVER_BASE_URL}/api/countdown-timer?deadline={deadline_iso}&title={encoded_title}"

    return countdown_url, deadline_iso


def main():
    """Generate countdown timer URL and set context variables."""
    try:
        # Generate the countdown timer URL
        countdown_url, deadline_iso = generate_countdown_timer_url()

        # Return results for display
        return_results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'countdown_timer_url': countdown_url,
                'response_deadline': deadline_iso,
                'response_window_hours': RESPONSE_WINDOW_HOURS
            },
            'HumanReadable': f"✅ Countdown timer configured\n\n"
                             f"**Response Deadline:** {deadline_iso}\n"
                             f"**Response Window:** {RESPONSE_WINDOW_HOURS} hours\n"
                             f"**Timer URL:** {countdown_url}\n\n"
                             f"The countdown timer URL has been set and can be used in the email template with {{{{ COUNTDOWN_TIMER_URL }}}}",
            'EntryContext': {
                'EmployeeReachOut': {
                    'CountdownTimerURL': countdown_url,
                    'ResponseDeadline': deadline_iso,
                    'ResponseWindowHours': RESPONSE_WINDOW_HOURS
                }
            }
        })

    except Exception as exc:
        return_error(f"Failed to generate countdown timer: {str(exc)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
