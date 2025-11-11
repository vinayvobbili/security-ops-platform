# Email Countdown Timer Integration Guide

## Overview

This guide explains how to use the custom email countdown timer for employee reach out emails sent from Cortex XSOAR.

The countdown timer is a dynamic image that updates each time the email is opened, showing the remaining time for the employee to respond.

## Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   XSOAR      │         │    Email     │         │ Web Server   │
│  Playbook    │  sends  │  (HTML)      │ fetches │  (Flask)     │
│              ├────────>│              ├────────>│              │
│  - Sets URL  │         │  <img src=>  │  image  │  - Generates │
└──────────────┘         └──────────────┘         │    PNG       │
                                                   └──────────────┘
```

1. **XSOAR Playbook** runs `SetEmployeeReachOutCountdownTimer` script
2. Script calculates deadline (current time + 24 hours)
3. Script generates countdown timer URL with deadline parameter
4. Email HTML template includes `<img>` tag with the countdown URL
5. When email is opened, client fetches image from web server
6. Web server generates countdown image on-the-fly based on current time vs deadline
7. Timer updates automatically each time email is reopened

## Files Created

### 1. Web Server Endpoint
**File:** `web/web_server.py` (line 2066)

**Endpoint:** `GET /api/countdown-timer`

**Query Parameters:**
- `deadline` (required): ISO 8601 timestamp (e.g., `2025-11-11T15:00:00-05:00`)
- `title` (optional): Title text shown on timer (default: "Time to Respond")

**Example URL:**
```
http://metcirt-lab-12.internal.company.com/api/countdown-timer?deadline=2025-11-11T15:00:00-05:00&title=Time%20to%20Respond
```

**Visual Features:**
- Displays hours, minutes, and seconds remaining
- Color-coded by urgency:
  - 🟢 Green (≥12 hours): "ACTIVE"
  - 🟡 Yellow (3-12 hours): "ACTIVE"
  - 🟠 Orange (<3 hours): "URGENT"
  - 🔴 Red (expired): "EXPIRED"
- 600x200px image optimized for email clients
- Rounded corners and professional styling matching Acme brand

### 2. Email Template
**File:** `email_templates/employee_reach_out.html` (line 145-156)

The countdown timer image has been added to the email template between the warning box and command details.

**Template Variable:** `{{ COUNTDOWN_TIMER_URL }}`

### 3. XSOAR Automation Script
**File:** `xsoar_scripts/SetEmployeeReachOutCountdownTimer.py`

This script must be uploaded to XSOAR and run before sending the email.

## XSOAR Integration Steps

### Step 1: Upload Automation Script to XSOAR

1. Go to **Settings > Automation**
2. Click **+ New Script**
3. Name: `SetEmployeeReachOutCountdownTimer`
4. Script Type: Python
5. Copy the contents of `xsoar_scripts/SetEmployeeReachOutCountdownTimer.py`
6. Save the script

### Step 2: Update Your Playbook

In your employee reach out playbook, add the following task **before** sending the email:

```yaml
- name: Set Countdown Timer URL
  task:
    scriptName: SetEmployeeReachOutCountdownTimer
  nexttasks:
    '#none#':
      - send_email
```

Or use the command in a task:
```
!SetEmployeeReachOutCountdownTimer
```

### Step 3: Update Email Template Variable Mapping

When sending the email from XSOAR, ensure the template variables are mapped:

```python
# In your email-sending task
email_body_html = template.render({
    'incident': incident,
    'COMMAND_DETAILS': command,
    'TIMESTAMP': timestamp,
    'SYSTEM_NAME': system_name,
    'COUNTDOWN_TIMER_URL': demisto.context().get('COUNTDOWN_TIMER_URL')
})
```

### Step 4: Configure Web Server URL

Update the `WEB_SERVER_BASE_URL` in `SetEmployeeReachOutCountdownTimer.py` to match your environment:

```python
WEB_SERVER_BASE_URL = "http://metcirt-lab-12.internal.company.com"  # Update to your server
```

Or use HTTPS if available:
```python
WEB_SERVER_BASE_URL = "https://your-domain.com"
```

## Configuration Options

### Change Response Window Duration

Edit `SetEmployeeReachOutCountdownTimer.py`:

```python
RESPONSE_WINDOW_HOURS = 24  # Change to desired hours (e.g., 48, 72)
```

### Customize Timer Title

Edit `SetEmployeeReachOutCountdownTimer.py`:

```python
TIMER_TITLE = "Time to Respond"  # Change to your desired text
```

### Adjust Color Thresholds

Edit `web/web_server.py` (countdown_timer function):

```python
if hours >= 12:
    bg_color = (0, 166, 81)  # Green - adjust threshold
elif hours >= 3:
    bg_color = (255, 184, 0)  # Yellow - adjust threshold
else:
    bg_color = (255, 87, 51)  # Orange
```

## Testing

### Test the Countdown Timer Endpoint

1. Start your web server:
   ```bash
   python web/web_server.py
   ```

2. Generate a test deadline (24 hours from now):
   ```python
   from datetime import datetime, timedelta
   import pytz

   eastern = pytz.timezone('US/Eastern')
   deadline = (datetime.now(eastern) + timedelta(hours=24)).isoformat()
   print(f"http://localhost:8080/api/countdown-timer?deadline={deadline}")
   ```

3. Open the URL in your browser to see the countdown timer

### Test in Email Client

1. Create a test HTML file:
   ```html
   <!DOCTYPE html>
   <html>
   <body>
       <h1>Test Email</h1>
       <img src="http://metcirt-lab-12.internal.company.com/api/countdown-timer?deadline=2025-11-11T15:00:00-05:00"
            alt="Countdown Timer"
            style="max-width:600px; width:100%;">
   </body>
   </html>
   ```

2. Send this as an email to yourself
3. Open the email multiple times and verify the countdown updates

### Test XSOAR Script

1. In XSOAR War Room, run:
   ```
   !SetEmployeeReachOutCountdownTimer
   ```

2. Verify the output shows:
   - Countdown timer URL
   - Response deadline timestamp
   - Response window (24 hours)

3. Check context data:
   ```
   !GetContext key=COUNTDOWN_TIMER_URL
   ```

## Troubleshooting

### Countdown Timer Not Showing in Email

**Problem:** Email shows broken image icon

**Solutions:**
1. Check web server is running and accessible
2. Verify URL in email source code
3. Test URL directly in browser
4. Check email client allows external images
5. Verify no firewall blocking the web server

### Timer Shows Wrong Time

**Problem:** Countdown time doesn't match expected value

**Solutions:**
1. Verify timezone settings in XSOAR script (should use US/Eastern)
2. Check web server timezone configuration
3. Ensure deadline parameter is in ISO 8601 format with timezone

### Timer Not Updating When Email Reopened

**Problem:** Countdown shows same time even after hours have passed

**Solutions:**
1. Email client is caching the image - this is expected for some clients
2. Add cache-busting parameter to URL (add `&t={{timestamp}}` to URL)
3. Some email clients cache images for performance - this is a limitation

### XSOAR Script Fails

**Problem:** `SetEmployeeReachOutCountdownTimer` returns an error

**Solutions:**
1. Verify `pytz` is installed in XSOAR Python environment
2. Check script syntax and indentation
3. Review XSOAR logs for detailed error messages
4. Ensure script has proper permissions

## Email Client Compatibility

The countdown timer is compatible with:

✅ **Fully Supported:**
- Outlook (Desktop, Web, Mobile)
- Gmail (Web, Mobile)
- Apple Mail (Desktop, iOS)
- Thunderbird

⚠️ **Partial Support (may cache images):**
- Yahoo Mail
- AOL Mail
- Proton Mail

❌ **Limited/No Support:**
- Some corporate email clients with strict security policies
- Email clients that block external images by default

**Note:** Users must enable "Load External Images" in their email client for the countdown to display.

## Security Considerations

1. **No authentication required** - The countdown timer endpoint is public and doesn't require authentication
   - This is intentional since emails may be opened from various devices
   - No sensitive data is exposed through the timer

2. **Input validation** - The endpoint validates the deadline parameter format

3. **Rate limiting** - Consider adding rate limiting if you experience abuse

4. **HTTPS recommended** - Use HTTPS in production for security

## Maintenance

### Monitoring

Monitor the countdown timer endpoint:

```bash
# Check endpoint health
curl "http://metcirt-lab-12.internal.company.com/api/countdown-timer?deadline=2025-12-01T12:00:00-05:00"

# Check web server logs
tail -f logs/web_server.log | grep countdown-timer
```

### Updates

If you need to change the timer design:

1. Edit the `countdown_timer()` function in `web/web_server.py`
2. Restart the web server
3. No XSOAR changes needed unless URL parameters change

## Support

For issues or questions:
- Check logs: `logs/web_server.log`
- Test endpoint directly in browser
- Review XSOAR execution logs
- Contact the Security Operations team

---

**Last Updated:** 2025-11-10
**Version:** 1.0
