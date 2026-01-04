# Pokedex Executive Summary Feature

## Overview

SOC analysts can now use Pokédex to automatically generate executive summaries for XSOAR tickets. This feature leverages AI to analyze ticket details and analyst notes, producing concise 5-6 bullet point summaries suitable for management review.

## How It Works

1. **Analyst sends message in Webex** - SOC analyst mentions a ticket in their message
2. **Pokédex extracts ticket ID** - The bot identifies the ticket number from the message
3. **Fetches ticket data** - Retrieves ticket details and all analyst notes from XSOAR
4. **Generates summary** - Uses AI to create a sharp, crisp executive summary
5. **Returns formatted summary** - Sends the summary back to Webex as a formatted message

## Usage Examples

SOC analysts can request summaries using natural language:

```
Write an executive summary for X#929947

Generate exec summary for ticket 123456

Summarize incident X#555555

Can you create an executive summary for case 789012?
```

## Summary Format

The executive summary includes:
- **5-6 bullet points** - Sharp and to the point
- **Who, what, when, where, why** - Key incident details
- **Actions taken** - What the SOC team did
- **Outcomes** - Results of the investigation
- **Outstanding risks** - Any remaining concerns
- **Next steps** - What needs to happen next

## Example Output

```markdown
**Executive Summary for Ticket #929947**
*Suspicious PowerShell Activity on Finance Server*

- A finance department server (FIN-SVR-01) exhibited suspicious PowerShell execution
  on 10/23/2025 at 2:24 PM ET, detected by CrowdStrike EDR

- The activity involved encoded PowerShell commands attempting to access credential
  stores and establish external network connections

- SOC analyst contained the host immediately and conducted forensic analysis,
  confirming the activity originated from a compromised admin account

- The compromised account was disabled, the host was isolated and reimaged, and
  all finance department credentials were reset as a precaution

- No data exfiltration was detected; the malicious activity was caught in the
  reconnaissance phase before any sensitive data was accessed

- Next steps: Complete user security awareness training for the affected user and
  review admin access policies for the finance department
```

## Technical Details

### Implementation

The feature is implemented as a LangChain tool that:

1. **Fetches ticket details** using `TicketHandler.get_case_data(ticket_id)`
   - Located in `services/xsoar/ticket_handler.py`
   - Retrieves all ticket metadata, custom fields, and status

2. **Fetches analyst notes** using `TicketHandler.get_user_notes(ticket_id)`
   - Gets all chronological notes from the investigation
   - Includes author and timestamp information

3. **Formats data for AI** into a structured prompt
   - Combines ticket details and notes
   - Provides clear instructions for summary generation

4. **Generates summary** using the Ollama LLM
   - Creates 5-6 bullet points
   - Focuses on executive-level content
   - Formats using Webex markdown

### Files Modified/Created

- **Created**: `my_bot/tools/xsoar_tools.py` - New tool module
- **Modified**: `my_bot/core/state_manager.py` - Registered the tool
- **Created**: `test_executive_summary.py` - Test script
- **Created**: `docs/POKEDEX_EXECUTIVE_SUMMARY.md` - This documentation

### Tool Function Signature

```python
@tool
def generate_executive_summary(ticket_id: str, environment: str = "prod") -> str:
    """
    Generate an executive summary for an XSOAR ticket.

    Args:
        ticket_id: The XSOAR ticket/incident ID (e.g., "123456")
        environment: XSOAR environment - "prod" (default) or "dev"

    Returns:
        Executive summary with 5-6 sharp, crisp bullet points
    """
```

## Testing

A test script is provided at `test_executive_summary.py`:

```bash
# Run the test script
python test_executive_summary.py

# Or run with your virtual environment
.venv/bin/python test_executive_summary.py
```

The test script includes:
- **Test 1**: Direct tool call (fast, <5 seconds)
- **Test 2**: Full LLM agent integration (slower, 20-30 seconds)

## Requirements

- **XSOAR Access**: The bot needs valid XSOAR API credentials
- **Network Access**: Connectivity to XSOAR instance required
- **Ollama**: LLM must be running and accessible
- **Ticket Permissions**: Bot must have read access to the specified ticket

## Error Handling

The tool handles common errors gracefully:

- **Invalid ticket ID**: Returns error message asking to verify ticket exists
- **Network issues**: Provides clear error with troubleshooting steps
- **Missing notes**: Still generates summary from available ticket data
- **LLM unavailable**: Returns error indicating LLM initialization issue

## Future Enhancements

Potential improvements:
- Support for summarizing multiple tickets at once
- Customizable summary length (brief, standard, detailed)
- Email delivery of summaries to stakeholders
- Automated summary generation when tickets are closed
- Integration with ticket metrics and SLA information

## Support

For issues or questions:
1. Check Pokedex logs in `logs/pokedex.log`
2. Run the test script to verify functionality
3. Check XSOAR API connectivity
4. Verify Ollama LLM is running

---

*Last Updated: 2026-01-04*
*Feature Version: 1.0*
*Author: AI Assistant*
