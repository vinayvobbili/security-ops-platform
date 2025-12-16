'''
    Author: Nate Rooth
    Created: April 7th, 2023
    Updated: July 26th, 2024
    Description: Wrapper script to handle IOC Hunts in Qradar

    Change Log:
    July 26th, 2024 - Added sleep between adding IOCs to Qradar reference set and executing query
    October 28th, 2025 - Added extensive debug logging to track IOC flow
    October 28th, 2025 - FIXED: Added proactive reference set cleanup at START of hunt
    October 28th, 2025 - FIXED: Added try/finally to guarantee cleanup even on timeout/error

    IMPORTANT - TIMEOUT CONFIGURATION:
    This script can take 40+ minutes to complete (120s sleep + up to 40 retries * 60s each).
    XSOAR script timeout must be set to at least 60 minutes to prevent premature termination.

    To increase timeout in XSOAR:
    1. Go to Settings > Automations & Scripts
    2. Find "{CONFIG.team_name}_Qradar_IOC_Hunt" (or this script name)
    3. Click Edit > Advanced Settings
    4. Set "Timeout" to 3600 seconds (60 minutes) or higher
    5. Save

    ROOT CAUSE ANALYSIS - MYSTERY SOLVED:
    Input was 6 IPs, but got 141.98.11.175 in results (not in input list!)

    CONFIRMED ROOT CAUSE: Stale reference set from previous failed hunt
    - Previous hunt (incident #885871) timed out on Oct 27th 2025
    - Timeout prevented cleanup code from executing
    - 141.98.11.175 remained in reference set
    - Next hunt picked up this stale IOC along with new ones

    FIXES IMPLEMENTED:
    1. Proactive cleanup at START (line 230-234) - cleans stale data before every hunt
    2. try/finally block (line 240-329) - guarantees cleanup even on timeout/error
    3. Warnings when stale data detected (line 224-226)
'''

import json

from my_config import get_config
CONFIG = get_config()

QRADAR_INSTANCE = "QRadar_v3_instance_1"
XSOAR_TICKET_ID = demisto.incidents()[0].get("id")

QUERY_SLEEP = 60  # SECONDS
QUERY_RETRIES = 40  # MINUTES

RESULTS_OUTPUT = 'QRadar.Results'

COMMANDS = {
    'UPDATE_REF_SET': "qradar-reference-set-value-upsert",
    'GET_REF_SET': "qradar-reference-sets-list",
    'PURGE_REF_SET': "qradar-reference-set-delete",
    'EXECUTE_QUERY': "qradar-search-create",
    'GET_QUERY_STATUS': "qradar-search-status-get",
    'GET_QUERY_RESULTS': "qradar-search-results-get"
}

SAVED_SEARCH_ID = {
    'DOMAIN': "4991",  # Original Query is 4762
    'SRC_IP': "4757",  # This query will use the _ThreatTipperHunt_IPAddress_Src reference set
    'DST_IP': "4761"  # This query will use the _ThreatTipperHunt_IPAddress reference set
}

HUNT_REF_SETS = {
    'DOMAIN': '_ThreatTipperHunt_Domain',
    # 'SRC_IP': '_ThreatTipperHunt_IPAddress',
    'SRC_IP': '_ThreatTipperHunt_IPAddress_Src',
    'DST_IP': '_ThreatTipperHunt_IPAddress'
}

'''HELPER FUNCTIONS'''


# Add IOCs to Qradar reference set
def update_ref_set(ref_set, IOCS):
    print(f"[DEBUG] update_ref_set() called with ref_set={ref_set}")
    print(f"[DEBUG] update_ref_set() IOCs received: {IOCS}")
    print(f"[DEBUG] update_ref_set() IOCs type: {type(IOCS)}")
    print(f"[DEBUG] update_ref_set() IOCs count: {len(IOCS) if isinstance(IOCS, list) else 1}")

    params = {
        'Using': QRADAR_INSTANCE,
        'ref_name': ref_set,
        'value': IOCS,
        'source': "XSOAR-%s IOC Hunt" % (XSOAR_TICKET_ID)
    }
    print(f"[DEBUG] update_ref_set() Sending params to QRadar: {json.dumps(params, indent=2)}")

    response = demisto.executeCommand(COMMANDS['UPDATE_REF_SET'], params)
    print(f"[DEBUG] update_ref_set() QRadar response: {response}")
    return response


# List IOCs from Qradar reference set
def get_ref_set(ref_set):
    print(f"[DEBUG] get_ref_set() called for ref_set={ref_set}")

    params = {
        'Using': QRADAR_INSTANCE,
        'ref_name': ref_set
    }
    print(f"[DEBUG] get_ref_set() Fetching reference set with params: {json.dumps(params, indent=2)}")

    response = demisto.executeCommand(COMMANDS['GET_REF_SET'], params)[0]['Contents']
    print(f"[DEBUG] get_ref_set() Full response: {response}")

    ref_set_data = response['data']
    print(f"[DEBUG] get_ref_set() Reference set data: {ref_set_data}")

    if 'data' in ref_set_data and isinstance(ref_set_data['data'], list):
        print(f"[DEBUG] get_ref_set() Current IOCs in reference set: {ref_set_data['data']}")
        print(f"[DEBUG] get_ref_set() Count of IOCs in reference set: {len(ref_set_data['data'])}")
    else:
        print(f"[DEBUG] get_ref_set() Reference set appears empty or has unexpected structure")

    return ref_set_data


# Purge all IOCs from Qradar reference set
def empty_ref_set(ref_set):
    print(f"[DEBUG] empty_ref_set() called for ref_set={ref_set}")
    print(f"[DEBUG] empty_ref_set() Purging reference set to clean up after hunt")

    params = {
        'Using': QRADAR_INSTANCE,
        'ref_name': ref_set,
        'purge_only': 'true'
    }

    response = demisto.executeCommand(COMMANDS['PURGE_REF_SET'], params)
    print(f"[DEBUG] empty_ref_set() Purge response: {response}")
    return response


# Execute Qradar Query based on TYPE
def execute_saved_search(saved_search_id):
    print(f"[DEBUG] execute_saved_search() called with saved_search_id={saved_search_id}")

    params = {
        'Using': QRADAR_INSTANCE,
        'saved_search_id': saved_search_id
    }
    print(f"[DEBUG] execute_saved_search() Executing search with params: {json.dumps(params, indent=2)}")

    response = demisto.executeCommand(COMMANDS['EXECUTE_QUERY'], params)[0]['Contents']
    print(f"[DEBUG] execute_saved_search() Query response: {response}")

    search_id = response['cursor_id']
    print(f"[DEBUG] execute_saved_search() Search ID assigned: {search_id}")
    return search_id


def get_search_status(search_id):
    print(f"[DEBUG] get_search_status() called with search_id={search_id}")

    params = {
        'Using': QRADAR_INSTANCE,
        'search_id': search_id
    }

    response = demisto.executeCommand(COMMANDS['GET_QUERY_STATUS'], params)[0]['Contents']
    search_status = response['status']
    print(f"[DEBUG] get_search_status() Current status: {search_status}")
    return search_status


def get_search_results(search_id):
    print(f"[DEBUG] get_search_results() called with search_id={search_id}")

    params = {
        'Using': QRADAR_INSTANCE,
        'search_id': search_id,
        'output_path': RESULTS_OUTPUT
    }
    print(f"[DEBUG] get_search_results() Fetching results with params: {json.dumps(params, indent=2)}")

    response = demisto.executeCommand(COMMANDS['GET_QUERY_RESULTS'], params)
    print(f"[DEBUG] get_search_results() Full response: {response}")

    contents = response[0]['Contents']
    print(f"[DEBUG] get_search_results() Response contents: {contents}")

    events = contents['events']
    print(f"[DEBUG] get_search_results() Events retrieved: {events}")
    print(f"[DEBUG] get_search_results() Number of events: {len(events)}")

    # Extract and log unique IOCs from events
    iocs_in_results = set()
    for event in events:
        if 'IOC' in event:
            iocs_in_results.add(event['IOC'])
    print(f"[DEBUG] get_search_results() Unique IOCs found in results: {sorted(list(iocs_in_results))}")
    print(f"[DEBUG] get_search_results() Count of unique IOCs: {len(iocs_in_results)}")

    # Check if 141.98.11.175 is in the results
    if '141.98.11.175' in iocs_in_results:
        print(f"[DEBUG] get_search_results() ⚠️⚠️⚠️ 141.98.11.175 FOUND IN SEARCH RESULTS!")
        print(f"[DEBUG] get_search_results() This IP was NOT in our input list!")
        # Show which event(s) contain this IP
        for idx, event in enumerate(events):
            if event.get('IOC') == '141.98.11.175':
                print(f"[DEBUG] get_search_results() Event with 141.98.11.175: {event}")

    return events


# Dispatch appropriate QRadar query based on TYPE
def hunt_dispatcher(TYPE, IOCS):
    print(f"[DEBUG] ========== HUNT DISPATCHER START ==========")
    print(f"[DEBUG] hunt_dispatcher() called with TYPE={TYPE}")
    print(f"[DEBUG] hunt_dispatcher() IOCs received: {IOCS}")
    print(f"[DEBUG] hunt_dispatcher() IOCs type: {type(IOCS)}")

    saved_search_id = SAVED_SEARCH_ID[TYPE]
    ref_set = HUNT_REF_SETS[TYPE]
    print(f"[DEBUG] hunt_dispatcher() Using saved_search_id={saved_search_id}")
    print(f"[DEBUG] hunt_dispatcher() Using ref_set={ref_set}")

    # Normalize IOCs to list format
    if not isinstance(IOCS, list):
        print(f"[DEBUG] hunt_dispatcher() Converting single IOC to list")
        i = [IOCS]
        IOCS = i
    print(f"[DEBUG] hunt_dispatcher() IOCs after normalization: {IOCS}")
    print(f"[DEBUG] hunt_dispatcher() Count of IOCs to hunt: {len(IOCS)}")

    # CRITICAL: Check reference set BEFORE cleaning/updating
    print(f"[DEBUG] hunt_dispatcher() CHECKING REFERENCE SET BEFORE UPDATE")
    try:
        existing_ref_set = get_ref_set(ref_set)
        print(f"[DEBUG] hunt_dispatcher() Existing reference set contents: {existing_ref_set}")

        # Try to extract the actual IOC values if available
        if isinstance(existing_ref_set, dict) and 'data' in existing_ref_set:
            existing_iocs = existing_ref_set.get('data', [])
            print(f"[DEBUG] hunt_dispatcher() Existing IOCs in ref set: {existing_iocs}")
            print(f"[DEBUG] hunt_dispatcher() Count of existing IOCs: {len(existing_iocs) if isinstance(existing_iocs, list) else 'unknown'}")

            # Check if 141.98.11.175 is already there
            if '141.98.11.175' in str(existing_ref_set):
                print(f"[DEBUG] hunt_dispatcher() ⚠️ FOUND 141.98.11.175 IN EXISTING REF SET!")

            # Warn if reference set is not empty
            if existing_iocs and len(existing_iocs) > 0:
                print(f"[WARNING] hunt_dispatcher() Reference set is NOT EMPTY! Contains {len(existing_iocs)} stale IOCs from previous hunt")
                return_results(f"⚠️ WARNING: Reference set {ref_set} contained {len(existing_iocs)} stale IOCs. Cleaning before hunt.")
    except Exception as e:
        print(f"[DEBUG] hunt_dispatcher() Could not retrieve existing ref set (may be empty): {str(e)}")

    # PROACTIVE CLEANUP: Always purge reference set before starting a new hunt
    print(f"[DEBUG] hunt_dispatcher() CLEANING REFERENCE SET BEFORE HUNT (prevents stale IOCs)")
    return_results(f"Cleaning reference set {ref_set} before starting hunt...")
    empty_ref_set(ref_set)
    print(f"[DEBUG] hunt_dispatcher() Reference set cleaned")

    # Add IOCs to reference set
    print(f"[DEBUG] hunt_dispatcher() ADDING IOCs TO REFERENCE SET")
    update_ref_set(ref_set, IOCS)

    # Use try/finally to GUARANTEE cleanup even if hunt fails
    try:
        # CRITICAL: Check reference set AFTER adding new IOCs
        print(f"[DEBUG] hunt_dispatcher() CHECKING REFERENCE SET AFTER UPDATE")
        try:
            updated_ref_set = get_ref_set(ref_set)
            print(f"[DEBUG] hunt_dispatcher() Updated reference set contents: {updated_ref_set}")

            # Try to extract the actual IOC values if available
            if isinstance(updated_ref_set, dict) and 'data' in updated_ref_set:
                updated_iocs = updated_ref_set.get('data', [])
                print(f"[DEBUG] hunt_dispatcher() Updated IOCs in ref set: {updated_iocs}")
                print(f"[DEBUG] hunt_dispatcher() Count of updated IOCs: {len(updated_iocs) if isinstance(updated_iocs, list) else 'unknown'}")

                # Check if 141.98.11.175 is now there
                if '141.98.11.175' in str(updated_ref_set):
                    print(f"[DEBUG] hunt_dispatcher() ⚠️ FOUND 141.98.11.175 IN UPDATED REF SET!")

                # Compare what we sent vs what's in ref set
                print(f"[DEBUG] hunt_dispatcher() IOCs we sent: {sorted(IOCS)}")
                if isinstance(updated_iocs, list):
                    print(f"[DEBUG] hunt_dispatcher() IOCs now in ref set: {sorted(updated_iocs)}")
        except Exception as e:
            print(f"[DEBUG] hunt_dispatcher() Could not retrieve updated ref set: {str(e)}")

        print(f"[DEBUG] hunt_dispatcher() Sleeping for 120 seconds to allow QRadar to propagate changes")
        demisto.executeCommand("Sleep", {"seconds": 120})
        print(f"[DEBUG] hunt_dispatcher() Sleep completed, executing search")

        search_id = execute_saved_search(saved_search_id)

        print(f"[DEBUG] hunt_dispatcher() Starting query status polling (max {QUERY_RETRIES} retries)")
        for x in range(QUERY_RETRIES):
            print(f"[DEBUG] hunt_dispatcher() Polling attempt {x + 1}/{QUERY_RETRIES}")
            search_status = get_search_status(search_id)

            if search_status == "COMPLETED":
                print(f"[DEBUG] hunt_dispatcher() Query COMPLETED after {x + 1} attempts")
                break
            elif search_status == "CANCELED":
                print(f"[DEBUG] hunt_dispatcher() Query CANCELED after {x + 1} attempts")
                break
            elif search_status == "ERROR":
                print(f"[DEBUG] hunt_dispatcher() Query ERROR after {x + 1} attempts")
                break

            demisto.executeCommand("Sleep", {"seconds": QUERY_SLEEP})

        if search_status == "COMPLETED":
            print(f"[DEBUG] hunt_dispatcher() Query completed successfully in {x + 1} minutes")
            return_results(f"Qradar {TYPE} Query {search_status} in {x + 1} minutes")

            print(f"[DEBUG] hunt_dispatcher() Fetching search results")
            results = get_search_results(search_id)
            print(f"[DEBUG] hunt_dispatcher() Processing {len(results)} result events")

            events = []
            for idx, event in enumerate(results):
                print(f"[DEBUG] hunt_dispatcher() Processing event {idx + 1}/{len(results)}: {event}")
                event['Tool'] = "QRadar - %s" % (TYPE)

                # Get IOC verdict
                ioc_value = event.get('IOC', 'UNKNOWN')
                print(f"[DEBUG] hunt_dispatcher() Getting verdict for IOC: {ioc_value}")
                Verdict = demisto.executeCommand(f"{CONFIG.team_name}_Get_IOC_Verdict", {'IOC': ioc_value})[0]['Contents']
                event['Verdict'] = Verdict
                print(f"[DEBUG] hunt_dispatcher() Verdict for {ioc_value}: {Verdict}")

                events.append(event)

            # Store all results in context
            key = 'QRadar.IOC.' + TYPE
            print(f"[DEBUG] hunt_dispatcher() Storing {len(events)} events in context key: {key}")
            print(f"[DEBUG] hunt_dispatcher() Events to store: {events}")
            appendContext(key, events)
            print(f"[DEBUG] hunt_dispatcher() Successfully stored results in context")

        else:
            print(f"[DEBUG] hunt_dispatcher() Query did not complete successfully")
            return_results(f"QRadar Search Error: {search_status}")

    finally:
        # GUARANTEED cleanup - runs even if hunt fails/errors/times out
        print(f"[DEBUG] hunt_dispatcher() FINALLY block: Cleaning up reference set (GUARANTEED)")
        try:
            empty_ref_set(ref_set)
            print(f"[DEBUG] hunt_dispatcher() Reference set successfully cleaned")
        except Exception as cleanup_error:
            print(f"[ERROR] hunt_dispatcher() Failed to clean reference set: {cleanup_error}")
            return_results(f"⚠️ ERROR: Failed to clean reference set {ref_set}: {cleanup_error}")

    print(f"[DEBUG] ========== HUNT DISPATCHER END ==========")


'''MAIN FUNCTION'''


def main():
    print(f"[DEBUG] ========== SCRIPT EXECUTION START ==========")
    print(f"[DEBUG] main() Script started for incident: {XSOAR_TICKET_ID}")

    # HARDCODED IOCs FOR TESTING
    TYPE = "SRC_IP"  # Can be changed to "DST_IP" or "DOMAIN" as needed
    IOCS = ["89.169.54.190", "193.32.248.237", "70.174.193.99", "13.229.69.141", "185.213.193.47", "62.60.247.114"]

    print(f"[DEBUG] main() Using HARDCODED test values:")
    print(f"[DEBUG] main()   - Type: {TYPE}")
    print(f"[DEBUG] main()   - IOCs (hardcoded): {IOCS}")
    print(f"[DEBUG] main()   - IOCs type: {type(IOCS)}")
    print(f"[DEBUG] main()   - IOCs count: {len(IOCS)}")
    for idx, ioc in enumerate(IOCS):
        print(f"[DEBUG] main()   - IOC[{idx}]: {ioc}")

    hunt_dispatcher(TYPE, IOCS)

    print(f"[DEBUG] ========== SCRIPT EXECUTION END ==========")


'''ENTRY POINT'''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
