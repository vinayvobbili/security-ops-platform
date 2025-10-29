# IOC Hunt Debugging Analysis

## The Mystery
**Input:** 6 IP addresses
- 89.169.54.190
- 193.32.248.237
- 70.174.193.99
- 13.229.69.141
- 185.213.193.47
- 62.60.247.114

**Output:** 1 different IP address
- 141.98.11.175 (DeviceCount: 5, EventCount: 89)

## Possible Root Causes

### 1. **Stale Reference Set (Most Likely)**
The `_ThreatTipperHunt_IPAddress_Src` reference set may have contained 141.98.11.175 from a previous hunt that didn't get cleaned up properly.

**Debug logs to check:**
- Look for: `[DEBUG] hunt_dispatcher() Existing reference set contents:`
- If 141.98.11.175 appears here, this is the culprit

### 2. **QRadar Saved Search Logic Issue**
The saved search (ID 4757) might:
- Not properly filter by the reference set
- Join with other reference sets
- Have additional WHERE clauses that override the reference set filter
- Use OR conditions that bring in IPs from other sources

**Debug logs to check:**
- `[DEBUG] execute_saved_search() Executing search with params:`
- Note: The script doesn't show the actual AQL query, you'd need to check QRadar directly

### 3. **None of Your Input IPs Had Events**
It's possible that during the time window searched:
- None of your 6 IPs had any network activity
- But 141.98.11.175 (already in the ref set) did have activity
- So it was the only one returned

**Debug logs to check:**
- `[DEBUG] get_search_results() Unique IOCs found in results:`
- This will show if any of your input IPs are in the results

### 4. **Reference Set Not Purged**
The `empty_ref_set()` call at the end might have failed in a previous run, leaving 141.98.11.175 behind.

**Debug logs to check:**
- `[DEBUG] empty_ref_set() Purge response:`
- Check if purge succeeded

## How to Investigate Further

### Step 1: Check the Reference Set State
Run the debug script and look for these specific log entries:

```
[DEBUG] hunt_dispatcher() CHECKING REFERENCE SET BEFORE UPDATE
[DEBUG] hunt_dispatcher() Existing reference set contents: {...}
```

If you see 141.98.11.175 here, **BINGO** - that's your answer.

### Step 2: Compare Before/After Reference Sets
```
[DEBUG] hunt_dispatcher() IOCs we sent: [sorted list of 6 IPs]
[DEBUG] hunt_dispatcher() IOCs now in ref set: [what's actually there]
```

If the "after" list has more than 6 IPs, the reference set wasn't empty.

### Step 3: Check What QRadar Returned
```
[DEBUG] get_search_results() Unique IOCs found in results: ['141.98.11.175']
[DEBUG] get_search_results() ⚠️⚠️⚠️ 141.98.11.175 FOUND IN SEARCH RESULTS!
```

This confirms 141.98.11.175 came from QRadar.

### Step 4: Verify the Saved Search Query
You'll need to log into QRadar directly and check saved search ID 4757:
1. Go to QRadar Console
2. Navigate to Search > Manage Searches
3. Find search ID 4757
4. View the AQL query
5. Look for how it uses the `_ThreatTipperHunt_IPAddress_Src` reference set

The query should look something like:
```sql
SELECT sourceip as "IOC", COUNT(DISTINCT deviceid) as "DeviceCount", COUNT(*) as "EventCount"
FROM events
WHERE sourceip IN (SELECT * FROM REFERENCE SET '_ThreatTipperHunt_IPAddress_Src')
GROUP BY sourceip
```

If the WHERE clause is missing or different, that's your problem.

## Recommended Fix

✅ **ALREADY IMPLEMENTED** - The script now includes proactive cleanup!

### Stale Reference Set Prevention (FIXED):
The script now automatically cleans the reference set at the START of every hunt:

```python
# At line 230-234 of the script
# PROACTIVE CLEANUP: Always purge reference set before starting a new hunt
print(f"[DEBUG] hunt_dispatcher() CLEANING REFERENCE SET BEFORE HUNT (prevents stale IOCs)")
return_results(f"Cleaning reference set {ref_set} before starting hunt...")
empty_ref_set(ref_set)
print(f"[DEBUG] hunt_dispatcher() Reference set cleaned")
```

This ensures:
1. Previous failed hunts won't leave stale IOCs
2. You get a warning if the ref set wasn't empty
3. Every hunt starts with a clean slate

### If it's the saved search query:
Work with your QRadar admin to fix saved search 4757 to properly filter by the reference set.

### If it's the purge not working:
Add error handling and retry logic to `empty_ref_set()`.

## Questions to Answer

1. **Was 141.98.11.175 already in the reference set?**
   - Check the "BEFORE UPDATE" logs

2. **Did any of your 6 input IPs return results?**
   - Check the "Unique IOCs found in results" logs

3. **Is the reference set being properly purged?**
   - Check the "empty_ref_set() Purge response" logs

4. **What does saved search 4757 actually query?**
   - Need to check QRadar console directly
