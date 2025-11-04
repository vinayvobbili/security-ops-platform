# Deployment Checklist for QRadar IOC Hunt Script

## Summary of Changes

### Problem Identified
- **Mystery IP 141.98.11.175** appeared in hunt results but was NOT in the input list
- **Root Cause:** Previous hunt (incident #885871) timed out on Oct 27th, 2025
- Timeout prevented cleanup, leaving stale IOCs in reference set

### Fixes Implemented
1. ✅ **Proactive cleanup at START** - Cleans reference set before every hunt
2. ✅ **try/finally block** - Guarantees cleanup even on timeout/error
3. ✅ **Debug logging with print()** - Extensive logs for troubleshooting
4. ✅ **Stale data warnings** - Alerts when reference set isn't empty

---

## Pre-Deployment Steps

### 1. Clean All Reference Sets (Manual - Do This First!)
Before deploying the new script, manually clean all reference sets to start fresh:

**In XSOAR, run these commands:**
```python
# QRadar Source IP hunts
demisto.executeCommand("qradar-reference-set-delete", {
    "Using": "QRadar_v3_instance_1",
    "ref_name": "_ThreatTipperHunt_IPAddress_Src",
    "purge_only": "true"
})

# QRadar Destination IP hunts
demisto.executeCommand("qradar-reference-set-delete", {
    "Using": "QRadar_v3_instance_1",
    "ref_name": "_ThreatTipperHunt_IPAddress",
    "purge_only": "true"
})

# QRadar Domain hunts
demisto.executeCommand("qradar-reference-set-delete", {
    "Using": "QRadar_v3_instance_1",
    "ref_name": "_ThreatTipperHunt_Domain",
    "purge_only": "true"
})
```

**Or via QRadar Console:**
1. Log into QRadar
2. Go to Admin > Reference Set Management
3. Find each reference set and click "Purge"

---

## Deployment Steps

### 2. Update Script in XSOAR

1. **Navigate to Automations:**
   - Settings > Automations & Scripts
   - Find "METCIRT_Qradar_IOC_Hunt" (or your script name)

2. **Update Script Code:**
   - Click Edit
   - Replace entire script with the new version from `Vinay_Qradar_IOC_Hunt.py`
   - **IMPORTANT:** Remove the hardcoded test IOCs from main() function (lines 353-354)
   - Restore the original dynamic input:
     ```python
     TYPE = demisto.args().get("Type")
     IOCS = json.loads(json.dumps(demisto.args().get("Value")))
     ```

3. **Save Changes**

### 3. Increase Script Timeout (CRITICAL!)

1. **In the same script editor:**
   - Click "Advanced Settings" tab
   - Find "Timeout" field

2. **Set timeout to 3600 seconds (60 minutes)**
   - Default is often 600 seconds (10 minutes) - NOT enough!
   - Recommended: **3600 seconds** minimum
   - Calculation:
     - 120s initial sleep
     - 40 retries × 60s = 2400s max polling
     - Total: ~2520s minimum, 3600s recommended for safety

3. **Save Settings**

### 4. Test with a Small Hunt

1. **Create a test incident** or use existing one
2. **Run a small hunt** (1-2 IOCs only)
3. **Check for these log messages:**
   - `[DEBUG] CHECKING REFERENCE SET BEFORE UPDATE`
   - `Cleaning reference set before starting hunt...`
   - `[DEBUG] Reference set cleaned`
   - `[DEBUG] FINALLY block: Cleaning up reference set (GUARANTEED)`

4. **Verify War Room shows:**
   - `Cleaning reference set {name} before starting hunt...`
   - `Qradar {TYPE} Query COMPLETED in X minutes`

---

## Post-Deployment Monitoring

### What to Watch For

#### ✅ Success Indicators:
- **No more mystery IOCs** appearing in results
- **Warning messages** if stale data is detected:
  ```
  ⚠️ WARNING: Reference set {name} contained X stale IOCs. Cleaning before hunt.
  ```
- **Hunt completes without timeout**
- **Results match input IOCs**

#### ⚠️ Warning Signs:
- Script still timing out → Increase timeout further (try 7200s / 2 hours)
- Still seeing stale IOCs → Check if cleanup is working properly
- Cleanup errors in logs → QRadar API permissions issue

### Troubleshooting

**If you see stale IOC warnings:**
- This is EXPECTED if old hunts left data behind
- The script will clean them automatically
- Document which incident left the stale data (for audit trail)

**If cleanup fails:**
```
[ERROR] hunt_dispatcher() Failed to clean reference set: {error}
```
- Check QRadar API permissions
- Verify reference set exists
- Check QRadar connectivity

**If script still times out:**
1. Increase timeout to 7200s (2 hours)
2. Consider reducing QUERY_RETRIES from 40 to 30 (line 47)
3. Check QRadar query performance (saved search might be slow)

---

## Rollback Plan

If issues occur after deployment:

### Quick Rollback:
1. Go to Settings > Automations & Scripts
2. Find the script
3. Click "Version History"
4. Restore previous version
5. Document the issue

### Manual Cleanup:
If reference sets are stuck/corrupted:
1. Log into QRadar Console
2. Admin > Reference Set Management
3. Delete problematic reference sets entirely
4. They will be auto-created on next hunt

---

## Testing Checklist

Before marking deployment complete, test:

- [ ] SRC_IP hunt with 2-3 IPs
- [ ] DST_IP hunt with 2-3 IPs
- [ ] Domain hunt with 2-3 domains
- [ ] Verify no mystery IOCs in results
- [ ] Check logs show cleanup messages
- [ ] Verify hunt completes within timeout
- [ ] Test with hunt that returns no results
- [ ] Test with hunt that returns results

---

## Documentation Updates

After successful deployment:

- [ ] Update playbook documentation if timeout increased
- [ ] Add note to incident response procedures about reference set cleanup
- [ ] Document the 141.98.11.175 incident for training purposes
- [ ] Update any automation timeout expectations

---

## Success Criteria

Deployment is successful when:

1. ✅ All reference sets cleaned manually before deployment
2. ✅ Script timeout increased to 3600s minimum
3. ✅ Test hunt completes successfully
4. ✅ No mystery IOCs appear in results
5. ✅ Cleanup warnings visible if stale data detected
6. ✅ Hunt results match input IOCs
7. ✅ No timeout errors in War Room

---

## Contact

If issues arise during deployment:
- Check `/Users/user/PycharmProjects/IR/xsoar_scripts/ROOT_CAUSE_ANALYSIS.md`
- Check `/Users/user/PycharmProjects/IR/xsoar_scripts/DEBUG_ANALYSIS.md`
- Review this checklist

## Change Summary for Audit Trail

**What Changed:**
- Added proactive reference set cleanup at hunt start
- Added try/finally for guaranteed cleanup
- Added extensive debug logging with print()
- Added warnings for stale reference set data
- Increased recommended timeout from 600s to 3600s

**Why Changed:**
- Prevent stale IOC contamination from failed hunts
- Ensure cleanup even on timeout/error
- Better visibility into hunt execution
- Fix timeout issues causing incomplete hunts

**Risk Assessment:** Low
- Changes are defensive (prevent bugs, don't change logic)
- Backwards compatible
- Enhanced error handling
- Better logging for troubleshooting
