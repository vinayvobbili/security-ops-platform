# Proxy Bypass Hunting Guide - QRadar Firewall Logs

## Overview

This guide provides QRadar AQL queries to detect users bypassing Zscaler by routing traffic through unmanaged VMs (VMs without Zscaler or CrowdStrike).

## Threat Scenario

**Attack Pattern:**
1. User connects to internal VM on proxy port (8080, 3128, 1080, etc.)
2. VM relays traffic to external destinations
3. Traffic bypasses Zscaler filtering and monitoring
4. User accesses blocked sites via VM proxy

**Key Challenge:** VMs don't have endpoint agents (Zscaler/CrowdStrike), so detection relies purely on firewall logs.

## Detection Strategy

### Core Detection Pattern

Look for the **two-hop correlation**:
- **Hop 1:** User workstation → VM (internal connection on proxy port)
- **Hop 2:** Same VM → External destination (internet access)

### Indicators of Compromise

- VMs receiving connections on common proxy ports (8080, 3128, 1080, 8888, 9050)
- VMs with multiple different users connecting to them
- VMs making numerous external connections to consumer sites
- High data transfer volumes through VMs
- External connections occurring immediately after internal connections

---

## Two Detection Approaches

This guide provides **two complementary detection methods**:

### Method 1: URL Parameter Analysis (Preferred - Most Accurate)
- **Best for:** Web-based proxy software (PHProxy, Glype, CGIProxy, custom web proxies)
- **Detection:** Looks for URLs encoded in URL parameters (e.g., `?u=http://blocked-site.com`)
- **Requires:** Firewall logs with HTTP URL/URI fields (next-gen firewalls with deep packet inspection)
- **Accuracy:** Very high - directly identifies what sites are being accessed
- **Use when:** Your firewall logs contain URL/URI data

### Method 2: Network-Level Correlation (Fallback)
- **Best for:** Traditional proxies (Squid, TinyProxy, SOCKS proxies)
- **Detection:** Correlates internal connections TO VMs with external connections FROM VMs
- **Requires:** Only basic firewall logs (IP, port, bytes)
- **Accuracy:** Medium - identifies suspicious patterns but not specific sites
- **Use when:** Firewall logs only contain IP/port level data

**Recommendation:** Start with the field check query below to determine which method to use.

---

## Quick Reference - Top Queries to Run

**If you're in a hurry, start here:**

1. **First:** Run "Step 0" query to check if you have URL data
2. **If you have URL data:** Run **URL Query 1** (highest accuracy)
3. **If no URL data:** Run **Query 3** (network correlation)
4. **For confirmation:** Run **URL Query 6** or **Query 2** (depending on method)

**Best queries by scenario:**
- **Web-based proxies (PHProxy, Glype):** URL Query 1, 2, 3
- **Traditional proxies (Squid, SOCKS):** Query 1, 3, 5
- **Quick triage:** URL Query 1 (if URLs available) or Query 3 (network-only)
- **Deep investigation:** URL Query 6 (combines both methods)

---

## Step 0: Check What Data You Have

**Run this first to determine which detection method to use:**

```sql
/* Check if your firewall logs contain URL fields */

SELECT TOP 10
    LOGSOURCETYPENAME(devicetype) as firewall_type,
    QIDNAME(qid) as event_name,
    SOURCEIP,
    DESTINATIONIP,
    DESTINATIONPORT,
    URL,  /* Check if this field is populated */
    UTF8(payload) as raw_log_sample  /* See actual log format */
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND STARTTIME > CURRENT_TIMESTAMP - 1 HOURS
LIMIT 10
```

**Decision Tree:**
- If `URL` field is populated → Use **Method 1 (URL Parameter queries)** below
- If `payload` shows HTTP data → Use **Method 1 (URL Parameter queries)** below
- If only IPs/ports visible → Skip to **Method 2 (Network-Level queries)**

---

## METHOD 1: URL Parameter Detection Queries

### These queries detect web-based proxies by finding URLs inside URL parameters

---

### URL Query 1: Detect URLs in URL Parameters (Core Detection)

**Purpose:** Find web proxy usage by identifying URLs encoded in query parameters

```sql
/* Look for URL patterns in URL parameters
   Web proxies pass destination URLs as parameters like:
   - http://proxy-vm/browse.php?u=http://facebook.com
   - http://proxy-vm/index.php?url=https://youtube.com
   - http://proxy-vm/proxy?target=http://blocked-site.com */

SELECT
    SOURCEIP as user_workstation,
    DESTINATIONIP as proxy_vm,
    URL as full_url,
    DESTINATIONPORT,
    COUNT(*) as requests,
    MIN(STARTTIME) as first_seen,
    MAX(STARTTIME) as last_seen
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    /* Look for URL encoding patterns in parameters */
    AND (
        /* Common proxy parameter names with http/https */
        URL LIKE '%?u=http%' OR
        URL LIKE '%?url=http%' OR
        URL LIKE '%?q=http%' OR
        URL LIKE '%?target=http%' OR
        URL LIKE '%?goto=http%' OR
        URL LIKE '%?site=http%' OR
        URL LIKE '%?link=http%' OR
        URL LIKE '%&u=http%' OR
        URL LIKE '%&url=http%' OR
        URL LIKE '%&target=http%' OR

        /* Common web proxy scripts */
        URL LIKE '%browse.php%' OR
        URL LIKE '%proxy.php%' OR
        URL LIKE '%nph-proxy.cgi%' OR
        URL LIKE '%index.php?q=%' OR

        /* URL encoded patterns (http:// becomes %3A%2F%2F or http%3A%2F%2F) */
        URL LIKE '%3A%2F%2F%' OR
        URL LIKE '%3a%2f%2f%' OR

        /* Base64 encoded URLs (http in base64 starts with aHR0c) */
        URL LIKE '%q=aHR0c%' OR
        URL LIKE '%u=aHR0c%' OR

        /* Anonymizer/unblock keywords */
        URL LIKE '%anonymize%' OR
        URL LIKE '%unblock%'
    )
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY SOURCEIP, DESTINATIONIP, URL, DESTINATIONPORT
ORDER BY requests DESC
LAST 500
```

**What to look for:**
- Multiple users accessing same VM with proxy patterns
- High request counts (>20 requests from single user)
- Suspicious parameter names (u=, url=, target=)

---

### URL Query 2: Identify Proxy VMs by URL Patterns

**Purpose:** Find all VMs serving web proxy pages (shows which VMs are proxy servers)

```sql
/* Aggregate by VM to identify which internal systems are serving proxy pages
   Shows the scale of proxy usage per VM */

SELECT
    DESTINATIONIP as suspicious_vm,
    DESTINATIONPORT as port,
    COUNT(DISTINCT SOURCEIP) as unique_users,
    COUNT(*) as total_proxy_requests,
    LIST(DISTINCT SOURCEIP) as user_list,
    MIN(STARTTIME) as first_proxy_request,
    MAX(STARTTIME) as last_proxy_request
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    /* Proxy URL patterns */
    AND (
        /* PHProxy, Glype, CGIProxy patterns */
        URL LIKE '%browse.php%' OR
        URL LIKE '%nph-proxy.cgi%' OR
        URL LIKE '%proxy.php%' OR
        URL LIKE '%index.php?q=%' OR

        /* Generic proxy parameters */
        URL MATCHES '.*[?&](u|url|q|target|goto|site|link)=.*http.*' OR

        /* URL encoded slashes (http:// encoded) */
        URL LIKE '%3A%2F%2F%' OR
        URL LIKE '%3a%2f%2f%' OR

        /* Base64 in parameters (minimum 20 chars to reduce false positives) */
        URL MATCHES '.*[?&]q=[A-Za-z0-9+/=]{20,}.*' OR
        URL MATCHES '.*[?&]u=[A-Za-z0-9+/=]{20,}.*' OR

        /* Anonymizer keywords */
        URL LIKE '%anonymize%' OR
        URL LIKE '%unblock%' OR
        URL LIKE '%bypass%'
    )
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY DESTINATIONIP, DESTINATIONPORT
HAVING COUNT(DISTINCT SOURCEIP) >= 1  /* Even single user is suspicious */
ORDER BY unique_users DESC, total_proxy_requests DESC
LAST 200
```

**What to look for:**
- VMs with 3+ unique users (shared proxy)
- High request volume (>100 requests/day)
- Non-web servers on proxy ports

---

### URL Query 3: Extract Actual Blocked Sites from URL Parameters

**Purpose:** Decode what external sites users are accessing through the proxy

```sql
/* Extract the actual destination URLs from proxy parameters
   This shows what sites users are trying to access via bypass */

SELECT
    SOURCEIP as user,
    DESTINATIONIP as proxy_vm,
    /* Extract the destination URL from common parameter names */
    COALESCE(
        REGEXCAPTURE(URL, '.*[?&]u=([^&]+).*', 1),
        REGEXCAPTURE(URL, '.*[?&]url=([^&]+).*', 1),
        REGEXCAPTURE(URL, '.*[?&]target=([^&]+).*', 1),
        REGEXCAPTURE(URL, '.*[?&]goto=([^&]+).*', 1),
        REGEXCAPTURE(URL, '.*[?&]site=([^&]+).*', 1),
        'Unable to extract'
    ) as actual_destination_url,
    URL as full_proxy_url,
    COUNT(*) as access_count,
    MIN(STARTTIME) as first_access,
    MAX(STARTTIME) as last_access
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND URL MATCHES '.*[?&](u|url|target|goto|site)=http.*'
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY SOURCEIP, DESTINATIONIP, actual_destination_url, URL
ORDER BY access_count DESC
LAST 500
```

**What to look for:**
- Social media sites (facebook, twitter, instagram)
- Streaming sites (youtube, netflix, twitch)
- Sites in Zscaler blocked categories
- High-risk domains (torrents, gambling, adult content)

---

### URL Query 4: Detect Specific Proxy Software by Signature

**Purpose:** Identify which web proxy software is running on VMs

```sql
/* Detect specific proxy software by URL patterns and signatures */

SELECT
    DESTINATIONIP as proxy_vm,
    CASE
        WHEN URL LIKE '%browse.php%' THEN 'PHProxy'
        WHEN URL LIKE '%nph-proxy.cgi%' THEN 'CGIProxy'
        WHEN URL LIKE '%includes/process.php%' THEN 'Glype'
        WHEN URL LIKE '%index.php?q=%' AND URL LIKE '%aHR0c%' THEN 'Glype (Base64)'
        WHEN URL LIKE '%proxy.php%' THEN 'Custom PHP Proxy'
        WHEN URL LIKE '%zelune%' THEN 'Zelune Proxy'
        WHEN URL LIKE '%anonymouse%' THEN 'Anonymouse'
        ELSE 'Unknown Web Proxy'
    END as proxy_software,
    COUNT(DISTINCT SOURCEIP) as users,
    COUNT(*) as requests,
    MIN(STARTTIME) as first_seen,
    LIST(DISTINCT SOURCEIP) as user_list
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND (
        URL LIKE '%browse.php%' OR
        URL LIKE '%nph-proxy.cgi%' OR
        URL LIKE '%includes/process.php%' OR
        URL LIKE '%index.php?q=%' OR
        URL LIKE '%proxy.php%' OR
        URL LIKE '%zelune%' OR
        URL LIKE '%anonymouse%'
    )
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY DESTINATIONIP, proxy_software
ORDER BY users DESC, requests DESC
LAST 100
```

**What to look for:**
- Known proxy software (PHProxy, Glype, CGIProxy are most common)
- Multiple VMs running same proxy software (organized effort)
- Outdated proxy software (security risk)

---

### URL Query 5: URL Encoding Detection (Advanced)

**Purpose:** Detect URL-encoded and Base64-encoded proxy requests

```sql
/* Advanced detection for obfuscated proxy requests
   Catches attempts to hide proxy usage with encoding */

SELECT
    SOURCEIP as user,
    DESTINATIONIP as proxy_vm,
    URL as encoded_url,
    CASE
        WHEN URL LIKE '%3A%2F%2F%' OR URL LIKE '%3a%2f%2f%' THEN 'URL Encoded'
        WHEN URL MATCHES '.*[?&](q|u|url)=[A-Za-z0-9+/=]{20,}.*' THEN 'Base64 Encoded'
        WHEN URL LIKE '%25%' THEN 'Double Encoded'
        ELSE 'Other Encoding'
    END as encoding_type,
    COUNT(*) as requests,
    MIN(STARTTIME) as first_seen,
    MAX(STARTTIME) as last_seen
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND (
        /* URL encoding: http:// = %3A%2F%2F */
        URL LIKE '%3A%2F%2F%' OR
        URL LIKE '%3a%2f%2f%' OR

        /* Base64: http in base64 starts with aHR0c */
        URL MATCHES '.*[?&](q|u|url)=[A-Za-z0-9+/=]{20,}.*' OR

        /* Double encoding */
        URL LIKE '%253A%252F%252F%'
    )
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY SOURCEIP, DESTINATIONIP, URL, encoding_type
ORDER BY requests DESC
LAST 500
```

**What to look for:**
- Base64 encoding (more sophisticated users)
- Double encoding (trying to evade detection)
- High volume of encoded requests

---

### URL Query 6: Correlate URL Proxy with External Connections

**Purpose:** Combine URL detection with network correlation (strongest evidence)

```sql
/* Advanced: Correlate web proxy URL patterns with actual external connections
   This provides strongest evidence of bypass activity */

SELECT
    url_proxy.proxy_vm,
    url_proxy.unique_users,
    url_proxy.proxy_requests,
    url_proxy.user_list,
    external.external_destinations,
    external.external_connections,
    external.total_gb
FROM
    /* Subquery 1: VMs serving web proxy pages */
    (SELECT
        DESTINATIONIP as proxy_vm,
        COUNT(DISTINCT SOURCEIP) as unique_users,
        COUNT(*) as proxy_requests,
        LIST(DISTINCT SOURCEIP) as user_list
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND (
            URL LIKE '%browse.php%' OR
            URL LIKE '%proxy.php%' OR
            URL MATCHES '.*[?&](u|url|q|target)=.*http.*' OR
            URL LIKE '%3A%2F%2F%'
        )
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY DESTINATIONIP
     HAVING COUNT(*) >= 5) url_proxy
INNER JOIN
    /* Subquery 2: Same VMs making external connections */
    (SELECT
        SOURCEIP as vm_ip,
        COUNT(DISTINCT DESTINATIONIP) as external_destinations,
        COUNT(*) as external_connections,
        (SUM(BYTESSENT) + SUM(BYTESRECEIVED))/1073741824 as total_gb
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
        AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY SOURCEIP
     HAVING COUNT(*) >= 10) external
ON url_proxy.proxy_vm = external.vm_ip
ORDER BY url_proxy.unique_users DESC, external.external_destinations DESC
LAST 200
```

**What to look for:**
- VMs with both proxy URLs AND external connections (definitive evidence)
- High user counts (3+ users)
- High data transfer volumes (>1GB)

---

## METHOD 2: Network-Level Detection Queries

### Use these queries if your firewall logs don't contain URL data

---

## QRadar AQL Hunting Queries

### Query 1: Identify VMs Acting as Proxies (Correlation Pattern)

**Purpose:** Find VMs that receive internal connections AND make external connections

```sql
/* Core proxy bypass detection - identifies the two-hop pattern */

SELECT
    DESTINATIONIP as potential_proxy_vm,
    SOURCEIP as user_workstation,
    COUNT(*) as connection_count,
    SUM(BYTESRECEIVED + BYTESSENT) as total_bytes
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND QIDNAME(qid) LIKE '%Accept%' OR QIDNAME(qid) LIKE '%Permit%'
    AND INOFFENSE(SOURCEIP) = FALSE  /* Exclude known malicious IPs */
    /* Internal to Internal connections */
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND DESTINATIONPORT IN (8080, 3128, 1080, 8888, 9050, 8118, 3129, 8123)
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY DESTINATIONIP, SOURCEIP
HAVING COUNT(*) > 10
ORDER BY total_bytes DESC
LAST 1000
```

**What to look for:**
- VMs with 5+ different source IPs connecting
- High connection counts (>50 connections)
- Large byte transfers (>1GB)

---

### Query 2: External Connections FROM Potential Proxy VMs

**Purpose:** After identifying VMs from Query 1, check what external sites they access

```sql
/* Validate proxy VMs by checking external destinations
   Replace <VM_IP> with IPs found in Query 1 */

SELECT
    SOURCEIP as vm_ip,
    DESTINATIONIP as external_destination,
    DESTINATIONPORT as dest_port,
    HOSTNAME(DESTINATIONIP) as destination_hostname,
    COUNT(*) as connection_count,
    SUM(BYTESSENT) as bytes_sent,
    SUM(BYTESRECEIVED) as bytes_received,
    MIN(STARTTIME) as first_seen,
    MAX(STARTTIME) as last_seen
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND QIDNAME(qid) LIKE '%Accept%' OR QIDNAME(qid) LIKE '%Permit%'
    /* VM source, external destination */
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    /* Optional: Uncomment to filter specific VM */
    /* AND SOURCEIP = '<VM_IP>' */
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY SOURCEIP, DESTINATIONIP, DESTINATIONPORT
ORDER BY connection_count DESC
LAST 1000
```

**What to look for:**
- Consumer websites (social media, streaming, gaming)
- Sites typically blocked by Zscaler
- High-risk categories (torrents, proxies, VPNs)

---

### Query 3: Combined Correlation Query (Most Powerful)

**Purpose:** Correlate internal→VM with VM→external in one query (identifies full proxy chain)

```sql
/* Advanced correlation - shows complete bypass pattern in one view */

SELECT
    t1.vm_ip,
    t1.users_connecting as suspicious_users,
    t1.inbound_connections,
    t2.external_destinations,
    t2.outbound_connections,
    t2.external_hosts
FROM
    /* Subquery 1: Internal users connecting TO VMs */
    (SELECT
        DESTINATIONIP as vm_ip,
        COUNT(DISTINCT SOURCEIP) as users_connecting,
        COUNT(*) as inbound_connections,
        LIST(SOURCEIP) as user_list
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
        AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY DESTINATIONIP
     HAVING COUNT(*) > 10) t1
INNER JOIN
    /* Subquery 2: VMs connecting to EXTERNAL destinations */
    (SELECT
        SOURCEIP as vm_ip,
        COUNT(DISTINCT DESTINATIONIP) as external_destinations,
        COUNT(*) as outbound_connections,
        LIST(DESTINATIONIP) as external_hosts
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
        AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY SOURCEIP
     HAVING COUNT(*) > 20) t2
ON t1.vm_ip = t2.vm_ip
ORDER BY t1.users_connecting DESC, t2.external_destinations DESC
LAST 500
```

**What to look for:**
- High user count (multiple employees using same proxy)
- Many external destinations (diverse browsing activity)
- Correlation between inbound and outbound traffic volumes

---

### Query 4: High Data Transfer VMs (Potential Tunnels)

**Purpose:** Identify VMs transferring large amounts of data to external destinations

```sql
/* Find VMs with high data transfer - could indicate active proxy/tunnel usage */

SELECT
    SOURCEIP as vm_ip,
    COUNT(DISTINCT DESTINATIONIP) as unique_external_ips,
    COUNT(*) as total_connections,
    SUM(BYTESSENT)/1073741824 as gb_sent,
    SUM(BYTESRECEIVED)/1073741824 as gb_received,
    (SUM(BYTESSENT) + SUM(BYTESRECEIVED))/1073741824 as total_gb
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND QIDNAME(qid) LIKE '%Accept%' OR QIDNAME(qid) LIKE '%Permit%'
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY SOURCEIP
HAVING SUM(BYTESSENT + BYTESRECEIVED) > 1073741824  /* > 1GB */
ORDER BY total_gb DESC
LAST 100
```

**What to look for:**
- VMs transferring >5GB/day (streaming, downloads)
- Unusual for server-class systems
- High upload volumes (data exfiltration concern)

---

### Query 5: VMs With Unusual Port Patterns

**Purpose:** Find VMs listening on common proxy ports and making external connections

```sql
/* Detect VMs with proxy port listeners and external connectivity */

SELECT
    inbound.listening_vm,
    inbound.listening_port,
    inbound.connection_count as inbound_count,
    outbound.external_conn_count,
    outbound.unique_destinations
FROM
    (SELECT
        DESTINATIONIP as listening_vm,
        DESTINATIONPORT as listening_port,
        COUNT(*) as connection_count
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND DESTINATIONPORT IN (8080, 3128, 1080, 8888, 9050, 8118, 3129, 8123, 8000, 8443)
        AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
        AND (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY DESTINATIONIP, DESTINATIONPORT) inbound
INNER JOIN
    (SELECT
        SOURCEIP as vm_ip,
        COUNT(*) as external_conn_count,
        COUNT(DISTINCT DESTINATIONIP) as unique_destinations
     FROM events
     WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
        AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
        AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
        AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
     GROUP BY SOURCEIP) outbound
ON inbound.listening_vm = outbound.vm_ip
ORDER BY inbound.connection_count DESC
LAST 500
```

**What to look for:**
- Port 8080, 3128, 1080 (common proxy ports)
- High connection counts on these ports
- VMs not designated as proxy servers

---

## Hunting Workflow

### Step-by-Step Process

**STEP 0: Determine Detection Method**
- Run "Step 0: Check What Data You Have" query
- If URL field is populated → Use **Method 1 Workflow** below
- If only IP/port data → Use **Method 2 Workflow** below

---

### Method 1 Workflow (URL Parameter Detection - Preferred)

**Use this if you have URL data in your firewall logs**

1. **Start with URL Query 1 (URL Parameter Detection)**
   - Run first for immediate, high-confidence detections
   - Look for VMs with URL proxy patterns
   - Identify users accessing proxy VMs

2. **Identify Proxy VMs with URL Query 2**
   - Aggregate results by VM
   - Focus on VMs with 3+ users
   - Build list of suspicious proxy VMs

3. **Extract Destinations with URL Query 3**
   - See what actual sites users are accessing
   - Correlate with Zscaler blocked categories
   - Identify high-risk domains being accessed

4. **Confirm with URL Query 6 (Correlation)**
   - Validate that proxy VMs are making external connections
   - This provides definitive evidence of bypass
   - High confidence findings for incident response

5. **Optional: URL Query 4 & 5 for Enrichment**
   - Identify specific proxy software (Query 4)
   - Detect encoding/obfuscation attempts (Query 5)
   - Use for attribution and sophistication assessment

6. **Enrich with User Identity**
   - Map internal IPs to usernames
   - Check Zscaler blocks for motivation
   - Build complete timeline

---

### Method 2 Workflow (Network-Level Detection - Fallback)

**Use this if you don't have URL data in your firewall logs**

1. **Start with Query 3 (Combined Correlation)**
   - Run first for strongest leads
   - Identifies VMs with both inbound and outbound patterns
   - Focus on VMs with 5+ users connecting

2. **Validate with Query 1 & 2**
   - Drill down on specific VMs found in Query 3
   - Check what specific users are connecting
   - Identify external destinations being accessed

3. **Check Query 4 (High Data Transfer)**
   - Look for abnormal data volumes
   - Cross-reference with VMs from previous queries
   - Investigate VMs transferring >10GB/day

4. **Cross-reference Query 5 (Port Patterns)**
   - Confirm proxy port usage
   - Validate port/protocol combinations
   - Check if ports align with legitimate services

5. **Enrich with User Identity**
   - Map internal IPs to usernames
   - Check AD logs or authentication events
   - Build user attribution

---

## Investigation Enrichment

### Get User Identity from Workstation IPs

```sql
/* Correlate internal workstation IPs to usernames */

SELECT
    username,
    SOURCEIP,
    COUNT(*) as connection_attempts,
    MIN(STARTTIME) as first_activity,
    MAX(STARTTIME) as last_activity
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%AD%'
    OR LOGSOURCETYPENAME(devicetype) LIKE '%Authentication%'
    OR LOGSOURCETYPENAME(devicetype) LIKE '%DHCP%'
    AND SOURCEIP = '<workstation_ip_from_query1>'
    AND STARTTIME > CURRENT_TIMESTAMP - 7 DAYS
GROUP BY username, SOURCEIP
ORDER BY connection_attempts DESC
LAST 100
```

### Check Zscaler Blocks for User Context

```sql
/* Find what sites were blocked by Zscaler for specific users
   This helps identify motivation for bypass */

SELECT
    username,
    DESTINATIONIP,
    URL,
    CATEGORYNAME(category) as blocked_category,
    COUNT(*) as block_count
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Zscaler%'
    AND QIDNAME(qid) LIKE '%Block%' OR QIDNAME(qid) LIKE '%Deny%'
    AND username = '<username_from_previous_query>'
    AND STARTTIME > CURRENT_TIMESTAMP - 7 DAYS
GROUP BY username, DESTINATIONIP, URL, category
ORDER BY block_count DESC
LAST 100
```

### Timeline Analysis for Specific VM

```sql
/* Create timeline of activity for suspicious VM */

SELECT
    DATEFORMAT(STARTTIME, 'yyyy-MM-dd HH:mm:ss') as timestamp,
    SOURCEIP as source,
    DESTINATIONIP as destination,
    DESTINATIONPORT as port,
    BYTESSENT + BYTESRECEIVED as bytes,
    QIDNAME(qid) as action
FROM events
WHERE (SOURCEIP = '<suspicious_vm_ip>' OR DESTINATIONIP = '<suspicious_vm_ip>')
    AND LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
ORDER BY STARTTIME ASC
LAST 5000
```

---

## Detection Patterns & Red Flags

### High-Confidence Indicators (Definitive Evidence)

**URL-Based Detection:**
- **URLs with proxy parameters** (e.g., `?u=http://`, `?url=`, `?target=`)
- **Known proxy scripts** (browse.php, nph-proxy.cgi, proxy.php)
- **Base64-encoded URLs** in parameters (aHR0c pattern)
- **URL-encoded destinations** (%3A%2F%2F pattern)
- **Multiple users** accessing same proxy VM (3+ users)
- **Extractable blocked sites** from URL parameters (social media, streaming)

**Network-Based Detection:**
- **5+ different users** connecting to same VM on proxy ports
- **VM transferring >5GB/day** to external destinations
- **External connections occur within 60 seconds** of internal connections
- **Consumer sites** (facebook.com, youtube.com, reddit.com) accessed from server IPs
- **Blocked Zscaler categories** appearing in VM's external connections

### Medium-Confidence Indicators

**URL-Based:**
- Anonymizer/unblock keywords in URLs
- Single user with high volume of proxy requests (>50/day)
- Custom proxy scripts (non-standard proxy software)

**Network-Based:**
- 2-4 users connecting to VM on proxy ports
- VM making 50+ external connections/day
- Unusual ports (8080, 3128) on non-designated proxy VMs
- High diversity of external destinations (>20 unique IPs)

### Low-Confidence (Requires Validation)

- Single user connecting to VM
- VM with legitimate proxy service designation
- Low volume traffic (<100MB/day)
- Connections to CDN/cloud services
- Legitimate web applications with URL parameters

---

## Response Actions

### Immediate Actions (Incident Response)

1. **Identify affected users**
   - Run user attribution queries
   - Check AD group memberships
   - Verify user access levels

2. **Review firewall logs**
   - Export full logs for suspicious VMs
   - Check historical activity (7-30 days)
   - Look for patterns and trends

3. **Validate VM purpose**
   - Check CMDB/asset management
   - Confirm legitimate business need for internet access
   - Review VM provisioning requests

4. **Check for data exfiltration**
   - Run Query 4 for high data transfers
   - Review upload volumes (high concern)
   - Check destination reputation

### Remediation Steps

1. **Block proxy ports on VMs**
   - Add firewall rules blocking 8080, 3128, 1080, 8888, 9050 to VMs
   - Allow exceptions only for legitimate proxy servers

2. **Restrict VM internet access**
   - Implement egress filtering for VMs
   - Require Zscaler for all outbound traffic
   - Whitelist only necessary external destinations

3. **Deploy endpoint agents**
   - Install CrowdStrike on VMs
   - Enable Zscaler on VM network
   - Implement monitoring agents

4. **User accountability**
   - Interview users identified in investigation
   - Document policy violations
   - Apply appropriate consequences

### Long-Term Prevention

1. **Enforce agent requirements**
   - No internet access without Zscaler
   - Mandatory CrowdStrike on all systems
   - Network access control (NAC) enforcement

2. **Network segmentation**
   - Isolate VMs in restricted VLAN
   - Implement micro-segmentation
   - Limit VM-to-VM lateral movement

3. **Continuous monitoring**
   - Schedule queries as QRadar rules
   - Create alerting for proxy patterns
   - Build dashboard for VM traffic

4. **Policy enforcement**
   - Document acceptable use policy
   - Security awareness training
   - Regular compliance audits

---

## Create QRadar Custom Rules

### Rule 1: Web Proxy Detection (URL-Based - High Confidence)

**Rule Name:** Web Proxy Bypass Detected - URL Parameters

**Rule Tests:**
1. When the event QID is one of the following (Firewall Accept/Permit)
2. When the source IP is in any of (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. When the destination IP is in any of (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
4. When the URL matches any of the following:
   - Contains `browse.php`
   - Contains `proxy.php`
   - Contains `nph-proxy.cgi`
   - Contains `?u=http`
   - Contains `?url=http`
   - Contains `?target=http`
   - Contains `%3A%2F%2F` (URL-encoded http://)
   - Contains `aHR0c` (Base64-encoded http)
5. When at least 5 events are seen with the same destination IP in 1 hour

**Rule Response:**
- Create offense: "Web Proxy Bypass Detected via URL Parameters"
- Severity: High
- Assign to: Security Operations
- Add to reference set: Proxy_Bypass_VMs

---

### Rule 2: Network Proxy Detection (Port-Based - Medium Confidence)

**Rule Name:** Potential Proxy Bypass via Unmanaged VM

**Rule Tests:**
1. When the event QID is one of the following (Firewall Accept/Permit)
2. When the source IP is in any of (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
3. When the destination IP is in any of (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
4. When the destination port is one of the following (8080, 3128, 1080, 8888, 9050)
5. When at least 20 events are seen with the same destination IP in 1 hour
6. When the destination IP is NOT in reference set: Legitimate_Proxies

**Rule Response:**
- Create offense: "Proxy Bypass Detected - VM Acting as Proxy"
- Severity: Medium
- Assign to: Security Operations

**Optional: Add correlation with external connections**
- Within 1 hour, the same destination IP (from above) makes external connections

---

### Rule 3: Proxy VM External Access Correlation

**Rule Name:** Confirmed Proxy Bypass - External Connection Correlation

**Rule Tests:**
1. When offense "Web Proxy Bypass Detected via URL Parameters" OR "Proxy Bypass Detected - VM Acting as Proxy" is created
2. Within 1 hour, the same VM IP (offense source) makes connections to external IPs
3. When external connection count > 10

**Rule Response:**
- Update offense severity to: Very High
- Add note: "Confirmed - VM is relaying traffic to external destinations"
- Send notification to: SOC Manager

---

## Useful QRadar Reference Queries

### List All Internal Proxy Port Listeners

```sql
SELECT DISTINCT
    DESTINATIONIP as potential_proxy,
    DESTINATIONPORT as proxy_port,
    COUNT(DISTINCT SOURCEIP) as unique_clients
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND DESTINATIONPORT IN (8080, 3128, 1080, 8888, 9050, 8118)
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND STARTTIME > CURRENT_TIMESTAMP - 7 DAYS
GROUP BY DESTINATIONIP, DESTINATIONPORT
HAVING COUNT(DISTINCT SOURCEIP) > 2
ORDER BY unique_clients DESC
```

### Top External Destinations from Internal VMs

```sql
SELECT
    DESTINATIONIP as external_destination,
    HOSTNAME(DESTINATIONIP) as hostname,
    COUNT(DISTINCT SOURCEIP) as unique_vms_accessing,
    COUNT(*) as total_connections
FROM events
WHERE LOGSOURCETYPENAME(devicetype) LIKE '%Firewall%'
    AND (SOURCEIP INCIDR '10.0.0.0/8' OR SOURCEIP INCIDR '172.16.0.0/12' OR SOURCEIP INCIDR '192.168.0.0/16')
    AND NOT (DESTINATIONIP INCIDR '10.0.0.0/8' OR DESTINATIONIP INCIDR '172.16.0.0/12' OR DESTINATIONIP INCIDR '192.168.0.0/16')
    AND STARTTIME > CURRENT_TIMESTAMP - 24 HOURS
GROUP BY DESTINATIONIP
ORDER BY unique_vms_accessing DESC
LAST 100
```

---

## Common Proxy Ports Reference

| Port | Service | Description |
|------|---------|-------------|
| 8080 | HTTP Proxy | Most common HTTP proxy port |
| 3128 | Squid Proxy | Default Squid proxy port |
| 1080 | SOCKS | SOCKS proxy protocol |
| 8888 | HTTP Alternate | Alternative HTTP proxy |
| 9050 | Tor | Tor SOCKS proxy |
| 8118 | Privoxy | Privacy proxy |
| 3129 | Squid HTTPS | Squid SSL proxy |
| 8123 | Polipo | Caching web proxy |
| 8000 | HTTP Alt | Development/alternate HTTP |
| 8443 | HTTPS Alt | Alternative HTTPS |

---

## Notes & Tips

### Query Optimization
- Adjust time ranges based on log volume (start with 24h, expand if needed)
- Use LAST clause to limit result sets for performance
- Consider adding LOGSOURCENAME filters for specific firewalls

### False Positive Reduction
- Whitelist legitimate proxy servers by IP
- Exclude infrastructure services (DNS, NTP, patching)
- Filter out monitoring/management traffic

### Customization for Your Environment
- Replace RFC1918 ranges with your specific subnets
- Add/remove proxy ports based on observed patterns
- Adjust byte thresholds for data transfer queries
- Modify firewall log source names to match your QRadar setup

---

## Contact & Support

For questions or assistance with this hunting guide:
- Update this document with findings and refinements
- Share results with SOC team for continuous improvement
- Document false positives to improve detection accuracy

**Last Updated:** 2025-11-25
**Version:** 2.0 (Added URL Parameter Detection)
**Author:** Threat Hunting Team

---

## Changelog

### Version 2.0 (2025-11-25)
- Added comprehensive URL parameter detection queries (Method 1)
- Included 6 new URL-based detection queries
- Added query to check firewall log capabilities
- Updated hunting workflow with dual methodology
- Enhanced detection patterns with URL-based indicators
- Added multiple QRadar custom rule templates
- Improved correlation query combining URL and network detection

### Version 1.0 (2025-11-25)
- Initial release with network-level correlation queries
- 5 core network detection queries
- Basic hunting workflow and response actions
