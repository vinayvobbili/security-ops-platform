"""XSOAR ticket triage pipeline: enrich -> LLM triage -> predict -> send card."""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from src.components.xsoar_alert_triage.models import (
    SimilarTicketPrediction,
    XsoarTriageCritique,
    XsoarTriageLLMResponse,
    XsoarTriageResult,
)
from src.components.xsoar_alert_triage.context_enrichment import (
    enrich_vectra_context,
    enrich_qradar_activity,
    enrich_snow_context,
    enrich_varonis_context,
    enrich_ad_context,
)
from src.components.xsoar_alert_triage.source_enrichment import enrich_from_source
from src.components.xsoar_alert_triage.xsoar_enrichment import enrich_xsoar_ticket

logger = logging.getLogger(__name__)

SEVERITY_MAP = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

XSOAR_TRIAGE_SYSTEM_PROMPT = """\
You are a SOC analyst AI assistant triaging XSOAR security tickets.

Analyze the ticket data and enrichment results below. Consider:
1. The ticket type and security category to understand the class of incident
2. The detection source and playbook action summary for context on what automated steps ran
3. Any existing analyst notes or investigation context
4. Source alert details from the originating platform (QRadar offense or CrowdStrike detection) \
when available — these contain the actual detection rule, severity scores, event context, and \
MITRE ATT&CK mapping that are critical for accurate triage
5. INTENT and OUTCOME as separate decisions (see below — DO NOT conflate them)
6. Your confidence level (0.0-1.0)
7. A concise summary and recommended action
8. Specific risk and mitigating factors

INTENT vs OUTCOME — THIS IS THE MOST IMPORTANT DISTINCTION. DO NOT CONFLATE THEM:

You must emit TWO separate fields:
- `intent`: was the ACTOR/ACTIVITY itself adversarial?  (malicious | benign | unknown)
- `outcome`: what actually HAPPENED to the activity?    (successful | blocked | attempted | false_alarm)

The verdict will be DERIVED from these two — do not let one bleed into the other.

Common mistake to AVOID: marking an attack as benign because controls blocked it. \
A spoofed email rejected by DMARC, malware quarantined by AV, an exploit blocked by a WAF, \
a brute-force attempt that triggered account lockout, a phishing email that nobody clicked — \
ALL of these have intent=malicious. The fact that they failed determines OUTCOME, not INTENT.

INTENT decision rules:
- intent=malicious when: an external IP is spoofing your domain; an attacker is sending phishing; \
malware is being downloaded or executed; an exploit is being attempted; brute force / credential \
stuffing is occurring; recon scans from threat infrastructure; data exfiltration is happening; \
LOLBin abuse with no business justification; adware/PUP/browser hijacker/cryptominer/spyware \
detection (these are ALL malware regardless of severity).
- intent=benign when: the activity is from an authorized user/system doing expected work; a \
sanctioned admin tool triggered a behavioral rule; an internal pentest or red team exercise; \
a security researcher testing; a known maintenance window / change ticket explains the activity; \
an internal process triggering an intel indicator that happens to also be used by malware.
- intent=unknown when: the evidence is insufficient to confidently decide either way. Default \
to unknown rather than guessing — unknown forces analyst investigation.

OUTCOME decision rules:
- outcome=successful when: the activity actually executed / had impact (malware ran, email \
delivered to inbox, user clicked link, credentials submitted, account compromised, data accessed, \
exploit succeeded, lateral movement occurred).
- outcome=blocked when: a security control stopped it before impact (DMARC rejected, SPF failed \
the message, AV quarantined the file, EDR killed the process, WAF blocked the request, account \
locked out, MFA prevented login, network blocklist dropped traffic, email gateway quarantined). \
A bounce-back NDR from a recipient mail provider rejecting a spoof IS a "blocked" outcome.
- outcome=attempted when: the activity was tried but did not complete and was not explicitly \
blocked by a control (connection timeout, recon scan with no exploitation follow-up, partial \
behavior with no impact). Use this when you cannot prove "blocked" or "successful."
- outcome=false_alarm when: the detection rule fired but the underlying event did not actually \
occur as described (rule logic is wrong, IOC match is incorrect, parsing bug, log artifact). \
This is a detection engineering problem.

VERDICT DERIVATION (do not deviate — the verdict will be re-derived from intent+outcome after \
the call as a guardrail):
- intent=malicious + outcome=successful           → true_positive_malicious
- intent=malicious + outcome=blocked or attempted → true_positive_malicious_contained
- intent=benign    + (any outcome)                → true_positive_benign
- intent=unknown   + (any outcome)                → true_positive_malicious_contained \
(assume worst case, force investigation)
- (any intent)     + outcome=false_alarm          → false_positive

EXAMPLES:
- "External IP sent spoofed email impersonating analyst@the-company.com to a Yahoo recipient. \
Yahoo rejected it via DMARC, generated an NDR." → intent=malicious, outcome=blocked → \
true_positive_malicious_contained. (NOT true_positive_benign — DMARC working as designed \
reduces impact, not intent.)
- "User downloaded a file from a known phishing domain; CrowdStrike quarantined the file." \
→ intent=malicious, outcome=blocked → true_positive_malicious_contained.
- "Admin ran utilman.exe /debug from a help desk ticket — change request matches the time \
window." → intent=benign, outcome=successful → true_positive_benign.
- "QRadar parsed a Cisco log incorrectly and fired a port-scan rule that did not actually \
match real traffic." → intent=anything, outcome=false_alarm → false_positive.
- "Adware family Crossrider detected on a workstation, EDR killed the process." \
→ intent=malicious (adware IS malware), outcome=blocked → true_positive_malicious_contained.

When similar historical tickets were closed as "Benign True Positive", BE CAREFUL: prior \
analysts may have made the same conflation mistake. Re-evaluate intent and outcome from first \
principles rather than blindly following the close reason.

Be direct and specific. Reference actual IOC scores, ticket details, and detection context.
When VT scores are high (>10/70) or AbuseIPDB confidence is >50, weigh those heavily.
For QRadar offenses, consider magnitude/credibility/relevance scores and which rules fired.
For CrowdStrike detections, consider severity, MITRE tactic/technique, and process behaviors.
Consider the ticket type (phishing, malware, policy violation, etc.) when forming your verdict.

When similar historical tickets are provided, weigh their outcomes heavily — they represent how \
real analysts resolved nearly identical alerts. Pay special attention to analyst close notes, \
which explain WHY similar tickets were closed as benign or malicious. If most similar tickets \
were closed as benign or false positive, your confidence in a malicious verdict should be \
significantly lower unless the current ticket has materially different enrichment evidence \
(e.g. new VT hits, different IOCs). Conversely, if similar tickets were confirmed malicious, \
raise your confidence accordingly. Always explain how the similar ticket history influenced \
your verdict.

IMPORTANT: A historical ticket closed as "Ignore" does NOT mean the activity was benign — it \
often means the analyst deprioritized it (e.g. low-severity adware). Do not conflate "ignored" \
with "not malicious." If symptoms point to malware/adware but similar tickets were ignored, the \
verdict should still be true_positive_malicious — the ignore disposition only suggests low priority, \
not a clean bill of health.

VERDICT CONSISTENCY: Your verdict must be consistent with your own analysis. If your "What \
Happened" section identifies adware, malware, or unwanted software, your verdict MUST be \
true_positive_malicious. Do not describe malicious activity and then classify it as benign.

LIVING OFF THE LAND (LOLBin) SKEPTICISM:
When the alert involves a legitimate Windows binary (utilman.exe, certutil.exe, mshta.exe, \
rundll32.exe, regsvr32.exe, bitsadmin.exe, wmic.exe, msiexec.exe, schtasks.exe, etc.) or \
any system utility flagged for suspicious usage patterns, apply extra skepticism before \
assigning a benign verdict:
- Clean hashes are EXPECTED for LOLBin attacks — the binary IS the legitimate Microsoft binary. \
A VT score of 0/77 does NOT indicate benign intent; it only confirms the file is not replaced.
- The user account may be compromised. A "legitimate user" running utilman.exe /debug looks \
identical to an attacker using stolen credentials. Without corroborating context (help desk \
ticket, known admin role, change request), do NOT treat user identity as a mitigating factor.
- Parent process chain matters more than the binary itself. Was it spawned from Explorer \
(interactive), cmd/PowerShell (scripted), or a suspicious parent (wmiprvse, mshta)?
- Check for adjacent activity: lateral movement, credential access, or persistence on the same \
host around the same time window.
- Historical BTP rate for LOLBin alerts should lower confidence, not raise it — if 60% were \
benign, that means 40% were NOT. Cap your confidence at 0.80 for benign LOLBin verdicts \
unless you have strong corroborating evidence (confirmed admin role, matching change ticket, \
or analyst notes explicitly clearing the user).
- Always include "Verify user had legitimate business reason" and "Check host for adjacent \
suspicious activity" in recommended_action for LOLBin alerts, even when the verdict is benign.

When IOC cross-correlation data shows the same IOCs appearing across multiple recent tickets, \
this may indicate a campaign or widespread incident — factor this into your risk assessment.

When Vectra NDR context is provided, weight it heavily:
- A host/user entity with high threat (>50) and high certainty (>50) scores is a strong risk \
escalator — Vectra uses behavioural AI on network traffic and false positives at high certainty \
are rare. Multiple active Vectra detections alongside this XSOAR alert suggests a real incident.
- An entity with zero active Vectra detections and low threat/certainty scores is a meaningful \
mitigating factor, especially for network-based alerts.
- A Vectra-prioritized entity should always be noted in risk factors regardless of verdict.

When ServiceNow context is provided:
- An active change ticket (state: Implement, Scheduled, or similar) for the affected host is a \
STRONG mitigating factor. Planned maintenance, patching, or migrations routinely trigger security \
alerts. If the change window overlaps the alert time, explicitly note this as a likely explanation \
and lower your confidence in a malicious verdict accordingly.
- Open SNOW incidents for the same CI may indicate a known issue — check if they predate the alert.
- If no change tickets exist for the host, note this absence as removing a common benign explanation.

When QRadar entity activity is provided (recent SIEM events for the host/user):
- A cluster of high-magnitude events across multiple log sources around the alert time is a strong \
indicator of a real incident, not an isolated rule fire.
- Repeated authentication failures, connections to unusual external IPs, or activity spanning \
endpoint, network, and identity log sources simultaneously suggest lateral movement or multi-stage \
attack activity.
- Only routine events (normal auth, expected network traffic) in QRadar supports a benign/FP verdict.

When Varonis DatAlert context is provided:
- Active Varonis alerts are a strong risk escalator — Varonis detects abnormal data access, privilege \
abuse, and insider threat patterns that other tools miss. A high-severity Varonis alert alongside the \
XSOAR alert significantly increases confidence in a malicious verdict.
- Data activity showing access to sensitive paths (finance, HR, executive) or unusually high volume \
is a meaningful risk factor.
- No Varonis alerts is a mild mitigating factor for data-exfiltration type detections, but does not \
rule out other attack types.

When Active Directory context is provided:
- A disabled or locked account that is somehow generating activity is a strong indicator of credential \
reuse or token-based attack — note this explicitly.
- Group membership reveals whether the user has legitimate access to the resources in question. Admin \
groups, privileged tiers, or service accounts warrant more scrutiny.
- OU placement distinguishes workstations from servers from privileged access workstations — suspicious \
process activity means more on a server OU than a standard user workstation.
- Last logon time can confirm or contradict whether the account is actively used.

When asset context is provided, consider the host's role, OS, EPP protection status, and tags. \
A suspicious process on an unprotected host or a server is more concerning than on a standard \
EPP-protected workstation.

When time context indicates activity outside business hours or on weekends, note this as a \
risk factor — legitimate activity is less common during these periods.

Note the evidence basis section — if the verdict relies on description-only with no IOC \
enrichment or source alert details, explicitly lower your confidence and recommend investigation.

TOOL USE — you have live integrations, not just canned enrichment:

The enrichment context below is a BASELINE summary of what was fetched automatically \
(recent QRadar events, SNOW changes, Vectra entity, IOC lookups, AD records). It is \
deliberately coarse. You also have tools that let you go deeper. Call them whenever \
a narrower or follow-up question would sharpen your verdict — do NOT defer these \
questions to the analyst as pivots.

Representative tool surface:
- `run_qradar_aql_query` — write targeted AQL for specific event names, time windows, \
log sources, or entity combinations (e.g. LSASS access on host X between 00:23-01:30 UTC, \
WinRM auth events for a specific user on a specific target)
- `get_qradar_offense` — deeper offense details when the baseline summary hints at it
- `get_servicenow_changes`, `get_servicenow_incidents`, `get_host_details_snow` — active \
change windows, open incident tickets, and CMDB details for hosts
- `search_vectra_entity_by_hostname`, `get_vectra_entity_details`, `get_vectra_detection_details` \
— NDR threat/certainty scoring and active detections beyond the baseline summary
- `get_ad_user`, `get_ad_computer` — group memberships, OU placement, enabled status, \
last logon for users/hosts
- `get_varonis_user_alerts`, `get_varonis_data_activity` — Varonis DatAlert user alerts \
and data access patterns
- `lookup_ip_virustotal`, `lookup_hash_virustotal`, `lookup_domain_virustotal`, \
`lookup_url_virustotal`, `lookup_ip_abuseipdb`, `lookup_ip_recorded_future`, \
`lookup_hash_recorded_future`, `lookup_domain_recorded_future` — IOC intel deep-dives
- `get_device_details_cs`, `search_crowdstrike_detections_by_hostname`, \
`get_crowdstrike_detection_details` — CrowdStrike host and detection context

Guidance:
- Use tools to verify or deepen baseline findings when the verdict hinges on specifics \
the baseline doesn't answer (e.g. a specific time window, a specific rule, an IOC not \
yet looked up, a lateral-target host not yet enriched).
- Do NOT re-run what the baseline already shows unless you have a specific reason \
(narrower filter, different time window, corroborating evidence from another tool).
- Budget: ~12 tool calls per ticket. Stop when you have enough evidence.
- If a tool returns an error or "not configured", don't retry the same call — note the \
gap and reason without that data.

INVESTIGATION PIVOTS — RESIDUAL HUMAN-ONLY QUESTIONS:

`investigation_pivots` is now a short list (0-3 entries) of things that CANNOT be \
answered by any tool you have — work that still requires a human. This means:
- Contacting a user to confirm intent ("Verify with X that they ran Y intentionally")
- Reviewing a custom script or process not in any integrated system
- Physical / out-of-band verification

If a question CAN be answered by a tool call, you should have called the tool instead \
of deferring to the analyst. DO NOT emit pivots like "Pull QRadar events for…" or \
"Check VirusTotal for…" — those are tool calls you failed to make.

For close_ticket verdicts, pivots MUST be an empty list.
"""


def _build_source_details_section(source: Dict[str, Any]) -> list:
    """Build LLM prompt section from source-platform alert details."""
    lines = []
    platform = source.get("source", "")

    if platform == "qradar":
        lines.append("\n## QRadar Offense Details")
        lines.append(f"- Offense ID: {source.get('offense_id', 'N/A')}")
        lines.append(f"- Description: {str(source.get('description', ''))[:500]}")
        lines.append(f"- Type: {source.get('offense_type_str', 'N/A')}")
        lines.append(f"- Magnitude: {source.get('magnitude', 'N/A')}/10")
        lines.append(f"- Relevance: {source.get('relevance', 'N/A')}/10")
        lines.append(f"- Credibility: {source.get('credibility', 'N/A')}/10")
        lines.append(f"- Severity: {source.get('severity', 'N/A')}/10")
        lines.append(f"- Event Count: {source.get('event_count', 0)}")
        lines.append(f"- Flow Count: {source.get('flow_count', 0)}")
        lines.append(f"- Status: {source.get('status', 'N/A')}")
        lines.append(f"- Offense Source: {source.get('offense_source', 'N/A')}")
        categories = source.get("categories", [])
        if categories:
            lines.append(f"- Categories: {', '.join(categories[:10])}")
        log_sources = source.get("log_sources", [])
        if log_sources:
            lines.append(f"- Log Sources: {', '.join(log_sources[:5])}")
        rules = source.get("rules", [])
        if rules:
            lines.append("\nDetection Rules:")
            for r in rules[:5]:
                name = r.get("name", "Unknown") if isinstance(r, dict) else r
                lines.append(f"  - {name}")
                if isinstance(r, dict) and r.get("notes"):
                    lines.append(f"    Description: {str(r['notes'])[:300]}")
        sample_events = source.get("sample_events", [])
        if sample_events:
            lines.append("\nSample Events (most recent):")
            for ev in sample_events[:3]:
                ev_name = ev.get("event_name", "N/A")
                ev_time = ev.get("event_time", "")
                src_ip = ev.get("sourceip", "")
                dst_ip = ev.get("destinationip", "")
                dst_port = ev.get("destinationport", "")
                category = ev.get("category", "")
                username = ev.get("username", "")
                log_src = ev.get("log_source", "")
                lines.append(f"  - [{ev_time}] {ev_name}")
                lines.append(f"    {src_ip} → {dst_ip}:{dst_port} | Category: {category}")
                if username:
                    lines.append(f"    User: {username}")
                if log_src:
                    lines.append(f"    Log Source: {log_src}")
                payload = ev.get("payload", "")
                if payload:
                    lines.append(f"    Payload: {payload[:300]}")
        notes = source.get("notes", [])
        if notes:
            lines.append("\nOffense Notes:")
            for n in notes[:5]:
                lines.append(f"  - {str(n.get('note_text', ''))[:200]}")

    elif platform == "crowdstrike":
        lines.append("\n## CrowdStrike Detection Details")
        lines.append(f"- Alert Name: {source.get('display_name', 'N/A')}")
        lines.append(f"- Description: {str(source.get('description', ''))[:500]}")
        lines.append(f"- Severity: {source.get('severity_name', '')} ({source.get('severity', 0)}/100)")
        lines.append(f"- Status: {source.get('status', 'N/A')}")
        lines.append(f"- Type: {source.get('type', 'N/A')}")
        lines.append(f"- Scenario: {source.get('scenario', 'N/A')}")
        tactic = source.get("tactic", "")
        technique = source.get("technique", "")
        if tactic or technique:
            mitre = []
            if tactic:
                mitre.append(f"Tactic: {tactic} ({source.get('tactic_id', '')})")
            if technique:
                mitre.append(f"Technique: {technique} ({source.get('technique_id', '')})")
            lines.append(f"- MITRE ATT&CK: {'; '.join(mitre)}")
        hostnames = source.get("hostnames", [])
        if hostnames:
            lines.append(f"- Hostnames: {', '.join(hostnames[:5])}")
        users = source.get("users", [])
        if users:
            lines.append(f"- Users: {', '.join(users[:5])}")
        user_principal = source.get("user_principal", "")
        if user_principal:
            lines.append(f"- User Principal: {user_principal}")
        lines.append(f"- Platform: {source.get('platform_name', 'N/A')} {source.get('os_version', '')}")

        # Smoking-gun facts — high-signal fields explicitly extracted from
        # the CS payload. The default field dump above gives the LLM the
        # surface-level details; this section gives it the smoking gun.
        sg = source.get("smoking_gun_facts") or {}
        if sg:
            lines.append("\n### Smoking-gun facts")

            # Process tree as ASCII chain
            tree = sg.get("process_tree") or []
            if tree:
                chain = " → ".join(p.get("filename") or "?" for p in tree)
                lines.append(f"- Process tree: {chain}")
                for p in tree:
                    label = p.get("level", "")
                    fn = p.get("filename", "?")
                    cmd = (p.get("cmdline", "") or "").strip()
                    user = p.get("user_name", "")
                    bits = [f"{label}={fn}"]
                    if user:
                        bits.append(f"user={user}")
                    if cmd:
                        bits.append(f"cmd={cmd[:200]}")
                    lines.append(f"    - {' | '.join(bits)}")

            # Files accessed from non-standard paths (the loaded-modules signal)
            faof = sg.get("files_accessed_of_interest") or []
            fa_total = sg.get("files_accessed_total", 0)
            if faof:
                lines.append(
                    f"- Files accessed from non-standard paths "
                    f"({len(faof)} flagged of {fa_total} total):"
                )
                for f in faof:
                    fn = f.get("filename", "?")
                    fp = f.get("filepath", "")
                    lines.append(f"    - {fn}  ({fp})")
            elif fa_total:
                lines.append(
                    f"- Files accessed: {fa_total} total, none from non-standard paths"
                )

            # Files written to non-standard paths (the dropper signal)
            fwof = sg.get("files_written_of_interest") or []
            fw_total = sg.get("files_written_total", 0)
            if fwof:
                lines.append(
                    f"- Files written to non-standard paths "
                    f"({len(fwof)} flagged of {fw_total} total):"
                )
                for f in fwof:
                    fn = f.get("filename", "?")
                    fp = f.get("filepath", "")
                    lines.append(f"    - {fn}  ({fp})")
            elif fw_total:
                lines.append(
                    f"- Files written: {fw_total} total, none to non-standard paths"
                )

            # DNS requests (domain context)
            dns = sg.get("dns_requests") or []
            dns_total = sg.get("dns_requests_total", 0)
            if dns:
                lines.append(
                    f"- DNS requests ({len(dns)} unique domains, {dns_total} total queries):"
                )
                for d in dns:
                    lines.append(f"    - {d}")

            # Network accesses
            nets = sg.get("network_accesses") or []
            net_total = sg.get("network_accesses_total", 0)
            if nets:
                lines.append(f"- Network accesses ({len(nets)} of {net_total} shown):")
                for n in nets:
                    direction = n.get("direction", "")
                    proto = n.get("protocol", "")
                    local = f"{n.get('local_address', '?')}:{n.get('local_port', '?')}"
                    remote = f"{n.get('remote_address', '?')}:{n.get('remote_port', '?')}"
                    lines.append(f"    - {direction} {proto} {local} → {remote}")

            # Quarantined files (the "did anything actually get blocked?" signal)
            qf = sg.get("quarantined_files") or []
            if qf:
                lines.append(f"- Quarantined files ({len(qf)}):")
                for q in qf:
                    lines.append(f"    - {q.get('filename', '?')} ({q.get('state', '')})")

            # Pattern disposition — was anything actually blocked, or just observed?
            disp = sg.get("pattern_disposition", "")
            blocked = sg.get("pattern_disposition_blocked", False)
            if disp:
                action_label = "BLOCKED/PREVENTED" if blocked else "OBSERVATION ONLY (no block)"
                lines.append(f"- Pattern disposition: {disp} — {action_label}")

            # Prevalence — rare binaries are much more interesting than common ones
            prev = sg.get("prevalence") or {}
            local_prev = prev.get("local", "")
            global_prev = prev.get("global", "")
            if local_prev or global_prev:
                lines.append(
                    f"- Prevalence: local=`{local_prev or 'unknown'}`, "
                    f"global=`{global_prev or 'unknown'}`"
                )

            # Structured MITRE list — multiple techniques per detection
            mitre_list = sg.get("mitre_attack") or []
            if len(mitre_list) > 1:
                lines.append(f"- Additional MITRE techniques on this detection ({len(mitre_list)}):")
                for m in mitre_list:
                    pid = m.get("pattern_id", "")
                    tac = m.get("tactic", "")
                    tac_id = m.get("tactic_id", "")
                    tech = m.get("technique", "")
                    tech_id = m.get("technique_id", "")
                    lines.append(
                        f"    - Pattern {pid}: {tac} ({tac_id}) / {tech} ({tech_id})"
                    )

            # Dual-use security/research tools detected in the file paths or cmdlines.
            # Naming the tool is often the difference between "weird PowerShell" and
            # "the user just installed NtObjectManager from PowerShell Gallery."
            dual_use = sg.get("dual_use_tools_detected") or []
            if dual_use:
                lines.append(
                    f"\n### Dual-use tools identified ({len(dual_use)})"
                )
                lines.append(
                    "These are well-known security/research tools matched against "
                    "the file paths and cmdlines in this alert. Many have legitimate "
                    "uses — name recognition is the foothold, not the verdict."
                )
                for tool in dual_use:
                    name = tool.get("name", "?")
                    author = tool.get("author", "")
                    cat = tool.get("category", "")
                    lines.append(f"- **{name}** _(category: {cat}, by {author})_")
                    legit = tool.get("legitimate_use", "")
                    if legit:
                        lines.append(f"    - Legitimate use: {legit}")
                    abuse = tool.get("common_abuse", "")
                    if abuse:
                        lines.append(f"    - Common abuse: {abuse}")
                    nxt = tool.get("if_malicious_next", "")
                    if nxt:
                        lines.append(f"    - If malicious, look at next: {nxt}")
                    ev = tool.get("evidence", []) or []
                    if ev:
                        lines.append(f"    - Evidence: {'; '.join(ev[:3])}")

        # CS baseline — has this user/host done this before? Behavior delta,
        # not raw alert content. Three CS API calls' worth of context boiled
        # down to a few lines so the LLM can weigh "first time ever" vs.
        # "47 times in 90 days" without pivoting into Falcon.
        baseline = source.get("cs_baseline") or {}
        if baseline and "error" not in baseline:
            lines.append("\n### CS baseline (behavior delta)")
            up = baseline.get("user_pattern") or {}
            ur = baseline.get("user_recent") or {}
            hr = baseline.get("host_recent") or {}
            user_lbl = baseline.get("user_name", "") or "?"
            host_lbl = baseline.get("hostname", "") or "?"
            pid_lbl = baseline.get("pattern_id", "") or "?"

            # 1. user x pattern intersection — the headline behavior delta
            if up and "error" not in up:
                up_count = up.get("count", 0)
                lookback = up.get("lookback_days", 0)
                trunc = "+" if up.get("truncated") else ""
                if up_count == 0:
                    lines.append(
                        f"- User x pattern: `{user_lbl}` has NEVER triggered "
                        f"Pattern `{pid_lbl}` in the last {lookback}d "
                        f"(this is the first occurrence)"
                    )
                else:
                    last_days = up.get("last_seen_days_ago")
                    last_str = f", last {last_days}d ago" if last_days is not None else ""
                    lines.append(
                        f"- User x pattern: `{user_lbl}` has triggered "
                        f"Pattern `{pid_lbl}` {up_count}{trunc} time(s) "
                        f"in the last {lookback}d{last_str} "
                        f"(recurring behavior — weigh against intent)"
                    )
            elif up.get("error"):
                lines.append(f"- User x pattern: query failed ({up['error']})")

            # 2. user_recent — what else has this user done lately
            if ur and "error" not in ur:
                ur_count = ur.get("count", 0)
                lookback = ur.get("lookback_days", 0)
                trunc = "+" if ur.get("truncated") else ""
                lines.append(
                    f"- User recent: `{user_lbl}` had {ur_count}{trunc} other "
                    f"CS detection(s) in the last {lookback}d"
                )
                top = ur.get("top_patterns") or []
                if top:
                    bits = [
                        f"`{p.get('pattern_id', '?')}` "
                        f"{p.get('name', '?') or '?'} ({p.get('count', 0)})"
                        for p in top
                    ]
                    lines.append(f"    - Top patterns: {', '.join(bits)}")
            elif ur.get("error"):
                lines.append(f"- User recent: query failed ({ur['error']})")

            # 3. host_recent — what else has this host done lately
            if hr and "error" not in hr:
                hr_count = hr.get("count", 0)
                lookback = hr.get("lookback_days", 0)
                trunc = "+" if hr.get("truncated") else ""
                lines.append(
                    f"- Host recent: `{host_lbl}` had {hr_count}{trunc} other "
                    f"CS detection(s) in the last {lookback}d"
                )
                top = hr.get("top_patterns") or []
                if top:
                    bits = [
                        f"`{p.get('pattern_id', '?')}` "
                        f"{p.get('name', '?') or '?'} ({p.get('count', 0)})"
                        for p in top
                    ]
                    lines.append(f"    - Top patterns: {', '.join(bits)}")
            elif hr.get("error"):
                lines.append(f"- Host recent: query failed ({hr['error']})")

        # CS process-tree correlation — other CS detections on this host
        # within +/- 2h that share a process tree, graph, aggregate, or
        # incident lead with this anchor. The "linked chain" siblings are
        # high-signal: they're probably the same incident playing out in
        # multiple stages. The "time-adjacent" siblings are weaker.
        ptc = source.get("cs_process_tree") or {}
        if ptc and "error" not in ptc:
            linked = ptc.get("linked_chain") or []
            adjacent = ptc.get("time_adjacent") or []
            window = ptc.get("window_minutes", 0)
            if linked or adjacent:
                lines.append("\n### CS process-tree correlation")
                if linked:
                    lines.append(
                        f"- Linked chain ({len(linked)} other CS detection(s) "
                        f"on this host within +/- {window} min that share a "
                        f"tree/graph/aggregate/lead identifier with this anchor):"
                    )
                    for s in linked:
                        offset = s.get("minutes_offset", 0)
                        sign = "+" if offset >= 0 else ""
                        pid = s.get("pattern_id", "?")
                        name = s.get("name", "?") or "?"
                        link_label = s.get("linkage", "?")
                        link_detail = s.get("linkage_detail", "")
                        cmd = (s.get("cmdline", "") or "").strip()
                        lines.append(
                            f"    - [{sign}{offset}m] Pattern `{pid}` "
                            f"{name} -- {link_label} ({link_detail})"
                        )
                        if cmd:
                            lines.append(f"        cmd: {cmd[:200]}")
                else:
                    lines.append(
                        f"- Linked chain: none (no other host detections in +/- "
                        f"{window} min share a tree/graph/aggregate/lead with this "
                        f"anchor)"
                    )
                if adjacent:
                    lines.append(
                        f"- Time-adjacent ({len(adjacent)} other CS detection(s) "
                        f"on this host within +/- {window} min, no graph linkage "
                        f"-- weaker signal):"
                    )
                    for s in adjacent[:5]:
                        offset = s.get("minutes_offset", 0)
                        sign = "+" if offset >= 0 else ""
                        pid = s.get("pattern_id", "?")
                        name = s.get("name", "?") or "?"
                        lines.append(
                            f"    - [{sign}{offset}m] Pattern `{pid}` {name}"
                        )
        elif ptc.get("error"):
            lines.append(
                f"\n### CS process-tree correlation\n- query failed ({ptc['error']})"
            )

        # CS lateral-target host context — internal IPs from network_accesses
        # resolved to CS host metadata. Tells the analyst what the source
        # host was actually trying to talk to (server vs. workstation, OU,
        # role, criticality) instead of just an IP address.
        lt = source.get("cs_lateral_targets") or {}
        if lt and "error" not in lt:
            targets = lt.get("targets") or []
            unresolved = lt.get("unresolved") or []
            if targets or unresolved:
                lines.append("\n### CS lateral-movement targets (host context)")
            if targets:
                lines.append(
                    f"- Resolved {len(targets)} internal target host(s) "
                    f"from network_accesses:"
                )
                for t in targets:
                    ip = t.get("target_ip", "?")
                    port = t.get("target_port", "")
                    proto = t.get("protocol", "")
                    proto_label = f" {proto}" if proto else ""
                    dev = t.get("target_device") or {}
                    hostname = dev.get("hostname", "?")
                    product = dev.get("product_type_desc", "")
                    os_ver = dev.get("os_version", "")
                    domain = dev.get("machine_domain", "")
                    ou = dev.get("ou") or []
                    status = dev.get("status", "")
                    sources = t.get("source_alerts") or []
                    src_bits = []
                    for s in sources:
                        role = s.get("role", "")
                        pid = s.get("pattern_id", "")
                        name = s.get("name", "")
                        if role == "anchor":
                            src_bits.append(f"anchor (Pattern `{pid}` {name})")
                        else:
                            offset = s.get("minutes_offset", 0)
                            sign = "+" if offset >= 0 else ""
                            src_bits.append(
                                f"chain [{sign}{offset}m] (Pattern `{pid}` {name})"
                            )
                    lines.append(
                        f"    - **{hostname}** (`{ip}:{port}`{proto_label}) -- "
                        f"{product or 'unknown type'}, {os_ver or 'unknown OS'}"
                    )
                    bits = []
                    if domain:
                        bits.append(f"domain={domain}")
                    if ou:
                        bits.append(f"OU={'/'.join(ou)}")
                    if status:
                        bits.append(f"status={status}")
                    if bits:
                        lines.append(f"        {' | '.join(bits)}")
                    if src_bits:
                        lines.append(f"        from: {'; '.join(src_bits)}")
            if unresolved:
                lines.append(
                    f"- Unresolved internal IPs ({len(unresolved)}, no CS host record):"
                )
                for u in unresolved[:5]:
                    ip = u.get("target_ip", "?")
                    port = u.get("target_port", "")
                    err = u.get("lookup_error", "")
                    lines.append(f"    - `{ip}:{port}` -- {err}")
        elif lt.get("error"):
            lines.append(
                f"\n### CS lateral-movement targets\n- query failed ({lt['error']})"
            )

        # IOC threat-intel checks — hashes, public IPs, DNS domains from
        # the anchor + linked chain checked against the local tipper TI
        # store. Hits = strong escalation signal; zero hits across many
        # checked IOCs = meaningful FP-leaning datapoint.
        ti = source.get("cs_ioc_ti") or {}
        if ti and "error" not in ti:
            total_checked = ti.get("total_checked", 0)
            total_hits = ti.get("total_hits", 0)
            if total_checked > 0:
                lines.append(
                    f"\n### IOC threat-intel checks "
                    f"(local tipper store)"
                )
                if total_hits == 0:
                    h_n = ti.get("hashes", {}).get("checked", 0)
                    i_n = ti.get("ips", {}).get("checked", 0)
                    d_n = ti.get("domains", {}).get("checked", 0)
                    skipped = ti.get("domains", {}).get("skipped_benign", 0)
                    skip_str = f" ({skipped} benign domains skipped)" if skipped else ""
                    lines.append(
                        f"- 0 of {total_checked} checked IOCs had TI hits "
                        f"(hashes={h_n}, ips={i_n}, domains={d_n}{skip_str}). "
                        f"FP-leaning datapoint."
                    )
                else:
                    lines.append(
                        f"- **{total_hits} of {total_checked} IOCs matched a "
                        f"prior tipper.** Strong escalation signal."
                    )
                    for sub_key, sub_label in (
                        ("hashes", "Hash"), ("ips", "IP"), ("domains", "Domain"),
                    ):
                        sub = ti.get(sub_key) or {}
                        for hit in sub.get("hits", []):
                            val = hit.get("value", "")
                            tipper_count = hit.get("tipper_count", 0)
                            display = val if sub_key != "hashes" else f"{val[:16]}..."
                            lines.append(
                                f"    - {sub_label} `{display}` -- "
                                f"{tipper_count} tipper(s)"
                            )
                            for t in hit.get("tippers", [])[:3]:
                                tid = t.get("azdo_id", "?")
                                title = t.get("title", "")[:80]
                                created = t.get("created_date", "")
                                lines.append(
                                    f"        - #{tid} [{created}] {title}"
                                )
        elif ti.get("error"):
            lines.append(
                f"\n### IOC threat-intel checks\n- query failed ({ti['error']})"
            )

        # Cross-source correlation — open QRadar offenses on the same
        # host/user (plus any lateral-movement target hostnames from Gap
        # 4). A corroborating SIEM signal is strong escalation evidence;
        # zero matches across many checked entities is a meaningful
        # single-source-noise datapoint.
        cs_xs = source.get("cs_cross_source") or {}
        if cs_xs and "error" not in cs_xs:
            total_matched = cs_xs.get("total_matched", 0)
            entities_checked = cs_xs.get("entities_checked") or []
            offenses = cs_xs.get("offenses") or []
            lookback_days = cs_xs.get("lookback_days", 0)
            if entities_checked:
                lines.append("\n### Cross-source correlation (QRadar)")
                ent_bits = []
                for e in entities_checked:
                    ent_str = f"{e.get('type', '?')}=`{e.get('value', '?')}`"
                    role = e.get("role", "")
                    if role and role != "anchor_source":
                        ent_str += f" ({role})"
                    ent_bits.append(ent_str)
                lines.append(
                    f"- Entities checked ({len(entities_checked)}): "
                    f"{', '.join(ent_bits)}"
                )
                if total_matched == 0:
                    lines.append(
                        f"- 0 open QRadar offenses matched these entities "
                        f"in the last {lookback_days}d. "
                        f"No corroborating SIEM signal."
                    )
                else:
                    trunc = "+" if cs_xs.get("truncated") else ""
                    lines.append(
                        f"- **{total_matched}{trunc} open QRadar offense(s)** "
                        f"matched in the last {lookback_days}d "
                        f"(showing {len(offenses)}, sorted by time proximity "
                        f"to CS anchor):"
                    )
                    for o in offenses:
                        oid = o.get("offense_id", "?")
                        desc = (o.get("description", "") or "")[:200]
                        mag = o.get("magnitude", 0)
                        sev = o.get("severity", 0)
                        hours = o.get("hours_from_anchor")
                        offset_str = ""
                        if hours is not None:
                            sign = "+" if hours >= 0 else ""
                            if abs(hours) < 1:
                                offset_str = f" [{sign}{round(hours * 60)}min from anchor]"
                            else:
                                offset_str = f" [{sign}{round(hours, 1)}h from anchor]"
                        lines.append(
                            f"    - Offense #{oid} | mag={mag} | "
                            f"sev={sev}{offset_str}"
                        )
                        if desc:
                            lines.append(f"        desc: {desc}")
                        osrc = o.get("offense_source", "")
                        if osrc:
                            lines.append(f"        offense_source: `{osrc}`")
                        matched = o.get("matched_entities") or []
                        if matched:
                            mb = [
                                f"{m.get('type', '?')}=`{m.get('value', '?')}`"
                                for m in matched
                            ]
                            lines.append(f"        matched: {', '.join(mb)}")
                        rules = o.get("rule_names") or []
                        if rules:
                            lines.append(
                                f"        rules: {', '.join(rules[:3])}"
                            )
                        log_sources = o.get("log_sources") or []
                        if log_sources:
                            lines.append(
                                f"        log_sources: {', '.join(log_sources[:3])}"
                            )
                errors = cs_xs.get("query_errors") or {}
                if errors:
                    lines.append(
                        f"- Note: {len(errors)} entity lookup(s) failed"
                    )
        elif cs_xs.get("error"):
            lines.append(
                f"\n### Cross-source correlation (QRadar)\n"
                f"- query failed ({cs_xs['error']})"
            )

        behaviors = source.get("behaviors", [])
        if behaviors:
            lines.append("\nProcess Behaviors:")
            for b in behaviors[:5]:
                bname = b.get("display_name", "")
                cmdline = b.get("cmdline", "")
                parent = b.get("parent_cmdline", "")
                btactic = b.get("tactic", "")
                btech = b.get("technique", "")
                sha = b.get("sha256", "")
                fpath = b.get("filepath", "")
                lines.append(f"  - {bname}")
                if cmdline:
                    lines.append(f"    Command: {cmdline[:200]}")
                if parent:
                    lines.append(f"    Parent: {parent[:200]}")
                if fpath:
                    lines.append(f"    Path: {fpath}")
                if sha:
                    lines.append(f"    SHA256: {sha}")
                if btactic or btech:
                    lines.append(f"    MITRE: {btactic} / {btech}")
        # Device details
        dev = source.get("device_details")
        if dev:
            lines.append("\nDevice Context:")
            lines.append(f"  - Containment Status: {dev.get('status', 'N/A')}")
            lines.append(f"  - Last Seen: {dev.get('last_seen', 'N/A')}")
            lines.append(f"  - Type: {dev.get('product_type', 'N/A')}")
            domain = dev.get("machine_domain", "")
            if domain:
                lines.append(f"  - Domain: {domain}")
            ou = dev.get("ou", [])
            if ou:
                lines.append(f"  - OU: {', '.join(ou)}")
            tags = dev.get("tags", [])
            if tags:
                lines.append(f"  - Tags: {', '.join(tags[:10])}")
            groups = dev.get("groups", [])
            if groups:
                lines.append(f"  - Groups: {', '.join(groups[:5])}")
        # Parent incident context
        inc = source.get("incident")
        if inc:
            lines.append("\nParent Incident:")
            lines.append(f"  - Incident ID: {inc.get('incident_id', 'N/A')}")
            lines.append(f"  - Severity Score: {inc.get('fine_score', 0)}/100")
            inc_status_map = {"20": "New", "25": "Reopened", "30": "In Progress", "40": "Closed"}
            lines.append(f"  - Status: {inc_status_map.get(str(inc.get('status', '')), str(inc.get('status', 'N/A')))}")
            lines.append(f"  - Timeline: {inc.get('start', 'N/A')} → {inc.get('end', 'N/A')}")
            host_count = inc.get("host_count", 0)
            if host_count > 1:
                inc_hosts = inc.get("hostnames", [])
                lines.append(f"  - Hosts Involved: {host_count} ({', '.join(inc_hosts[:5])})")
            tactics = inc.get("tactics", [])
            if tactics:
                lines.append(f"  - Tactics: {', '.join(tactics)}")
            techniques = inc.get("techniques", [])
            if techniques:
                lines.append(f"  - Techniques: {', '.join(techniques)}")
            objectives = inc.get("objectives", [])
            if objectives:
                lines.append(f"  - Objectives: {', '.join(objectives)}")

    return lines


def _build_vectra_context_section(vectra_context: Dict[str, Any]) -> list:
    """Build LLM prompt section from Vectra NDR entity context."""
    lines = ["\n## Vectra NDR Context"]

    for entity_key, label in (("host_entity", "Host Entity"), ("account_entity", "Account Entity")):
        entity = vectra_context.get(entity_key)
        if not entity:
            continue

        threat = entity.get("threat", 0)
        certainty = entity.get("certainty", 0)
        threat_level = entity.get("threat_level", "UNKNOWN")
        det_count = entity.get("detection_count", 0)
        is_prioritized = entity.get("is_prioritized", False)

        lines.append(
            f"- {label}: {entity.get('name', 'N/A')} | "
            f"Threat: {threat}/100 | Certainty: {certainty}/100 | "
            f"Level: {threat_level} | Detections: {det_count} | "
            f"Prioritized: {'YES' if is_prioritized else 'No'}"
        )
        if entity.get("state"):
            lines.append(f"  State: {entity['state']}")
        if entity.get("tags"):
            lines.append(f"  Tags: {', '.join(str(t) for t in entity['tags'][:5])}")
        if entity.get("last_detection_type"):
            lines.append(f"  Last Detection Type: {entity['last_detection_type']}")

        active_dets = entity.get("active_detections", [])
        if active_dets:
            lines.append(f"  Active Detections ({len(active_dets)}):")
            for d in active_dets[:5]:
                triaged = " [triaged]" if d.get("is_triaged") else ""
                lines.append(
                    f"    - {d.get('type', 'N/A')} "
                    f"(category: {d.get('category', 'N/A')}, "
                    f"threat: {d.get('threat', 0)}, "
                    f"certainty: {d.get('certainty', 0)}){triaged}"
                )
                if d.get("summary"):
                    lines.append(f"      Summary: {d['summary'][:150]}")

    if not vectra_context.get("host_entity") and not vectra_context.get("account_entity"):
        lines.append("- No matching Vectra entities found for this host/user")

    return lines


def _build_snow_context_section(snow_context: Dict[str, Any]) -> list:
    """Build LLM prompt section from ServiceNow incident and change ticket context."""
    lines = ["\n## ServiceNow Context"]

    incidents = snow_context.get("incidents", [])
    incident_count = snow_context.get("incident_count", len(incidents))
    if incidents:
        lines.append(f"Open/Recent Incidents ({incident_count} in last 72h):")
        for inc in incidents[:5]:
            number = inc.get("number", "?")
            desc = inc.get("short_description", "")[:100]
            state = inc.get("state", "?")
            opened = inc.get("opened_at", "")[:16]
            lines.append(f"  - {number}: \"{desc}\" | State: {state} | Opened: {opened}")
    else:
        lines.append("- No open/recent SNOW incidents for this CI")

    changes = snow_context.get("changes", [])
    change_count = snow_context.get("change_count", len(changes))
    if changes:
        lines.append(f"Change Tickets ({change_count} found):")
        for chg in changes[:5]:
            number = chg.get("number", "?")
            desc = chg.get("short_description", "")[:100]
            state = chg.get("state", "?")
            chg_type = chg.get("type", "")
            start = chg.get("planned_start", "")[:16]
            end = chg.get("planned_end", "")[:16]
            lines.append(
                f"  - {number}: \"{desc}\" | Type: {chg_type} | "
                f"State: {state} | Window: {start} → {end}"
            )
    else:
        lines.append("- No SNOW change tickets found for this CI")

    return lines


def _build_qradar_activity_section(qradar_entity_activity: Dict[str, Any]) -> list:
    """Build LLM prompt section from QRadar recent entity activity."""
    hours = qradar_entity_activity.get("hours", 4)
    event_count = qradar_entity_activity.get("event_count", 0)
    searched_by = qradar_entity_activity.get("searched_by", [])
    lines = [
        f"\n## QRadar Recent Activity (Last {hours}h, searched by: {', '.join(searched_by)})"
    ]

    if event_count == 0:
        lines.append(f"- No SIEM events found in the last {hours} hours")
        return lines

    lines.append(f"- Total events found: {event_count} (showing top 10 by magnitude)")

    # Log source summary
    ls_summary = qradar_entity_activity.get("log_source_summary", {})
    if ls_summary:
        ls_parts = [f"{ls}: {count}" for ls, count in sorted(ls_summary.items(), key=lambda x: -x[1])[:6]]
        lines.append(f"- Log sources: {', '.join(ls_parts)}")

    events = qradar_entity_activity.get("events", [])
    if events:
        lines.append("Events (by magnitude):")
        for ev in events[:10]:
            evt_time = ev.get("event_time", "")[:16]
            evt_name = ev.get("event_name", "N/A")
            src = ev.get("sourceip", "")
            dst = ev.get("destinationip", "")
            mag = ev.get("magnitude", "")
            log_src = ev.get("log_source", "")
            user = ev.get("username", "") or ev.get("Computer Hostname", "")
            line = f"  [{evt_time}] {evt_name} | {src} → {dst} | mag={mag} | {log_src}"
            if user:
                line += f" | user={user}"
            lines.append(line)

    return lines


def _build_varonis_section(varonis_context: Dict[str, Any]) -> list:
    """Build LLM prompt section from Varonis DatAlert context."""
    import json
    lines = ["\n## Varonis DatAlert Context"]

    user_alerts = varonis_context.get("user_alerts")
    if user_alerts:
        lines.append(f"User Alerts ({len(user_alerts) if isinstance(user_alerts, list) else 1}):")
        alerts = user_alerts if isinstance(user_alerts, list) else [user_alerts]
        for alert in alerts[:5]:
            if isinstance(alert, dict):
                rule = alert.get("RuleName", alert.get("rule", alert.get("name", "N/A")))
                severity = alert.get("Severity", alert.get("severity", "N/A"))
                status = alert.get("Status", alert.get("status", "N/A"))
                lines.append(f"  - Rule: {rule} | Severity: {severity} | Status: {status}")
            else:
                lines.append(f"  - {str(alert)[:200]}")
    else:
        lines.append("- No Varonis user alerts found")

    data_activity = varonis_context.get("data_activity")
    if data_activity:
        activity_list = data_activity if isinstance(data_activity, list) else [data_activity]
        lines.append(f"Data Activity ({len(activity_list)} records):")
        for record in activity_list[:5]:
            if isinstance(record, dict):
                path = record.get("EventType", record.get("path", record.get("resource", "")))
                op = record.get("Operation", record.get("operation", ""))
                ts = record.get("EventTime", record.get("timestamp", ""))
                lines.append(f"  - {op} {path} @ {ts}".strip())
            else:
                lines.append(f"  - {str(record)[:200]}")
    else:
        lines.append("- No Varonis data activity found")

    return lines


def _build_ad_section(ad_context: Dict[str, Any]) -> list:
    """Build LLM prompt section from Active Directory context."""
    lines = ["\n## Active Directory Context"]

    user = ad_context.get("user")
    if user and isinstance(user, dict):
        name = user.get("displayName", user.get("name", user.get("sAMAccountName", "N/A")))
        enabled = user.get("userAccountControl", user.get("enabled", "N/A"))
        dept = user.get("department", "N/A")
        title = user.get("title", "N/A")
        manager = user.get("manager", "N/A")
        last_logon = user.get("lastLogon", user.get("lastLogonDate", "N/A"))
        ou = user.get("distinguishedName", user.get("dn", ""))
        groups = user.get("memberOf", [])

        lines.append(f"User: {name} | Enabled: {enabled} | Title: {title} | Dept: {dept}")
        lines.append(f"  Manager: {manager} | Last Logon: {last_logon}")
        if ou:
            lines.append(f"  OU: {ou}")
        if groups:
            group_list = groups if isinstance(groups, list) else [groups]
            lines.append(f"  Groups ({len(group_list)}): {', '.join(str(g) for g in group_list[:5])}")
    else:
        lines.append("- No AD user record found")

    computer = ad_context.get("computer")
    if computer and isinstance(computer, dict):
        name = computer.get("name", computer.get("cn", "N/A"))
        os_name = computer.get("operatingSystem", computer.get("os", "N/A"))
        os_ver = computer.get("operatingSystemVersion", "")
        enabled = computer.get("enabled", "N/A")
        last_logon = computer.get("lastLogon", computer.get("lastLogonDate", "N/A"))
        ou = computer.get("distinguishedName", computer.get("dn", ""))
        lines.append(f"Computer: {name} | OS: {os_name} {os_ver} | Enabled: {enabled}")
        lines.append(f"  Last Logon: {last_logon}")
        if ou:
            lines.append(f"  OU: {ou}")
    else:
        lines.append("- No AD computer record found")

    return lines


def _build_xsoar_triage_prompt(
    ticket: dict, enrichment: dict,
    similar_prediction: Optional[SimilarTicketPrediction] = None,
    similar_notes: Optional[Dict[str, dict]] = None,
    asset_context: Optional[Dict[str, Any]] = None,
    time_context: str = "",
    ioc_correlated_tickets: Optional[List[dict]] = None,
    evidence_basis: str = "",
    vectra_context: Optional[Dict[str, Any]] = None,
    qradar_entity_activity: Optional[Dict[str, Any]] = None,
    snow_context: Optional[Dict[str, Any]] = None,
    varonis_context: Optional[Dict[str, Any]] = None,
    ad_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Build the user prompt for LLM triage of an XSOAR ticket."""
    custom = ticket.get("CustomFields") or {}

    sections = [
        "## Ticket Details",
        f"- Name: {ticket.get('name', 'Unknown')}",
        f"- Type: {ticket.get('type', 'N/A')}",
        f"- Security Category: {custom.get('securitycategory', 'N/A')}",
        f"- Severity: {SEVERITY_MAP.get(ticket.get('severity', 0), 'Unknown')}",
        f"- Detection Source: {custom.get('detectionsource', 'N/A')}",
        f"- Status: {ticket.get('status', 'N/A')}",
        f"- Owner: {ticket.get('owner', 'N/A')}",
        f"- Created: {ticket.get('created', 'N/A')}",
    ]
    if time_context:
        sections.append(f"- Time Context: {time_context}")

    # Affected host/user
    hostname = custom.get("affectedhostname", "") or custom.get("hostname", "")
    username = custom.get("affectedusername", "") or custom.get("username", "")
    if hostname or username:
        sections.append("\n## Affected Host/User")
        if hostname:
            sections.append(f"- Hostname: {hostname}")
        if username:
            sections.append(f"- Username: {username}")

    # Asset context from Tanium
    if asset_context:
        sections.append("\n## Asset Context")
        sections.append(f"- OS: {asset_context.get('os_platform', 'N/A')}")
        sections.append(f"- Status: {asset_context.get('eid_status', 'N/A')}")
        sections.append(f"- Last Seen: {asset_context.get('last_seen', 'N/A')}")
        sections.append(f"- Source: {asset_context.get('source', 'N/A')}")
        if asset_context.get("has_epp") is not None:
            sections.append(f"- EPP Protected: {'Yes' if asset_context['has_epp'] else 'No'}")
        tags = asset_context.get("custom_tags", [])
        if tags:
            sections.append(f"- Tags: {', '.join(str(t) for t in tags[:10])}")

    # Playbook action summary
    action_summary = custom.get("actionsummary", "")
    if action_summary:
        sections.append("\n## Playbook Action Summary")
        sections.append(str(action_summary)[:1000])

    # Ticket description/details
    details = ticket.get("details", "")
    if details:
        sections.append("\n## Ticket Description")
        sections.append(str(details)[:1500])

    # Source alert details (QRadar offense or CrowdStrike detection)
    source_details = enrichment.get("source_details")
    if source_details and "error" not in source_details:
        sections.extend(_build_source_details_section(source_details))

    # Enrichment results
    vt = enrichment.get("virustotal", {})
    if vt and "error" not in vt:
        sections.append("\n## VirusTotal")
        for h, data in vt.get("hashes", {}).items():
            sections.append(f"- Hash {h[:16]}...: {data.get('malicious', 0)}/{data.get('total', 0)} ({data.get('threat_level', 'N/A')})")
        for ip, data in vt.get("ips", {}).items():
            sections.append(f"- IP {ip}: {data.get('malicious', 0)}/{data.get('total', 0)}")
        for d, data in vt.get("domains", {}).items():
            sections.append(f"- Domain {d}: {data.get('malicious', 0)}/{data.get('total', 0)}")

    abuse = enrichment.get("abuseipdb", {})
    if abuse and "error" not in abuse:
        sections.append("\n## AbuseIPDB")
        for ip, data in abuse.items():
            sections.append(f"- {ip}: confidence={data.get('abuse_confidence_score', 0)}/100, reports={data.get('total_reports', 0)}, ISP={data.get('isp', 'N/A')}")

    rf = enrichment.get("recorded_future", {})
    if rf and "error" not in rf:
        sections.append("\n## Recorded Future")
        for val, data in rf.items():
            sections.append(f"- {val}: risk_score={data.get('risk_score', 'N/A')}, level={data.get('risk_level', 'N/A')}")

    # Similar historical tickets — analyst outcomes for nearly identical alerts
    if similar_prediction and similar_prediction.similar_tickets:
        sections.append(f"\n## Similar Historical Tickets ({similar_prediction.sample_size} found)")
        if similar_prediction.top_close_reasons:
            reason_summary = ", ".join(
                f"{reason}: {count}" for reason, count in
                sorted(similar_prediction.top_close_reasons.items(), key=lambda x: -x[1])
            )
            sections.append(f"- Close reason distribution: {reason_summary}")
        sections.append(f"- Closure rate: {similar_prediction.closure_rate:.0%}")
        if similar_prediction.avg_resolution_hours is not None:
            sections.append(f"- Avg resolution time: {similar_prediction.avg_resolution_hours}h")
        sections.append("")
        notes_map = similar_notes or {}
        for i, sim in enumerate(similar_prediction.similar_tickets[:5], 1):
            meta = sim.get("metadata", {})
            tid = meta.get("id", "?")
            similarity = sim.get("similarity_score", 0)
            sections.append(
                f"{i}. #{tid} \"{meta.get('name', '?')}\" — "
                f"similarity={similarity:.0%}, "
                f"close_reason={meta.get('close_reason', 'N/A')}, "
                f"severity={SEVERITY_MAP.get(meta.get('severity', 0), 'Unknown')}, "
                f"owner={meta.get('owner', 'N/A')}"
            )
            # Analyst close notes — the most valuable signal for why it was closed
            ticket_notes = notes_map.get(str(tid), {})
            close_notes = (ticket_notes.get("close_notes") or "")[:200].strip()
            if close_notes:
                sections.append(f"   Analyst close notes: \"{close_notes}\"")

    # IOC cross-correlation — same IOCs appearing in other recent tickets
    if ioc_correlated_tickets:
        sections.append(f"\n## IOC Cross-Correlation ({len(ioc_correlated_tickets)} related tickets in last 24h)")
        sections.append("WARNING: The same IOCs appear in multiple recent tickets. This may indicate a campaign or widespread incident.")
        for ct in ioc_correlated_tickets[:5]:
            sections.append(
                f"- #{ct.get('id', '?')} \"{ct.get('name', '?')[:60]}\" — "
                f"type={ct.get('type', 'N/A')}, host={ct.get('hostname', 'N/A')}, "
                f"user={ct.get('username', 'N/A')}, created={str(ct.get('created_date', ''))[:16]}"
            )

    # Vectra NDR context — threat/certainty scores and active detections
    if vectra_context and "error" not in vectra_context:
        sections.extend(_build_vectra_context_section(vectra_context))

    # ServiceNow context — incidents and change tickets for the affected CI
    if snow_context and "error" not in snow_context:
        sections.extend(_build_snow_context_section(snow_context))

    # QRadar entity activity — recent SIEM events for the host/user
    if qradar_entity_activity and "error" not in qradar_entity_activity:
        sections.extend(_build_qradar_activity_section(qradar_entity_activity))

    # Varonis DatAlert context — user alerts and data activity
    if varonis_context and "error" not in varonis_context:
        sections.extend(_build_varonis_section(varonis_context))

    # Active Directory context — user and computer object details
    if ad_context and "error" not in ad_context:
        sections.extend(_build_ad_section(ad_context))

    # Evidence basis — what data this verdict is grounded in
    if evidence_basis:
        sections.append(f"\n## Evidence Basis")
        sections.append(f"{evidence_basis}")

    return "\n".join(sections)


_JSON_FENCE_RE = __import__("re").compile(
    r"```(?:json)?\s*(\{.*\})\s*```", __import__("re").DOTALL,
)


def _strip_json_fence(content: str) -> str:
    """Extract a JSON object from a model response that may be wrapped in a
    ```json ... ``` markdown fence and/or carry leading/trailing commentary.

    Returns the cleaned string ready for `model_validate_json()`. The
    extraction is greedy on both ends:

      1. If a ```json ... ``` (or lang-less ``` ... ```) fence is present,
         return its inner JSON object as-is.
      2. Otherwise slice from the first `{` to the matching last `}` so any
         leading "Here is the JSON:" or trailing "That's the response."
         commentary is dropped.
      3. Otherwise return the original string unchanged (lets the parser
         emit its own error pointing at the actual content).
    """
    if not content:
        return content
    s = content.strip()
    m = _JSON_FENCE_RE.search(s)
    if m:
        return m.group(1).strip()
    first = s.find("{")
    last = s.rfind("}")
    if first >= 0 and last > first:
        return s[first:last + 1]
    return s


_TRIAGE_TOOL_BUDGET = 12


def _build_triage_tools(ticket_id: str) -> list:
    """Return the list of @tool-decorated functions the triage LLM can call.

    AD and Varonis tools require the current ticket_id (they execute XSOAR war
    room commands in the ticket's investigation) — we wrap those in closures
    so the LLM doesn't need to know its own ticket_id.
    """
    from langchain_core.tools import tool as _tool_decorator

    # Stateless tools — import and pass through directly
    from my_bot.tools.qradar_tools import (
        get_qradar_offense,
        run_qradar_aql_query,
    )
    from my_bot.tools.servicenow_tools import (
        get_host_details_snow,
        get_servicenow_changes,
        get_servicenow_incidents,
    )
    from my_bot.tools.vectra_tools import (
        search_vectra_entity_by_hostname,
        get_vectra_entity_details,
        get_vectra_detection_details,
    )
    from my_bot.tools.virustotal_tools import (
        lookup_ip_virustotal,
        lookup_hash_virustotal,
        lookup_domain_virustotal,
        lookup_url_virustotal,
    )
    from my_bot.tools.abuseipdb_tools import lookup_ip_abuseipdb
    from my_bot.tools.recorded_future_tools import (
        lookup_ip_recorded_future,
        lookup_hash_recorded_future,
        lookup_domain_recorded_future,
    )
    from my_bot.tools.crowdstrike_tools import (
        get_device_details_cs,
        search_crowdstrike_detections_by_hostname,
        get_crowdstrike_detection_details,
    )

    # Ticket-bound tools — close over ticket_id so the LLM sees a simpler signature
    from my_bot.tools.active_directory_tools import (
        get_ad_user as _ad_user_raw,
        get_ad_computer as _ad_computer_raw,
    )
    from my_bot.tools.varonis_tools import (
        get_varonis_user_alerts as _varonis_user_raw,
        get_varonis_data_activity as _varonis_data_raw,
    )

    @_tool_decorator
    def get_ad_user(username: str) -> str:
        """Get Active Directory details for a user: group memberships, OU placement,
        enabled status, last logon time. Helps establish whether the activity is
        consistent with the account's role."""
        return _ad_user_raw.invoke({"username": username, "ticket_id": ticket_id})

    @_tool_decorator
    def get_ad_computer(hostname: str) -> str:
        """Get Active Directory details for a computer: OS, OU placement, enabled
        status. Helps distinguish workstations vs servers vs privileged tier."""
        return _ad_computer_raw.invoke({"hostname": hostname, "ticket_id": ticket_id})

    @_tool_decorator
    def get_varonis_user_alerts(username: str) -> str:
        """Get Varonis DatAlert user alerts — abnormal data access, privilege
        abuse, and insider-threat patterns for the given user."""
        return _varonis_user_raw.invoke({"username": username, "ticket_id": ticket_id})

    @_tool_decorator
    def get_varonis_data_activity(hostname: str) -> str:
        """Get Varonis data activity for a host — volume, paths accessed, and
        sensitivity of data touched."""
        return _varonis_data_raw.invoke({"hostname": hostname, "ticket_id": ticket_id})

    return [
        get_qradar_offense, run_qradar_aql_query,
        get_host_details_snow, get_servicenow_changes, get_servicenow_incidents,
        search_vectra_entity_by_hostname, get_vectra_entity_details,
        get_vectra_detection_details,
        get_ad_user, get_ad_computer,
        get_varonis_user_alerts, get_varonis_data_activity,
        lookup_ip_virustotal, lookup_hash_virustotal,
        lookup_domain_virustotal, lookup_url_virustotal,
        lookup_ip_abuseipdb,
        lookup_ip_recorded_future, lookup_hash_recorded_future,
        lookup_domain_recorded_future,
        get_device_details_cs, search_crowdstrike_detections_by_hostname,
        get_crowdstrike_detection_details,
    ]


def _run_triage_tool_loop(
    llm_with_tools,
    messages: list,
    tool_map: dict,
    max_iterations: int = _TRIAGE_TOOL_BUDGET,
) -> tuple:
    """Drive the tool-use conversation until the LLM stops requesting tools.

    Returns (final_messages, tool_trace). `messages` is mutated in-place to
    accumulate the full conversation (AIMessage + ToolMessage pairs) so the
    subsequent structured-output call has the complete context.
    """
    from langchain_core.messages import ToolMessage
    tool_trace: list = []

    for iteration in range(max_iterations):
        response = llm_with_tools.invoke(messages)
        messages.append(response)
        tool_calls = getattr(response, "tool_calls", None) or []
        if not tool_calls:
            return messages, tool_trace

        for tc in tool_calls:
            name = tc.get("name", "")
            args = tc.get("args", {}) or {}
            call_id = tc.get("id", "") or ""
            fn = tool_map.get(name)
            if fn is None:
                result = f"Unknown tool: {name}"
            else:
                try:
                    result = fn.invoke(args)
                except Exception as e:
                    result = f"Tool {name} raised: {type(e).__name__}: {e}"
                    logger.warning(f"Triage tool {name} raised: {e}")
            result_str = str(result) if result is not None else ""
            tool_trace.append({
                "tool": name,
                "args": args,
                "result_preview": result_str[:400],
            })
            messages.append(ToolMessage(content=result_str, tool_call_id=call_id))

    logger.warning(
        f"XSOAR triage tool loop hit budget={max_iterations}; "
        f"forcing final verdict with partial evidence."
    )
    return messages, tool_trace


_TRIAGE_CRITIC_SYSTEM_PROMPT = """\
You are an independent SOC verifier reviewing the work of another agent that \
has just finished a tool-use loop for XSOAR ticket triage. You do NOT produce \
the verdict. Your only job is to identify gaps or misalignments that would \
degrade verdict quality if left unchecked.

Review the conversation below (system prompt + ticket context + tool calls + \
tool results) and critique it on three axes:

1. EVIDENCE ALIGNMENT: Are the tool RESULTS actually consistent with the \
   direction the investigating agent is heading? Flag partial use (results \
   returned but ignored) and contradictions (results undermine the working \
   hypothesis).

2. UNUSED PIVOTS: Given the ticket type, were any obvious tool calls skipped? \
   Example: a malicious-IP ticket with no VT/AbuseIPDB lookup; a suspicious \
   PowerShell ticket with no QRadar AQL for the host; a hash-based detection \
   with no VT hash lookup. Only flag tools whose absence is clearly wrong — \
   not every possible pivot. Skip this check if the tool budget was exhausted \
   (12+ calls made) — budget ceiling is a known limit, not a pivot gap.

3. HALLUCINATIONS / PREMATURE CONCLUSIONS: Did the agent state specifics that \
   are NOT supported by any tool result in the transcript?

Be terse. Emit 0-3 concerns and 0-3 unused pivots. If the trace is clean, set \
flagged=false and return empty lists. Do not invent work.
"""


def _serialize_tool_trace_for_critic(tool_trace: list) -> str:
    """Render the Phase 1 tool trace as a compact transcript for the critic.

    Router LLM has a short context; feed it just the tool name + args + the
    400-char result_preview we already capture per call.
    """
    if not tool_trace:
        return "(no tool calls were made)"
    lines = []
    for i, entry in enumerate(tool_trace, 1):
        name = entry.get("tool", "?")
        args = entry.get("args", {}) or {}
        preview = entry.get("result_preview", "") or ""
        lines.append(f"[{i}] {name}({args}) -> {preview}")
    return "\n".join(lines)


def _run_triage_critic(
    ticket_id: str,
    prompt: str,
    tool_trace: list,
) -> Optional[XsoarTriageCritique]:
    """Run the Reflector-style critic over the Phase 1 tool trace.

    Gated by env var XSOAR_TRIAGE_CRITIC=1. Uses the router LLM (Qwen3-8B)
    on an independent session — no access to the Phase 1 messages object,
    only the rendered transcript. Returns None on failure or when disabled.
    """
    import os
    if os.getenv("XSOAR_TRIAGE_CRITIC", "") != "1":
        return None

    try:
        from src.components.tipper_analyzer.llm_init import get_router_llm
        router = get_router_llm()
        if router is None:
            logger.info(f"[critic] router LLM unavailable for {ticket_id}; skipping")
            return None
    except Exception as e:
        logger.warning(f"[critic] router LLM init failed for {ticket_id}: {e}")
        return None

    from langchain_core.messages import SystemMessage, HumanMessage
    transcript = _serialize_tool_trace_for_critic(tool_trace)
    user_msg = (
        "## TICKET CONTEXT (what the investigating agent saw)\n"
        f"{prompt}\n\n"
        "## TOOL TRACE (Phase 1 results)\n"
        f"{transcript}\n\n"
        "Emit the structured critique now."
    )
    messages = [
        SystemMessage(content=_TRIAGE_CRITIC_SYSTEM_PROMPT),
        HumanMessage(content=user_msg),
    ]
    try:
        critic_structured = router.with_structured_output(XsoarTriageCritique)
        critique = critic_structured.invoke(messages)
        logger.info(
            f"[critic] ticket={ticket_id} flagged={critique.flagged} "
            f"alignment={critique.evidence_alignment} "
            f"concerns={len(critique.concerns)} unused={len(critique.unused_pivots)}"
        )
        return critique
    except Exception as e:
        logger.warning(f"[critic] critic pass failed for {ticket_id}: {e}")
        return None


def _format_critique_for_verdict_prompt(critique: XsoarTriageCritique) -> str:
    """Render the critique as a short block injected into the Phase 2 prompt."""
    parts = [
        "## VERIFIER CRITIQUE (independent review of your tool trace above)",
        f"evidence_alignment: {critique.evidence_alignment}",
        f"rationale: {critique.rationale}",
    ]
    if critique.concerns:
        parts.append("concerns:")
        parts.extend(f"  - {c}" for c in critique.concerns)
    if critique.unused_pivots:
        parts.append(
            "unused_pivots (tools the verifier thinks you should have called): "
        )
        parts.extend(f"  - {p}" for p in critique.unused_pivots)
    parts.append(
        "Incorporate the above into your verdict. If the verifier is wrong, "
        "explain briefly in `summary`. Do NOT retry tool calls — Phase 2 is "
        "verdict-only."
    )
    return "\n".join(parts)


def _run_xsoar_llm_triage(
    ticket: dict, enrichment: dict,
    similar_prediction: Optional[SimilarTicketPrediction] = None,
    **prompt_kwargs,
) -> tuple:
    """Run tool-using LLM triage on an XSOAR ticket.

    Two-phase execution:

      Phase 1 (tool loop): LLM has ServiceNow / QRadar / Vectra / AD / Varonis /
      IOC tools bound. Loop invoke → execute tool_calls → append ToolMessages
      until the LLM stops requesting tools (or the call budget is exhausted).
      The baseline enrichment is still provided in the user prompt — tools are
      for going deeper.

      Phase 2 (structured verdict): the accumulated conversation is re-invoked
      with `with_structured_output(XsoarTriageLLMResponse)` to produce the
      strict JSON verdict. Falls back to plain invoke + fence-strip for local
      backends (e.g. mlx-lm / GLM-4.7-Flash) that ignore strict JSON mode.

    Returns (response, tool_trace, critique). Response is None only if both
    phases fail. Critique is None unless XSOAR_TRIAGE_CRITIC=1 and the critic
    pass succeeded.
    """
    try:
        from src.components.tipper_analyzer.llm_init import get_llm
        llm = get_llm()
        if llm is None:
            logger.error("LLM not available for XSOAR triage")
            return None, [], None
    except Exception as e:
        logger.error(f"XSOAR LLM init failed: {e}", exc_info=True)
        return None, [], None

    try:
        prompt = _build_xsoar_triage_prompt(
            ticket, enrichment, similar_prediction, **prompt_kwargs,
        )
    except Exception as e:
        logger.error(f"XSOAR LLM prompt build failed: {e}", exc_info=True)
        return None, [], None

    ticket_id = str(ticket.get("id", "") or ticket.get("investigationId", "") or "")

    # ---- Phase 1: tool loop ----
    tool_trace: list = []
    from langchain_core.messages import SystemMessage, HumanMessage
    messages: list = [
        SystemMessage(content=XSOAR_TRIAGE_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]
    try:
        triage_tools = _build_triage_tools(ticket_id)
        tool_map = {t.name: t for t in triage_tools}
        llm_with_tools = llm.bind_tools(triage_tools)
        messages, tool_trace = _run_triage_tool_loop(
            llm_with_tools, messages, tool_map,
        )
    except Exception as loop_err:
        logger.warning(
            f"XSOAR triage tool loop failed "
            f"({type(loop_err).__name__}: {str(loop_err)[:200]}); "
            f"proceeding to verdict with baseline enrichment only."
        )

    # ---- Phase 1.5: optional critic pass (gated by XSOAR_TRIAGE_CRITIC=1) ----
    critique = _run_triage_critic(ticket_id, prompt, tool_trace)

    # ---- Phase 2: structured verdict on accumulated conversation ----
    verdict_prompt_body = (
        "Based on the baseline enrichment and any tool results above, emit the "
        "final structured triage verdict as strict JSON. investigation_pivots "
        "must be limited to residual human-only questions (contact user, review "
        "custom script, etc.) — do not list tool calls you could have made."
    )
    if critique is not None:
        # Always inject — even "aligned" critiques carry signal for the
        # verdict LLM ("an independent reviewer blessed the trace"). The
        # flagged bit is preserved in the SentinelTriage JSON for analytics
        # but no longer gates prompt injection.
        verdict_prompt_body = (
            verdict_prompt_body
            + "\n\n"
            + _format_critique_for_verdict_prompt(critique)
        )
    verdict_prompt = HumanMessage(content=verdict_prompt_body)
    verdict_messages = messages + [verdict_prompt]

    try:
        structured_llm = llm.with_structured_output(XsoarTriageLLMResponse)
        return structured_llm.invoke(verdict_messages), tool_trace, critique
    except Exception as parse_err:
        logger.warning(
            f"XSOAR LLM structured-output path failed "
            f"({type(parse_err).__name__}: {str(parse_err)[:200]}); "
            f"falling back to plain invoke + fence strip."
        )

    # ---- Fallback: plain invoke with schema injected into the system prompt ----
    import json as _json
    schema_aware_system = (
        XSOAR_TRIAGE_SYSTEM_PROMPT
        + "\n\n## OUTPUT FORMAT (CRITICAL)\n\n"
        "Return ONLY a JSON object matching this Pydantic schema. "
        "Do NOT wrap in markdown code fences. Do NOT add any commentary "
        "or explanation. Your response must start with `{` and end with `}`.\n\n"
        "Schema:\n"
        + _json.dumps(XsoarTriageLLMResponse.model_json_schema(), indent=2)
    )
    try:
        # Rebuild messages with schema-aware system prompt so the fallback path
        # still benefits from the tool-call context accumulated in phase 1.
        fallback_messages = [SystemMessage(content=schema_aware_system)] + \
            messages[1:] + [verdict_prompt]
        raw = llm.invoke(fallback_messages)
        content = getattr(raw, "content", None) or str(raw)
        cleaned = _strip_json_fence(content)
        return XsoarTriageLLMResponse.model_validate_json(cleaned), tool_trace, critique
    except Exception as fallback_err:
        logger.error(
            f"XSOAR LLM fallback path also failed "
            f"({type(fallback_err).__name__}: {fallback_err})",
            exc_info=True,
        )
        return None, tool_trace, critique


class XsoarTriagePipeline:
    """Orchestrates XSOAR ticket triage: enrich -> LLM -> predict -> send card."""

    def __init__(self, webex_api=None, room_id: str = ""):
        self.webex_api = webex_api
        self.room_id = room_id

    def triage_ticket(self, ticket: dict) -> Optional[XsoarTriageResult]:
        """Run full triage pipeline on a single XSOAR ticket.

        Args:
            ticket: Raw XSOAR ticket dict from get_tickets()

        Returns:
            XsoarTriageResult or None if already processed or triage fails
        """
        ticket_id = str(ticket.get("id", ""))
        alert_id = f"xsoar:{ticket_id}"
        ticket_name = ticket.get("name", "Unknown")
        custom = ticket.get("CustomFields") or {}
        hostname = custom.get("affectedhostname", "") or custom.get("hostname", "")
        username = custom.get("affectedusername", "") or custom.get("username", "")
        source_ip = custom.get("sourceip", "")

        logger.info(f"Triaging XSOAR ticket: {ticket_id} ({ticket_name})")

        # Step 1: All enrichments in parallel — IOC/source/similar/asset + Vectra/QRadar/SNOW
        enrichment = {}
        source_details = None
        similar_prediction = None
        asset_context = {}
        vectra_context = {}
        qradar_entity_activity = {}
        snow_context = {}
        varonis_context = {}
        ad_context = {}
        with ThreadPoolExecutor(max_workers=9, thread_name_prefix="xsoar-enrich") as pool:
            ioc_future = pool.submit(enrich_xsoar_ticket, ticket)
            source_future = pool.submit(enrich_from_source, ticket)
            similar_future = pool.submit(self._get_similar_ticket_prediction, ticket)
            asset_future = pool.submit(self._enrich_asset_context, hostname)
            vectra_future = pool.submit(enrich_vectra_context, hostname, username, source_ip)
            qradar_activity_future = pool.submit(
                enrich_qradar_activity, hostname, username, source_ip
            )
            snow_future = pool.submit(enrich_snow_context, hostname, username)
            varonis_future = pool.submit(enrich_varonis_context, hostname, username, ticket_id)
            ad_future = pool.submit(enrich_ad_context, hostname, username, ticket_id)

            enrichment = ioc_future.result()
            try:
                source_details = source_future.result()
            except Exception as e:
                logger.warning(f"Source enrichment failed for {ticket_id}: {e}")
            try:
                similar_prediction = similar_future.result()
            except Exception as e:
                logger.warning(f"Similar ticket prediction failed for {ticket_id}: {e}")
            try:
                asset_context = asset_future.result() or {}
            except Exception as e:
                logger.warning(f"Asset context enrichment failed for {ticket_id}: {e}")
            try:
                vectra_context = vectra_future.result() or {}
            except Exception as e:
                logger.warning(f"Vectra context enrichment failed for {ticket_id}: {e}")
            try:
                qradar_entity_activity = qradar_activity_future.result() or {}
            except Exception as e:
                logger.warning(f"QRadar entity activity enrichment failed for {ticket_id}: {e}")
            try:
                snow_context = snow_future.result() or {}
            except Exception as e:
                logger.warning(f"SNOW context enrichment failed for {ticket_id}: {e}")
            try:
                varonis_context = varonis_future.result() or {}
            except Exception as e:
                logger.warning(f"Varonis context enrichment failed for {ticket_id}: {e}")
            try:
                ad_context = ad_future.result() or {}
            except Exception as e:
                logger.warning(f"AD context enrichment failed for {ticket_id}: {e}")

        if source_details:
            enrichment["source_details"] = source_details
            src = source_details.get("source", "unknown")
            has_error = "error" in source_details
            logger.info(f"Source enrichment ({src}) {'failed' if has_error else 'succeeded'} for {ticket_id}")

        # Step 1.5: Quick sequential computations that feed into the LLM prompt

        # Fetch close notes for similar tickets (analyst rationale)
        similar_notes = {}
        if similar_prediction and similar_prediction.similar_tickets:
            sim_ids = [
                str(sim.get("metadata", {}).get("id", ""))
                for sim in similar_prediction.similar_tickets
                if sim.get("metadata", {}).get("id")
            ]
            similar_notes = self._fetch_similar_ticket_notes(sim_ids)

        # IOC cross-correlation — campaign detection
        iocs = enrichment.get("iocs_extracted", {})
        ioc_correlated = self._cross_correlate_iocs(iocs, ticket_id)

        # Time context
        time_context = self._compute_time_context(ticket.get("created", ""))

        # Evidence basis classification
        evidence_basis = self._classify_evidence_basis(
            enrichment, similar_prediction, asset_context,
            vectra_context=vectra_context,
            qradar_entity_activity=qradar_entity_activity,
            snow_context=snow_context,
            varonis_context=varonis_context,
            ad_context=ad_context,
        )

        # Step 2: LLM triage — full context from all enrichment sources.
        # The LLM can also call tools (SNOW/QRadar/Vectra/AD/Varonis/IOC lookups)
        # to dig deeper than the coarse baseline enrichment.
        llm_response, llm_tool_trace, llm_critique = _run_xsoar_llm_triage(
            ticket, enrichment, similar_prediction,
            similar_notes=similar_notes,
            asset_context=asset_context,
            time_context=time_context,
            ioc_correlated_tickets=ioc_correlated,
            evidence_basis=evidence_basis,
            vectra_context=vectra_context,
            qradar_entity_activity=qradar_entity_activity,
            snow_context=snow_context,
            varonis_context=varonis_context,
            ad_context=ad_context,
        )

        security_category = custom.get("securitycategory", "")
        severity = SEVERITY_MAP.get(ticket.get("severity", 0), "Unknown")

        # Build result
        result = XsoarTriageResult(
            ticket_id=ticket_id,
            ticket_name=ticket_name,
            ticket_type=ticket.get("type", ""),
            security_category=security_category,
            hostname=hostname,
            username=username,
            severity=severity,
            detection_source=custom.get("detectionsource", ""),
            ticket_timestamp=ticket.get("created", ""),
            ticket_status=str(ticket.get("status", "")),
            ticket_owner=ticket.get("owner", ""),
            enrichment=enrichment,
            similar_ticket_prediction=similar_prediction,
            asset_context=asset_context,
            vectra_context=vectra_context,
            qradar_entity_activity=qradar_entity_activity,
            snow_context=snow_context,
            varonis_context=varonis_context,
            ad_context=ad_context,
            time_context=time_context,
            evidence_basis=evidence_basis,
            ioc_correlated_tickets=ioc_correlated,
            raw_ticket=ticket,
        )

        result.llm_tool_calls = llm_tool_trace

        if llm_critique is not None:
            result.llm_critique_flagged = llm_critique.flagged
            result.llm_critique_alignment = llm_critique.evidence_alignment
            result.llm_critique_concerns = list(llm_critique.concerns)
            result.llm_critique_unused_pivots = list(llm_critique.unused_pivots)
            result.llm_critique_rationale = llm_critique.rationale

        if llm_response:
            result.llm_what_happened = llm_response.what_happened
            result.llm_why_concern = llm_response.why_is_this_a_concern
            result.llm_intent = llm_response.intent
            result.llm_outcome = llm_response.outcome
            result.llm_confidence = llm_response.confidence
            result.llm_summary = llm_response.summary
            result.llm_recommended_action = llm_response.recommended_action
            result.llm_recommended_action_detail = llm_response.recommended_action_detail
            result.llm_risk_factors = llm_response.risk_factors
            result.llm_mitigating_factors = llm_response.mitigating_factors
            result.llm_investigation_pivots = llm_response.investigation_pivots or []

            # Guardrail: deterministically derive verdict from intent+outcome,
            # overriding the LLM's own verdict field if it disagrees. This is
            # the source of truth for verdict classification — the LLM's verdict
            # is advisory, used only for logging divergence below.
            from src.components.xsoar_alert_triage.models import derive_verdict
            derived = derive_verdict(llm_response.intent, llm_response.outcome)
            if derived != llm_response.verdict:
                logger.info(
                    f"Verdict derivation override for {ticket_id}: "
                    f"LLM said '{llm_response.verdict}' but "
                    f"intent={llm_response.intent!r} + outcome={llm_response.outcome!r} "
                    f"→ '{derived}'"
                )
            result.llm_verdict = derived

            # For contained-malicious verdicts, force the action to 'investigate'
            # unless the LLM explicitly escalated (e.g. active campaign, repeat
            # targeting). Never auto-close a contained-malicious ticket.
            if derived == "true_positive_malicious_contained":
                if result.llm_recommended_action == "close_ticket":
                    logger.info(
                        f"Overriding recommended_action for {ticket_id}: "
                        f"'close_ticket' → 'investigate' "
                        f"(contained-malicious should never auto-close)"
                    )
                    result.llm_recommended_action = "investigate"
        else:
            logger.warning(f"Skipping card send for {ticket_id}: no AI verdict available")

        # Step 3: Verdict disagreement check (LLM vs similar ticket consensus)
        if llm_response:
            conflicts, conflict_detail = self._check_verdict_disagreement(
                llm_response.verdict, similar_prediction,
            )
            result.verdict_conflicts_history = conflicts
            result.verdict_conflict_detail = conflict_detail

        # Step 4: Repeat offender detection
        result.repeat_offender_count = self._get_repeat_offender_count(
            username=username, hostname=hostname, window_days=7,
        )

        # Step 5: Suggested close reason from similar ticket consensus
        if similar_prediction and similar_prediction.top_close_reasons:
            top_reason = max(similar_prediction.top_close_reasons, key=similar_prediction.top_close_reasons.get)
            top_count = similar_prediction.top_close_reasons[top_reason]
            if top_count / similar_prediction.sample_size >= 0.6:
                result.suggested_close_reason = top_reason

        # Step 6: Compute composite priority score (1-10)
        result.priority_score = self._compute_priority_score(result)

        # Step 6b: Tuning recommendation (is this rule historically noisy?)
        result.tuning_recommendation = self._compute_tuning_recommendation(
            ticket_name, similar_prediction,
        )

        # Step 7: Write AI triage to XSOAR ticket — long-form note + context JSON.
        # Done BEFORE the Webex post so the link in the brief points to a ticket
        # that already has the full note attached.
        if result.llm_verdict:
            self._write_triage_to_xsoar(result)

        # Only send the card if we have an AI verdict — no point without it
        if result.llm_verdict:
            card_message_id = self._send_triage_card(result)
            if card_message_id:
                result.card_message_id = card_message_id

        logger.info(
            f"XSOAR triage complete for {ticket_id}: verdict={result.llm_verdict}, "
            f"confidence={result.llm_confidence:.0%}, action={result.llm_recommended_action}, "
            f"priority={result.priority_score}"
        )
        return result

    @staticmethod
    def _get_similar_ticket_prediction(
        ticket: dict, k: int = 5, k_stats: int = 30,
    ) -> Optional[SimilarTicketPrediction]:
        """Find similar past tickets using multi-dimensional scoring and aggregate into a prediction.

        Uses vector similarity (narrative) from ChromaDB, then re-scores with structural
        dimensions (detection rule, IOC overlap, category/type, host/user) for composite ranking.

        Two queries are issued:
        - k (default 5): top display results with full fingerprint re-scoring
        - k_stats (default 30): wider pool for stats aggregation (close reasons,
          resolution hours, severity distribution) — no fingerprint re-scoring needed

        Args:
            ticket: Raw XSOAR ticket dict
            k: Number of similar tickets for display (fingerprint re-scored)
            k_stats: Number of similar tickets for stats aggregation

        Returns:
            SimilarTicketPrediction or None on failure / empty index
        """
        try:
            from src.components.xsoar_ticket_indexer import XsoarTicketIndexer, strip_ticket_id
            from src.components.xsoar_ticket_similarity import (
                compute_xsoar_similarity_breakdown,
                fingerprint_from_ticket,
            )

            name = strip_ticket_id(ticket.get("name", ""))
            ticket_type = ticket.get("type", "")
            details = (ticket.get("details", "") or "")[:300]

            query_text = " ".join(p for p in [name, details, ticket_type] if p)
            if not query_text.strip():
                return None

            indexer = XsoarTicketIndexer()

            # Wide query for stats aggregation (lightweight — no fingerprint re-scoring)
            stats_results = indexer.find_similar_tickets(query_text, k=k_stats)
            if not stats_results:
                return None

            # Display query: re-use top-k from stats_results, apply fingerprint re-scoring
            results = stats_results[:k]

            # Build query fingerprint for multi-dimensional scoring
            query_entities = None
            raw_details = (ticket.get("details", "") or "").strip()
            if raw_details:
                try:
                    from src.utils.entity_extractor import extract_entities
                    query_entities = extract_entities(raw_details, include_apt_database=False)
                except Exception:
                    pass
            query_fp = fingerprint_from_ticket(ticket, query_entities)

            # Fetch candidate fingerprints (only for display set)
            candidate_ids = [r["metadata"].get("id", "") for r in results]
            candidate_fps = {}
            try:
                candidate_fps = indexer.fingerprint_store.get_batch(candidate_ids)
            except Exception as e:
                logger.warning(f"Fingerprint fetch failed, using narrative-only: {e}")

            # Re-score display set with composite breakdown
            for r in results:
                cid = r["metadata"].get("id", "")
                narrative_score = r["similarity_score"]
                if cid in candidate_fps:
                    breakdown = compute_xsoar_similarity_breakdown(
                        query_fp, candidate_fps[cid], narrative_score,
                    )
                    r["similarity_score"] = breakdown.composite_score
                    r["narrative_similarity"] = narrative_score
                    r["similarity_breakdown"] = breakdown
                else:
                    r["narrative_similarity"] = narrative_score
                    r["similarity_breakdown"] = None

            # Re-sort display set by composite score
            results.sort(key=lambda x: x["similarity_score"], reverse=True)

            # Aggregate metadata from the wider stats pool
            resolution_hours_list = []
            severity_dist: dict = {}
            close_reasons: dict = {}
            closed_count = 0

            for r in stats_results:
                meta = r["metadata"]

                res_h = meta.get("resolution_hours", 0)
                if res_h and res_h > 0:
                    resolution_hours_list.append(res_h)

                sev = meta.get("severity", 0)
                severity_dist[sev] = severity_dist.get(sev, 0) + 1

                reason = meta.get("impact", "") or meta.get("close_reason", "")
                if reason:
                    close_reasons[reason] = close_reasons.get(reason, 0) + 1
                    closed_count += 1

            avg_resolution = (
                round(sum(resolution_hours_list) / len(resolution_hours_list), 1)
                if resolution_hours_list else None
            )
            sample_size = len(stats_results)
            closure_rate = round(closed_count / sample_size, 3) if sample_size > 0 else 0.0

            return SimilarTicketPrediction(
                sample_size=sample_size,
                avg_resolution_hours=avg_resolution,
                severity_distribution=severity_dist,
                closure_rate=closure_rate,
                top_close_reasons=close_reasons,
                similar_tickets=results,
            )

        except Exception as e:
            logger.warning(f"Similar ticket prediction failed (graceful degradation): {e}")
            return None

    @staticmethod
    def _fetch_similar_ticket_notes(ticket_ids: List[str]) -> Dict[str, dict]:
        """Fetch close_notes and user_notes from timeline DB for similar ticket IDs.

        Returns {ticket_id: {"close_notes": str, "user_notes": str, ...}}
        """
        if not ticket_ids:
            return {}
        try:
            from services.xsoar_timeline_db import get_connection

            placeholders = ",".join("?" * len(ticket_ids))
            with get_connection() as conn:
                rows = conn.execute(
                    f"SELECT id, close_notes, user_notes, close_reason, closing_user "
                    f"FROM xsoar_tickets WHERE id IN ({placeholders})",
                    ticket_ids,
                ).fetchall()
            return {str(row["id"]): dict(row) for row in rows}
        except Exception as e:
            logger.warning(f"Failed to fetch similar ticket notes: {e}")
            return {}

    @staticmethod
    def _enrich_asset_context(hostname: str) -> Dict[str, Any]:
        """Enrich with asset context from Tanium (OS, tags, EPP status, last seen)."""
        if not hostname:
            return {}
        try:
            from services.tanium import TaniumClient

            client = TaniumClient()
            computer = client.find_computer_by_name(hostname)
            if computer:
                return {
                    "name": computer.name,
                    "ip": computer.ip,
                    "os_platform": computer.os_platform,
                    "eid_status": computer.eid_status,
                    "last_seen": computer.eidLastSeen,
                    "source": computer.source,
                    "custom_tags": computer.custom_tags,
                    "has_epp": computer.has_epp_ring_tag(),
                }
        except Exception as e:
            logger.warning(f"Asset context enrichment failed for {hostname}: {e}")
        return {}

    @staticmethod
    def _cross_correlate_iocs(
        iocs: dict, current_ticket_id: str, window_hours: int = 24,
    ) -> List[dict]:
        """Find other recent tickets sharing the same IOCs (campaign detection).

        Queries the timeline DB for tickets in the last window_hours that contain
        any of the same IPs, hashes, or domains in their details/name fields.
        """
        if not iocs:
            return []

        # Collect searchable IOC values
        search_values = []
        for h in iocs.get("sha256", [])[:5]:
            search_values.append(h)
        for h in iocs.get("md5", [])[:5]:
            search_values.append(h)
        for ip in iocs.get("ips", [])[:5]:
            search_values.append(ip)
        for d in iocs.get("domains", [])[:3]:
            search_values.append(d)

        if not search_values:
            return []

        try:
            from datetime import datetime, timedelta, timezone
            from services.xsoar_timeline_db import get_connection

            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=window_hours)
            ).strftime("%Y-%m-%dT%H:%M:%S")

            # Build OR conditions for each IOC value
            conditions = []
            params: list = [cutoff, str(current_ticket_id)]
            for value in search_values:
                conditions.append("(details LIKE ? OR name LIKE ?)")
                pattern = f"%{value}%"
                params.extend([pattern, pattern])

            where = " OR ".join(conditions)

            with get_connection() as conn:
                rows = conn.execute(
                    f"SELECT id, name, type, severity, hostname, username, "
                    f"created_date, status "
                    f"FROM xsoar_tickets "
                    f"WHERE created_date >= ? AND id != ? AND ({where}) "
                    f"ORDER BY created_date DESC LIMIT 10",
                    params,
                ).fetchall()

            results = [dict(row) for row in rows]
            if results:
                logger.info(
                    f"IOC cross-correlation found {len(results)} related tickets "
                    f"for {current_ticket_id}"
                )
            return results

        except Exception as e:
            logger.warning(f"IOC cross-correlation failed: {e}")
            return []

    @staticmethod
    def _compute_time_context(ticket_timestamp: str) -> str:
        """Compute time-of-day context for the alert (business hours, weekend, etc.)."""
        if not ticket_timestamp:
            return ""
        try:
            from datetime import datetime as _dt
            from pytz import timezone as _tz

            raw = str(ticket_timestamp)[:19]
            dt = _dt.strptime(raw, "%Y-%m-%d %H:%M:%S")
            utc = _tz("UTC").localize(dt)
            et = utc.astimezone(_tz("US/Eastern"))

            hour = et.hour
            day_name = et.strftime("%A")
            time_str = et.strftime("%I:%M %p ET")
            is_weekend = et.weekday() >= 5

            if is_weekend:
                return f"Weekend activity ({day_name} {time_str})"
            elif hour < 6 or hour >= 21:
                return f"Outside business hours ({time_str}, {day_name})"
            elif 6 <= hour < 8:
                return f"Early morning ({time_str}, {day_name})"
            elif 18 <= hour < 21:
                return f"After hours ({time_str}, {day_name})"
            else:
                return f"Business hours ({time_str}, {day_name})"
        except Exception:
            return ""

    @staticmethod
    def _classify_evidence_basis(
        enrichment: dict,
        similar_prediction: Optional[SimilarTicketPrediction],
        asset_context: dict,
        vectra_context: Optional[dict] = None,
        qradar_entity_activity: Optional[dict] = None,
        snow_context: Optional[dict] = None,
        varonis_context: Optional[dict] = None,
        ad_context: Optional[dict] = None,
    ) -> str:
        """Classify what evidence the verdict is grounded in.

        Returns a human-readable string like:
          "IOC enrichment hits (VT) + QRadar alert + 5 similar tickets (all benign)"
          "Description-only (no IOC enrichment, no source alert, no similar tickets)"
        """
        parts = []

        # Check IOC enrichment results
        vt = enrichment.get("virustotal", {})
        abuse = enrichment.get("abuseipdb", {})
        rf = enrichment.get("recorded_future", {})

        has_vt_hits = False
        if vt and "error" not in vt:
            for data in vt.get("hashes", {}).values():
                if data.get("malicious", 0) > 0:
                    has_vt_hits = True
            for data in {**vt.get("ips", {}), **vt.get("domains", {})}.values():
                if data.get("malicious", 0) > 0:
                    has_vt_hits = True

        has_abuse_hits = False
        if abuse and "error" not in abuse:
            for data in abuse.values():
                if data.get("abuse_confidence_score", 0) > 0:
                    has_abuse_hits = True

        has_rf_hits = False
        if rf and "error" not in rf:
            for data in rf.values():
                if isinstance(data, dict) and data.get("risk_score", 0) > 25:
                    has_rf_hits = True

        hit_sources = []
        if has_vt_hits:
            hit_sources.append("VT")
        if has_abuse_hits:
            hit_sources.append("AbuseIPDB")
        if has_rf_hits:
            hit_sources.append("RF")

        if hit_sources:
            parts.append(f"IOC enrichment hits ({', '.join(hit_sources)})")
        else:
            iocs = enrichment.get("iocs_extracted", {})
            has_iocs = any(iocs.get(k) for k in ("sha256", "md5", "ips", "domains"))
            if has_iocs:
                parts.append("IOCs extracted (all clean)")

        # Source platform alert
        source = enrichment.get("source_details")
        if source and "error" not in source:
            src_name = source.get("source", "source platform")
            parts.append(f"{src_name} alert details")

        # Similar tickets
        if similar_prediction and similar_prediction.sample_size > 0:
            n = similar_prediction.sample_size
            reasons = similar_prediction.top_close_reasons
            if reasons:
                top = max(reasons, key=reasons.get)
                pct = reasons[top] / n
                if pct >= 0.6:
                    parts.append(f"{n} similar tickets ({reasons[top]}/{n} {top})")
                else:
                    parts.append(f"{n} similar tickets (mixed outcomes)")
            else:
                parts.append(f"{n} similar tickets")

        # Asset context
        if asset_context:
            parts.append("asset context")

        # Vectra NDR context
        if vectra_context and "error" not in vectra_context:
            host_ent = vectra_context.get("host_entity") or {}
            acct_ent = vectra_context.get("account_entity") or {}
            threat = max(host_ent.get("threat", 0), acct_ent.get("threat", 0))
            det_count = host_ent.get("detection_count", 0) + acct_ent.get("detection_count", 0)
            if threat > 0 or det_count > 0:
                parts.append(f"Vectra NDR (threat={threat}, detections={det_count})")
            else:
                parts.append("Vectra NDR (no detections)")

        # SNOW context
        if snow_context and "error" not in snow_context:
            n_changes = snow_context.get("change_count", len(snow_context.get("changes", [])))
            n_incidents = snow_context.get("incident_count", len(snow_context.get("incidents", [])))
            if n_changes > 0:
                parts.append(f"SNOW ({n_changes} change ticket{'s' if n_changes != 1 else ''})")
            elif n_incidents > 0:
                parts.append(f"SNOW ({n_incidents} incident{'s' if n_incidents != 1 else ''})")
            else:
                parts.append("SNOW (no changes or incidents)")

        # QRadar entity activity
        if qradar_entity_activity and "error" not in qradar_entity_activity:
            n_events = qradar_entity_activity.get("event_count", 0)
            hours = qradar_entity_activity.get("hours", 4)
            if n_events > 0:
                parts.append(f"QRadar activity ({n_events} events, {hours}h window)")
            else:
                parts.append(f"QRadar activity (no events in {hours}h window)")

        # Varonis context
        if varonis_context and "error" not in varonis_context:
            has_alerts = bool(varonis_context.get("user_alerts"))
            has_activity = bool(varonis_context.get("data_activity"))
            if has_alerts or has_activity:
                parts.append(f"Varonis ({'alerts' if has_alerts else ''}{'+'if has_alerts and has_activity else ''}{'activity' if has_activity else ''})")
            else:
                parts.append("Varonis (no alerts or activity)")

        # AD context
        if ad_context and "error" not in ad_context:
            items = [k for k in ("user", "computer") if ad_context.get(k)]
            if items:
                parts.append(f"AD ({', '.join(items)})")
            else:
                parts.append("AD (no records found)")

        if not parts:
            return (
                "Description-only — no IOC enrichment, no source alert, "
                "no similar tickets. Verdict has low evidence support."
            )

        return " + ".join(parts)

    @staticmethod
    def _check_verdict_disagreement(
        llm_verdict: str,
        similar_prediction: Optional[SimilarTicketPrediction],
    ) -> tuple:
        """Check if LLM verdict conflicts with similar ticket consensus.

        Returns (conflicts: bool, detail: str).
        """
        if not similar_prediction or similar_prediction.sample_size < 3:
            return False, ""

        reasons = similar_prediction.top_close_reasons
        total = similar_prediction.sample_size
        if not reasons:
            return False, ""

        # Count benign-ish close reasons
        benign_keywords = {
            "ignore", "false positive", "resolved - fp", "resolved",
            "duplicate", "benign true positive",
        }
        benign_count = sum(
            v for k, v in reasons.items() if k.lower() in benign_keywords
        )

        # Count malicious close reasons (exclude "benign true positive")
        malicious_count = sum(
            v for k, v in reasons.items()
            if "benign" not in k.lower()
            and any(m in k.lower() for m in ("confirmed", "true positive", "malicious"))
        )

        # Treat both fully-malicious and contained-malicious as "malicious"
        # for disagreement purposes — both represent adversarial intent
        is_malicious_verdict = llm_verdict in (
            "true_positive_malicious", "true_positive_malicious_contained",
        )

        if is_malicious_verdict and benign_count / total >= 0.6:
            return True, (
                f"AI says Malicious but {benign_count}/{total} similar tickets "
                f"were closed as benign/FP. Review enrichment for new evidence "
                f"that differentiates this alert. (Note: prior closures may have "
                f"conflated 'blocked attack' with 'benign' — re-evaluate intent.)"
            )

        if (
            llm_verdict in ("false_positive", "true_positive_benign")
            and malicious_count / total >= 0.6
        ):
            return True, (
                f"AI says Benign/FP but {malicious_count}/{total} similar tickets "
                f"were confirmed malicious. Investigate carefully — this pattern "
                f"was previously escalated."
            )

        return False, ""

    @staticmethod
    def _compute_tuning_recommendation(
        ticket_name: str,
        similar_prediction: Optional[SimilarTicketPrediction] = None,
    ) -> str:
        """Check if this alert's rule/pattern is historically noisy.

        Uses the similar ticket prediction from ChromaDB semantic search.
        If 75%+ of similar tickets were closed as non-actionable, recommends tuning.

        Returns a recommendation string, or "" if no recommendation.
        """
        if not similar_prediction or similar_prediction.sample_size < 5:
            return ""

        try:
            reasons = similar_prediction.top_close_reasons or {}
            total = similar_prediction.sample_size
            noise = sum(
                v for k, v in reasons.items()
                if k.lower() in (
                    "ignore", "false positive", "duplicate",
                    "resolved", "benign true positive",
                )
            )
            noise_pct = noise / total
            # Build breakdown from actual close reasons (e.g. "5 Benign True Positive, 1 Ignore")
            noise_reasons = {
                k: v for k, v in reasons.items()
                if k.lower() in (
                    "ignore", "false positive", "duplicate",
                    "resolved", "benign true positive",
                )
            }
            breakdown = ", ".join(
                f"{v} {k}" for k, v in sorted(noise_reasons.items(), key=lambda x: -x[1])
            )
            if noise_pct >= 0.9:
                return (
                    f"This alert pattern has produced {total} similar alerts historically, "
                    f"{noise}/{total} ({noise_pct:.0%}) closed as {breakdown}. "
                    f"Strong candidate for tuning or disabling."
                )
            elif noise_pct >= 0.75:
                return (
                    f"This alert pattern has produced {total} similar alerts historically, "
                    f"{noise}/{total} ({noise_pct:.0%}) closed as {breakdown}. "
                    f"Consider tuning the rule to reduce noise."
                )
            return ""

        except Exception as e:
            logger.debug(f"Tuning recommendation failed: {e}")
            return ""

    @staticmethod
    def _write_triage_to_xsoar(result: XsoarTriageResult) -> None:
        """Write the AI triage result to the XSOAR ticket — note + context JSON.

        Two writes happen here, both best-effort:

        1. **Long-form note** (human-visible): the full triage rendered as
           markdown via build_xsoar_triage_note() is posted as a war room
           entry via /xsoar/entry/note. This is the analyst's investigation
           starting point — they see it inline when working the ticket.
           build_xsoar_triage_note() is a superset of the Webex markdown:
           it includes everything Webex shows, plus additional enrichment
           sections (smoking-gun facts, and as more is added — baselines,
           process-tree correlation, host context, investigation pivots,
           etc.) that don't fit within the Webex character budget.

        2. **Context JSON** (machine-readable): a structured JSON blob is
           written under the key "SentinelTriage" via !Set. Used downstream
           for comparing AI verdict against analyst verdict (accuracy
           analytics) — not surfaced to analysts directly.

        Both writes are wrapped independently so a failure in one doesn't
        block the other. Neither failure blocks the pipeline.
        """
        try:
            from services.xsoar.ticket_handler import TicketHandler
            handler = TicketHandler()
        except Exception as e:
            logger.warning(f"Failed to init XSOAR handler for ticket {result.ticket_id}: {e}")
            return

        # ---- Write 1: Long-form note (human-visible war room entry) ----
        try:
            from webex_bots.cards.sentinel_cards import build_xsoar_triage_note
            from services.xsoar._entries import create_new_entry_in_existing_ticket

            note_md = build_xsoar_triage_note(result)
            create_new_entry_in_existing_ticket(
                client=handler.client,
                incident_id=str(result.ticket_id),
                entry_data=note_md,
                markdown=True,
            )
            logger.info(f"AI triage note posted to XSOAR ticket {result.ticket_id}")
        except Exception as e:
            logger.warning(f"Failed to post triage note to XSOAR ticket {result.ticket_id}: {e}")

        # ---- Write 2: Context JSON (analytics) ----
        try:
            import json
            from datetime import datetime, timezone

            similar = result.similar_ticket_prediction
            triage_data = {
                # v2: intent + outcome split from verdict.
                # v3: Reflector critique fields. critique_alignment == ""
                # means the critic did not run (flag off or router LLM
                # unavailable); "aligned"/"partial"/"contradicted" otherwise.
                "version": 3,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "verdict": result.llm_verdict,
                "intent": result.llm_intent,
                "outcome": result.llm_outcome,
                "confidence": round(result.llm_confidence, 3),
                "priority_score": result.priority_score,
                "recommended_action": result.llm_recommended_action,
                "what_happened": result.llm_what_happened,
                "why_concern": result.llm_why_concern,
                "summary": result.llm_summary,
                "recommended_action_detail": result.llm_recommended_action_detail,
                "risk_factors": result.llm_risk_factors,
                "mitigating_factors": result.llm_mitigating_factors,
                "investigation_pivots": result.llm_investigation_pivots,
                "critique_flagged": result.llm_critique_flagged,
                "critique_alignment": result.llm_critique_alignment,
                "critique_concerns": result.llm_critique_concerns,
                "critique_unused_pivots": result.llm_critique_unused_pivots,
                "critique_rationale": result.llm_critique_rationale,
                "evidence_basis": result.evidence_basis,
                "time_context": result.time_context,
                "verdict_conflicts_history": result.verdict_conflicts_history,
                "verdict_conflict_detail": result.verdict_conflict_detail,
                "repeat_offender_count": result.repeat_offender_count,
                "suggested_close_reason": result.suggested_close_reason,
                "tuning_recommendation": result.tuning_recommendation,
                "similar_tickets": {
                    "sample_size": similar.sample_size if similar else 0,
                    "avg_resolution_hours": similar.avg_resolution_hours if similar else None,
                    "closure_rate": similar.closure_rate if similar else 0,
                    "top_close_reasons": similar.top_close_reasons if similar else {},
                },
                "ioc_correlated_ticket_count": len(result.ioc_correlated_tickets),
                "asset_context": result.asset_context or {},
                "enrichment_summary": {
                    k: ("present" if v and "error" not in v else "error" if v else "absent")
                    for k, v in (result.enrichment or {}).items()
                    if k != "iocs_extracted"
                },
            }

            triage_json = json.dumps(triage_data)
            handler.client.generic_request(
                path="/entry/execute/sync",
                method="POST",
                body={
                    "investigationId": result.ticket_id,
                    "data": "!Set",
                    "args": {
                        "key": {"simple": "SentinelTriage"},
                        "value": {"simple": triage_json},
                    },
                },
            )
            logger.info(f"AI triage context written to XSOAR ticket {result.ticket_id}")

        except Exception as e:
            logger.warning(f"Failed to write triage context to XSOAR ticket {result.ticket_id}: {e}")

    def _send_triage_card(self, result: XsoarTriageResult) -> str:
        """Send triage as two messages: markdown details + action button card reply.

        The markdown message is filled to roughly Webex's character limit — we
        show as much as fits. Any additional enrichment that doesn't fit lives
        in the XSOAR ticket war room note instead (see _write_triage_to_xsoar).

        Returns the markdown message ID (the parent message).
        """
        if not self.webex_api or not self.room_id:
            logger.debug("Webex API or room_id not configured, skipping card send")
            return ""

        try:
            from webex_bots.cards.sentinel_cards import (
                build_xsoar_triage_markdown,
                build_xsoar_triage_card,
            )

            # Message 1: Markdown with all triage details
            markdown_text = build_xsoar_triage_markdown(result)
            detail_msg = self.webex_api.messages.create(
                roomId=self.room_id,
                markdown=markdown_text,
            )
            logger.info(f"XSOAR triage details sent for {result.ticket_id}, message_id={detail_msg.id}")

            # Message 2: Adaptive card with action buttons (threaded reply)
            card = build_xsoar_triage_card(result)
            self.webex_api.messages.create(
                roomId=self.room_id,
                parentId=detail_msg.id,
                text=f"Actions for XSOAR #{result.ticket_id}",
                attachments=[{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }],
            )

            return detail_msg.id

        except Exception as e:
            logger.error(f"Failed to send XSOAR triage for {result.ticket_id}: {e}")
            return ""

    @staticmethod
    def _get_repeat_offender_count(username: str, hostname: str, window_days: int = 7) -> int:
        """Count recent tickets involving the same user or host."""
        if not username and not hostname:
            return 0
        try:
            from datetime import datetime, timedelta, timezone
            from services.xsoar_timeline_db import get_connection

            cutoff = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%S")
            clauses, params = [], [cutoff]
            if username:
                clauses.append("LOWER(username) = LOWER(?)")
                params.append(username)
            if hostname:
                clauses.append("LOWER(hostname) = LOWER(?)")
                params.append(hostname)
            where = " OR ".join(clauses)

            with get_connection() as conn:
                row = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM xsoar_tickets"
                    f" WHERE created_date >= ? AND ({where})",
                    params,
                ).fetchone()
                return row["cnt"] if row else 0
        except Exception as e:
            logger.warning(f"Repeat offender check failed: {e}")
            return 0

    @staticmethod
    def _compute_priority_score(result: XsoarTriageResult) -> int:
        """Compute a 1-10 priority score combining multiple signals.

        Higher = more urgent. Factors:
        - Severity (Critical=4, High=3, Medium=2, Low=1)
        - LLM verdict (malicious=3, benign=1, FP=0)
        - LLM confidence (scales verdict weight)
        - Enrichment hits (VT, AbuseIPDB)
        - Repeat offender
        - Similar ticket consensus (all-ignored lowers score)
        """
        score = 0.0

        # Severity: 0-4 points
        sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 1, "Info": 0}
        score += sev_map.get(result.severity, 1)

        # LLM verdict * confidence: 0-3 points
        # contained-malicious gets weight 2 (not 3) — real threat but blast
        # radius is limited, so it's still lower urgency than a successful attack
        verdict_weight = {
            "true_positive_malicious": 3,
            "true_positive_malicious_contained": 2,
            "true_positive_benign": 1,
            "false_positive": 0,
        }
        vw = verdict_weight.get(result.llm_verdict, 1)
        score += vw * (result.llm_confidence or 0.5)

        # Enrichment hits: 0-2 points
        enrichment = result.enrichment or {}
        vt = enrichment.get("virustotal", {})
        if vt and "error" not in vt:
            for data in vt.get("hashes", {}).values():
                if data.get("malicious", 0) > 5:
                    score += 1.5
                    break
            for data in {**vt.get("ips", {}), **vt.get("domains", {})}.values():
                if data.get("malicious", 0) > 3:
                    score += 0.5
                    break
        abuse = enrichment.get("abuseipdb", {})
        if abuse and "error" not in abuse:
            for data in abuse.values():
                if data.get("abuse_confidence_score", 0) > 50:
                    score += 1
                    break

        # Repeat offender: 0-1 point
        if result.repeat_offender_count > 3:
            score += 1

        # Similar ticket consensus lowers score if all were ignored/FP
        prediction = result.similar_ticket_prediction
        if prediction and prediction.sample_size >= 3:
            ignore_count = prediction.top_close_reasons.get("Ignore", 0) + prediction.top_close_reasons.get("False Positive", 0)
            if ignore_count / prediction.sample_size >= 0.8:
                score -= 1

        return max(1, min(10, round(score)))
