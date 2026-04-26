"""
control-efficacy analytics Mappings — Classification rules for deriving security categories,
root causes, technology owners, and dispositions from XSOAR ticket data.

The cached ticket data has `type` (Detection Source) and `impact` fields but no
explicit "Security Category" or "Root Cause" fields. This module derives them
using keyword/pattern matching on the `type` and `name` fields.
"""

import re
from typing import Dict, Any

# ---------------------------------------------------------------------------
# 1. Security Category — derived from ticket type + name overrides
# ---------------------------------------------------------------------------

TYPE_TO_CATEGORY: Dict[str, str] = {
    "CrowdStrike Falcon Detection": "Endpoint Security",
    "CrowdStrike Falcon Incident": "Endpoint Security",
    "Qradar Alert": "SIEM / Network Security",
    "Splunk Alert": "SIEM / Network Security",
    "Vectra Detection": "Network Detection",
    "Akamai Alert": "Web Application Security",
    "Prisma Cloud Compute Runtime Alert": "Cloud Security",
    "UEBA Prisma Cloud": "Cloud Security",
    "DSPM Risk Findings": "Data Security",
    "Varonis Alert": "Data Security",
    "Employee Reported Incident": "User Reported",
    "Lost or Stolen Computer": "Physical Security",
    "Leaked Credentials": "Identity / Access Management",
    "Third Party Compromise": "Third Party Risk",
    "Area1 Alert": "Email Security",
    "IOC Hunt": "Threat Intelligence",
    "SDM Escalation": "Service Escalation",
    "Case": "General Investigation",
}

# Regex patterns applied to the ticket `name` field to override the type-based
# default. Order matters — first match wins.
_NAME_CATEGORY_OVERRIDES = [
    (re.compile(r"phish", re.IGNORECASE), "Email Security"),
    (re.compile(r"Access\s*Pass", re.IGNORECASE), "Identity / Access Management"),
    (re.compile(r"credential|password|brute.?force|login.?fail", re.IGNORECASE), "Identity / Access Management"),
    (re.compile(r"malware|ransomware|trojan|worm", re.IGNORECASE), "Malware"),
    (re.compile(r"DLP|data.?loss|exfiltrat", re.IGNORECASE), "Data Security"),
    (re.compile(r"insider", re.IGNORECASE), "Insider Threat"),
    (re.compile(r"(vulnerability|CVE-\d)", re.IGNORECASE), "Vulnerability Management"),
]

# ---------------------------------------------------------------------------
# 2. Root Cause — derived from security category + name overrides
# ---------------------------------------------------------------------------

CATEGORY_TO_ROOT_CAUSE: Dict[str, str] = {
    "Endpoint Security": "Endpoint Misconfiguration",
    "SIEM / Network Security": "Policy Violation",
    "Network Detection": "Anomalous Network Activity",
    "Web Application Security": "Web Attack",
    "Cloud Security": "Cloud Misconfiguration",
    "Data Security": "Unauthorized Data Access",
    "User Reported": "Human Error",
    "Physical Security": "Physical Loss",
    "Identity / Access Management": "Credential Compromise",
    "Third Party Risk": "Third Party Vulnerability",
    "Email Security": "Social Engineering",
    "Threat Intelligence": "Known Threat Actor",
    "Service Escalation": "Process Gap",
    "Malware": "Malware Infection",
    "Insider Threat": "Insider Threat",
    "Vulnerability Management": "Unpatched Vulnerability",
    "General Investigation": "Unknown",
}

_NAME_ROOT_CAUSE_OVERRIDES = [
    (re.compile(r"phish", re.IGNORECASE), "Social Engineering"),
    (re.compile(r"brute.?force", re.IGNORECASE), "Credential Compromise"),
    (re.compile(r"misconfig", re.IGNORECASE), "Misconfiguration"),
    (re.compile(r"(vulnerability|CVE-\d)", re.IGNORECASE), "Unpatched Vulnerability"),
]

# ---------------------------------------------------------------------------
# 3. Technology Owner — direct mapping from ticket type
# ---------------------------------------------------------------------------

TYPE_TO_OWNER: Dict[str, str] = {
    "CrowdStrike Falcon Detection": "Endpoint Team",
    "CrowdStrike Falcon Incident": "Endpoint Team",
    "Qradar Alert": "SIEM Team",
    "Splunk Alert": "SIEM Team",
    "Vectra Detection": "NDR Team",
    "Akamai Alert": "Web Security Team",
    "Prisma Cloud Compute Runtime Alert": "Cloud Security Team",
    "UEBA Prisma Cloud": "Cloud Security Team",
    "DSPM Risk Findings": "Cloud Security Team",
    "Varonis Alert": "Data Security Team",
    "Employee Reported Incident": "SOC",
    "Lost or Stolen Computer": "SOC",
    "Leaked Credentials": "Identity Team",
    "Third Party Compromise": "Third Party Risk Team",
    "Area1 Alert": "Email Security Team",
    "IOC Hunt": "Threat Intel Team",
    "SDM Escalation": "Service Desk",
    "Case": "SOC",
}

# ---------------------------------------------------------------------------
# 4. Disposition — derived from impact field
# ---------------------------------------------------------------------------

IMPACT_TO_DISPOSITION: Dict[str, str] = {
    "Benign True Positive": "Blocked by Controls",
    "False Positive": "Blocked by Controls",
    "Malicious True Positive": "Escalated to Human",
    "Security Testing": "Other",
    "Automated": "Other",
    "": "Other",
}

# ---------------------------------------------------------------------------
# 5. Remediation Suggestions — keyed by (category, root_cause)
# ---------------------------------------------------------------------------

REMEDIATION_SUGGESTIONS: Dict[tuple, Dict[str, str]] = {
    ("Endpoint Security", "Endpoint Misconfiguration"): {
        "action": "Review and enforce endpoint hardening baselines via CrowdStrike prevention policies",
        "priority": "High",
    },
    ("Endpoint Security", "Malware Infection"): {
        "action": "Validate CrowdStrike sensor coverage and enable aggressive prevention mode",
        "priority": "Critical",
    },
    ("SIEM / Network Security", "Policy Violation"): {
        "action": "Review and update SIEM correlation rules; validate policy enforcement controls",
        "priority": "Medium",
    },
    ("Network Detection", "Anomalous Network Activity"): {
        "action": "Tune Vectra detection models and verify network segmentation controls",
        "priority": "Medium",
    },
    ("Web Application Security", "Web Attack"): {
        "action": "Review Akamai WAF rules and conduct application vulnerability assessment",
        "priority": "High",
    },
    ("Cloud Security", "Cloud Misconfiguration"): {
        "action": "Run Prisma Cloud compliance scan and remediate critical misconfigurations",
        "priority": "High",
    },
    ("Data Security", "Unauthorized Data Access"): {
        "action": "Review Varonis data access policies and enforce least-privilege permissions",
        "priority": "High",
    },
    ("User Reported", "Human Error"): {
        "action": "Schedule targeted security awareness training for affected business units",
        "priority": "Medium",
    },
    ("Physical Security", "Physical Loss"): {
        "action": "Enforce disk encryption verification and remote wipe readiness",
        "priority": "Medium",
    },
    ("Identity / Access Management", "Credential Compromise"): {
        "action": "Enforce MFA, rotate affected credentials, review conditional access policies",
        "priority": "Critical",
    },
    ("Third Party Risk", "Third Party Vulnerability"): {
        "action": "Notify vendor risk management; assess exposure and apply compensating controls",
        "priority": "High",
    },
    ("Email Security", "Social Engineering"): {
        "action": "Launch phishing simulation campaign and update email gateway rules",
        "priority": "High",
    },
    ("Threat Intelligence", "Known Threat Actor"): {
        "action": "Update IOC blocklists and validate detection coverage for known TTPs",
        "priority": "Critical",
    },
    ("Service Escalation", "Process Gap"): {
        "action": "Review escalation workflows and update runbooks",
        "priority": "Low",
    },
    ("Malware", "Malware Infection"): {
        "action": "Isolate affected hosts, run forensic analysis, update AV/EDR signatures",
        "priority": "Critical",
    },
    ("Insider Threat", "Insider Threat"): {
        "action": "Engage insider threat program; review DLP and UEBA alerts for affected users",
        "priority": "Critical",
    },
    ("Vulnerability Management", "Unpatched Vulnerability"): {
        "action": "Prioritize patching per CVSS score; apply virtual patching where immediate fix unavailable",
        "priority": "High",
    },
}

# Fallback for (category, root_cause) pairs not explicitly listed
_DEFAULT_REMEDIATION = {
    "action": "Investigate and document findings; escalate to appropriate team",
    "priority": "Medium",
}

# Priority ordering for sorting
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ---------------------------------------------------------------------------
# 6. Attack Vector — derived from security category
# ---------------------------------------------------------------------------

CATEGORY_TO_ATTACK_VECTOR: Dict[str, str] = {
    "Email Security":                 "Email",
    "SIEM / Network Security":        "Network",
    "Network Detection":              "Network",
    "Web Application Security":       "Network",
    "Cloud Security":                 "Cloud / SaaS",
    "Data Security":                  "Data",
    "Endpoint Security":              "Endpoint",
    "Identity / Access Management":   "Identity",
    "User Reported":                  "Email",      # most user-reported = phishing
    "Physical Security":              "Physical",
    "Third Party Risk":               "Third Party",
    "Malware":                        "Endpoint",
    "Insider Threat":                 "Identity",
    "Vulnerability Management":       "Endpoint",
    "Threat Intelligence":            "Threat Intel",
    "Service Escalation":             "Other",
    "General Investigation":          "Other",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_ticket(ticket: Dict[str, Any]) -> Dict[str, Any]:
    """Add derived fields to a ticket dict (mutates in-place and returns it).

    Added fields: security_category, root_cause, technology_owner, disposition.
    """
    ticket_type = ticket.get("type", "")
    name = ticket.get("name", "")
    impact = ticket.get("impact", "")

    # --- security_category ---
    category = TYPE_TO_CATEGORY.get(ticket_type, "Other")
    for pattern, override_cat in _NAME_CATEGORY_OVERRIDES:
        if pattern.search(name):
            category = override_cat
            break
    ticket["security_category"] = category

    # --- root_cause ---
    root_cause = CATEGORY_TO_ROOT_CAUSE.get(category, "Unknown")
    for pattern, override_rc in _NAME_ROOT_CAUSE_OVERRIDES:
        if pattern.search(name):
            root_cause = override_rc
            break
    ticket["root_cause"] = root_cause

    # --- technology_owner ---
    ticket["technology_owner"] = TYPE_TO_OWNER.get(ticket_type, "SOC")

    # --- disposition ---
    ticket["disposition"] = IMPACT_TO_DISPOSITION.get(impact, "Other")

    # --- attack_vector ---
    ticket["attack_vector"] = CATEGORY_TO_ATTACK_VECTOR.get(category, "Other")

    return ticket


def get_remediation(category: str, root_cause: str) -> Dict[str, str]:
    """Return remediation suggestion for a (category, root_cause) pair."""
    return REMEDIATION_SUGGESTIONS.get((category, root_cause), _DEFAULT_REMEDIATION)


def priority_sort_key(priority: str) -> int:
    """Return numeric sort key for priority string (lower = more urgent)."""
    return PRIORITY_ORDER.get(priority, 99)
