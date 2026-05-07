"""Power BI demo mode — realistic mock data for when the API key isn't configured yet.

Provides a DemoClient with the same interface as PowerBIClient so the chat
handler works identically. Data models a Global Endpoint Compliance dataset
typical of an ASM / SecOps team.
"""

import random
import re
from datetime import datetime, timedelta

# ── Demo datasets ──

DEMO_DATASETS = [
    {"id": "demo-endpoint-compliance", "name": "Global Endpoint Compliance", "configuredBy": "pbi-engineer@the-company.com"},
    {"id": "demo-vuln-management", "name": "Vulnerability Management", "configuredBy": "pbi-engineer@the-company.com"},
    {"id": "demo-security-incidents", "name": "Security Incidents 2026", "configuredBy": "pbi-engineer@the-company.com"},
]

# ── Schemas ──

DEMO_SCHEMAS = {
    "demo-endpoint-compliance": """\
Table: Endpoints
  - HostName (String)
  - Region (String) — AMER, EMEA, APAC, LATAM
  - Country (String)
  - EndpointType (String) — Server, Workstation, Virtual Desktop
  - OS (String) — Windows Server 2019, Windows Server 2022, Windows 10, Windows 11, RHEL 8, RHEL 9, Ubuntu 22.04, macOS 14
  - BusinessUnit (String) — Corporate Technology, Global Operations, Investments, Insurance Products, Claims, Human Resources, Finance, Legal
  - PatchStatus (String) — Compliant, Non-Compliant, Pending Reboot, Excluded
  - LastPatchDate (DateTime)
  - DaysSinceLastPatch (Integer)
  - CrowdStrikeInstalled (Boolean)
  - CrowdStrikeVersion (String)
  - TaniumManaged (Boolean)
  - LastSeenDate (DateTime)
  - IsOnline (Boolean)
  - CriticalPatchesMissing (Integer)
  - HighPatchesMissing (Integer)

Table: PatchCycles
  - PatchCycleID (String)
  - ReleaseDate (DateTime)
  - Deadline (DateTime)
  - Title (String)
  - AffectedEndpoints (Integer)
  - CompletedEndpoints (Integer)
  - CompliancePercent (Decimal)

Table: RegionSummary
  - Region (String)
  - TotalEndpoints (Integer)
  - CompliantCount (Integer)
  - NonCompliantCount (Integer)
  - PendingRebootCount (Integer)
  - ComplianceRate (Decimal)
  - CrowdStrikeCoverage (Decimal)
  - TaniumCoverage (Decimal)""",

    "demo-vuln-management": """\
Table: Vulnerabilities
  - CVEID (String)
  - Title (String)
  - Severity (String) — Critical, High, Medium, Low
  - CVSSScore (Decimal)
  - PublishedDate (DateTime)
  - Status (String) — Open, Remediated, Mitigated, Accepted Risk, In Progress
  - AffectedHosts (Integer)
  - RemediatedHosts (Integer)
  - SLADeadline (DateTime)
  - SLABreached (Boolean)
  - Vendor (String)
  - Product (String)
  - ExploitAvailable (Boolean)
  - InCISAKEV (Boolean)

Table: HostVulnerabilities
  - HostName (String)
  - CVEID (String)
  - DetectedDate (DateTime)
  - RemediatedDate (DateTime)
  - Region (String)
  - OS (String)
  - EndpointType (String)

Table: SLAPerformance
  - Month (String)
  - Severity (String)
  - TotalVulns (Integer)
  - WithinSLA (Integer)
  - BreachedSLA (Integer)
  - SLAComplianceRate (Decimal)""",

    "demo-security-incidents": """\
Table: Incidents
  - IncidentID (String)
  - Title (String)
  - Severity (String) — Critical, High, Medium, Low
  - Status (String) — New, Investigating, Contained, Remediated, Closed
  - CreatedDate (DateTime)
  - ClosedDate (DateTime)
  - MTTR_Hours (Decimal)
  - AssignedTeam (String) — SOC Tier 1, SOC Tier 2, Incident Response, Threat Intel, Automation Engineering
  - Source (String) — CrowdStrike, QRadar, Sentinel, Tanium, Vectra, Abnormal, Manual
  - Region (String)
  - TTPCategory (String)
  - AffectedAssets (Integer)
  - ContainmentActions (Integer)
  - FalsePositive (Boolean)

Table: MonthlyMetrics
  - Month (String)
  - TotalIncidents (Integer)
  - CriticalCount (Integer)
  - HighCount (Integer)
  - MTTR_Avg_Hours (Decimal)
  - FalsePositiveRate (Decimal)
  - AutomatedClosureRate (Decimal)

Table: SourceBreakdown
  - Source (String)
  - IncidentCount (Integer)
  - FalsePositiveCount (Integer)
  - AvgMTTR_Hours (Decimal)
  - AutoClosedCount (Integer)""",
}

# ── Pre-built result sets keyed by (dataset_id, pattern) ──

_REGIONS = ["AMER", "EMEA", "APAC", "LATAM"]
_OS_TYPES = ["Windows Server 2022", "Windows Server 2019", "Windows 11", "Windows 10", "RHEL 9", "RHEL 8", "Ubuntu 22.04", "macOS 14"]
_BUS_UNITS = ["Corporate Technology", "Global Operations", "Investments", "Insurance Products", "Claims", "Human Resources", "Finance", "Legal"]
_SEVERITIES = ["Critical", "High", "Medium", "Low"]
_PATCH_STATUSES = ["Compliant", "Non-Compliant", "Pending Reboot", "Excluded"]


def _endpoint_region_summary():
    """Regional endpoint compliance breakdown."""
    data = [
        {"Region": "AMER", "TotalEndpoints": 62480, "CompliantCount": 54968, "NonCompliantCount": 4998, "PendingRebootCount": 1889, "ExcludedCount": 625, "ComplianceRate": 0.880, "CrowdStrikeCoverage": 0.974, "TaniumCoverage": 0.961},
        {"Region": "EMEA", "TotalEndpoints": 41250, "CompliantCount": 34650, "NonCompliantCount": 4537, "PendingRebootCount": 1650, "ExcludedCount": 413, "ComplianceRate": 0.840, "CrowdStrikeCoverage": 0.958, "TaniumCoverage": 0.943},
        {"Region": "APAC", "TotalEndpoints": 28900, "CompliantCount": 25432, "NonCompliantCount": 2312, "PendingRebootCount": 867, "ExcludedCount": 289, "ComplianceRate": 0.880, "CrowdStrikeCoverage": 0.982, "TaniumCoverage": 0.955},
        {"Region": "LATAM", "TotalEndpoints": 15370, "CompliantCount": 12603, "NonCompliantCount": 1845, "PendingRebootCount": 768, "ExcludedCount": 154, "ComplianceRate": 0.820, "CrowdStrikeCoverage": 0.941, "TaniumCoverage": 0.928},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_os_breakdown():
    """OS distribution across all endpoints."""
    data = [
        {"OS": "Windows 11", "Count": 52340, "CompliantPct": 0.912},
        {"OS": "Windows 10", "Count": 31200, "CompliantPct": 0.834},
        {"OS": "Windows Server 2022", "Count": 24180, "CompliantPct": 0.891},
        {"OS": "Windows Server 2019", "Count": 18960, "CompliantPct": 0.856},
        {"OS": "RHEL 9", "Count": 8420, "CompliantPct": 0.928},
        {"OS": "RHEL 8", "Count": 5630, "CompliantPct": 0.901},
        {"OS": "Ubuntu 22.04", "Count": 3920, "CompliantPct": 0.945},
        {"OS": "macOS 14", "Count": 3350, "CompliantPct": 0.967},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_noncompliant_by_region_type():
    """Non-compliant endpoints by region and type."""
    data = [
        {"Region": "AMER", "EndpointType": "Server", "NonCompliant": 1842, "CriticalPatchesMissing": 423},
        {"Region": "AMER", "EndpointType": "Workstation", "NonCompliant": 2680, "CriticalPatchesMissing": 312},
        {"Region": "AMER", "EndpointType": "Virtual Desktop", "NonCompliant": 476, "CriticalPatchesMissing": 89},
        {"Region": "EMEA", "EndpointType": "Server", "NonCompliant": 1891, "CriticalPatchesMissing": 567},
        {"Region": "EMEA", "EndpointType": "Workstation", "NonCompliant": 2198, "CriticalPatchesMissing": 289},
        {"Region": "EMEA", "EndpointType": "Virtual Desktop", "NonCompliant": 448, "CriticalPatchesMissing": 71},
        {"Region": "APAC", "EndpointType": "Server", "NonCompliant": 924, "CriticalPatchesMissing": 198},
        {"Region": "APAC", "EndpointType": "Workstation", "NonCompliant": 1156, "CriticalPatchesMissing": 134},
        {"Region": "APAC", "EndpointType": "Virtual Desktop", "NonCompliant": 232, "CriticalPatchesMissing": 38},
        {"Region": "LATAM", "EndpointType": "Server", "NonCompliant": 712, "CriticalPatchesMissing": 189},
        {"Region": "LATAM", "EndpointType": "Workstation", "NonCompliant": 945, "CriticalPatchesMissing": 156},
        {"Region": "LATAM", "EndpointType": "Virtual Desktop", "NonCompliant": 188, "CriticalPatchesMissing": 24},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_missing_crowdstrike():
    """Endpoints missing CrowdStrike by region."""
    data = [
        {"Region": "AMER", "EndpointType": "Server", "MissingCS": 487, "TotalInScope": 18740},
        {"Region": "AMER", "EndpointType": "Workstation", "MissingCS": 1136, "TotalInScope": 43740},
        {"Region": "EMEA", "EndpointType": "Server", "MissingCS": 398, "TotalInScope": 12375},
        {"Region": "EMEA", "EndpointType": "Workstation", "MissingCS": 1335, "TotalInScope": 28875},
        {"Region": "APAC", "EndpointType": "Server", "MissingCS": 142, "TotalInScope": 8670},
        {"Region": "APAC", "EndpointType": "Workstation", "MissingCS": 378, "TotalInScope": 20230},
        {"Region": "LATAM", "EndpointType": "Server", "MissingCS": 251, "TotalInScope": 4611},
        {"Region": "LATAM", "EndpointType": "Workstation", "MissingCS": 653, "TotalInScope": 10759},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_patch_cycle():
    """Recent patch cycles and compliance."""
    data = [
        {"PatchCycleID": "2026-03", "Title": "March 2026 Cumulative Update", "ReleaseDate": "2026-03-11", "Deadline": "2026-03-25", "AffectedEndpoints": 134200, "CompletedEndpoints": 118096, "CompliancePercent": 0.880},
        {"PatchCycleID": "2026-02", "Title": "February 2026 Cumulative Update", "ReleaseDate": "2026-02-11", "Deadline": "2026-02-25", "AffectedEndpoints": 131850, "CompletedEndpoints": 122620, "CompliancePercent": 0.930},
        {"PatchCycleID": "2026-01", "Title": "January 2026 Cumulative Update", "ReleaseDate": "2026-01-14", "Deadline": "2026-01-28", "AffectedEndpoints": 129400, "CompletedEndpoints": 123162, "CompliancePercent": 0.952},
        {"PatchCycleID": "2025-12", "Title": "December 2025 Cumulative Update", "ReleaseDate": "2025-12-10", "Deadline": "2025-12-24", "AffectedEndpoints": 128750, "CompletedEndpoints": 124244, "CompliancePercent": 0.965},
        {"PatchCycleID": "2025-11", "Title": "November 2025 Cumulative Update", "ReleaseDate": "2025-11-12", "Deadline": "2025-11-26", "AffectedEndpoints": 127300, "CompletedEndpoints": 123281, "CompliancePercent": 0.968},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_bu_compliance():
    """Business unit compliance."""
    data = [
        {"BusinessUnit": "Corporate Technology", "TotalEndpoints": 28450, "ComplianceRate": 0.921, "AvgDaysSincePatch": 8.2},
        {"BusinessUnit": "Global Operations", "TotalEndpoints": 24380, "ComplianceRate": 0.873, "AvgDaysSincePatch": 12.4},
        {"BusinessUnit": "Investments", "TotalEndpoints": 19200, "ComplianceRate": 0.908, "AvgDaysSincePatch": 9.1},
        {"BusinessUnit": "Insurance Products", "TotalEndpoints": 22750, "ComplianceRate": 0.862, "AvgDaysSincePatch": 13.7},
        {"BusinessUnit": "Claims", "TotalEndpoints": 18900, "ComplianceRate": 0.845, "AvgDaysSincePatch": 14.9},
        {"BusinessUnit": "Human Resources", "TotalEndpoints": 12340, "ComplianceRate": 0.891, "AvgDaysSincePatch": 10.3},
        {"BusinessUnit": "Finance", "TotalEndpoints": 14200, "ComplianceRate": 0.917, "AvgDaysSincePatch": 8.8},
        {"BusinessUnit": "Legal", "TotalEndpoints": 7780, "ComplianceRate": 0.904, "AvgDaysSincePatch": 9.6},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _endpoint_totals():
    """High-level totals."""
    data = [{"TotalEndpoints": 148000, "Compliant": 127653, "NonCompliant": 13692, "PendingReboot": 5174, "Excluded": 1481, "OverallComplianceRate": 0.863}]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": 1}


def _endpoint_server_count_by_region():
    """Servers by region with patch status."""
    data = [
        {"Region": "AMER", "TotalServers": 18740, "Compliant": 16304, "NonCompliant": 1842, "PendingReboot": 469, "ComplianceRate": 0.870},
        {"Region": "EMEA", "TotalServers": 12375, "Compliant": 10264, "NonCompliant": 1891, "PendingReboot": 186, "ComplianceRate": 0.829},
        {"Region": "APAC", "TotalServers": 8670, "Compliant": 7630, "NonCompliant": 924, "PendingReboot": 104, "ComplianceRate": 0.880},
        {"Region": "LATAM", "TotalServers": 4611, "Compliant": 3761, "NonCompliant": 712, "PendingReboot": 115, "ComplianceRate": 0.816},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


# ── Vulnerability dataset results ──

def _vuln_severity_summary():
    data = [
        {"Severity": "Critical", "TotalVulns": 142, "OpenCount": 38, "InProgressCount": 47, "RemediatedCount": 51, "MitigatedCount": 6, "SLABreachedCount": 12, "AvgRemediationDays": 6.8},
        {"Severity": "High", "TotalVulns": 487, "OpenCount": 89, "InProgressCount": 134, "RemediatedCount": 238, "MitigatedCount": 26, "SLABreachedCount": 31, "AvgRemediationDays": 14.2},
        {"Severity": "Medium", "TotalVulns": 1243, "OpenCount": 312, "InProgressCount": 287, "RemediatedCount": 589, "MitigatedCount": 55, "SLABreachedCount": 67, "AvgRemediationDays": 28.5},
        {"Severity": "Low", "TotalVulns": 2891, "OpenCount": 1204, "InProgressCount": 423, "RemediatedCount": 1109, "MitigatedCount": 155, "SLABreachedCount": 89, "AvgRemediationDays": 45.1},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _vuln_top_critical():
    data = [
        {"CVEID": "CVE-2026-21413", "Title": "Windows Kerberos Elevation of Privilege", "CVSSScore": 9.8, "AffectedHosts": 4280, "RemediatedHosts": 3412, "SLABreached": False, "ExploitAvailable": True, "InCISAKEV": True},
        {"CVEID": "CVE-2026-21390", "Title": "Exchange Server Remote Code Execution", "CVSSScore": 9.6, "AffectedHosts": 847, "RemediatedHosts": 623, "SLABreached": True, "ExploitAvailable": True, "InCISAKEV": True},
        {"CVEID": "CVE-2026-0215", "Title": "OpenSSL Buffer Overflow", "CVSSScore": 9.4, "AffectedHosts": 3190, "RemediatedHosts": 2871, "SLABreached": False, "ExploitAvailable": True, "InCISAKEV": False},
        {"CVEID": "CVE-2026-1847", "Title": "Linux Kernel Privilege Escalation", "CVSSScore": 9.1, "AffectedHosts": 1420, "RemediatedHosts": 1207, "SLABreached": False, "ExploitAvailable": False, "InCISAKEV": False},
        {"CVEID": "CVE-2026-21352", "Title": "Windows Print Spooler RCE", "CVSSScore": 8.8, "AffectedHosts": 8940, "RemediatedHosts": 6258, "SLABreached": True, "ExploitAvailable": True, "InCISAKEV": True},
        {"CVEID": "CVE-2026-3021", "Title": "VMware vCenter Server Auth Bypass", "CVSSScore": 8.6, "AffectedHosts": 312, "RemediatedHosts": 289, "SLABreached": False, "ExploitAvailable": True, "InCISAKEV": True},
        {"CVEID": "CVE-2026-21298", "Title": "SQL Server Elevation of Privilege", "CVSSScore": 8.4, "AffectedHosts": 1890, "RemediatedHosts": 1512, "SLABreached": False, "ExploitAvailable": False, "InCISAKEV": False},
        {"CVEID": "CVE-2026-0198", "Title": "Apache Log4j Incomplete Fix", "CVSSScore": 8.2, "AffectedHosts": 2340, "RemediatedHosts": 2106, "SLABreached": False, "ExploitAvailable": True, "InCISAKEV": False},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _vuln_sla_monthly():
    data = [
        {"Month": "2026-03", "Severity": "Critical", "TotalVulns": 23, "WithinSLA": 17, "BreachedSLA": 6, "SLAComplianceRate": 0.739},
        {"Month": "2026-03", "Severity": "High", "TotalVulns": 78, "WithinSLA": 64, "BreachedSLA": 14, "SLAComplianceRate": 0.821},
        {"Month": "2026-02", "Severity": "Critical", "TotalVulns": 31, "WithinSLA": 27, "BreachedSLA": 4, "SLAComplianceRate": 0.871},
        {"Month": "2026-02", "Severity": "High", "TotalVulns": 92, "WithinSLA": 81, "BreachedSLA": 11, "SLAComplianceRate": 0.880},
        {"Month": "2026-01", "Severity": "Critical", "TotalVulns": 19, "WithinSLA": 18, "BreachedSLA": 1, "SLAComplianceRate": 0.947},
        {"Month": "2026-01", "Severity": "High", "TotalVulns": 84, "WithinSLA": 77, "BreachedSLA": 7, "SLAComplianceRate": 0.917},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


# ── Incidents dataset results ──

def _incident_summary():
    data = [
        {"Month": "2026-03", "TotalIncidents": 342, "CriticalCount": 8, "HighCount": 47, "MTTR_Avg_Hours": 4.2, "FalsePositiveRate": 0.23, "AutomatedClosureRate": 0.41},
        {"Month": "2026-02", "TotalIncidents": 298, "CriticalCount": 5, "HighCount": 39, "MTTR_Avg_Hours": 3.8, "FalsePositiveRate": 0.21, "AutomatedClosureRate": 0.44},
        {"Month": "2026-01", "TotalIncidents": 317, "CriticalCount": 6, "HighCount": 43, "MTTR_Avg_Hours": 4.5, "FalsePositiveRate": 0.25, "AutomatedClosureRate": 0.38},
        {"Month": "2025-12", "TotalIncidents": 264, "CriticalCount": 3, "HighCount": 31, "MTTR_Avg_Hours": 3.1, "FalsePositiveRate": 0.19, "AutomatedClosureRate": 0.46},
        {"Month": "2025-11", "TotalIncidents": 329, "CriticalCount": 7, "HighCount": 52, "MTTR_Avg_Hours": 5.1, "FalsePositiveRate": 0.27, "AutomatedClosureRate": 0.36},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _incident_by_source():
    data = [
        {"Source": "CrowdStrike", "IncidentCount": 128, "FalsePositiveCount": 18, "AvgMTTR_Hours": 3.2, "AutoClosedCount": 52},
        {"Source": "QRadar", "IncidentCount": 67, "FalsePositiveCount": 21, "AvgMTTR_Hours": 5.8, "AutoClosedCount": 12},
        {"Source": "Sentinel", "IncidentCount": 54, "FalsePositiveCount": 14, "AvgMTTR_Hours": 4.1, "AutoClosedCount": 23},
        {"Source": "Vectra", "IncidentCount": 38, "FalsePositiveCount": 9, "AvgMTTR_Hours": 3.7, "AutoClosedCount": 16},
        {"Source": "Abnormal", "IncidentCount": 31, "FalsePositiveCount": 8, "AvgMTTR_Hours": 2.4, "AutoClosedCount": 19},
        {"Source": "Tanium", "IncidentCount": 18, "FalsePositiveCount": 6, "AvgMTTR_Hours": 6.2, "AutoClosedCount": 4},
        {"Source": "Manual", "IncidentCount": 6, "FalsePositiveCount": 2, "AvgMTTR_Hours": 8.9, "AutoClosedCount": 0},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _incident_by_region():
    data = [
        {"Region": "AMER", "TotalIncidents": 156, "CriticalCount": 4, "HighCount": 22, "MTTR_Avg_Hours": 3.6},
        {"Region": "EMEA", "TotalIncidents": 98, "CriticalCount": 2, "HighCount": 14, "MTTR_Avg_Hours": 4.8},
        {"Region": "APAC", "TotalIncidents": 62, "CriticalCount": 1, "HighCount": 8, "MTTR_Avg_Hours": 5.2},
        {"Region": "LATAM", "TotalIncidents": 26, "CriticalCount": 1, "HighCount": 3, "MTTR_Avg_Hours": 4.1},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


def _incident_ttp_breakdown():
    data = [
        {"TTPCategory": "Phishing / Initial Access", "Count": 89, "AvgMTTR": 2.8},
        {"TTPCategory": "Credential Access", "Count": 64, "AvgMTTR": 4.1},
        {"TTPCategory": "Malware Execution", "Count": 52, "AvgMTTR": 3.4},
        {"TTPCategory": "Lateral Movement", "Count": 41, "AvgMTTR": 6.7},
        {"TTPCategory": "Data Exfiltration", "Count": 18, "AvgMTTR": 8.2},
        {"TTPCategory": "Privilege Escalation", "Count": 34, "AvgMTTR": 5.1},
        {"TTPCategory": "Command & Control", "Count": 27, "AvgMTTR": 4.5},
        {"TTPCategory": "Denial of Service", "Count": 12, "AvgMTTR": 2.1},
        {"TTPCategory": "Policy Violation", "Count": 5, "AvgMTTR": 1.4},
    ]
    cols = list(data[0].keys())
    return {"columns": cols, "rows": data, "row_count": len(data)}


# ── Pattern matching for DAX queries ──

_ENDPOINT_PATTERNS = [
    (r"(?i)(region|emea|amer|apac|latam).*(?:summar|breakdown|compli|count)", _endpoint_region_summary),
    (r"(?i)(os|operating.system|windows|linux|rhel|ubuntu|macos)", _endpoint_os_breakdown),
    (r"(?i)(non.?compliant|missing.*patch|patch.*missing).*(?:region|type|server|workstation)", _endpoint_noncompliant_by_region_type),
    (r"(?i)(crowdstrike|falcon|cs).*(?:missing|install|coverage|gap)", _endpoint_missing_crowdstrike),
    (r"(?i)(patch.?cycle|cumulative|update.*cycle|monthly.*patch)", _endpoint_patch_cycle),
    (r"(?i)(business.?unit|bu|department|org)", _endpoint_bu_compliance),
    (r"(?i)(server).*(?:region|count|how many|total)", _endpoint_server_count_by_region),
    (r"(?i)(total|overall|how many|count|summar)", _endpoint_totals),
    (r"(?i)(non.?compliant|missing|gap|fail)", _endpoint_noncompliant_by_region_type),
    (r"(?i)(compli|patch|status)", _endpoint_region_summary),
]

_VULN_PATTERNS = [
    (r"(?i)(critical|top|worst|severe|highest|cve).*(?:vuln|cve)", _vuln_top_critical),
    (r"(?i)(sla|breach|deadline|overdue)", _vuln_sla_monthly),
    (r"(?i)(severity|breakdown|summar|status|overview|how many)", _vuln_severity_summary),
    (r"(?i)(vuln|cve|patch)", _vuln_severity_summary),
]

_INCIDENT_PATTERNS = [
    (r"(?i)(source|crowdstrike|qradar|sentinel|detection|tool)", _incident_by_source),
    (r"(?i)(region|emea|amer|apac|latam)", _incident_by_region),
    (r"(?i)(ttp|technique|tactic|mitre|attack|category|phish|malware)", _incident_ttp_breakdown),
    (r"(?i)(month|trend|time|over time|summar|overview|total|how many|count)", _incident_summary),
    (r"(?i)(incident|alert|event)", _incident_summary),
]

_DATASET_PATTERNS = {
    "demo-endpoint-compliance": _ENDPOINT_PATTERNS,
    "demo-vuln-management": _VULN_PATTERNS,
    "demo-security-incidents": _INCIDENT_PATTERNS,
}

# Default fallbacks per dataset
_DATASET_DEFAULTS = {
    "demo-endpoint-compliance": _endpoint_region_summary,
    "demo-vuln-management": _vuln_severity_summary,
    "demo-security-incidents": _incident_summary,
}


# ── Chart data builders for the visual dashboard ──

def get_chart_data(dataset_id: str) -> dict | None:
    """Return pre-built chart configs, KPIs, and chips for a dataset."""
    builders = {
        "demo-endpoint-compliance": _build_endpoint_charts,
        "demo-vuln-management": _build_vuln_charts,
        "demo-security-incidents": _build_incident_charts,
    }
    fn = builders.get(dataset_id)
    return fn() if fn else None


def _build_endpoint_charts() -> dict:
    reg = _endpoint_region_summary()["rows"]
    os_data = _endpoint_os_breakdown()["rows"]
    bu = _endpoint_bu_compliance()["rows"]
    pc = _endpoint_patch_cycle()["rows"]

    return {
        "kpis": [
            {"label": "Total Endpoints", "value": "148,000", "color": "#0046ad"},
            {"label": "Overall Compliance", "value": "86.3%", "color": "#00a651"},
            {"label": "Non-Compliant", "value": "13,692", "color": "#dc2626"},
            {"label": "Pending Reboot", "value": "5,174", "color": "#f59e0b"},
        ],
        "charts": [
            {
                "id": "region-status",
                "title": "Endpoint Status by Region",
                "type": "bar",
                "stacked": True,
                "labels": [r["Region"] for r in reg],
                "datasets": [
                    {"label": "Compliant", "data": [r["CompliantCount"] for r in reg], "color": "#00a651"},
                    {"label": "Non-Compliant", "data": [r["NonCompliantCount"] for r in reg], "color": "#dc2626"},
                    {"label": "Pending Reboot", "data": [r["PendingRebootCount"] for r in reg], "color": "#f59e0b"},
                ],
                "xLabel": "Region",
                "yLabel": "Endpoints",
                "insight": "LATAM has the lowest compliance at 82%",
                "clickQuery": "Why does LATAM have the lowest compliance rate?",
            },
            {
                "id": "os-distribution",
                "title": "OS Distribution",
                "type": "doughnut",
                "labels": [r["OS"] for r in os_data],
                "datasets": [{
                    "label": "Endpoints",
                    "data": [r["Count"] for r in os_data],
                    "colors": ["#0046ad", "#3b82f6", "#00a651", "#10b981", "#dc2626", "#f59e0b", "#6a1b9a", "#8b5cf6"],
                }],
                "clickQuery": "Which OS has the worst patch compliance?",
            },
            {
                "id": "bu-compliance",
                "title": "Compliance by Business Unit",
                "type": "horizontalBar",
                "labels": [r["BusinessUnit"] for r in sorted(bu, key=lambda x: x["ComplianceRate"])],
                "datasets": [{
                    "label": "Compliance Rate",
                    "data": [round(r["ComplianceRate"] * 100, 1) for r in sorted(bu, key=lambda x: x["ComplianceRate"])],
                    "colors": [
                        "#dc2626" if r["ComplianceRate"] < 0.86 else "#f59e0b" if r["ComplianceRate"] < 0.90 else "#00a651"
                        for r in sorted(bu, key=lambda x: x["ComplianceRate"])
                    ],
                }],
                "xLabel": "Compliance %",
                "yLabel": "Business Unit",
                "insight": "Claims has the most room to improve at 84.5%",
                "clickQuery": "What is driving low compliance in the Claims business unit?",
            },
            {
                "id": "patch-trend",
                "title": "Patch Cycle Compliance Trend",
                "type": "line",
                "labels": [r["PatchCycleID"] for r in reversed(pc)],
                "datasets": [{
                    "label": "Compliance %",
                    "data": [round(r["CompliancePercent"] * 100, 1) for r in reversed(pc)],
                    "color": "#0046ad",
                }],
                "xLabel": "Patch Cycle",
                "yLabel": "Compliance %",
                "insight": "Compliance dropped 8.8 points over 5 months",
                "clickQuery": "Why has patch compliance been declining over the last few months?",
            },
        ],
        "chips": [
            {"label": "Missing patches in EMEA", "query": "How many servers in EMEA are missing a patch?"},
            {"label": "Compliance by region", "query": "How does compliance compare across regions?"},
            {"label": "Worst business units", "query": "Which business units have the lowest patch compliance?"},
            {"label": "CrowdStrike coverage gaps", "query": "Where are the gaps in CrowdStrike coverage?"},
            {"label": "Patch compliance trend", "query": "How has patch compliance changed over time?"},
            {"label": "Summarize the data", "query": "Give me a high-level summary of this data"},
        ],
    }


def _build_vuln_charts() -> dict:
    sev = _vuln_severity_summary()["rows"]
    crit = _vuln_top_critical()["rows"]
    sla = _vuln_sla_monthly()["rows"]

    return {
        "kpis": [
            {"label": "Total Vulns", "value": "4,763", "color": "#0046ad"},
            {"label": "Critical Open", "value": "38", "color": "#dc2626"},
            {"label": "SLA Breached", "value": "199", "color": "#f59e0b"},
            {"label": "Exploits Available", "value": "5", "color": "#6a1b9a"},
        ],
        "charts": [
            {
                "id": "vuln-by-severity",
                "title": "Vulnerability Status by Severity",
                "type": "bar",
                "stacked": True,
                "labels": [r["Severity"] for r in sev],
                "datasets": [
                    {"label": "Open", "data": [r["OpenCount"] for r in sev], "color": "#dc2626"},
                    {"label": "In Progress", "data": [r["InProgressCount"] for r in sev], "color": "#f59e0b"},
                    {"label": "Remediated", "data": [r["RemediatedCount"] for r in sev], "color": "#00a651"},
                    {"label": "Mitigated", "data": [r["MitigatedCount"] for r in sev], "color": "#3b82f6"},
                ],
                "xLabel": "Severity",
                "yLabel": "Vulnerabilities",
                "insight": "1,204 low-severity vulns still open",
                "clickQuery": "Why are there so many open low-severity vulnerabilities?",
            },
            {
                "id": "top-critical",
                "title": "Top Critical CVEs — Affected vs Remediated",
                "type": "horizontalBar",
                "labels": [r["CVEID"] for r in crit[:6]],
                "datasets": [
                    {"label": "Affected Hosts", "data": [r["AffectedHosts"] for r in crit[:6]], "color": "#dc2626"},
                    {"label": "Remediated", "data": [r["RemediatedHosts"] for r in crit[:6]], "color": "#00a651"},
                ],
                "xLabel": "Hosts",
                "yLabel": "CVE",
                "insight": "CVE-2026-21352 has 2,682 hosts still unpatched",
                "clickQuery": "Which critical CVEs have active exploits and are not yet fully remediated?",
            },
            {
                "id": "severity-dist",
                "title": "Severity Distribution",
                "type": "doughnut",
                "labels": [r["Severity"] for r in sev],
                "datasets": [{
                    "label": "Count",
                    "data": [r["TotalVulns"] for r in sev],
                    "colors": ["#dc2626", "#f59e0b", "#3b82f6", "#94a3b8"],
                }],
                "clickQuery": "Give me a breakdown of vulnerabilities by severity",
            },
            {
                "id": "sla-trend",
                "title": "SLA Compliance — Critical & High",
                "type": "bar",
                "labels": sorted(set(r["Month"] for r in sla)),
                "datasets": [
                    {"label": "Critical Within SLA", "data": [r["WithinSLA"] for r in sla if r["Severity"] == "Critical"], "color": "#dc2626"},
                    {"label": "Critical Breached", "data": [r["BreachedSLA"] for r in sla if r["Severity"] == "Critical"], "color": "#fca5a5"},
                    {"label": "High Within SLA", "data": [r["WithinSLA"] for r in sla if r["Severity"] == "High"], "color": "#f59e0b"},
                    {"label": "High Breached", "data": [r["BreachedSLA"] for r in sla if r["Severity"] == "High"], "color": "#fde68a"},
                ],
                "xLabel": "Month",
                "yLabel": "Count",
                "insight": "Critical SLA compliance dropped to 73.9% in March",
                "clickQuery": "Why did critical SLA compliance drop in March?",
            },
        ],
        "chips": [
            {"label": "Critical CVEs with exploits", "query": "Which critical CVEs have active exploits?"},
            {"label": "SLA compliance over time", "query": "How has SLA compliance changed over time?"},
            {"label": "CISA KEV vulnerabilities", "query": "Are any of our vulnerabilities in the CISA KEV catalog?"},
            {"label": "Open vs remediated", "query": "How many vulnerabilities are open vs remediated by severity?"},
            {"label": "Most vulnerable products", "query": "Which products have the most vulnerabilities?"},
            {"label": "Summarize the data", "query": "Give me a high-level summary of this data"},
        ],
    }


def _build_incident_charts() -> dict:
    monthly = _incident_summary()["rows"]
    sources = _incident_by_source()["rows"]
    ttps = _incident_ttp_breakdown()["rows"]
    regions = _incident_by_region()["rows"]

    return {
        "kpis": [
            {"label": "Incidents (Mar)", "value": "342", "color": "#0046ad"},
            {"label": "Avg MTTR", "value": "4.2h", "color": "#00a651"},
            {"label": "False Positive Rate", "value": "23%", "color": "#f59e0b"},
            {"label": "Automation Rate", "value": "41%", "color": "#6a1b9a"},
        ],
        "charts": [
            {
                "id": "monthly-trend",
                "title": "Monthly Incident Volume",
                "type": "bar",
                "labels": [r["Month"] for r in reversed(monthly)],
                "datasets": [
                    {"label": "Total Incidents", "data": [r["TotalIncidents"] for r in reversed(monthly)], "color": "#0046ad"},
                    {"label": "Critical", "data": [r["CriticalCount"] for r in reversed(monthly)], "color": "#dc2626"},
                    {"label": "High", "data": [r["HighCount"] for r in reversed(monthly)], "color": "#f59e0b"},
                ],
                "xLabel": "Month",
                "yLabel": "Incidents",
                "insight": "March saw the highest incident volume in 5 months",
                "clickQuery": "What caused the spike in incidents in March?",
            },
            {
                "id": "by-source",
                "title": "Incidents by Detection Source",
                "type": "doughnut",
                "labels": [r["Source"] for r in sources],
                "datasets": [{
                    "label": "Count",
                    "data": [r["IncidentCount"] for r in sources],
                    "colors": ["#0046ad", "#3b82f6", "#6a1b9a", "#00a651", "#f59e0b", "#dc2626", "#94a3b8"],
                }],
                "insight": "CrowdStrike detects 37% of all incidents",
                "clickQuery": "Which detection source has the most false positives?",
            },
            {
                "id": "ttp-categories",
                "title": "TTP Categories",
                "type": "horizontalBar",
                "labels": [r["TTPCategory"] for r in sorted(ttps, key=lambda x: x["Count"])],
                "datasets": [{
                    "label": "Incidents",
                    "data": [r["Count"] for r in sorted(ttps, key=lambda x: x["Count"])],
                    "color": "#6a1b9a",
                }],
                "xLabel": "Count",
                "yLabel": "TTP Category",
                "clickQuery": "Tell me more about the phishing and initial access incidents",
            },
            {
                "id": "by-region",
                "title": "Incidents & MTTR by Region",
                "type": "bar",
                "labels": [r["Region"] for r in regions],
                "datasets": [
                    {"label": "Total Incidents", "data": [r["TotalIncidents"] for r in regions], "color": "#0046ad"},
                    {"label": "Critical", "data": [r["CriticalCount"] for r in regions], "color": "#dc2626"},
                    {"label": "High", "data": [r["HighCount"] for r in regions], "color": "#f59e0b"},
                ],
                "xLabel": "Region",
                "yLabel": "Incidents",
                "insight": "APAC has the slowest MTTR at 5.2 hours",
                "clickQuery": "Why does APAC have the slowest mean time to respond?",
            },
        ],
        "chips": [
            {"label": "False positive sources", "query": "Which detection source produces the most false positives?"},
            {"label": "Response time by region", "query": "How does mean time to respond compare across regions?"},
            {"label": "Top TTP categories", "query": "What are the top TTP categories this month?"},
            {"label": "Incident trend", "query": "How has the incident volume changed over the last 5 months?"},
            {"label": "Automated vs manual", "query": "What percentage of incidents are closed automatically vs manually?"},
            {"label": "Summarize the data", "query": "Give me a high-level summary of this data"},
        ],
    }


class DemoClient:
    """Drop-in replacement for PowerBIClient that returns realistic mock data."""

    def list_datasets(self, workspace_id=None):
        return DEMO_DATASETS

    def get_tables(self, dataset_id, workspace_id=None):
        return []

    def get_last_refresh(self, dataset_id, workspace_id=None):
        from datetime import datetime, timedelta
        fake_time = datetime.utcnow() - timedelta(hours=2, minutes=15)
        return {"endTime": fake_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "status": "Completed"}

    def execute_dax(self, dataset_id, dax_query, workspace_id=None):
        """Match the DAX query against keyword patterns and return appropriate mock data."""
        patterns = _DATASET_PATTERNS.get(dataset_id, _ENDPOINT_PATTERNS)
        for pattern, result_fn in patterns:
            if re.search(pattern, dax_query):
                return result_fn()
        # Fallback
        default_fn = _DATASET_DEFAULTS.get(dataset_id, _endpoint_totals)
        return default_fn()
