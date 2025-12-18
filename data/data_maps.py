from my_config import get_config

CONFIG = get_config()

TICKET_TYPE_MAPPING = {
    "Prisma Cloud Compute Runtime Alert": "Pr. Comp",
    "UEBA Prisma Cloud": "Pr. UEBA",
    "Third Party Compromise": "Third Party",
    "Qradar Alert": "QRadar",
    "Ticket QA": "QA",
    "Employee Reported Incident": "ER",
    "CrowdStrike Falcon Incident": "CS I",
    "CrowdStrike Falcon Detection": "CS D",
    "Akamai Alert": "Akamai",
    "Vectra Detection": "Vectra",
    "Splunk Alert": "Splunk",
    "Lost or Stolen Computer": "Lost/Stolen"
}

impact_colors = {
    "Significant": "#ff0000",  # red
    "Confirmed": "#ffa500",  # orange
    "Detected": "#ffd700",  # gold
    "Prevented": "#008000",  # green
    "Ignore": "#808080",  # gray
    "Testing": "#add8e6",  # light blue
    "False Positive": "#90ee90",  # light green
}

# Azure DevOps projects - using values from CONFIG
# These map to CONFIG.azdo_platforms_project, CONFIG.azdo_re_project, etc.
azdo_projects = {
    'platforms': 'Cyber-Platforms',
    'rea': CONFIG.azdo_re_project or 'Cyber-Security',  # Response Engineering Automation
    'reo': CONFIG.azdo_re_project or 'Cyber-Security',  # Response Engineering Operations
    'de': CONFIG.azdo_de_project or 'Detection-Engineering',
    'gdr': 'Security Operations Shared'
}

azdo_orgs = {
    'platforms': CONFIG.azdo_org or 'Company-Org',
    'rea': CONFIG.azdo_org or 'Company-Org',
    'reo': CONFIG.azdo_org or 'Company-Org',
    'de': CONFIG.azdo_org or 'Company-Org',
    'gdr': f'{CONFIG.azdo_org}-2' if CONFIG.azdo_org else 'Company-Org-2'
}

azdo_area_paths = {
    're': f'{CONFIG.azdo_re_project or "Cyber-Security"}\\{CONFIG.team_name}\\{CONFIG.team_name} Tier III',
    'tuning_request': f'{CONFIG.azdo_de_project or "Detection-Engineering"}\\Detection Engineering\\Tuning',
    'threat_hunting': f'{CONFIG.azdo_de_project or "Detection-Engineering"}\\DE Rules\\Threat Hunting'
}
