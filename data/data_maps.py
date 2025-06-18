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
azdo_projects = {
    'platforms': 'Acme-Cyber-Platforms',
    'rea': 'Acme-Cyber-Security',  # Response Engineering Automation
    'reo': 'Acme-Cyber-Security',  # Response Engineering Operations
    'de': 'Detection-Engineering',
    'gdr': 'Global Detection and Response Shared'
}
azdo_orgs = {
    'platforms': 'Acme-US',
    'rea': 'Acme-US',
    'reo': 'Acme-US',
    'de': 'Acme-US',
    'gdr': 'Acme-US-2'
}
azdo_area_paths = {
    're': 'Acme-Cyber-Security\\METCIRT\\METCIRT Tier III',
    'tuning_request': 'Detection-Engineering\\Detection Engineering\\Tuning',
    'threat_hunting': 'Detection-Engineering\\DE Rules\\Threat Hunting'
}
