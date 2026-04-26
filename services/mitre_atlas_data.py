"""
MITRE ATLAS Reference Data Service

Hardcoded ATLAS (Adversarial Threat Landscape for AI Systems) taxonomy
for the threat intel dashboard.  Provides the same matrix-ready structure
as mitre_attack_data.get_matrix_data() so the frontend can render it with
the same ATT&CK-style heatmap.

When HiddenLayer integration comes online, technique_counts from the DB
will be merged in — identical to how ATT&CK counts work today.
"""

import logging

logger = logging.getLogger(__name__)

# Canonical left-to-right ordering of the 16 ATLAS tactics
TACTIC_ORDER = [
    'AML.TA0002',  # Reconnaissance
    'AML.TA0003',  # Resource Development
    'AML.TA0004',  # Initial Access
    'AML.TA0000',  # AI Model Access
    'AML.TA0005',  # Execution
    'AML.TA0006',  # Persistence
    'AML.TA0012',  # Privilege Escalation
    'AML.TA0007',  # Defense Evasion
    'AML.TA0013',  # Credential Access
    'AML.TA0008',  # Discovery
    'AML.TA0015',  # Lateral Movement
    'AML.TA0009',  # Collection
    'AML.TA0001',  # AI Attack Staging
    'AML.TA0014',  # Command and Control
    'AML.TA0010',  # Exfiltration
    'AML.TA0011',  # Impact
]

TACTIC_DISPLAY = {
    'AML.TA0002': 'Reconnaissance',
    'AML.TA0003': 'Resource Development',
    'AML.TA0004': 'Initial Access',
    'AML.TA0000': 'AI Model Access',
    'AML.TA0005': 'Execution',
    'AML.TA0006': 'Persistence',
    'AML.TA0012': 'Privilege Escalation',
    'AML.TA0007': 'Defense Evasion',
    'AML.TA0013': 'Credential Access',
    'AML.TA0008': 'Discovery',
    'AML.TA0015': 'Lateral Movement',
    'AML.TA0009': 'Collection',
    'AML.TA0001': 'AI Attack Staging',
    'AML.TA0014': 'Command and Control',
    'AML.TA0010': 'Exfiltration',
    'AML.TA0011': 'Impact',
}

# Full ATLAS technique taxonomy (from atlas-data v4.x, March 2026)
# Each entry: (technique_id, name, [tactic_ids], is_subtechnique, parent_id)
_ATLAS_TECHNIQUES = [
    # --- Reconnaissance ---
    ('AML.T0000', 'Search Open Technical Databases', ['AML.TA0002'], False, None),
    ('AML.T0000.000', 'Journals and Conference Proceedings', ['AML.TA0002'], True, 'AML.T0000'),
    ('AML.T0000.001', 'Pre-Print Repositories', ['AML.TA0002'], True, 'AML.T0000'),
    ('AML.T0000.002', 'Technical Blogs', ['AML.TA0002'], True, 'AML.T0000'),
    ('AML.T0001', 'Search Open AI Vulnerability Analysis', ['AML.TA0002'], False, None),
    ('AML.T0003', 'Search Victim-Owned Websites', ['AML.TA0002'], False, None),
    ('AML.T0004', 'Search Application Repositories', ['AML.TA0002'], False, None),
    ('AML.T0006', 'Active Scanning', ['AML.TA0002'], False, None),
    ('AML.T0064', 'Gather RAG-Indexed Targets', ['AML.TA0002'], False, None),

    # --- Resource Development ---
    ('AML.T0002', 'Acquire Public AI Artifacts', ['AML.TA0003'], False, None),
    ('AML.T0002.000', 'Datasets', ['AML.TA0003'], True, 'AML.T0002'),
    ('AML.T0002.001', 'Models', ['AML.TA0003'], True, 'AML.T0002'),
    ('AML.T0016', 'Obtain Capabilities', ['AML.TA0003'], False, None),
    ('AML.T0016.000', 'Adversarial AI Attack Implementations', ['AML.TA0003'], True, 'AML.T0016'),
    ('AML.T0016.001', 'Software Tools', ['AML.TA0003'], True, 'AML.T0016'),
    ('AML.T0016.002', 'Generative AI', ['AML.TA0003'], True, 'AML.T0016'),
    ('AML.T0017', 'Develop Capabilities', ['AML.TA0003'], False, None),
    ('AML.T0017.000', 'Adversarial AI Attacks', ['AML.TA0003'], True, 'AML.T0017'),
    ('AML.T0008', 'Acquire Infrastructure', ['AML.TA0003'], False, None),
    ('AML.T0008.000', 'AI Development Workspaces', ['AML.TA0003'], True, 'AML.T0008'),
    ('AML.T0008.001', 'Consumer Hardware', ['AML.TA0003'], True, 'AML.T0008'),
    ('AML.T0008.002', 'Domains', ['AML.TA0003'], True, 'AML.T0008'),
    ('AML.T0008.003', 'Physical Countermeasures', ['AML.TA0003'], True, 'AML.T0008'),
    ('AML.T0019', 'Publish Poisoned Datasets', ['AML.TA0003'], False, None),
    ('AML.T0021', 'Establish Accounts', ['AML.TA0003'], False, None),
    ('AML.T0058', 'Publish Poisoned Models', ['AML.TA0003'], False, None),
    ('AML.T0060', 'Publish Hallucinated Entities', ['AML.TA0003'], False, None),
    ('AML.T0065', 'LLM Prompt Crafting', ['AML.TA0003'], False, None),
    ('AML.T0066', 'Retrieval Content Crafting', ['AML.TA0003'], False, None),

    # --- Initial Access ---
    ('AML.T0010', 'AI Supply Chain Compromise', ['AML.TA0004'], False, None),
    ('AML.T0010.000', 'Hardware', ['AML.TA0004'], True, 'AML.T0010'),
    ('AML.T0010.001', 'AI Software', ['AML.TA0004'], True, 'AML.T0010'),
    ('AML.T0010.002', 'Data', ['AML.TA0004'], True, 'AML.T0010'),
    ('AML.T0010.003', 'Model', ['AML.TA0004'], True, 'AML.T0010'),
    ('AML.T0010.004', 'Container Registry', ['AML.TA0004'], True, 'AML.T0010'),
    ('AML.T0049', 'Exploit Public-Facing Application', ['AML.TA0004'], False, None),
    ('AML.T0052', 'Phishing', ['AML.TA0004', 'AML.TA0015'], False, None),
    ('AML.T0052.000', 'Spearphishing via Social Engineering LLM', ['AML.TA0004'], True, 'AML.T0052'),

    # --- AI Model Access ---
    ('AML.T0040', 'AI Model Inference API Access', ['AML.TA0000'], False, None),
    ('AML.T0047', 'AI-Enabled Product or Service', ['AML.TA0000'], False, None),
    ('AML.T0041', 'Physical Environment Access', ['AML.TA0000'], False, None),
    ('AML.T0044', 'Full AI Model Access', ['AML.TA0000'], False, None),

    # --- Execution ---
    ('AML.T0011', 'User Execution', ['AML.TA0005'], False, None),
    ('AML.T0011.000', 'Unsafe AI Artifacts', ['AML.TA0005'], True, 'AML.T0011'),
    ('AML.T0011.001', 'Malicious Package', ['AML.TA0005'], True, 'AML.T0011'),
    ('AML.T0050', 'Command and Scripting Interpreter', ['AML.TA0005'], False, None),
    ('AML.T0051', 'LLM Prompt Injection', ['AML.TA0005'], False, None),
    ('AML.T0051.000', 'Direct', ['AML.TA0005'], True, 'AML.T0051'),
    ('AML.T0051.001', 'Indirect', ['AML.TA0005'], True, 'AML.T0051'),

    # --- Persistence ---
    ('AML.T0020', 'Poison Training Data', ['AML.TA0003', 'AML.TA0006'], False, None),
    ('AML.T0018', 'Manipulate AI Model', ['AML.TA0006', 'AML.TA0001'], False, None),
    ('AML.T0018.000', 'Poison AI Model', ['AML.TA0006'], True, 'AML.T0018'),
    ('AML.T0018.001', 'Modify AI Model Architecture', ['AML.TA0006'], True, 'AML.T0018'),
    ('AML.T0018.002', 'Embed Malware', ['AML.TA0006'], True, 'AML.T0018'),
    ('AML.T0061', 'LLM Prompt Self-Replication', ['AML.TA0006'], False, None),
    ('AML.T0070', 'RAG Poisoning', ['AML.TA0006'], False, None),

    # --- Privilege Escalation ---
    ('AML.T0012', 'Valid Accounts', ['AML.TA0004', 'AML.TA0012'], False, None),
    ('AML.T0053', 'AI Agent Tool Invocation', ['AML.TA0005', 'AML.TA0012'], False, None),
    ('AML.T0054', 'LLM Jailbreak', ['AML.TA0012', 'AML.TA0007'], False, None),

    # --- Defense Evasion ---
    ('AML.T0015', 'Evade AI Model', ['AML.TA0004', 'AML.TA0007', 'AML.TA0011'], False, None),
    ('AML.T0067', 'LLM Trusted Output Components Manipulation', ['AML.TA0007'], False, None),
    ('AML.T0067.000', 'Citations', ['AML.TA0007'], True, 'AML.T0067'),
    ('AML.T0068', 'LLM Prompt Obfuscation', ['AML.TA0007'], False, None),
    ('AML.T0071', 'False RAG Entry Injection', ['AML.TA0007'], False, None),
    ('AML.T0073', 'Impersonation', ['AML.TA0007'], False, None),
    ('AML.T0074', 'Masquerading', ['AML.TA0007'], False, None),

    # --- Credential Access ---
    ('AML.T0055', 'Unsecured Credentials', ['AML.TA0013'], False, None),

    # --- Discovery ---
    ('AML.T0013', 'Discover AI Model Ontology', ['AML.TA0008'], False, None),
    ('AML.T0014', 'Discover AI Model Family', ['AML.TA0008'], False, None),
    ('AML.T0007', 'Discover AI Artifacts', ['AML.TA0008'], False, None),
    ('AML.T0062', 'Discover LLM Hallucinations', ['AML.TA0008'], False, None),
    ('AML.T0063', 'Discover AI Model Outputs', ['AML.TA0008'], False, None),
    ('AML.T0069', 'Discover LLM System Information', ['AML.TA0008'], False, None),
    ('AML.T0069.000', 'Special Character Sets', ['AML.TA0008'], True, 'AML.T0069'),
    ('AML.T0069.001', 'System Instruction Keywords', ['AML.TA0008'], True, 'AML.T0069'),
    ('AML.T0069.002', 'System Prompt', ['AML.TA0008'], True, 'AML.T0069'),
    ('AML.T0075', 'Cloud Service Discovery', ['AML.TA0008'], False, None),

    # --- Lateral Movement ---
    # AML.T0052 (Phishing) already defined above with both TA0004 + TA0015

    # --- Collection ---
    ('AML.T0035', 'AI Artifact Collection', ['AML.TA0009'], False, None),
    ('AML.T0036', 'Data from Information Repositories', ['AML.TA0009'], False, None),
    ('AML.T0037', 'Data from Local System', ['AML.TA0009'], False, None),

    # --- AI Attack Staging ---
    ('AML.T0005', 'Create Proxy AI Model', ['AML.TA0001'], False, None),
    ('AML.T0005.000', 'Train Proxy via Gathered AI Artifacts', ['AML.TA0001'], True, 'AML.T0005'),
    ('AML.T0005.001', 'Train Proxy via Replication', ['AML.TA0001'], True, 'AML.T0005'),
    ('AML.T0005.002', 'Use Pre-Trained Model', ['AML.TA0001'], True, 'AML.T0005'),
    ('AML.T0043', 'Craft Adversarial Data', ['AML.TA0001'], False, None),
    ('AML.T0043.000', 'White-Box Optimization', ['AML.TA0001'], True, 'AML.T0043'),
    ('AML.T0043.001', 'Black-Box Optimization', ['AML.TA0001'], True, 'AML.T0043'),
    ('AML.T0043.002', 'Black-Box Transfer', ['AML.TA0001'], True, 'AML.T0043'),
    ('AML.T0043.003', 'Manual Modification', ['AML.TA0001'], True, 'AML.T0043'),
    ('AML.T0043.004', 'Insert Backdoor Trigger', ['AML.TA0001'], True, 'AML.T0043'),
    ('AML.T0042', 'Verify Attack', ['AML.TA0001'], False, None),

    # --- Command and Control ---
    ('AML.T0072', 'Reverse Shell', ['AML.TA0014'], False, None),

    # --- Exfiltration ---
    ('AML.T0024', 'Exfiltration via AI Inference API', ['AML.TA0010'], False, None),
    ('AML.T0024.000', 'Infer Training Data Membership', ['AML.TA0010'], True, 'AML.T0024'),
    ('AML.T0024.001', 'Invert AI Model', ['AML.TA0010'], True, 'AML.T0024'),
    ('AML.T0024.002', 'Extract AI Model', ['AML.TA0010'], True, 'AML.T0024'),
    ('AML.T0025', 'Exfiltration via Cyber Means', ['AML.TA0010'], False, None),
    ('AML.T0056', 'Extract LLM System Prompt', ['AML.TA0010'], False, None),
    ('AML.T0057', 'LLM Data Leakage', ['AML.TA0010'], False, None),

    # --- Impact ---
    ('AML.T0029', 'Denial of AI Service', ['AML.TA0011'], False, None),
    ('AML.T0046', 'Spamming AI System with Chaff Data', ['AML.TA0011'], False, None),
    ('AML.T0031', 'Erode AI Model Integrity', ['AML.TA0011'], False, None),
    ('AML.T0034', 'Cost Harvesting', ['AML.TA0011'], False, None),
    ('AML.T0048', 'External Harms', ['AML.TA0011'], False, None),
    ('AML.T0048.000', 'Financial Harm', ['AML.TA0011'], True, 'AML.T0048'),
    ('AML.T0048.001', 'Reputational Harm', ['AML.TA0011'], True, 'AML.T0048'),
    ('AML.T0048.002', 'Societal Harm', ['AML.TA0011'], True, 'AML.T0048'),
    ('AML.T0048.003', 'User Harm', ['AML.TA0011'], True, 'AML.T0048'),
    ('AML.T0048.004', 'AI Intellectual Property Theft', ['AML.TA0011'], True, 'AML.T0048'),
    ('AML.T0059', 'Erode Dataset Integrity', ['AML.TA0011'], False, None),
]


def get_atlas_matrix_data(technique_counts: dict | None = None) -> dict:
    """Build ATLAS matrix data, optionally merging in occurrence counts.

    Returns the same shape as mitre_attack_data.get_matrix_data():
        {
            'tactics':     [{id, name, technique_count}, ...],
            'techniques':  [{id, name, tactics, count, is_subtechnique, parent_id}, ...],
            'max_count':   int,
        }
    """
    counts = technique_counts or {}

    enriched = []
    for tech_id, name, tactics, is_sub, parent_id in _ATLAS_TECHNIQUES:
        enriched.append({
            'id': tech_id,
            'name': name,
            'tactics': tactics,
            'count': counts.get(tech_id, 0),
            'is_subtechnique': is_sub,
            'parent_id': parent_id,
        })

    max_count = max((t['count'] for t in enriched), default=0)

    tactic_info = []
    for tactic_id in TACTIC_ORDER:
        tech_in_tactic = [t for t in enriched if tactic_id in t['tactics']]
        tactic_info.append({
            'id': tactic_id,
            'name': TACTIC_DISPLAY.get(tactic_id, tactic_id),
            'technique_count': len(tech_in_tactic),
        })

    return {
        'tactics': tactic_info,
        'techniques': enriched,
        'max_count': max_count,
    }
