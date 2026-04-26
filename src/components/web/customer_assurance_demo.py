"""Demo data + canned drafts for the Customer Assurance page.

Used when no real KB is ingested yet — lets us run the full end-to-end flow
(intake -> queue -> drafting workspace -> approved answers -> export) for
business stakeholder demos without needing real policy documents or a working
LLM connection.

All data here is synthetic. Customer names, due dates, etc. are placeholders.
"""

from typing import Any, Dict, List


# ------------------------------------------------------------------ Sample requests

SAMPLE_REQUESTS: List[Dict[str, Any]] = [
    {
        "customer_name": "Globex Industries",
        "customer_segment": "National",
        "account_team_contact": "Jane Smith",
        "request_type": "RFP",
        "source_format": "Excel",
        "due_date": "2026-04-22",
        "priority": "High",
        "title": "Globex 2026 Vendor Security Assessment",
        "raw_text": (
            "1. Do you encrypt customer data at rest?\n"
            "2. Describe your multi-factor authentication policy.\n"
            "3. Please provide your most recent SOC 2 Type II report.\n"
            "4. What is your incident response SLA?\n"
            "5. How is access to production systems controlled?\n"
            "6. Do you conduct annual penetration testing?\n"
        ),
        "notes": "Annual renewal — they're asking the same questions as last year.",
        "assigned_to": "demo",
        "status": "drafting",
        "questions": [
            {"section": "Encryption", "question": "Do you encrypt customer data at rest?"},
            {"section": "Access Control", "question": "Describe your multi-factor authentication policy."},
            {"section": "Compliance", "question": "Please provide your most recent SOC 2 Type II report."},
            {"section": "Incident Response", "question": "What is your incident response SLA?"},
            {"section": "Access Control", "question": "How is access to production systems controlled?"},
            {"section": "Testing", "question": "Do you conduct annual penetration testing?"},
        ],
    },
    {
        "customer_name": "Initech Financial",
        "customer_segment": "Regional",
        "account_team_contact": "Mark Chen",
        "request_type": "Questionnaire",
        "source_format": "Word",
        "due_date": "2026-04-18",
        "priority": "Urgent",
        "title": "Initech Cybersecurity Questionnaire Q2",
        "raw_text": (
            "1. What encryption standards does your organization use?\n"
            "2. Do you have a formal vulnerability management program?\n"
            "3. How often are employees trained on security awareness?\n"
        ),
        "notes": "Short questionnaire, deadline is tight.",
        "assigned_to": "demo",
        "status": "new",
        "questions": [
            {"section": "Encryption", "question": "What encryption standards does your organization use?"},
            {"section": "Vulnerability Management", "question": "Do you have a formal vulnerability management program?"},
            {"section": "Training", "question": "How often are employees trained on security awareness?"},
        ],
    },
    {
        "customer_name": "Soylent Corp",
        "customer_segment": "Public Sector",
        "account_team_contact": "Priya Desai",
        "request_type": "On-Site Assessment",
        "source_format": "Online",
        "due_date": "2026-05-02",
        "priority": "Medium",
        "title": "Soylent On-Site Security Review Prep",
        "raw_text": "Assessor will be on-site for 2 days covering physical + logical controls.",
        "notes": "Legal wants to review any statements about contractual commitments before they go out.",
        "assigned_to": "demo",
        "status": "needs_legal",
        "needs_legal_review": 1,
        "legal_note": "Any response mentioning breach notification timelines must be reviewed by IP/IT Legal before release.",
        "questions": [
            {"section": "Physical Security", "question": "Describe physical access controls at primary data centers."},
            {"section": "Logical Access", "question": "How is privileged access to production reviewed and certified?"},
            {"section": "Breach Notification", "question": "What is your contractual breach notification timeline?"},
        ],
    },
    {
        "customer_name": "Hooli Pensions",
        "customer_segment": "Pensions",
        "account_team_contact": "Alex Park",
        "request_type": "General Questions",
        "source_format": "Email",
        "due_date": "2026-04-15",
        "priority": "Low",
        "title": "Hooli — Data Residency Follow-Up",
        "raw_text": "Where is our data stored? Is any of it outside the US?",
        "notes": "One-off follow-up from a meeting last week.",
        "assigned_to": "demo",
        "status": "ready",
        "questions": [
            {"section": "Data Residency", "question": "Where is customer data stored?"},
            {"section": "Data Residency", "question": "Is customer data ever replicated or stored outside the United States?"},
        ],
    },
]


# ------------------------------------------------------------------ Canned drafts
# Keyed by lowercased keywords that appear in the question. The matcher picks the
# first entry whose keyword list all appears in the question text. If nothing
# matches, we fall back to GENERIC_DRAFT.

CANNED_DRAFTS: List[Dict[str, Any]] = [
    {
        "match": ["encrypt", "rest"],
        "answer": (
            "Yes. All customer data at rest is encrypted using AES-256. Encryption keys "
            "are managed via our enterprise KMS with annual rotation and separation of "
            "duties between key custodians and data administrators. Key access is logged "
            "and reviewed quarterly."
        ),
        "confidence": 0.91,
        "citations": [
            {"source_path": "the company-InfoSec-Standard-v4.2.pdf", "chunk_text": "All customer data at rest shall be encrypted using AES-256 or equivalent approved algorithm.", "score": 0.93},
            {"source_path": "SOC2-TypeII-2025.pdf", "chunk_text": "Encryption at rest controls were tested and found operating effectively for the period under review.", "score": 0.81},
            {"source_path": "KMS-Operating-Procedures.docx", "chunk_text": "Keys are rotated annually and access is logged in the central SIEM.", "score": 0.74},
        ],
    },
    {
        "match": ["mfa"],
        "answer": (
            "MFA is required for all employees accessing corporate and production systems. "
            "We use phishing-resistant factors (FIDO2 security keys and platform "
            "authenticators) for privileged access. SMS-based OTP is not permitted as a "
            "primary factor. MFA bypass requires ticketed approval and is time-bound."
        ),
        "confidence": 0.88,
        "citations": [
            {"source_path": "Access-Control-Policy.pdf", "chunk_text": "Multi-factor authentication is mandatory for all user access to corporate systems...", "score": 0.90},
            {"source_path": "Privileged-Access-Standard.pdf", "chunk_text": "Privileged accounts must use phishing-resistant MFA (FIDO2).", "score": 0.85},
        ],
    },
    {
        "match": ["multi-factor", "authentication"],
        "answer": (
            "MFA is required for all employees accessing corporate and production systems. "
            "We use phishing-resistant factors (FIDO2 security keys and platform "
            "authenticators) for privileged access. SMS-based OTP is not permitted as a "
            "primary factor."
        ),
        "confidence": 0.88,
        "citations": [
            {"source_path": "Access-Control-Policy.pdf", "chunk_text": "Multi-factor authentication is mandatory for all user access...", "score": 0.90},
        ],
    },
    {
        "match": ["soc 2"],
        "answer": (
            "We can share our most recent SOC 2 Type II report under NDA. Please have your "
            "account team submit an NDA request through the standard process and we will "
            "provide the report within 2 business days of execution."
        ),
        "confidence": 0.82,
        "citations": [
            {"source_path": "Standard-Responses-Library.xlsx", "chunk_text": "SOC 2 reports are shared under executed NDA only. SLA: 2 business days from NDA execution.", "score": 0.88},
        ],
    },
    {
        "match": ["incident response", "sla"],
        "answer": (
            "Our Incident Response team operates 24x7x365. Triage begins within 15 minutes "
            "of a confirmed security event. Customer notification timelines for confirmed "
            "incidents impacting customer data are governed by contractual commitments and "
            "applicable law — **this response should be reviewed by Legal before release.**"
        ),
        "confidence": 0.68,
        "needs_sme": True,
        "citations": [
            {"source_path": "Incident-Response-Plan-v3.pdf", "chunk_text": "Triage begins within 15 minutes of a confirmed event. 24x7x365 coverage.", "score": 0.89},
            {"source_path": "Contracts-Legal-Guidance.pdf", "chunk_text": "Customer notification timelines vary by contract. Do not commit to a specific number of hours without Legal review.", "score": 0.77},
        ],
    },
    {
        "match": ["production", "access"],
        "answer": (
            "Access to production systems is controlled via least-privilege role-based "
            "access (RBAC), enforced through a central identity provider. Privileged "
            "access requires an approved ticket, is time-bound (JIT), and all sessions are "
            "logged and reviewed. Access is certified quarterly by system owners."
        ),
        "confidence": 0.87,
        "citations": [
            {"source_path": "Privileged-Access-Standard.pdf", "chunk_text": "Production access is JIT and time-bound. All sessions are logged.", "score": 0.89},
            {"source_path": "Access-Review-Procedure.pdf", "chunk_text": "Quarterly access certifications are performed by system owners.", "score": 0.80},
        ],
    },
    {
        "match": ["penetration testing"],
        "answer": (
            "Yes. External penetration testing is performed at least annually by an "
            "independent third party. Critical findings are remediated within 30 days; "
            "high findings within 60 days. Remediation is tracked to closure and reported "
            "to executive leadership."
        ),
        "confidence": 0.90,
        "citations": [
            {"source_path": "Vulnerability-Management-Policy.pdf", "chunk_text": "External pen tests are performed annually. Critical: 30 days. High: 60 days.", "score": 0.92},
        ],
    },
    {
        "match": ["vulnerability management"],
        "answer": (
            "Yes. We operate a formal vulnerability management program aligned to NIST "
            "SP 800-40. Assets are continuously scanned; findings are triaged by severity "
            "and tracked to remediation against defined SLAs (Critical: 30d, High: 60d, "
            "Medium: 90d). Metrics are reported monthly to security leadership."
        ),
        "confidence": 0.89,
        "citations": [
            {"source_path": "Vulnerability-Management-Policy.pdf", "chunk_text": "Program aligned to NIST SP 800-40. SLAs: Crit 30d, High 60d, Med 90d.", "score": 0.91},
        ],
    },
    {
        "match": ["security awareness", "training"],
        "answer": (
            "All employees and contractors complete mandatory security awareness training "
            "at onboarding and annually thereafter. Phishing simulation exercises are run "
            "monthly. Role-specific training (e.g., secure coding for engineers, privileged "
            "access training for admins) is additionally required."
        ),
        "confidence": 0.89,
        "citations": [
            {"source_path": "Security-Awareness-Program.pdf", "chunk_text": "All personnel complete annual training. Monthly phishing simulations.", "score": 0.90},
        ],
    },
    {
        "match": ["encryption standards"],
        "answer": (
            "We align to NIST-approved cryptographic standards. Data at rest uses AES-256; "
            "data in transit uses TLS 1.2+ (with TLS 1.3 preferred). Deprecated protocols "
            "(SSL, TLS 1.0/1.1) are disabled. Cryptographic controls are reviewed annually "
            "as part of our compliance program."
        ),
        "confidence": 0.90,
        "citations": [
            {"source_path": "Cryptography-Standard.pdf", "chunk_text": "AES-256 at rest; TLS 1.2+ in transit. TLS 1.3 preferred.", "score": 0.92},
        ],
    },
    {
        "match": ["data", "stored"],
        "answer": (
            "Customer data for US-based clients is stored in our primary data centers "
            "located in the United States. Disaster recovery replicas are also maintained "
            "in geographically separated US facilities."
        ),
        "confidence": 0.86,
        "citations": [
            {"source_path": "Data-Residency-Statement.pdf", "chunk_text": "US client data is stored and replicated within US facilities only.", "score": 0.90},
        ],
    },
    {
        "match": ["outside", "united states"],
        "answer": (
            "For US-based customers, data is stored and processed within the United States. "
            "We do not replicate US customer data outside the country. Specific contractual "
            "commitments around data residency may apply — **please have Legal confirm the "
            "specific agreement language for this customer before release.**"
        ),
        "confidence": 0.65,
        "needs_sme": True,
        "citations": [
            {"source_path": "Data-Residency-Statement.pdf", "chunk_text": "US customer data is not replicated outside the US.", "score": 0.88},
        ],
    },
    {
        "match": ["physical access"],
        "answer": (
            "Primary data centers use layered physical controls: perimeter fencing, "
            "badge-controlled entry, biometric access for sensitive zones, 24x7 on-site "
            "security, and continuous CCTV recording with retention per policy. Visitor "
            "access requires pre-authorization and escort."
        ),
        "confidence": 0.89,
        "citations": [
            {"source_path": "Physical-Security-Standard.pdf", "chunk_text": "Layered controls: badge entry, biometrics, 24x7 guards, CCTV.", "score": 0.91},
        ],
    },
    {
        "match": ["breach notification"],
        "answer": (
            "Our contractual breach notification timelines vary by customer agreement and "
            "applicable regulation (GDPR, state breach laws, etc.). **This response must be "
            "reviewed by Legal against the specific customer contract before release.** Do "
            "not quote a specific number of hours without Legal confirmation."
        ),
        "confidence": 0.55,
        "needs_sme": True,
        "citations": [
            {"source_path": "Contracts-Legal-Guidance.pdf", "chunk_text": "Breach notification timelines are contract-specific. Always route through Legal.", "score": 0.93},
        ],
    },
    {
        "match": ["privileged access", "review"],
        "answer": (
            "Privileged access is reviewed and recertified quarterly by system owners. The "
            "process is tracked in our GRC platform, and unresolved recertifications "
            "trigger automated access revocation after the grace period."
        ),
        "confidence": 0.87,
        "citations": [
            {"source_path": "Access-Review-Procedure.pdf", "chunk_text": "Quarterly recertifications; unresolved items trigger auto-revocation.", "score": 0.89},
        ],
    },
]

GENERIC_DRAFT = {
    "answer": (
        "Thank you for the question. This area is covered by our information security "
        "program. A subject-matter expert will provide a detailed response tailored to "
        "this question. **This is a placeholder — please route to the appropriate SME "
        "before release.**"
    ),
    "confidence": 0.35,
    "needs_sme": True,
    "citations": [],
}


def generate_demo_draft(question_text: str) -> Dict[str, Any]:
    """Return a canned draft for a question by matching keywords.

    Used as a fallback when the KB is empty or LLM is unavailable — lets the
    drafting workspace demonstrate the full flow without real infrastructure.
    """
    q = (question_text or "").lower()
    for entry in CANNED_DRAFTS:
        if all(kw in q for kw in entry["match"]):
            return {
                "answer": entry["answer"],
                "confidence": entry["confidence"],
                "needs_sme": entry.get("needs_sme", False),
                "citations": entry.get("citations", []),
                "source": "demo",
            }
    return {
        "answer": GENERIC_DRAFT["answer"],
        "confidence": GENERIC_DRAFT["confidence"],
        "needs_sme": GENERIC_DRAFT["needs_sme"],
        "citations": GENERIC_DRAFT["citations"],
        "source": "demo",
    }


# ------------------------------------------------------------------ Sample KB files
# When the user clicks "Load demo KB" on the KB admin page, these stub files
# appear in the source list so the demo shows what ingested sources look like
# without actually needing real documents.

DEMO_KB_FILENAMES = [
    "the company-InfoSec-Standard-v4.2.pdf",
    "SOC2-TypeII-2025.pdf",
    "KMS-Operating-Procedures.docx",
    "Access-Control-Policy.pdf",
    "Privileged-Access-Standard.pdf",
    "Incident-Response-Plan-v3.pdf",
    "Vulnerability-Management-Policy.pdf",
    "Cryptography-Standard.pdf",
    "Data-Residency-Statement.pdf",
    "Physical-Security-Standard.pdf",
    "Standard-Responses-Library.xlsx",
    "Security-Awareness-Program.pdf",
    "Contracts-Legal-Guidance.pdf",
]
