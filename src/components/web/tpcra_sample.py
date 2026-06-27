"""Sample data for the Third-Party Risk Assessment page.

A single fully-worked sample assessment for a FICTIONAL vendor, so a reviewer can
open the page and see the whole flow — evidence in, controls evaluated, risk
synthesized, DD Form exportable — without having to run a real vendor first.

The evidence documents below are written so the result is a realistic MIX: most
controls are Met, a few are deliberately unaddressed so the reviewer sees the
"Not Met — evidence not provided" handling exactly as it behaves on real data.

Everything here is invented. No real vendor, person, or document is referenced.
"""

SAMPLE_VENDOR = {
    "vendor_name": "Helios Data Systems",
    "title": "2026 Annual Cyber Due Diligence — Helios Analytics Platform",
    "vendor_tier": "Tier 2 — High",
    "assessment_type": "Initial Due Diligence",
    "aravo_ref": "ARV-SAMPLE-0042",
    "scope_notes": "SaaS analytics platform processing confidential business data; "
                   "cloud-hosted on a major IaaS provider. Sample assessment for review.",
}

# Each entry becomes an indexed vendor-evidence document on the sample assessment.
SAMPLE_DOCS = [
    {
        "filename": "Helios_SOC2_TypeII_2025.txt",
        "content": """HELIOS DATA SYSTEMS — SOC 2 TYPE II REPORT (INDEPENDENT SERVICE AUDITOR'S REPORT)

Report type: SOC 2 Type II.
Trust Services Criteria in scope: Security, Availability, and Confidentiality.
Privacy and Processing Integrity are NOT in scope for this examination.
Coverage period: October 1, 2024 through September 30, 2025 (12 months).
Auditor: independent CPA firm. Opinion: unqualified, except as noted below.

Subservice organizations: Helios uses a major cloud infrastructure-as-a-service
provider for hosting. The report uses the CARVE-OUT method for this subservice
organization; the IaaS provider's controls are not included in the scope of this
examination. Complementary subservice organization controls are listed in
Section 4.

Noted exceptions:
1. For 2 of 25 sampled terminations, access removal exceeded the 24-hour target
   (completed within 3 business days). Management response: an automated
   deprovisioning workflow was implemented in Q3 2025 to close this gap.
2. For 1 of 12 sampled change tickets, evidence of peer code review could not be
   located. Management response: branch-protection rules now enforce mandatory
   review before merge.

Controls tested covered logical access, encryption, change management, incident
response, vulnerability management, and availability/backup. No other exceptions
were noted.""",
    },
    {
        "filename": "Helios_Information_Security_Policy.txt",
        "content": """HELIOS DATA SYSTEMS — INFORMATION SECURITY POLICY (v6.2)

1. Program & Governance. Helios maintains a formal information security program
   aligned to ISO 27001 and the NIST Cybersecurity Framework. The program is
   owned by the Chief Information Security Officer (CISO) and reviewed and
   approved by executive leadership at least annually.

2. Risk Management. A formal risk assessment is performed at least annually and
   upon significant change. Identified risks are recorded in a risk register and
   tracked through remediation with assigned owners and due dates.

3. Policy Lifecycle. All security policies are reviewed, updated, and re-approved
   at least annually and are published to all personnel via the internal portal.

4. Security Awareness. All personnel complete security awareness training at hire
   and at least annually thereafter. Phishing simulations are conducted quarterly.

5. Personnel Security. Background checks are performed on all new hires where
   permitted by law. Confidentiality agreements are required as a condition of
   employment.""",
    },
    {
        "filename": "Helios_Access_Control_Standard.txt",
        "content": """HELIOS DATA SYSTEMS — ACCESS CONTROL & IDENTITY STANDARD (v4.0)

Multi-Factor Authentication. MFA is enforced for all remote access (VPN and SSO)
and for all privileged and administrative accounts, without exception.

Least Privilege. Access is granted on a least-privilege, role-based basis.
Access entitlements are reviewed quarterly by system owners; exceptions are
documented and re-approved.

Joiner/Mover/Leaver. Access is provisioned through a ticketed workflow. Upon
termination, access is revoked through an automated deprovisioning workflow,
with a target of within 24 hours of the HR event.

Privileged Access. Administrative accounts are unique and individually
attributable; shared administrative credentials are prohibited. All privileged
sessions are logged and the logs are monitored by the security operations team.

Password Policy. Minimum 14 characters, complexity enforced, and credentials are
stored using salted, adaptive hashing.""",
    },
    {
        "filename": "Helios_Data_Protection_Standard.txt",
        "content": """HELIOS DATA SYSTEMS — DATA PROTECTION & ENCRYPTION STANDARD (v3.1)

Encryption in Transit. All data in transit is encrypted using TLS 1.2 or higher.
TLS 1.0 and 1.1 are disabled across all public endpoints.

Encryption at Rest. All customer data at rest is encrypted using AES-256.
Encryption is applied at the storage and database layers.

Key Management. Cryptographic keys are managed in a dedicated key management
service (KMS). Access to key material is restricted to a small number of
authorized administrators and is logged. Keys are rotated at least annually.

Data Classification, Retention & Disposal. Data is classified (Public, Internal,
Confidential, Restricted). Confidential and Restricted customer data is retained
per the contractual retention schedule and securely destroyed at end of life
using cryptographic erasure or certified media destruction.""",
    },
    {
        "filename": "Helios_Network_and_VulnMgmt_Overview.txt",
        "content": """HELIOS DATA SYSTEMS — NETWORK SECURITY & VULNERABILITY MANAGEMENT OVERVIEW

Network Security. Production environments are segmented from corporate networks.
Stateful firewalls restrict ingress/egress, and an intrusion detection and
prevention system (IDS/IPS) monitors production traffic. Administrative access to
production requires MFA and passes through a bastion host.

Endpoint Protection. An endpoint detection and response (EDR) agent is deployed
to all servers and workstations and is centrally managed by the security team.

Vulnerability Management. Authenticated vulnerability scans run weekly.
Remediation service levels: Critical within 14 days, High within 30 days,
Medium within 90 days. Critical findings are escalated to system owners.

Penetration Testing. An independent third party performs application and network
penetration testing at least annually. Findings are tracked to remediation and a
summary attestation is available upon request.""",
    },
    {
        "filename": "Helios_Business_Continuity_Summary.txt",
        "content": """HELIOS DATA SYSTEMS — BUSINESS CONTINUITY & DISASTER RECOVERY SUMMARY

Helios maintains documented Business Continuity (BCP) and Disaster Recovery (DR)
plans. The plans are reviewed annually and tested at least annually through a
combination of tabletop exercises and failover tests.

Recovery objectives for the production analytics platform:
- Recovery Time Objective (RTO): 4 hours.
- Recovery Point Objective (RPO): 1 hour.

Backups of customer data are performed daily, encrypted, and replicated to a
geographically separate region. Backup restoration is tested as part of the
annual DR exercise.

Incident Response. Helios maintains a documented incident response plan that
defines roles, severity levels, and escalation paths. Customers are notified of
confirmed security incidents affecting their data without undue delay and in
accordance with contractual commitments.""",
    },
]

# NOTE on the deliberate gaps: nothing above describes a secure software
# development lifecycle with SAST/DAST or code-review tooling beyond the SOC 2
# exception note, nor explicit security-event log centralization/retention
# periods, nor management of the vendor's own fourth parties beyond the carved-out
# IaaS provider. Those controls should land as "Not Met — evidence not provided",
# which is exactly the behavior worth showing a reviewer.
