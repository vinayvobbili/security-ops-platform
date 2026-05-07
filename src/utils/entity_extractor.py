"""
Entity Extractor for Threat Intelligence

Extracts IOCs (IPs, domains, hashes, URLs, CVEs) and threat actor names
from unstructured text for enrichment with threat intelligence APIs.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import List, Set

logger = logging.getLogger(__name__)

# tldextract for proper TLD validation (uses Mozilla Public Suffix List)
import tldextract

# Benign domains to exclude during extraction.
# IOC hunt flow bypasses VT filtering, so this list must be comprehensive.
BENIGN_DOMAINS = {
    # Test/placeholder domains
    'example.com', 'localhost', 'test.com', 'company.com',
    # Common email providers (email addresses still extracted, just not as domain IOCs)
    'gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'live.com',
    # Internal/company domains - never hunt for these
    'acme.com', 'internal.local', 'acmecorp.com',
    'the-company.com',
    # Package registries - legitimate infrastructure, not IOCs
    'npmjs.org', 'registry.npmjs.org', 'yarn.npmjs.org',
    'yarnpkg.com', 'registry.yarnpkg.com',
    'github.com', 'raw.githubusercontent.com', 'gist.github.com',
    'pypi.org', 'files.pythonhosted.org',
    'rubygems.org', 'nuget.org', 'crates.io',
    'packagist.org', 'mvnrepository.com', 'maven.org',
    'docker.io', 'docker.com', 'hub.docker.com',
    # Cybersecurity vendors - appear as references in tippers, not IOCs
    'paloaltonetworks.com', 'unit42.paloaltonetworks.com',
    'crowdstrike.com', 'falcon.crowdstrike.com',
    'mandiant.com', 'cloud.google.com',
    'microsoft.com', 'learn.microsoft.com', 'security.microsoft.com',
    'cisco.com', 'talosintelligence.com',
    'fortinet.com', 'fortiguard.com',
    'sentinelone.com', 'sentinellabs.com',
    'trendmicro.com',
    'sophos.com', 'news.sophos.com',
    'symantec.com', 'broadcom.com',
    'mcafee.com', 'trellix.com',
    'fireeye.com',
    'elastic.co', 'elastic.github.io',
    'proofpoint.com',
    'checkpoint.com', 'research.checkpoint.com',
    'recordedfuture.com',
    'sekoia.io',
    'group-ib.com',
    'kaspersky.com', 'securelist.com',
    'eset.com', 'welivesecurity.com',
    'bitdefender.com',
    'malwarebytes.com',
    'cybereason.com',
    'rapid7.com',
    'qualys.com',
    'tenable.com',
    'dragos.com',
    'volexity.com',
    'huntress.com',
    'infoblox.com',
    # Threat intel / research references
    'mitre.org', 'attack.mitre.org', 'cve.mitre.org',
    'krebsonsecurity.com',
    'bleepingcomputer.com',
    'thehackernews.com',
    'therecord.media',
    'darkreading.com',
    'securityweek.com',
    'threatpost.com',
    'cyberscoop.com',
    'schneier.com',
    'nist.gov', 'nvd.nist.gov',
    'cisa.gov', 'us-cert.cisa.gov',
    'cert.org',
    'virustotal.com',
    'shodan.io',
    'abuse.ch', 'bazaar.abuse.ch', 'urlhaus.abuse.ch', 'threatfox.abuse.ch',
    'otx.alienvault.com', 'alienvault.com',
    'hybrid-analysis.com',
    'any.run',
    'joesandbox.com', 'joesecurity.org',
    'app.any.run',
    'urlscan.io',
    'whois.domaintools.com', 'domaintools.com',
    'abuseipdb.com',
    # Cloud / CDN infrastructure
    'amazonaws.com', 'azure.com', 'azureedge.net',
    'cloudflare.com', 'cloudfront.net',
    'akamai.com', 'akamaitechnologies.com',
    'googleapis.com',
    'windows.net', 'office365.com', 'office.com',
    'sharepoint.com', 'onedrive.com',
    'google.com', 'gstatic.com',
    'linkedin.com', 'twitter.com', 'x.com',
    'wikipedia.org', 'medium.com',
}

# Known benign IPs to exclude
BENIGN_IPS = {
    '127.0.0.1', '0.0.0.0', '255.255.255.255',
    '8.8.8.8', '8.8.4.4',  # Google DNS
    '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
}


@dataclass
class ThreatActorInfo:
    """Threat actor with alias information."""
    name: str  # The name as it appeared in text
    common_name: str = ""  # Standardized common name from database
    region: str = ""  # Attribution region (e.g., "Russia", "North Korea")
    all_names: List[str] = field(default_factory=list)  # All known aliases

    def get_aliases_display(self, max_aliases: int = 5) -> str:
        """Get formatted alias string for display."""
        if not self.all_names:
            return ""
        # Exclude the matched name from aliases display
        aliases = [n for n in self.all_names if n.lower() != self.name.lower()][:max_aliases]
        return ", ".join(aliases) if aliases else ""


@dataclass
class ExtractedEntities:
    """Container for extracted entities from text."""
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    filenames: List[str] = field(default_factory=list)  # Malicious filenames (install.ps1, etc.)
    hashes: dict = field(default_factory=lambda: {'md5': [], 'sha1': [], 'sha256': []})
    cves: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)  # Simple list for backward compat
    threat_actors_enriched: List[ThreatActorInfo] = field(default_factory=list)  # With alias info
    malware_families: List[str] = field(default_factory=list)  # Malware tools/families
    mitre_techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs

    def is_empty(self) -> bool:
        """Check if no entities were extracted."""
        return (
            not self.ips and
            not self.domains and
            not self.urls and
            not self.filenames and
            not self.hashes['md5'] and
            not self.hashes['sha1'] and
            not self.hashes['sha256'] and
            not self.cves and
            not self.emails and
            not self.threat_actors and
            not self.malware_families and
            not self.mitre_techniques
        )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'ips': self.ips,
            'domains': self.domains,
            'urls': self.urls,
            'filenames': self.filenames,
            'hashes': self.hashes,
            'cves': self.cves,
            'emails': self.emails,
            'threat_actors': self.threat_actors,
            'threat_actors_enriched': [
                {
                    'name': ta.name,
                    'common_name': ta.common_name,
                    'region': ta.region,
                    'all_names': ta.all_names,
                }
                for ta in self.threat_actors_enriched
            ],
            'malware_families': self.malware_families,
            'mitre_techniques': self.mitre_techniques,
        }

    def summary(self) -> str:
        """Get a summary of extracted entities."""
        parts = []
        if self.ips:
            parts.append(f"{len(self.ips)} IPs")
        if self.domains:
            parts.append(f"{len(self.domains)} domains")
        if self.urls:
            parts.append(f"{len(self.urls)} URLs")
        if self.filenames:
            parts.append(f"{len(self.filenames)} filenames")
        hash_count = len(self.hashes['md5']) + len(self.hashes['sha1']) + len(self.hashes['sha256'])
        if hash_count:
            parts.append(f"{hash_count} hashes")
        if self.cves:
            parts.append(f"{len(self.cves)} CVEs")
        if self.emails:
            parts.append(f"{len(self.emails)} emails")
        if self.threat_actors:
            parts.append(f"{len(self.threat_actors)} threat actors")
        if self.malware_families:
            parts.append(f"{len(self.malware_families)} malware families")
        if self.mitre_techniques:
            parts.append(f"{len(self.mitre_techniques)} MITRE techniques")
        return ", ".join(parts) if parts else "No entities found"


def extract_ips(text: str) -> List[str]:
    """Extract IPv4 addresses from text."""
    # Match IPv4 addresses, excluding common benign ones
    pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    matches = re.findall(pattern, text)

    # Filter out benign IPs and deduplicate
    ips = []
    seen = set()
    for ip in matches:
        if ip not in seen and ip not in BENIGN_IPS:
            # Skip private ranges
            if (ip.startswith('10.') or
                    ip.startswith('192.168.') or
                    ip.startswith('172.16.') or ip.startswith('172.17.') or
                    ip.startswith('172.18.') or ip.startswith('172.19.') or
                    ip.startswith('172.2') or ip.startswith('172.30.') or ip.startswith('172.31.')):
                continue

            # Skip version number patterns (e.g., 122.0.0.0 from Chrome/122.0.0.0 User-Agent)
            # These typically end with .0.0.0 or .0.0 and aren't real threat IPs
            parts = ip.split('.')
            if parts[1] == '0' and parts[2] == '0' and parts[3] == '0':
                continue  # x.0.0.0 pattern - likely a version number
            if parts[2] == '0' and parts[3] == '0' and int(parts[0]) > 100:
                continue  # High first octet with .0.0 ending - likely version number

            ips.append(ip)
            seen.add(ip)

    return ips


# File extensions that are also valid TLDs - filter these as they're usually filenames not domains
FILE_EXTENSION_TLDS = {
    'sh', 'py', 'pl', 'rs', 'ps', 'cc', 'py', 'md', 'so', 'la', 'do', 'to',
    'ai', 'st', 'fm', 'am', 'dj', 'gs', 'ms', 'lk', 'im', 'ws', 'nu', 'tk',
}


def extract_domains(text: str) -> List[str]:
    """Extract domain names from text using tldextract for proper TLD validation.

    Uses Mozilla Public Suffix List via tldextract - no manual TLD maintenance needed.
    """
    # Match anything that looks like a domain (word.word pattern)
    # tldextract will validate if it's actually a valid TLD
    pattern = r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
    candidates = re.findall(pattern, text.lower())

    # Filter using tldextract for proper TLD validation
    domains = []
    seen = set()
    for candidate in candidates:
        if candidate in seen or candidate in BENIGN_DOMAINS:
            continue
        # Also skip subdomains of benign domains (e.g., portal.the-company.com)
        if any(candidate.endswith('.' + bd) for bd in BENIGN_DOMAINS):
            continue

        # Skip if it looks like a version number (e.g., 1.2.3)
        if re.match(r'^\d+\.\d+\.\d+$', candidate):
            continue

        # Use tldextract to validate - it uses Mozilla Public Suffix List
        extracted = tldextract.extract(candidate)

        # Valid domain must have both a domain part and a recognized suffix
        if not (extracted.domain and extracted.suffix):
            continue

        # Filter out filenames that look like domains (install.sh, script.py)
        # These TLDs are commonly file extensions - only accept if domain part
        # looks like a real domain (has multiple parts or is known malicious pattern)
        if extracted.suffix in FILE_EXTENSION_TLDS:
            # If there's no subdomain and domain looks like a filename, skip it
            # e.g., "install.sh" -> domain="install", subdomain="", suffix="sh"
            # vs "openclaw.ai" -> domain="openclaw", subdomain="", suffix="ai"
            # Heuristic: filenames are typically common words, domains are brandnames
            common_filenames = {'install', 'setup', 'script', 'run', 'start', 'init',
                               'main', 'index', 'test', 'build', 'deploy', 'config'}
            if extracted.domain.lower() in common_filenames and not extracted.subdomain:
                continue

        domains.append(candidate)
        seen.add(candidate)

    return domains


def _url_has_benign_domain(url: str) -> bool:
    """Check if a URL's domain is in the benign domains list."""
    # Strip protocol
    domain_part = re.sub(r'^https?://', '', url.lower())
    # Strip path
    domain_part = domain_part.split('/')[0]
    # Strip port
    domain_part = domain_part.split(':')[0]

    if domain_part in BENIGN_DOMAINS:
        return True
    # Check if it's a subdomain of a benign domain (e.g., www.paloaltonetworks.com)
    if any(domain_part.endswith('.' + bd) for bd in BENIGN_DOMAINS):
        return True
    return False


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text, including paths without protocol.

    Captures both:
    - Full URLs: https://example.com/path
    - URL paths: example.com/path (without protocol)

    This is important for hunting package registry paths like
    registry.npmjs.org/openclaw/ where the domain is benign but
    the path indicates a malicious package.
    """
    urls = []
    seen = set()

    # Pattern 1: Full URLs with protocol
    full_url_pattern = r'https?://[^\s<>"\')\]]+[^\s<>"\')\].,;:!?]'
    for match in re.findall(full_url_pattern, text, re.IGNORECASE):
        if match.lower() not in seen and not _url_has_benign_domain(match):
            urls.append(match)
            seen.add(match.lower())

    # Pattern 2: URL paths without protocol (domain.tld/path)
    # Must have a path component (/) to distinguish from plain domains
    path_pattern = r'\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/[^\s<>"\')\]]+[^\s<>"\')\].,;:!?/]'
    for match in re.findall(path_pattern, text.lower()):
        # The pattern captures groups, so reconstruct the full match
        pass  # This pattern doesn't work well with groups

    # Better approach: match domain/path combinations
    path_pattern2 = r'\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}/[^\s<>"\')\]]+)'
    for match in re.finditer(path_pattern2, text, re.IGNORECASE):
        url_path = match.group(1).rstrip('.,;:!?')
        # Must have meaningful path (not just domain/)
        if '/' in url_path and len(url_path.split('/', 1)[1]) > 0:
            # Add https:// prefix for consistency
            full_url = f"https://{url_path}"
            if full_url.lower() not in seen and not _url_has_benign_domain(full_url):
                urls.append(full_url)
                seen.add(full_url.lower())

    return urls[:30]  # Limit to 30 URLs


def extract_filenames(text: str, urls: List[str] = None) -> List[str]:
    """Extract malicious script/executable filenames from text and URLs.

    Looks for:
    - Script files: .ps1, .sh, .bat, .cmd, .vbs, .js, .py
    - Executables: .exe, .dll, .msi, .scr
    - Documents with macros: .doc, .docm, .xls, .xlsm
    - Archives: .zip, .rar, .7z, .iso

    Args:
        text: Text to extract from
        urls: Optional list of URLs to extract filenames from

    Returns:
        List of unique filenames
    """
    filenames = []
    seen = set()

    # Extensions that indicate potentially malicious files
    # Note: .com is excluded because it conflicts with domain names (github.com)
    suspicious_extensions = {
        # Scripts
        'ps1', 'sh', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
        # Executables (excluding .com to avoid domain false positives)
        'exe', 'dll', 'msi', 'scr', 'pif',
        # Documents with macros
        'docm', 'xlsm', 'pptm', 'dotm', 'xltm',
        # Archives (can contain malware)
        'iso', 'img', 'vhd', 'vhdx',
        # Other
        'hta', 'lnk', 'jar', 'msc',
    }

    # Pattern to match filenames with suspicious extensions
    # Matches: install.ps1, malware.exe, script.sh, etc.
    ext_pattern = '|'.join(re.escape(ext) for ext in suspicious_extensions)
    filename_pattern = rf'\b([a-zA-Z0-9_\-\.]+\.(?:{ext_pattern}))\b'

    for match in re.finditer(filename_pattern, text, re.IGNORECASE):
        filename = match.group(1)
        if filename.lower() not in seen:
            filenames.append(filename)
            seen.add(filename.lower())

    # Also extract filenames from URLs
    if urls:
        for url in urls:
            # Get the last path component
            path = url.split('/')[-1]
            if path and '.' in path:
                ext = path.rsplit('.', 1)[-1].lower()
                if ext in suspicious_extensions and path.lower() not in seen:
                    filenames.append(path)
                    seen.add(path.lower())

    return filenames[:20]  # Limit to 20 filenames


def refang_text(text: str) -> str:
    """
    Convert defanged IOCs back to normal format for extraction.

    Handles common defanging patterns used in threat intel reports:
    - [.] or [dot] -> .
    - [@] or [at] -> @
    - hxxp -> http
    - [://] -> ://
    """
    result = text
    # Domain/IP defanging
    result = re.sub(r'\[\.\]', '.', result)
    result = re.sub(r'\[dot\]', '.', result, flags=re.IGNORECASE)
    # Email defanging
    result = re.sub(r'\[@\]', '@', result)
    result = re.sub(r'\[at\]', '@', result, flags=re.IGNORECASE)
    # URL defanging
    result = re.sub(r'hxxp', 'http', result, flags=re.IGNORECASE)
    result = re.sub(r'\[://\]', '://', result)
    return result


def extract_emails(text: str) -> List[str]:
    """Extract email addresses from text."""
    # Standard email pattern
    pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    matches = re.findall(pattern, text, re.IGNORECASE)

    # Deduplicate and lowercase
    emails = list(dict.fromkeys(email.lower() for email in matches))
    return emails[:20]  # Limit to 20 emails


def extract_hashes(text: str) -> dict:
    """Extract file hashes (MD5, SHA1, SHA256) from text."""
    hashes = {'md5': [], 'sha1': [], 'sha256': []}

    # SHA256 (64 hex chars) - check first to avoid partial matches
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    sha256_matches = re.findall(sha256_pattern, text)
    hashes['sha256'] = list(dict.fromkeys(h.lower() for h in sha256_matches))

    # SHA1 (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha1_matches = re.findall(sha1_pattern, text)
    # Filter out SHA256 prefixes
    sha256_prefixes = {h[:40] for h in hashes['sha256']}
    hashes['sha1'] = list(dict.fromkeys(
        h.lower() for h in sha1_matches if h.lower() not in sha256_prefixes
    ))

    # MD5 (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    md5_matches = re.findall(md5_pattern, text)
    # Filter out SHA1/SHA256 prefixes
    sha1_prefixes = {h[:32] for h in hashes['sha1']}
    sha256_prefixes_32 = {h[:32] for h in hashes['sha256']}
    hashes['md5'] = list(dict.fromkeys(
        h.lower() for h in md5_matches
        if h.lower() not in sha1_prefixes and h.lower() not in sha256_prefixes_32
    ))

    return hashes


def extract_cves(text: str) -> List[str]:
    """Extract CVE identifiers from text."""
    pattern = r'\bCVE-\d{4}-\d{4,}\b'
    matches = re.findall(pattern, text, re.IGNORECASE)

    # Normalize to uppercase and deduplicate
    cves = list(dict.fromkeys(cve.upper() for cve in matches))
    return cves


def extract_mitre_procedures(text: str) -> dict:
    """Extract MITRE technique procedure summaries from tipper text.

    Parses the tipper MITRE section format:
        T1005: Data from Local System - File manager plugin enables browsing...
        T1552.003: Unsecured Credentials: Bash History - Environment-variable scanner...

    Returns:
        {technique_id: "Technique Name - Procedure description"}
    """
    procedures = {}
    # Match: T1xxx[.xxx]: Technique Name - Procedure text
    # The technique name may contain colons (e.g., "Unsecured Credentials: Bash History")
    pattern = re.compile(r'(T1\d{3}(?:\.\d{3})?)\s*:\s*(.+?)\s*-\s*(.+)')
    for line in text.split('\n'):
        m = pattern.search(line.strip())
        if m:
            tech_id = m.group(1).upper()
            tech_name = m.group(2).strip()
            proc_text = m.group(3).strip()
            procedures[tech_id] = f"{tech_name} - {proc_text}"
    return procedures


def extract_mitre_techniques(text: str) -> List[str]:
    """Extract MITRE ATT&CK technique IDs from text.

    Matches patterns like:
    - T1059 (technique)
    - T1059.001 (sub-technique)
    - TA0001 (tactic - less common but useful)
    """
    # Match technique IDs: T followed by 4 digits, optionally with .NNN sub-technique
    technique_pattern = r'\bT1\d{3}(?:\.\d{3})?\b'
    matches = re.findall(technique_pattern, text, re.IGNORECASE)

    # Normalize to uppercase and deduplicate, preserving order
    techniques = list(dict.fromkeys(t.upper() for t in matches))
    return techniques


def extract_threat_actors(text: str, known_apt_names: Set[str] = None) -> List[str]:
    """
    Extract threat actor names from text.

    Uses multiple strategies:
    1. Match against known APT names database (if provided)
    2. Match APT/UNC/FIN patterns (APT28, UNC2452, FIN7)
    3. Match CamelCase names that look like threat actors

    Args:
        text: Text to search
        known_apt_names: Set of known APT names for exact matching

    Returns:
        List of unique threat actor names found
    """
    actors = set()

    # Common English words that are real APT names but cause too many false positives
    apt_name_blocklist = {'lead'}

    # Strategy 1: Match known APT names (with word boundaries to avoid partial matches)
    if known_apt_names:
        for apt_name in known_apt_names:
            # Skip very short names (3 chars or less) to avoid false positives
            if len(apt_name) <= 3:
                continue
            if apt_name.lower() in apt_name_blocklist:
                continue
            # Use word boundaries to match whole words only
            pattern = re.compile(r'\b' + re.escape(apt_name) + r'\b', re.IGNORECASE)
            match = pattern.search(text)
            if match:
                actors.add(match.group())

    # Strategy 2: Match APT/UNC/FIN/TA patterns
    apt_patterns = [
        r'\bAPT[-]?\d+\b',           # APT28, APT-28
        r'\bUNC\d+\b',                # UNC2452
        r'\bFIN\d+\b',                # FIN7
        r'\bTA\d+\b',                 # TA505
        r'\bDEV-\d+\b',               # DEV-0537
        r'\bSTORM-\d+\b',             # STORM-0558
    ]
    for pattern in apt_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        actors.update(m.upper() for m in matches)

    # Strategy 3: Match well-known threat actor names (with word boundaries)
    well_known_actors = [
        # APT groups
        'Lazarus', 'Lazarus Group',
        'Fancy Bear', 'Cozy Bear',
        'Sandworm', 'Turla',
        'Kimsuky', 'Charming Kitten',
        'OceanLotus', 'Ocean Lotus',
        'Equation Group',
        'Scattered Spider',
        'Nobelium', 'Midnight Blizzard',
        'Volt Typhoon', 'Salt Typhoon',
        # Ransomware families
        'ALPHV', 'BlackCat',
        'LockBit', 'Conti', 'REvil',
        'CrazyHunter', 'Akira', 'Play',
        'Royal', 'Black Basta', 'BlackBasta',
        'Cl0p', 'Clop', 'Cuba', 'Hive',
        'Medusa', 'Rhysida', 'BianLian',
        'NoEscape', 'Cactus', 'Hunters International',
        'Qilin', 'INC Ransom', 'RansomHub',
        'DragonForce', 'Fog', 'Lynx',
    ]
    for actor in well_known_actors:
        # Use word boundaries to avoid matching "Conti" in "continues"
        pattern = re.compile(r'\b' + re.escape(actor) + r'\b', re.IGNORECASE)
        match = pattern.search(text)
        if match:
            actors.add(match.group())

    # Strategy 4: Catch "X ransomware" pattern (e.g., "CrazyHunter ransomware")
    # Only match proper noun names - CamelCase (CrazyHunter) or capitalized (Akira)
    # Case-sensitive to avoid matching "the ransomware", "go-based ransomware", etc.
    ransomware_pattern = re.compile(r'\b([A-Z][a-z]+(?:[A-Z][a-z0-9]*)*)\s+ransomware\b')
    # Skip common words, verbs (from MITRE descriptions), and generic terms
    false_positives = {
        'The', 'This', 'That', 'New', 'Old', 'Some', 'Any', 'Each', 'Our', 'Their',
        'Executed', 'Propagated', 'Deployed', 'Distributed', 'Disguised', 'Downloaded',
        'Encrypted', 'Delivered', 'Launched', 'Installed', 'Targeted', 'Modified',
        'Prince',  # Often appears as "fork of Prince ransomware" - context, not actor
    }
    for match in ransomware_pattern.finditer(text):
        name = match.group(1)
        # Skip false positives and names < 4 chars
        if name not in false_positives and len(name) >= 4:
            actors.add(name)

    return list(actors)


def load_known_malware_names() -> tuple:
    """Load known malware/tool names from MITRE ATT&CK dataset.

    Returns:
        (all_names: Set[str], alias_map: dict) where alias_map maps
        lowercase name -> canonical MITRE name.
    """
    global _malware_names_cache, _malware_alias_map_cache

    if _malware_names_cache is not None:
        return _malware_names_cache, _malware_alias_map_cache

    try:
        from services.mitre_attack_data import get_attack_malware_names
        entries = get_attack_malware_names()
    except Exception as e:
        logger.debug(f"Could not load MITRE malware names: {e}")
        _malware_names_cache = set()
        _malware_alias_map_cache = {}
        return _malware_names_cache, _malware_alias_map_cache

    all_names = set()
    alias_map = {}  # lowercase -> canonical name
    for entry in entries:
        canonical = entry['name']
        for alias in entry.get('aliases', []):
            all_names.add(alias)
            alias_map[alias.lower()] = canonical

    _malware_names_cache = all_names
    _malware_alias_map_cache = alias_map
    logger.debug(f"Loaded {len(all_names)} MITRE malware/tool names")
    return all_names, alias_map


# Common English words that happen to be MITRE malware/tool names
MALWARE_BLOCKLIST = {
    'anchor', 'chaos', 'empire', 'expand', 'flame', 'havoc',
    'james', 'kevin', 'milan', 'mango', 'meteor', 'net', 'ninja',
    'ping', 'rover', 'royal', 'ruler', 'shark', 'snake', 'spark',
    'solar', 'page', 'play',
}

# Windows/system utilities that MITRE tracks as "tools" but aren't malware families.
# These are LOLBins — legitimate tools abused by attackers.
SYSTEM_TOOL_BLOCKLIST = {
    'arp', 'at', 'attrib', 'bitsadmin', 'certutil', 'cipher.exe',
    'cmd', 'dsquery', 'esentutl', 'forfiles', 'ftp', 'ifconfig',
    'ipconfig', 'nbtstat', 'nbtscan', 'net', 'netsh', 'netstat',
    'nltest', 'ping', 'psexec', 'pwdump', 'rclone', 'reg', 'route',
    'schtasks', 'sdelete', 'systeminfo', 'tasklist', 'tor', 'wevtutil',
    # Legitimate remote access tools
    'connectwise', 'quick assist',
}


def extract_malware_families(text: str, hashes: dict = None) -> List[str]:
    """Extract malware family names from text using MITRE ATT&CK dataset.

    Uses MITRE's curated malware and tool names (~784 entries, ~1060 names+aliases).
    Three-layer false-positive defense:
    1. Skip names <= 3 chars (e.g. 'at', 'cmd', 'ftp')
    2. Case-sensitive matching for single-word names; case-insensitive for multi-word
    3. Blocklist for common English words that are also MITRE names

    When an alias matches, normalizes to the canonical MITRE name.
    """
    all_names, alias_map = load_known_malware_names()
    if not all_names:
        return []

    matched = set()

    for name in all_names:
        # Layer 1: skip short names
        if len(name) <= 3:
            continue

        # Layer 3: blocklist (common words + system utilities)
        name_lower = name.lower()
        if name_lower in MALWARE_BLOCKLIST or name_lower in SYSTEM_TOOL_BLOCKLIST:
            continue

        # Layer 2: case sensitivity based on word count
        is_multi_word = ' ' in name
        flags = re.IGNORECASE if is_multi_word else 0
        pattern = re.compile(r'\b' + re.escape(name) + r'\b', flags)
        if pattern.search(text):
            canonical = alias_map.get(name_lower, name)
            # Also check canonical name against blocklists
            canon_lower = canonical.lower()
            if canon_lower in MALWARE_BLOCKLIST or canon_lower in SYSTEM_TOOL_BLOCKLIST:
                continue
            matched.add(canonical)

    return sorted(matched)


def _get_apt_database_path() -> str:
    """Get absolute path to APT database file."""
    import os
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(project_root, 'data', 'transient', 'de', 'APTAKAcleaned.xlsx')


def load_known_apt_names() -> Set[str]:
    """
    Load known APT names from the APT names database.

    Returns empty set if database is not available.
    """
    try:
        import os
        from src.components.apt_names_fetcher import get_all_apt_names

        apt_file = _get_apt_database_path()

        if os.path.exists(apt_file):
            names = get_all_apt_names(file_path=apt_file)
            return set(names) if names else set()
        else:
            logger.debug(f"APT database not found at {apt_file}")
            return set()
    except Exception as e:
        logger.debug(f"Could not load APT names database: {e}")
        return set()


# Cache for APT alias index to avoid reloading
_apt_alias_index_cache: dict = None

# Cache for MITRE malware/tool names
_malware_names_cache: Set[str] = None
_malware_alias_map_cache: dict = None


def load_apt_alias_index() -> dict:
    """
    Load the APT alias index for cross-referencing names.

    Returns dict mapping lowercase name -> actor info with all aliases.
    Cached after first load.
    """
    global _apt_alias_index_cache

    if _apt_alias_index_cache is not None:
        return _apt_alias_index_cache

    try:
        import os
        from src.components.apt_names_fetcher import build_apt_alias_index

        apt_file = _get_apt_database_path()

        if os.path.exists(apt_file):
            _apt_alias_index_cache = build_apt_alias_index(file_path=apt_file)
            return _apt_alias_index_cache
        else:
            logger.debug(f"APT database not found at {apt_file}")
            _apt_alias_index_cache = {}
            return {}
    except Exception as e:
        logger.debug(f"Could not load APT alias index: {e}")
        _apt_alias_index_cache = {}
        return {}


def extract_entities(text: str, include_apt_database: bool = True) -> ExtractedEntities:
    """
    Extract all entity types from text.

    Args:
        text: Text to extract entities from
        include_apt_database: Whether to load and match against APT names database

    Returns:
        ExtractedEntities with all extracted IOCs and threat actors
    """
    if not text:
        return ExtractedEntities()

    # Clean HTML tags if present
    clean_text = re.sub(r'<[^>]+>', ' ', text)
    clean_text = re.sub(r'\s+', ' ', clean_text)

    # Refang defanged IOCs (convert [.] to ., [@] to @, etc.)
    clean_text = refang_text(clean_text)

    # Load APT names and alias index if requested
    known_apt_names = set()
    alias_index = {}
    if include_apt_database:
        known_apt_names = load_known_apt_names()
        alias_index = load_apt_alias_index()

    # Extract raw threat actor names
    raw_actors = extract_threat_actors(clean_text, known_apt_names)

    # Enrich threat actors with alias information
    threat_actors_enriched = []
    seen_common_names = set()  # Avoid duplicates when same actor matched by different names

    for actor_name in raw_actors:
        actor_info = alias_index.get(actor_name.lower())

        if actor_info:
            common_name = actor_info.get('common_name', actor_name)

            # Skip if we already have this actor (matched by another alias)
            if common_name.lower() in seen_common_names:
                continue
            seen_common_names.add(common_name.lower())

            enriched = ThreatActorInfo(
                name=actor_name,
                common_name=common_name,
                region=actor_info.get('region', ''),
                all_names=actor_info.get('all_names', []),
            )
        else:
            # No database match, just use the raw name
            enriched = ThreatActorInfo(
                name=actor_name,
                common_name=actor_name,
                region='',
                all_names=[],
            )
        threat_actors_enriched.append(enriched)

    # Extract hashes first so we can use them for VT malware family lookup
    extracted_hashes = extract_hashes(clean_text)

    # Extract URLs first so we can get filenames from them
    extracted_urls = extract_urls(clean_text)

    entities = ExtractedEntities(
        ips=extract_ips(clean_text),
        domains=extract_domains(clean_text),
        urls=extracted_urls,
        filenames=extract_filenames(clean_text, urls=extracted_urls),
        hashes=extracted_hashes,
        cves=extract_cves(clean_text),
        emails=extract_emails(clean_text),
        threat_actors=raw_actors,
        threat_actors_enriched=threat_actors_enriched,
        malware_families=extract_malware_families(clean_text),
        mitre_techniques=extract_mitre_techniques(clean_text),
    )

    if not entities.is_empty():
        logger.info(f"Extracted entities: {entities.summary()}")

    return entities


# CLI for testing
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    test_text = """
    APT28 (also known as Fancy Bear) has been observed using Cobalt Strike
    to target organizations. The campaign uses C2 infrastructure at 185.123.45.67
    and evil-domain.ru. Malware hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 (MD5).
    Exploits CVE-2021-44228 (Log4Shell) and CVE-2023-12345.
    """

    if len(sys.argv) > 1:
        test_text = " ".join(sys.argv[1:])

    print("Extracting entities from text...")
    print("-" * 60)

    entities = extract_entities(test_text)

    print(f"\nIPs: {entities.ips}")
    print(f"Domains: {entities.domains}")
    print(f"URLs: {entities.urls}")
    print(f"Hashes (MD5): {entities.hashes['md5']}")
    print(f"Hashes (SHA1): {entities.hashes['sha1']}")
    print(f"Hashes (SHA256): {entities.hashes['sha256']}")
    print(f"CVEs: {entities.cves}")
    print(f"Threat Actors: {entities.threat_actors}")
    print(f"\nSummary: {entities.summary()}")
