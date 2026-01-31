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

# Common TLDs for domain extraction
COMMON_TLDS = {
    'com', 'net', 'org', 'io', 'co', 'info', 'biz', 'edu', 'gov', 'mil',
    'ru', 'cn', 'uk', 'de', 'fr', 'jp', 'kr', 'br', 'in', 'au', 'ca',
    'it', 'es', 'nl', 'pl', 'se', 'no', 'fi', 'dk', 'ch', 'at', 'be',
    'ir', 'kp', 'su', 'cc', 'tv', 'me', 'ly', 'to', 'xyz', 'top', 'site',
    'online', 'club', 'app', 'dev', 'cloud', 'tech', 'pro', 'agency',
    'work', 'live', 'store', 'shop', 'space', 'world', 'today', 'life',
    'onion',  # Tor hidden services
}

# Minimal benign domains to exclude during extraction (reduces unnecessary VT API calls)
# VT filtering in analyzer.py handles the rest - this is just a fast first-pass filter
BENIGN_DOMAINS = {
    # Test/placeholder domains
    'example.com', 'localhost', 'test.com', 'company.com',
    # Common email providers (email addresses still extracted, just not as domain IOCs)
    'gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'live.com',
    # Internal domains - never hunt for these
    'acme.com', 'acme-internal.net', 'acmecorp.com',
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
            if not (ip.startswith('10.') or
                    ip.startswith('192.168.') or
                    ip.startswith('172.16.') or ip.startswith('172.17.') or
                    ip.startswith('172.18.') or ip.startswith('172.19.') or
                    ip.startswith('172.2') or ip.startswith('172.30.') or ip.startswith('172.31.')):
                ips.append(ip)
                seen.add(ip)

    return ips


def extract_domains(text: str) -> List[str]:
    """Extract domain names from text."""
    # Build TLD pattern
    tld_pattern = '|'.join(re.escape(tld) for tld in COMMON_TLDS)

    # Match domains with common TLDs
    pattern = rf'\b(?:[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.)+(?:{tld_pattern})\b'
    matches = re.findall(pattern, text.lower())

    # Filter out benign domains and deduplicate
    domains = []
    seen = set()
    for domain in matches:
        if domain not in seen and domain not in BENIGN_DOMAINS:
            # Skip if it looks like a version number (e.g., 1.2.3)
            if not re.match(r'^\d+\.\d+\.\d+$', domain):
                domains.append(domain)
                seen.add(domain)

    return domains


def extract_urls(text: str) -> List[str]:
    """Extract URLs from text."""
    pattern = r'https?://[^\s<>"\')\]]+[^\s<>"\')\].,;:!?]'
    matches = re.findall(pattern, text, re.IGNORECASE)

    # Deduplicate
    urls = list(dict.fromkeys(matches))
    return urls[:20]  # Limit to 20 URLs


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

    # Strategy 1: Match known APT names (with word boundaries to avoid partial matches)
    if known_apt_names:
        for apt_name in known_apt_names:
            # Skip very short names (3 chars or less) to avoid false positives
            if len(apt_name) <= 3:
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


def extract_malware_families(text: str) -> List[str]:
    """
    Extract malware family/tool names from text.

    Includes RATs, infostealers, backdoors, loaders, and offensive tools.
    """
    malware = set()

    # Known malware families, RATs, infostealers, backdoors, loaders
    known_malware = [
        # RATs and backdoors
        'Cobalt Strike', 'CobaltStrike', 'Beacon',
        'Mimikatz', 'Meterpreter', 'Metasploit',
        'AsyncRAT', 'QuasarRAT', 'Quasar', 'NjRAT', 'njRAT',
        'DarkComet', 'Remcos', 'RemcosRAT', 'NanoCore',
        'Poison Ivy', 'PoisonIvy', 'Gh0st', 'Gh0stRAT',
        'PlugX', 'ShadowPad', 'Winnti',
        'InvisibleFerret', 'BeaverTail',  # North Korea tools
        'AppleJeus', 'TraderTraitor',
        'KEYMARBLE', 'HARDRAIN', 'BADCALL',
        # Infostealers
        'RedLine', 'Redline Stealer', 'Raccoon', 'Raccoon Stealer',
        'Vidar', 'Lumma', 'LummaC2', 'Lumma Stealer',
        'StealC', 'Rhadamanthys', 'Stealc',
        'FormBook', 'Formbook', 'XLoader',
        'AgentTesla', 'Agent Tesla', 'SnakeKeylogger', 'Snake Keylogger',
        'Pony', 'Lokibot', 'LokiBot', 'AZORult', 'Azorult',
        # Loaders and droppers
        'Emotet', 'TrickBot', 'Trickbot', 'BazarLoader', 'Bazar',
        'IcedID', 'QakBot', 'Qakbot', 'QBot', 'Qbot',
        'BumbleBee', 'Bumblebee', 'PikaBot', 'Pikabot',
        'SmokeLoader', 'Smokeloader', 'GuLoader', 'Guloader',
        'SocGholish', 'FakeUpdates',
        # Other malware families
        'SystemBC', 'Sliver', 'Brute Ratel', 'BruteRatel',
        'Havoc', 'Nighthawk', 'Mythic',
        'PyLangGhost', 'GolangGhost',  # North Korea tools
        'KANDYKORN', 'SugarLoader', 'SUGARLOADER',
        'RustBucket', 'KandyKorn',
        # Additional tools and frameworks
        'Empire', 'PowerShell Empire',
        'BloodHound', 'SharpHound',
        'Rubeus', 'Certify', 'Seatbelt',
        'LaZagne', 'SharpDPAPI',
        'Impacket', 'PsExec', 'WMIExec',
        # Windows-based backdoors and frameworks
        'Winos4.0', 'Winos', 'WinosStager',
    ]

    for malware_name in known_malware:
        # Use word boundaries to match whole words only
        pattern = re.compile(r'\b' + re.escape(malware_name) + r'\b', re.IGNORECASE)
        match = pattern.search(text)
        if match:
            # Normalize the name (use the matched case or standardize)
            malware.add(match.group())

    return list(malware)


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

    entities = ExtractedEntities(
        ips=extract_ips(clean_text),
        domains=extract_domains(clean_text),
        urls=extract_urls(clean_text),
        hashes=extract_hashes(clean_text),
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
