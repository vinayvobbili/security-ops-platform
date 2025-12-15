#!/usr/bin/env python3
"""
Sanitization script for making the IR repository public-ready.

This script replaces sensitive company-specific references with generic placeholders
in all git-tracked files. It reads configuration from environment variables.

Usage:
    python sanitize_for_public.py --dry-run  # Preview changes
    python sanitize_for_public.py            # Apply changes

    # Override target values
    python sanitize_for_public.py --company-name "Acme Corp" --team-name "SecOps"
"""

import os
import re
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Read source values from environment
SOURCE_COMPANY_DOMAIN = os.getenv('MY_WEB_DOMAIN', 'company.com')
SOURCE_TEAM_NAME = os.getenv('TEAM_NAME', 'METCIRT')

# Extract company name from domain (company.com -> acme)
SOURCE_COMPANY_NAME = SOURCE_COMPANY_DOMAIN.split('.')[0]


def get_replacement_mappings(target_company: str = 'company', target_team: str = 'sirt') -> Dict[str, str]:
    """
    Generate replacement mappings dynamically based on source and target values.

    Args:
        target_company: Target company name to replace with (default: 'company')
        target_team: Target team name to replace with (default: 'sirt')

    Returns:
        Dictionary of regex patterns to replacement strings
    """
    # Capitalize variants
    source_company_title = SOURCE_COMPANY_NAME.title()
    source_company_upper = SOURCE_COMPANY_NAME.upper()
    source_company_lower = SOURCE_COMPANY_NAME.lower()

    source_team_upper = SOURCE_TEAM_NAME.upper()
    source_team_lower = SOURCE_TEAM_NAME.lower()
    source_team_title = SOURCE_TEAM_NAME.title()

    target_company_title = target_company.title()
    target_company_upper = target_company.upper()
    target_company_lower = target_company.lower()

    target_team_upper = target_team.upper()
    target_team_lower = target_team.lower()
    target_team_title = target_team.title()

    return {
        # Company name replacements (order matters - most specific first)
        rf'\b{source_company_upper}\b': target_company_upper,
        rf'\b{source_company_title}\b': target_company_title,
        rf'\b{source_company_lower}\b': target_company_lower,

        # Team name replacements
        rf'\b{source_team_upper}\b': target_team_upper,
        rf'\b{source_team_title}\b': target_team_title,
        rf'\b{source_team_lower}\b': target_team_lower,
        rf'\b{source_team_upper.replace("CIRT", "-CIRT")}\b': target_team_upper,  # Handle MET-CIRT

        # Domain replacements
        rf'@{SOURCE_COMPANY_DOMAIN}': f'@example.com',
        rf'{SOURCE_COMPANY_DOMAIN}': 'example.com',
        r'\.metnet\.net': '.internal.example.com',
        r'metnet\.net': 'internal.example.com',
        rf'{source_team_lower}-lab-12\.metnet\.net': 'lab-server.example.com',
        r'lab-vm-12\.metnet\.net': 'lab-vm.example.com',
        rf'gdnr\.{SOURCE_COMPANY_DOMAIN}': 'internal-app.example.com',

        # Infrastructure URLs
        rf'https://api\.{SOURCE_COMPANY_DOMAIN}/{source_company_lower}/production': f'https://api.example.com/servicenow/production',
        rf'https://{source_company_lower}portal-api\.cloud\.tanium\.com': 'https://cloud-api.tanium.example.com',
        rf'https://onprem\.tanium\.{SOURCE_COMPANY_DOMAIN}': 'https://onprem.tanium.example.com',
        rf'https://infoblox\.{SOURCE_COMPANY_DOMAIN}': 'https://infoblox.example.com',

        # ServiceNow endpoints
        rf'/api/x_metli_{source_company_lower}_it/': '/api/x_company_it/',
        rf'https://{source_company_lower}prod\.service-now\.com': 'https://company-prod.service-now.com',

        # Azure DevOps paths
        rf'{source_company_title}-Cyber-Security': 'Cyber-Security',
        rf'{source_company_title}-Cyber-Platforms': 'Cyber-Platforms',
        rf'{source_company_title}-US-2': 'Company-Org-2',
        rf'{source_company_title}-US': 'Company-Org',

        # Hostnames (generic patterns)
        r'USAZEMETV038E\.METNET\.NET': 'HOST001.INTERNAL.EXAMPLE.COM',
        rf'VV10-MLKR-029\.{source_company_lower}\.co\.kr': 'TEST-HOST-001.example.com',
        r'USHZK3C64\.metnet\.net': 'TEST-HOST-002.internal.example.com',

        # LaunchAgent/Service names
        rf'com\.{source_company_lower}\.soc-bot-preloader': 'com.company.soc-bot-preloader',

        # Personal emails (specific people mentioned in code)
        rf'chelsea\.koester@{SOURCE_COMPANY_DOMAIN}': 'automation.lead@example.com',
        rf'kyle\.stephens@{SOURCE_COMPANY_DOMAIN}': 'ops.lead@example.com',
        rf'nate\.isaksen@{SOURCE_COMPANY_DOMAIN}': 'metrics.receiver@example.com',
        rf'user@{SOURCE_COMPANY_DOMAIN}': 'user@example.com',

        # Personal paths - make them relative or generic
        rf'/Users/user@{SOURCE_COMPANY_DOMAIN}/PycharmProjects/IR': './project',
        rf'/Users/user@{SOURCE_COMPANY_DOMAIN}/Library/LaunchAgents': '~/Library/LaunchAgents',

        # Field names (using source team name)
        rf'{source_team_lower}triagetime': f'{target_team_lower}triagetime',
        rf'{source_team_lower}lessonslearnedtime': f'{target_team_lower}lessonslearnedtime',
        rf'{source_team_lower}investigatetime': f'{target_team_lower}investigatetime',
        rf'{source_team_lower}eradicationtime': f'{target_team_lower}eradicationtime',
        rf'{source_team_lower}closuretime': f'{target_team_lower}closuretime',
        rf'{source_team_lower}incidentnotificationsla': f'{target_team_lower}incidentnotificationsla',

        # Specific branding in comments
        rf'Created for {source_company_title} Security Operations': 'Security Operations Automation',
        rf'{source_company_title} branding': f'{target_company_title} branding',
        rf'{source_company_title} Brand': f'{target_company_title} Brand',

        # CSS variable names
        rf'--{source_company_lower}-': f'--{target_company_lower}-',

        # File names in config
        rf'"{source_team_upper.replace("CIRT", "-CIRT")} SHIELD Daily Work Schedule\.xlsx"': f'"{target_team_upper} Daily Work Schedule.xlsx"',

        # Test credentials
        rf'user: {source_team_lower}, pass: {source_team_lower}': 'user: demo, pass: demo',
        rf'username: {source_team_lower}, password: {source_team_lower}': 'username: demo, password: demo',
        rf'Username: `{source_team_lower}`': 'Username: `demo`',
        rf'Password: `{source_team_lower}`': 'Password: `demo`',

        # Regional data
        rf'Malaysia - AM{source_company_title}': f'Malaysia - {target_company_title}-APAC',
    }

# Files to skip (binary, generated, or special cases)
SKIP_PATTERNS = [
    r'\.png$',
    r'\.jpg$',
    r'\.jpeg$',
    r'\.gif$',
    r'\.webp$',
    r'\.ico$',
    r'\.svg$',  # SVG files might contain fontawesome metadata
    r'\.whl$',
    r'\.pyc$',
    r'\.pem$',
    r'\.key$',
    r'\.lock$',
    r'\.bak$',
    r'/\.git/',
    r'package-lock\.json$',
    r'SECURITY_AUDIT_REPORT\.md$',  # Don't sanitize the audit report itself
]


def get_tracked_files() -> List[str]:
    """Get list of all git-tracked files."""
    result = subprocess.run(
        ['git', 'ls-files'],
        capture_output=True,
        text=True,
        check=True
    )
    return [f.strip() for f in result.stdout.split('\n') if f.strip()]


def should_skip_file(filepath: str) -> bool:
    """Check if file should be skipped based on patterns."""
    for pattern in SKIP_PATTERNS:
        if re.search(pattern, filepath):
            return True
    return False


def sanitize_file(filepath: str, replacements: Dict[str, str], dry_run: bool = False) -> Tuple[int, List[str]]:
    """
    Sanitize a single file.

    Args:
        filepath: Path to file to sanitize
        replacements: Dictionary of pattern -> replacement mappings
        dry_run: If True, don't write changes to file

    Returns:
        Tuple of (number_of_changes, list_of_changes)
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_content = f.read()
    except Exception as e:
        print(f"  ⚠️  Error reading {filepath}: {e}")
        return 0, []

    content = original_content
    changes = []

    # Apply all replacements
    for pattern, replacement in replacements.items():
        if re.search(pattern, content):
            matches = len(re.findall(pattern, content))
            content = re.sub(pattern, replacement, content)
            # Simplify pattern display for readability
            pattern_display = pattern.replace(r'\b', '').replace(r'\.', '.')
            changes.append(f"    - Replaced '{pattern_display}' → '{replacement}' ({matches} occurrences)")

    # Write changes if not dry run
    if content != original_content:
        if not dry_run:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                print(f"  ⚠️  Error writing {filepath}: {e}")
                return 0, []
        return len(changes), changes

    return 0, []


def main():
    parser = argparse.ArgumentParser(description='Sanitize repository for public release')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without applying them')
    parser.add_argument('--company-name', default='company',
                       help='Target company name to replace with (default: company)')
    parser.add_argument('--team-name', default='sirt',
                       help='Target team name to replace with (default: sirt)')
    args = parser.parse_args()

    print("=" * 80)
    print("Repository Sanitization Script")
    print("=" * 80)
    print(f"\n📋 Configuration:")
    print(f"   Source Company: {SOURCE_COMPANY_NAME.title()} (from .env: MY_WEB_DOMAIN)")
    print(f"   Source Team:    {SOURCE_TEAM_NAME} (from .env: TEAM_NAME)")
    print(f"   Target Company: {args.company_name}")
    print(f"   Target Team:    {args.team_name}")

    # Generate replacement mappings based on configuration
    replacements = get_replacement_mappings(args.company_name, args.team_name)

    if args.dry_run:
        print("\n🔍 DRY RUN MODE - No files will be modified\n")
    else:
        print("\n⚠️  LIVE MODE - Files will be modified!\n")
        response = input("Are you sure you want to proceed? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            return

    print("\n📁 Getting list of tracked files...")
    tracked_files = get_tracked_files()
    print(f"   Found {len(tracked_files)} tracked files")

    print("\n🔧 Processing files...\n")

    total_files_changed = 0
    total_changes = 0
    files_with_changes = []

    for filepath in tracked_files:
        if should_skip_file(filepath):
            continue

        if not os.path.exists(filepath):
            continue

        num_changes, changes = sanitize_file(filepath, replacements, dry_run=args.dry_run)

        if num_changes > 0:
            total_files_changed += 1
            total_changes += num_changes
            files_with_changes.append((filepath, changes))
            print(f"✏️  {filepath}")
            for change in changes:
                print(change)
            print()

    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Files changed: {total_files_changed}")
    print(f"Total replacements: {total_changes}")

    if args.dry_run:
        print("\n✅ Dry run complete. Review the changes above.")
        print("   Run without --dry-run to apply changes.")
    else:
        print("\n✅ Sanitization complete!")
        print("\n📋 Next steps:")
        print("   1. Review changes with: git diff")
        print("   2. Test the application locally")
        print("   3. Update docs/SECURITY_AUDIT_REPORT.md")
        print("   4. Commit changes: git add . && git commit -m 'Sanitize for public release'")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
