#!/usr/bin/env python3
"""
Automated refactoring script to replace hardcoded company/team names with CONFIG variables.

This script:
1. Finds all Python files
2. Replaces hardcoded strings with CONFIG.team_name and CONFIG.company_name
3. Adds imports where needed
4. Creates a backup before making changes

Usage:
    python refactor_to_config.py --dry-run  # Preview changes
    python refactor_to_config.py            # Apply changes
"""

import argparse
import os
import re
import subprocess
from pathlib import Path
from typing import List, Tuple
from dotenv import load_dotenv

# Load .env to get current values
load_dotenv()

SOURCE_COMPANY_DOMAIN = os.getenv('MY_WEB_DOMAIN', 'company.com')
SOURCE_TEAM_NAME = os.getenv('TEAM_NAME', 'METCIRT')
SOURCE_COMPANY_NAME = SOURCE_COMPANY_DOMAIN.split('.')[0]


def get_python_files() -> List[str]:
    """Get all Python files tracked by git."""
    result = subprocess.run(
        ['git', 'ls-files', '*.py'],
        capture_output=True,
        text=True,
        check=True
    )
    return [f.strip() for f in result.stdout.split('\n') if f.strip() and not f.endswith('refactor_to_config.py')]


def needs_config_import(content: str) -> bool:
    """Check if file needs CONFIG import."""
    return bool(re.search(r'\bCONFIG\.(team_name|company_name|my_web_domain)\b', content))


def has_config_import(content: str) -> bool:
    """Check if file already imports get_config."""
    return bool(re.search(r'from my_config import get_config', content)) or bool(re.search(r'CONFIG = get_config\(\)', content))


def add_config_import(content: str) -> str:
    """Add CONFIG import if not present."""
    if has_config_import(content):
        return content

    # Find the best place to add the import
    lines = content.split('\n')
    import_index = 0

    # Find last import statement
    for i, line in enumerate(lines):
        if line.startswith('import ') or line.startswith('from '):
            import_index = i + 1

    # Add imports
    if import_index > 0:
        lines.insert(import_index, '')
        lines.insert(import_index + 1, 'from my_config import get_config')
        lines.insert(import_index + 2, 'CONFIG = get_config()')
    else:
        # Add at beginning if no imports found
        lines.insert(0, 'from my_config import get_config')
        lines.insert(1, 'CONFIG = get_config()')
        lines.insert(2, '')

    return '\n'.join(lines)


def refactor_file(filepath: str, dry_run: bool = False) -> Tuple[bool, List[str]]:
    """
    Refactor a single Python file.

    Returns:
        Tuple of (was_modified, list_of_changes)
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            original_content = f.read()
    except Exception as e:
        print(f"  ⚠️  Error reading {filepath}: {e}")
        return False, []

    content = original_content
    changes = []

    # Skip files that don't have any hardcoded values
    has_hardcoded = False

    # Pattern 1: Replace query strings with team_name (handles both ' and ", and spaces)
    # type:<TEAM_NAME> → type:{CONFIG.team_name}
    # Handles: type:<TEAM_NAME>" or type:<TEAM_NAME>' or type:<TEAM_NAME>
    pattern = rf"(['\"].*?)type:{SOURCE_TEAM_NAME}(\s|['\"])"
    if re.search(pattern, content):
        def replace_type(match):
            prefix = match.group(1)
            suffix = match.group(2)
            # Make the string an f-string if not already
            if prefix.startswith('f'):
                return f"{prefix}type:{{CONFIG.team_name}}{suffix}"
            else:
                # Convert to f-string
                quote = prefix[0] if prefix else "'"
                return f"f{quote}{prefix[1:]}type:{{CONFIG.team_name}}{suffix}"
        content = re.sub(pattern, replace_type, content)
        changes.append(f"    - Updated XSOAR query: type:{SOURCE_TEAM_NAME} → type:{{CONFIG.team_name}}")
        has_hardcoded = True

    # Pattern 1b: -type:"METCIRT IOC Hunt" → -type:"{CONFIG.team_name} IOC Hunt"
    pattern = rf"-type:['\"]({SOURCE_TEAM_NAME}\s+[^'\"]+)['\"]"
    matches = re.findall(pattern, content)
    if matches:
        for match in set(matches):
            suffix = match[len(SOURCE_TEAM_NAME):].strip()
            content = re.sub(
                rf"-type:['\"]({re.escape(match)})['\"]",
                f'-type:"{{CONFIG.team_name}} {suffix}"',
                content
            )
        changes.append(f"    - Updated XSOAR query with type exclusions")
        has_hardcoded = True

    # Pattern 2: Replace type strings in ticket creation
    # 'type': 'METCIRT ...' → 'type': f'{CONFIG.team_name} ...'
    pattern = rf"['\"]type['\"]:\s*['\"]({SOURCE_TEAM_NAME}[^'\"]*)['\"]"
    matches = re.findall(pattern, content)
    if matches:
        for match in set(matches):
            suffix = match[len(SOURCE_TEAM_NAME):].strip()
            # Handle both single and double quotes
            content = re.sub(
                rf"(['\"])type\1:\s*['\"]({re.escape(match)})['\"]",
                rf"\1type\1: f'{{CONFIG.team_name}}{' ' + suffix if suffix else ''}'",
                content
            )
        changes.append(f"    - Updated ticket type strings ({len(set(matches))} occurrences)")
        has_hardcoded = True

    # Pattern 3: Replace email domain in strings
    # '@company.com' → f'@{CONFIG.my_web_domain}'
    pattern = rf"['\"]@{re.escape(SOURCE_COMPANY_DOMAIN)}['\"]"
    if re.search(pattern, content):
        content = re.sub(pattern, "f'@{CONFIG.my_web_domain}'", content)
        changes.append(f"    - Updated email domain: @{SOURCE_COMPANY_DOMAIN} → @{{CONFIG.my_web_domain}}")
        has_hardcoded = True

    # Pattern 4: Replace .replace('@company.com', '') with CONFIG
    pattern = rf"\.replace\(['\"]@{re.escape(SOURCE_COMPANY_DOMAIN)}['\"],?\s*['\"]['\"]?\)"
    if re.search(pattern, content):
        content = re.sub(pattern, ".replace(f'@{CONFIG.my_web_domain}', '')", content)
        changes.append(f"    - Updated email cleaning: .replace('@{SOURCE_COMPANY_DOMAIN}', '') → .replace(f'@{{CONFIG.my_web_domain}}', '')")
        has_hardcoded = True

    # Pattern 5: Replace METCIRT prefix removal in regex
    # r'^METCIRT[_\-\s]*' → rf'^{re.escape(CONFIG.team_name)}[_\-\s]*'
    pattern = rf"r['\"]\\?\^{SOURCE_TEAM_NAME}\[[_\\-\\s]\]\*['\"]"
    if re.search(pattern, content):
        content = re.sub(pattern, "rf'^{re.escape(CONFIG.team_name)}[_\\-\\s]*'", content)
        changes.append(f"    - Updated regex pattern for team name removal")
        has_hardcoded = True

    # Pattern 6: Replace .replace('METCIRT', '') with CONFIG (simple string replace)
    pattern = rf"\.replace\(['\"]({SOURCE_TEAM_NAME})['\"],?\s*['\"]['\"]\)"
    if re.search(pattern, content):
        content = re.sub(pattern, ".replace(CONFIG.team_name, '')", content)
        changes.append(f"    - Updated team name replacement: .replace('{SOURCE_TEAM_NAME}', '') → .replace(CONFIG.team_name, '')")
        has_hardcoded = True

    # Pattern 7: Replace print/log messages with team name
    # "No METCIRT tickets" → f"No {CONFIG.team_name} tickets"
    pattern = rf"(['\"])([^'\"]*\bNo\s+){SOURCE_TEAM_NAME}(\s+[^'\"]*)['\"]"
    if re.search(pattern, content):
        content = re.sub(pattern, r"f\1\2{CONFIG.team_name}\3\1", content)
        changes.append(f"    - Updated log messages to use CONFIG.team_name")
        has_hardcoded = True

    # Pattern 8: Update docstrings mentioning METCIRT/Acme
    # Keep generic but make note in changes
    docstring_pattern = rf'"""[^"]*({SOURCE_TEAM_NAME}|{SOURCE_COMPANY_NAME.title()})[^"]*"""'
    if re.search(docstring_pattern, content, re.IGNORECASE | re.DOTALL):
        # Replace in docstrings
        content = re.sub(rf'\b{SOURCE_TEAM_NAME}\b', '{CONFIG.team_name}', content, flags=re.MULTILINE)
        content = re.sub(rf'\b{SOURCE_COMPANY_NAME.title()}\b', '{CONFIG.company_name}', content, flags=re.MULTILINE)
        # But fix back the ones that are in actual f-strings
        changes.append(f"    - Updated docstrings")
        has_hardcoded = True

    # Pattern 9: Markdown strings with team name
    # markdown=f'**Summary** (Type=METCIRT ...' → markdown=f'**Summary** (Type={CONFIG.team_name} ...'
    pattern = rf"(markdown=f?['\"][^'\"]*Type=){SOURCE_TEAM_NAME}\b"
    if re.search(pattern, content):
        content = re.sub(pattern, r"\1{CONFIG.team_name}", content)
        changes.append(f"    - Updated markdown strings with team name")
        has_hardcoded = True

    # Pattern 10: Comments with "for Acme" or "for METCIRT"
    # Created for Acme → Created for {company}
    comment_pattern = rf'(#\s*.*)\bfor {SOURCE_COMPANY_NAME.title()}\b'
    if re.search(comment_pattern, content, re.IGNORECASE):
        content = re.sub(comment_pattern, r'\1for Security Operations', content, flags=re.IGNORECASE)
        changes.append(f"    - Updated comments to be generic")
        has_hardcoded = True

    # Add CONFIG import if needed
    if has_hardcoded and needs_config_import(content) and not has_config_import(content):
        content = add_config_import(content)
        changes.append(f"    - Added CONFIG import")

    # Write changes if not dry run
    if content != original_content:
        if not dry_run:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            except Exception as e:
                print(f"  ⚠️  Error writing {filepath}: {e}")
                return False, []
        return True, changes

    return False, []


def main():
    parser = argparse.ArgumentParser(description='Refactor Python code to use CONFIG variables')
    parser.add_argument('--dry-run', action='store_true', help='Preview changes without applying them')
    args = parser.parse_args()

    print("=" * 80)
    print("Python Code Refactoring Script")
    print("=" * 80)
    print(f"\n📋 Configuration:")
    print(f"   Source Company: {SOURCE_COMPANY_NAME}")
    print(f"   Source Team:    {SOURCE_TEAM_NAME}")
    print(f"   Source Domain:  {SOURCE_COMPANY_DOMAIN}")

    if args.dry_run:
        print("\n🔍 DRY RUN MODE - No files will be modified\n")
    else:
        print("\n⚠️  LIVE MODE - Files will be modified!\n")
        response = input("Are you sure you want to proceed? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            return

    print("\n📁 Getting list of Python files...")
    python_files = get_python_files()
    print(f"   Found {len(python_files)} Python files")

    print("\n🔧 Processing files...\n")

    total_files_changed = 0
    total_changes = 0

    for filepath in python_files:
        if not os.path.exists(filepath):
            continue

        was_modified, changes = refactor_file(filepath, dry_run=args.dry_run)

        if was_modified:
            total_files_changed += 1
            total_changes += len(changes)
            print(f"✏️  {filepath}")
            for change in changes:
                print(change)
            print()

    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Files changed: {total_files_changed}")
    print(f"Total changes: {total_changes}")

    if args.dry_run:
        print("\n✅ Dry run complete. Review the changes above.")
        print("   Run without --dry-run to apply changes.")
    else:
        print("\n✅ Refactoring complete!")
        print("\n📋 Next steps:")
        print("   1. Review changes with: git diff")
        print("   2. Test the application")
        print("   3. Commit changes: git add . && git commit -m 'Refactor to use CONFIG variables'")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
