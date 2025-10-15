#!/usr/bin/env python3
"""
Split environment variables into plaintext (.env) and encrypted (.env.age) files.

This script helps migrate from a single encrypted .env.age to a dual-file setup:
- .env (plaintext, non-sensitive config like model names)
- .env.age (encrypted, secrets like API keys)

Usage:
    python scripts/split_env_files.py
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.env_encryption import load_encrypted_env, encrypt_env_file

# Non-sensitive variables (safe for .env plaintext file)
NON_SENSITIVE_KEYS = {
    'OLLAMA_LLM_MODEL',
    'OLLAMA_EMBEDDING_MODEL',
    'TEAM_NAME',
    'TRIAGE_TIMER',
    'LESSONS_LEARNED_TIME',
    'INVESTIGATION_TIME',
    'ERADICATION_TIME',
    'CLOSURE_TIME',
    'AZDO_ORGANIZATION',
    'AZDO_DE_PROJECT',
    'AZDO_RE_PROJECT',
    'AZDO_PLATFORMS_PARENT_URL',
    'AZDO_REA_PARENT_URL',
    'AZDO_REA_ITERATION',
    'XSOAR_PROD_UI_BASE_URL',
    'XSOAR_DEV_UI_BASE_URL',
    'XSOAR_PROD_API_BASE_URL',
    'XSOAR_DEV_API_BASE_URL',
    'SNOW_BASE_URL',
    'WEBEX_API_URL',
    'TANIUM_CLOUD_API_URL',
    'TANIUM_ONPREM_API_URL',
    'ZSCALER_BASE_URL',
    'INFOBLOX_BASE_URL',
    'PALO_ALTO_HOST',
    'XSOAR_LISTS_FILENAME',
    'SECOPS_STAFFING_FILENAME',
    'MY_NAME',
    'MY_WEB_DOMAIN',
    'RESP_ENG_AUTO_LEAD',
    'RESP_ENG_OPS_LEAD',
    'EFFICACY_CHARTS_RECEIVER',
    'MY_EMAIL_ADDRESS',
    'JUMP_SERVER_HOST',
    'TWILIO_WHATSAPP_NUMBER',
    'MY_WHATSAPP_NUMBER',
    'WHATSAPP_RECEIVER_NUMBERS',
}


def split_environment():
    """Split current environment into plaintext and encrypted files."""

    project_root = Path(__file__).parent.parent
    env_dir = project_root / 'data' / 'transient'

    plaintext_path = env_dir / '.env'
    secrets_temp_path = env_dir / '.env.secrets.tmp'
    encrypted_path = env_dir / '.env.age'
    backup_path = env_dir / '.env.age.backup'

    print("🔐 Environment File Splitter")
    print("=" * 60)

    # Backup existing .env.age
    if encrypted_path.exists():
        import shutil
        shutil.copy2(encrypted_path, backup_path)
        print(f"✓ Backed up {encrypted_path.name} → {backup_path.name}")

    # Load current environment
    print(f"\n📖 Loading current environment from {encrypted_path.name}...")
    try:
        # Save current env state
        old_env = dict(os.environ)

        # Load encrypted env
        load_encrypted_env()

        # Get newly loaded vars
        all_vars = {k: v for k, v in os.environ.items() if k not in old_env or old_env[k] != v}

    except Exception as e:
        print(f"✗ Error loading environment: {e}")
        return 1

    # Split into non-sensitive and sensitive
    plaintext_vars = {}
    secret_vars = {}

    for key, value in all_vars.items():
        if key in NON_SENSITIVE_KEYS:
            plaintext_vars[key] = value
        else:
            secret_vars[key] = value

    print(f"\n📊 Found {len(all_vars)} total variables:")
    print(f"   • {len(plaintext_vars)} non-sensitive (→ .env)")
    print(f"   • {len(secret_vars)} secrets (→ .env.age)")

    # Write plaintext .env
    print(f"\n✍️  Writing plaintext config to {plaintext_path.name}...")
    with open(plaintext_path, 'w') as f:
        f.write("# Non-Sensitive Configuration\n")
        f.write("# Safe to commit to git - secrets are in .env.age\n\n")

        # Group by category
        categories = {
            'Ollama': ['OLLAMA_'],
            'Team': ['TEAM_'],
            'Timers': ['_TIME', '_TIMER'],
            'Azure DevOps': ['AZDO_'],
            'XSOAR': ['XSOAR_'],
            'ServiceNow': ['SNOW_'],
            'External Services': ['WEBEX_', 'TANIUM_', 'ZSCALER_', 'INFOBLOX_', 'PALO_'],
            'Files': ['_FILENAME'],
            'Personal': ['MY_', 'RESP_', 'EFFICACY_', 'JUMP_'],
            'Communication': ['WHATSAPP_', 'TWILIO_'],
        }

        written = set()
        for category, prefixes in categories.items():
            category_vars = {k: v for k, v in sorted(plaintext_vars.items())
                           if any(p in k for p in prefixes) and k not in written}
            if category_vars:
                f.write(f"# {category}\n")
                for key, value in category_vars.items():
                    f.write(f"{key}={value}\n")
                    written.add(key)
                f.write("\n")

        # Write remaining uncategorized vars
        remaining = {k: v for k, v in sorted(plaintext_vars.items()) if k not in written}
        if remaining:
            f.write("# Other Configuration\n")
            for key, value in remaining.items():
                f.write(f"{key}={value}\n")

    print(f"✓ Created {plaintext_path.name}")

    # Write secrets to temp file
    print(f"\n✍️  Writing secrets to temporary file...")
    with open(secrets_temp_path, 'w') as f:
        f.write("# SECRETS - DO NOT COMMIT THIS FILE\n")
        f.write("# This will be encrypted to .env.age\n\n")
        for key, value in sorted(secret_vars.items()):
            f.write(f"{key}={value}\n")

    print(f"✓ Created temporary secrets file")

    # Re-encrypt secrets
    print(f"\n🔐 Re-encrypting secrets to {encrypted_path.name}...")
    try:
        encrypt_env_file(str(secrets_temp_path), str(encrypted_path))

        # Delete temp file
        secrets_temp_path.unlink()
        print(f"✓ Deleted temporary secrets file")

    except Exception as e:
        print(f"✗ Error encrypting: {e}")
        print(f"⚠️  Temporary secrets file left at: {secrets_temp_path}")
        return 1

    print("\n" + "=" * 60)
    print("✅ Environment split complete!")
    print(f"\n📁 Files created:")
    print(f"   • {plaintext_path.name} - Non-sensitive config (commit to git)")
    print(f"   • {encrypted_path.name} - Encrypted secrets (commit to git)")
    print(f"   • {backup_path.name} - Backup of original (keep for safety)")

    print(f"\n💡 Next steps:")
    print(f"   1. Review {plaintext_path.name} and update as needed")
    print(f"   2. Test: python -c 'from my_config import get_config; print(get_config().ollama_llm_model)'")
    print(f"   3. Commit both .env and .env.age to git")
    print(f"   4. Delete {backup_path.name} once verified working")

    return 0


if __name__ == '__main__':
    sys.exit(split_environment())
