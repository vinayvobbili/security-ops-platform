#!/usr/bin/env python3
"""
Decrypt the .secrets.age file using age encryption.

This script:
1. Reads the encrypted .secrets.age file
2. Decrypts it to .secrets (plaintext)
3. Reminds you to re-encrypt and delete after editing

Usage:
    python misc_scripts/decrypt_secrets.py
    python misc_scripts/decrypt_secrets.py --force  # Overwrite existing .secrets
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt .secrets.age file using age encryption'
    )
    parser.add_argument(
        '--input',
        default='data/transient/.secrets.age',
        help='Path to encrypted secrets file (default: data/transient/.secrets.age)'
    )
    parser.add_argument(
        '--output',
        default='data/transient/.secrets',
        help='Path to plaintext output file (default: data/transient/.secrets)'
    )
    parser.add_argument(
        '--key',
        default=None,
        help='Path to age private key (default: ~/.config/age/key.txt)'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing .secrets file'
    )

    args = parser.parse_args()

    # Resolve paths
    input_path = project_root / args.input
    output_path = project_root / args.output
    key_path = Path(args.key).expanduser() if args.key else Path.home() / '.config' / 'age' / 'key.txt'

    print("========================================")
    print("Decrypting secrets file")
    print("========================================")
    print()

    # Check encrypted file exists
    if not input_path.exists():
        print(f"✗ Error: Encrypted file not found: {input_path}")
        sys.exit(1)

    # Check key exists
    if not key_path.exists():
        print(f"✗ Error: Age key not found: {key_path}")
        print()
        print("Run the setup script to generate a key:")
        print("  bash scripts/setup_age_encryption.sh")
        sys.exit(1)

    # Check if output already exists
    if output_path.exists() and not args.force:
        print(f"⚠️  Warning: Plaintext file already exists: {output_path}")
        response = input("Overwrite? (y/N): ").strip().lower()
        if response != 'y':
            print("Aborted.")
            sys.exit(0)

    # Perform decryption
    try:
        result = subprocess.run(
            ['age', '-d', '-i', str(key_path), str(input_path)],
            capture_output=True,
            text=True,
            check=True
        )

        output_path.write_text(result.stdout)
        print(f"✓ Decrypted to {output_path}")
        print()
        print("⚠️  IMPORTANT: .secrets is now on disk in plaintext.")
        print("   After editing, re-encrypt and delete it:")
        print()
        print("   python misc_scripts/encrypt_secrets.py --delete-plaintext")

    except FileNotFoundError:
        print("✗ Error: age command not found. Install it with:")
        print("  brew install age      # macOS")
        print("  sudo apt install age  # Ubuntu/Debian")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"✗ Decryption failed: {e.stderr.strip()}")
        sys.exit(1)


if __name__ == '__main__':
    main()
