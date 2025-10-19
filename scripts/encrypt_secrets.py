#!/usr/bin/env python3
"""
Encrypt the .env file using age encryption.

This script:
1. Reads the plaintext .env file
2. Encrypts it to .env.age
3. Optionally deletes the plaintext version for security

Usage:
    python scripts/encrypt_secrets.py
    python scripts/encrypt_secrets.py --delete-plaintext
    python scripts/encrypt_secrets.py --force  # Overwrite existing .env.age
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.env_encryption import encrypt_env_file, EncryptionError


def main():
    parser = argparse.ArgumentParser(
        description='Encrypt .env file using age encryption'
    )
    parser.add_argument(
        '--plaintext',
        default='data/transient/.env',
        help='Path to plaintext .env file (default: data/transient/.env)'
    )
    parser.add_argument(
        '--output',
        default='data/transient/.env.age',
        help='Path to encrypted output file (default: data/transient/.env.age)'
    )
    parser.add_argument(
        '--key',
        default=None,
        help='Path to age private key (default: ~/.config/age/key.txt)'
    )
    parser.add_argument(
        '--delete-plaintext',
        action='store_true',
        help='Delete plaintext .env file after encryption'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Overwrite existing .env.age file'
    )

    args = parser.parse_args()

    # Resolve paths
    plaintext_path = project_root / args.plaintext
    output_path = project_root / args.output

    print("========================================")
    print("Encrypting .env file")
    print("========================================")
    print()

    # Check if plaintext exists
    if not plaintext_path.exists():
        print(f"✗ Error: Plaintext file not found: {plaintext_path}")
        print()
        print("Make sure your .env file exists at:")
        print(f"  {plaintext_path}")
        sys.exit(1)

    # Check if output already exists
    if output_path.exists() and not args.force:
        print(f"⚠️  Warning: Encrypted file already exists: {output_path}")
        response = input("Overwrite? (y/N): ").strip().lower()
        if response != 'y':
            print("Aborted.")
            sys.exit(0)

    # Perform encryption
    try:
        encrypt_env_file(
            plaintext_path=str(plaintext_path),
            output_path=str(output_path),
            key_path=args.key
        )
        print()
        print("✓ Encryption successful!")
        print()

        # Handle plaintext deletion
        if args.delete_plaintext:
            response = input(
                "⚠️  Delete plaintext .env file? This cannot be undone! (yes/no): "
            ).strip().lower()
            if response == 'yes':
                plaintext_path.unlink()
                print(f"✓ Deleted {plaintext_path}")
                print()
                print("⚠️  IMPORTANT: Your plaintext .env has been deleted.")
                print("   To edit secrets, you must decrypt, edit, and re-encrypt:")
                print()
                print("   # Decrypt temporarily")
                print(f"   age -d -i ~/.config/age/key.txt {output_path} > {plaintext_path}")
                print()
                print("   # Edit the file")
                print(f"   nano {plaintext_path}")
                print()
                print("   # Re-encrypt")
                print("   python scripts/encrypt_secrets.py --delete-plaintext")
            else:
                print("Plaintext file kept.")
                print()
                print("For security, you should delete it manually:")
                print(f"  rm {plaintext_path}")
        else:
            print("Next steps:")
            print()
            print("1. Test the encryption:")
            print("   python src/utils/env_encryption.py")
            print()
            print("2. Update your application to use encrypted secrets")
            print()
            print("3. Delete the plaintext .env for security:")
            print(f"   rm {plaintext_path}")
            print()
            print("   Or re-run with --delete-plaintext flag:")
            print("   python scripts/encrypt_secrets.py --delete-plaintext")

    except EncryptionError as e:
        print(f"✗ Encryption failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
