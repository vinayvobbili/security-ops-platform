"""
Utility for loading encrypted .env files using age encryption.

This module provides secure environment variable loading by:
1. Decrypting .env.age files into memory (never to disk)
2. Loading variables into os.environ
3. Protecting secrets from sudo users who could read plaintext files

Usage:
    from src.utils.env_encryption import load_encrypted_env

    load_encrypted_env()  # Auto-detects paths
    # or
    load_encrypted_env(
        encrypted_path='data/transient/.env.age',
        key_path='~/.config/age/key.txt'
    )
"""

import os
import subprocess
from pathlib import Path
from io import StringIO
from typing import Optional


class EncryptionError(Exception):
    """Raised when encryption/decryption operations fail."""
    pass


def load_encrypted_env(
    encrypted_path: Optional[str] = None,
    key_path: Optional[str] = None,
    fallback_to_plaintext: bool = True
) -> None:
    """
    Load environment variables from .env (plaintext config) and .secrets.age (encrypted secrets).

    File structure:
    - .env: Non-sensitive config (model names, URLs, etc.) - committed to git
    - .secrets: Plaintext secrets (API keys, passwords) - gitignored, not committed
    - .secrets.age: Encrypted secrets - committed to git

    Workflow:
    1. Edit .secrets with your API keys
    2. Run: age -e -r $(age-keygen -y ~/.config/age/key.txt) .secrets > .secrets.age
    3. Delete .secrets (it's in .gitignore)
    4. Commit .secrets.age

    Args:
        encrypted_path: Path to .secrets.age file. Defaults to data/transient/.secrets.age
        key_path: Path to age private key. Defaults to ~/.config/age/key.txt
        fallback_to_plaintext: If True and .secrets.age not found, try loading .secrets

    Raises:
        EncryptionError: If decryption fails or required files are missing
    """
    # Set default paths
    if encrypted_path is None:
        project_root = Path(__file__).parent.parent.parent
        encrypted_path = project_root / 'data' / 'transient' / '.secrets.age'
    else:
        encrypted_path = Path(encrypted_path)

    if key_path is None:
        key_path = Path.home() / '.config' / 'age' / 'key.txt'
    else:
        key_path = Path(key_path).expanduser()

    # Note: This function now only loads encrypted secrets
    # Caller should load plaintext .env separately if needed

    # Check if encrypted secrets file exists
    if not encrypted_path.exists():
        # Try plaintext .secrets as fallback
        plaintext_secrets = encrypted_path.parent / '.secrets'
        if fallback_to_plaintext and plaintext_secrets.exists():
            print(f"⚠️  Using plaintext .secrets file. Encrypt it with:")
            print(f"     age -e -r $(age-keygen -y {key_path}) {plaintext_secrets} > {encrypted_path}")
            load_plaintext_env(plaintext_secrets)
            return

        print(f"⚠️  No encrypted secrets file found: {encrypted_path.name}")
        print(f"     This is OK if you only use .env for non-sensitive config")
        return

    # Check if key exists
    if not key_path.exists():
        raise EncryptionError(
            f"Age key not found: {key_path}\n"
            f"Run: bash scripts/setup_age_encryption.sh"
        )

    # Decrypt to memory
    try:
        result = subprocess.run(
            ['age', '-d', '-i', str(key_path), str(encrypted_path)],
            capture_output=True,
            text=True,
            check=True
        )

        if result.returncode != 0:
            raise EncryptionError(f"Decryption failed: {result.stderr}")

        # Parse and load environment variables (overrides any duplicates from .env)
        _parse_env_content(result.stdout)

        print(f"✓ Loaded encrypted secrets from {encrypted_path.name}")

    except FileNotFoundError:
        raise EncryptionError(
            "age command not found. Install it with:\n"
            "  sudo apt install age  # Ubuntu/Debian\n"
            "  brew install age      # macOS"
        )
    except subprocess.CalledProcessError as e:
        raise EncryptionError(f"Decryption failed: {e.stderr}")


def _parse_env_content(content: str) -> None:
    """Parse .env content and load into os.environ."""
    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue

        # Parse KEY=VALUE
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip()

            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]

            os.environ[key] = value


def load_plaintext_env(env_path: Path) -> None:
    """Load plaintext .env file."""
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
    except ImportError:
        # Manual parsing if python-dotenv not available
        with open(env_path) as f:
            _parse_env_content(f.read())


# Alias for backwards compatibility
_load_plaintext_env = load_plaintext_env


def encrypt_env_file(
    plaintext_path: str,
    output_path: str,
    key_path: Optional[str] = None
) -> None:
    """
    Encrypt a plaintext .env file using age.

    Args:
        plaintext_path: Path to plaintext .env file
        output_path: Where to save .env.age file
        key_path: Path to age private key (to extract public key)

    Raises:
        EncryptionError: If encryption fails
    """
    plaintext_path = Path(plaintext_path)
    output_path = Path(output_path)

    if key_path is None:
        key_path = Path.home() / '.config' / 'age' / 'key.txt'
    else:
        key_path = Path(key_path).expanduser()

    if not plaintext_path.exists():
        raise EncryptionError(f"Plaintext file not found: {plaintext_path}")

    if not key_path.exists():
        raise EncryptionError(f"Age key not found: {key_path}")

    try:
        # Extract public key from private key
        pubkey_result = subprocess.run(
            ['age-keygen', '-y', str(key_path)],
            capture_output=True,
            text=True,
            check=True
        )
        public_key = pubkey_result.stdout.strip()

        # Encrypt file
        with open(plaintext_path, 'rb') as infile:
            result = subprocess.run(
                ['age', '-e', '-r', public_key, '-o', str(output_path)],
                stdin=infile,
                capture_output=True,
                check=True
            )

        print(f"✓ Encrypted {plaintext_path} → {output_path}")
        print(f"  You can now delete the plaintext file for security")

    except FileNotFoundError:
        raise EncryptionError("age or age-keygen not found. Install age first.")
    except subprocess.CalledProcessError as e:
        raise EncryptionError(f"Encryption failed: {e.stderr.decode()}")


if __name__ == '__main__':
    # Test the decryption
    try:
        load_encrypted_env()
        print("\n✓ Environment loaded successfully!")
        print(f"  Loaded {len([k for k in os.environ.keys() if k.isupper()])} variables")
    except EncryptionError as e:
        print(f"✗ Error: {e}")
