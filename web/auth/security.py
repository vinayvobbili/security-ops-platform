"""Password hashing + opaque-token generation/verification."""
from __future__ import annotations

import hashlib
import secrets

from werkzeug.security import check_password_hash, generate_password_hash

MIN_PASSWORD_LEN = 6
PAT_PREFIX = 'irp_'
EMAIL_VERIFY_PREFIX = 'ev_'
PASSWORD_RESET_PREFIX = 'pr_'


def hash_password(plain: str) -> str:
    return generate_password_hash(plain, method='scrypt')


def verify_password(plain: str, stored_hash: str) -> bool:
    try:
        return check_password_hash(stored_hash, plain)
    except Exception:
        return False


def new_token(prefix: str = '') -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 of the token. Tokens are 256-bit URL-safe random, so a fast
    hash is fine — there's no dictionary attack surface."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()
