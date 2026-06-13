"""Password hashing + opaque-token generation/verification."""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

# Password policy. Length-first: a long passphrase is the easiest strong
# password to remember, so 16+ chars is accepted on length alone, while
# shorter passwords must mix character classes. MIN is the hard floor.
MIN_PASSWORD_LEN = 8
PASSPHRASE_LEN = 16        # at/above this length, the class-mix rule is waived
MAX_PASSWORD_LEN = 200     # scrypt input guard
PASSWORD_POLICY_TEXT = (
    f'At least {MIN_PASSWORD_LEN} characters with 3 of: a lowercase letter, '
    f'an uppercase letter, a number, a symbol — or a passphrase of {PASSPHRASE_LEN}+ characters.'
)

PAT_PREFIX = 'irp_'
EMAIL_VERIFY_PREFIX = 'ev_'
PASSWORD_RESET_PREFIX = 'pr_'


def validate_password(pw: str) -> Optional[str]:
    """Return an error message if the password violates policy, else None.

    Existing accounts are unaffected — login never re-validates, so this
    gates only newly set passwords (register / reset / change). Old short
    passwords keep working until their owner changes them.
    """
    pw = pw or ''
    if len(pw) < MIN_PASSWORD_LEN:
        return f'Password must be at least {MIN_PASSWORD_LEN} characters.'
    if len(pw) > MAX_PASSWORD_LEN:
        return f'Password must be at most {MAX_PASSWORD_LEN} characters.'
    classes = sum((
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw),
    ))
    if len(pw) < PASSPHRASE_LEN and classes < 3:
        return ('Password needs at least 3 of: a lowercase letter, an uppercase '
                f'letter, a number, a symbol — or make it a {PASSPHRASE_LEN}+ character passphrase.')
    return None


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
